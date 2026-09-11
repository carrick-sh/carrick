//! # Unit and Conformance Tests for Foreign MM Operations

#![cfg(all(test, target_os = "macos", target_arch = "aarch64"))]

use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use carrick_guest_mem::{Gpa, GuestVa};

const TEST_VA: u64 = 0x6000_2000_0000;
const OWNER_LEN: usize = 0x4000;
use crate::trap::foreign_mm_tests::FOREIGN_MM_TEST_LOCK;

#[test]
fn cow_refusal_history_is_bounded_and_selects_the_exact_carrier_extent() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let mut history = CowDiagnosticHistory::default();
    for sequence in 0..(COW_DIAGNOSTIC_HISTORY_LIMIT as u64 + 4) {
        history.push(CowDiagnosticEvent::Retirement {
            custody: 7,
            ipa: 0x9b00_0000 + sequence * OWNER_LEN as u64,
            length: OWNER_LEN as u64,
            expected_generation: Some(sequence + 1),
            outcome: CowDiagnosticRetirementOutcome::Retired,
        });
    }
    history.push(CowDiagnosticEvent::Retirement {
        custody: 8,
        ipa: 0x9c00_0000,
        length: OWNER_LEN as u64,
        expected_generation: Some(99),
        outcome: CowDiagnosticRetirementOutcome::Retired,
    });

    assert_eq!(history.rows.len(), COW_DIAGNOSTIC_HISTORY_LIMIT);
    let target = 0x9b00_0000 + (COW_DIAGNOSTIC_HISTORY_LIMIT as u64 + 3) * OWNER_LEN as u64;
    let relevant = history.relevant(7, target, None, 8);
    assert_eq!(relevant.len(), 1);
    assert!(matches!(
        relevant[0],
        CowDiagnosticEvent::Retirement {
            custody: 7,
            ipa,
            length,
            ..
        } if ipa == target && length == OWNER_LEN as u64
    ));
}

#[test]
fn cow_refusal_history_retains_exact_extent_across_unrelated_churn() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let mut history = CowDiagnosticHistory::default();
    let target = 0x9b7f_0000;
    history.push(CowDiagnosticEvent::ReplacementCommitted {
        custody: 7,
        linux_pid: 41,
        mm: 43,
        semantic_va: TEST_VA,
        old_physical_ipa: 0x9b7e_c000,
        new_physical_ipa: target,
        new_host_addr: 0x7100_0000,
        new_owner_generation: 47,
        new_frame: 49,
        new_mapping: 51,
        retired_old_stage2: true,
    });
    for sequence in 0..(COW_DIAGNOSTIC_HISTORY_LIMIT as u64 + 4) {
        history.push(CowDiagnosticEvent::Retirement {
            custody: 7,
            ipa: 0x9c00_0000 + sequence * OWNER_LEN as u64,
            length: OWNER_LEN as u64,
            expected_generation: Some(sequence + 1),
            outcome: CowDiagnosticRetirementOutcome::Retired,
        });
    }

    let relevant = history.relevant(7, target, None, 8);
    assert!(
        relevant.iter().any(|event| matches!(
            event,
            CowDiagnosticEvent::ReplacementCommitted {
                new_physical_ipa,
                new_owner_generation: 47,
                ..
            } if *new_physical_ipa == target
        )),
        "unrelated physical churn evicted the exact replacement lifecycle: {relevant:?}"
    );
}

#[derive(Clone, Copy)]
enum CowSourceInventoryFixture {
    Absent,
    CurrentOffsetLogicalKey,
    ZeroGeneration,
    MismatchedGeneration,
    ConflictingOwners,
}

fn inventoried_cow_source_fixture(
    inventory: CowSourceInventoryFixture,
) -> (HvfTaskState, Arc<CarrierVmCustody>, (u64, u64), u64) {
    let custody = Arc::new(CarrierVmCustody::new_live_fixture());
    let mut lease = GlobalFrameStage2Lease::reserve(OWNER_LEN as u64, OWNER_LEN as u64)
        .expect("reserve COW source global-frame IPA");
    let key = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        OWNER_LEN,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate COW source host backing");
    let host_addr = host.as_ptr() as usize;
    unsafe { host.as_ptr().write_bytes(0xa5, OWNER_LEN) };
    assert_eq!(
        unsafe { inventory_hv_vm_map(host.as_ptr().cast(), key.0, OWNER_LEN, 3) },
        0,
    );
    lease.mark_mapped();
    let generation = register_global_frame_host_owner_in(&custody, lease, host, 3)
        .expect("register COW source owner");

    let mut task = HvfTaskState::neutral();
    task.persistent_vm_lifecycle = true;
    task.mm_root_slot = Some((0x9a00_f000_0000, 0x20_0000));
    task.container_root = ContainerRootToken::from_raw(250);
    if !matches!(inventory, CowSourceInventoryFixture::Absent) {
        let inventory_generation = match inventory {
            CowSourceInventoryFixture::CurrentOffsetLogicalKey
            | CowSourceInventoryFixture::ConflictingOwners => generation,
            CowSourceInventoryFixture::ZeroGeneration => 0,
            CowSourceInventoryFixture::MismatchedGeneration => generation.saturating_add(1),
            CowSourceInventoryFixture::Absent => unreachable!(),
        };
        let mut frame_inventory = task.frame_inventory.lock();
        frame_inventory.extents.insert(
            (key.0 + 0x1000, 0x1000),
            InventoryExtent {
                frame: carrick_hal::FrameId::from_kernel_allocation(
                    NonZeroU64::new(9_601).unwrap(),
                ),
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    NonZeroU64::new(9_602).unwrap(),
                ),
                backing: InventoryBackingIdentity::Private(9_603),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr,
                    generation: inventory_generation,
                },
            },
        );
        if matches!(inventory, CowSourceInventoryFixture::ConflictingOwners) {
            frame_inventory.extents.insert(
                (key.0 + 0x2000, 0x1000),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        NonZeroU64::new(9_604).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        NonZeroU64::new(9_605).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(9_606),
                    stage2_base: key.0,
                    stage2_length: key.1,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr,
                        generation: generation.saturating_add(1),
                    },
                },
            );
        }
    }
    (task, custody, key, generation)
}

#[derive(Debug, Eq, PartialEq)]
struct InventoryExtentFingerprint {
    key: (u64, u64),
    frame: carrick_hal::FrameId,
    mapping: carrick_hal::MappingId,
    backing: InventoryBackingIdentity,
    stage2_base: u64,
    stage2_length: u64,
    owner_host_addr: usize,
    owner_generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct InventoryFingerprint {
    initialized: bool,
    extents: Vec<InventoryExtentFingerprint>,
    shared: std::collections::BTreeMap<InventoryBackingIdentity, carrick_hal::FrameId>,
    references: std::collections::BTreeMap<carrick_hal::FrameId, usize>,
    extent_references: std::collections::BTreeMap<(carrick_hal::FrameId, u64, u64), usize>,
    stage2_references: std::collections::BTreeMap<(u64, u64), usize>,
    authority_retained_stage2: std::collections::BTreeSet<(u64, u64)>,
}

fn inventory_fingerprint(inventory: &HvpatchFrameInventory) -> InventoryFingerprint {
    let frames = inventory.frames.lock();
    InventoryFingerprint {
        initialized: inventory.initialized,
        extents: inventory
            .extents
            .iter()
            .map(|(&key, extent)| InventoryExtentFingerprint {
                key,
                frame: extent.frame,
                mapping: extent.mapping,
                backing: extent.backing,
                stage2_base: extent.stage2_base,
                stage2_length: extent.stage2_length,
                owner_host_addr: extent.stage2_owner.host_addr,
                owner_generation: extent.stage2_owner.generation,
            })
            .collect(),
        shared: frames.shared.clone(),
        references: frames.references.clone(),
        extent_references: frames.extent_references.clone(),
        stage2_references: frames.stage2_references.clone(),
        authority_retained_stage2: frames.authority_retained_stage2.clone(),
    }
}

pub(crate) struct ExternalAliasStateRestore {
    aliases: Vec<AliasBacking>,
    replay: std::collections::BTreeSet<ReplayMappingKey>,
}

impl ExternalAliasStateRestore {
    pub(crate) fn capture() -> Self {
        let replay = replay_mappings().lock().clone();
        let aliases = alias_registry().lock().ordered();
        Self { aliases, replay }
    }
}

impl Drop for ExternalAliasStateRestore {
    fn drop(&mut self) {
        mutate_external_alias_state(|replay, aliases| {
            *replay = std::mem::take(&mut self.replay);
            aliases.replace_all(std::mem::take(&mut self.aliases));
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestSnapshot {
    mm: NonZeroU64,
    asid: NonZeroU16,
    stage1_root: Gpa,
    backend_revision: carrick_hal::ForeignBackendRevision,
    vma_revision: carrick_hal::ForeignVmaRevision,
    frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision,
    mapping_ids: Vec<carrick_hal::MappingId>,
    executable_ranges: Vec<carrick_hal::ForeignExecutableRange>,
    readable_ranges: Vec<carrick_hal::ForeignReadableRange>,
}

impl carrick_hal::ForeignMmSnapshot for TestSnapshot {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        carrick_hal::ForeignMmId::from_kernel_allocation(self.mm)
    }
    fn binding(&self) -> carrick_hal::ForeignMmBinding {
        carrick_hal::ForeignMmBinding::for_aarch64(
            carrick_hal::ForeignAsid::from_kernel_allocation(self.asid),
            self.stage1_root,
        )
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.backend_revision
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.vma_revision
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.frame_inventory_revision
    }
    fn mapping_ids(&self) -> &[carrick_hal::MappingId] {
        &self.mapping_ids
    }

    fn executable_ranges(&self) -> &[carrick_hal::ForeignExecutableRange] {
        &self.executable_ranges
    }

    fn readable_ranges(&self) -> &[carrick_hal::ForeignReadableRange] {
        &self.readable_ranges
    }
}

struct TestPtraceTextAuthority {
    snapshot: TestSnapshot,
    start: GuestVa,
    len: usize,
}

// SAFETY: This test authority is constructed only from the exact snapshot
// retained by the test lease and remains borrowed through plan use.
unsafe impl carrick_hal::ForeignPtraceTextAuthority for TestPtraceTextAuthority {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        carrick_hal::ForeignMmSnapshot::mm(&self.snapshot)
    }

    fn binding(&self) -> carrick_hal::ForeignMmBinding {
        carrick_hal::ForeignMmSnapshot::binding(&self.snapshot)
    }

    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        carrick_hal::ForeignMmSnapshot::backend_revision(&self.snapshot)
    }

    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        carrick_hal::ForeignMmSnapshot::vma_revision(&self.snapshot)
    }

    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        carrick_hal::ForeignMmSnapshot::frame_inventory_revision(&self.snapshot)
    }

    fn start(&self) -> GuestVa {
        self.start
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
struct TestLiveAuthority(Arc<parking_lot::RwLock<TestSnapshot>>);

impl carrick_hal::ForeignMmLiveAuthority for TestLiveAuthority {
    fn snapshot(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn carrick_hal::ForeignMmSnapshot>, carrick_hal::ForeignMmTransportError> {
        let observed = self
            .0
            .try_read_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        Ok(Box::new(observed.clone()))
    }
}

struct InstalledMm {
    snapshot: TestSnapshot,
    live: TestLiveAuthority,
    state: Arc<MmAccessState>,
    owners: OwnerCleanup,
}

struct OwnerCleanup(Vec<(u64, u64)>);

impl Drop for OwnerCleanup {
    fn drop(&mut self) {
        alias_registry().lock().retain(|alias| {
            !self.0.iter().any(|&(ipa, length)| {
                (alias.physical_ipa, alias.physical_size as u64) == (ipa, length)
            })
        });
        let mut owners = global_frame_host_owners().lock();
        for key in self.0.drain(..) {
            owners.remove(&key);
        }
    }
}

#[derive(Debug)]
struct TestForeignCowAuthority {
    live: Arc<parking_lot::RwLock<TestSnapshot>>,
    old_frame: carrick_hal::FrameId,
    allow_quiesce: bool,
    serial: std::sync::atomic::AtomicU64,
    published: parking_lot::Mutex<Option<(carrick_hal::MappingId, carrick_hal::FrameId, Gpa, u64)>>,
}

impl TestForeignCowAuthority {
    fn new(installed: &InstalledMm) -> Self {
        let old_frame = installed
            .state
            .frame_inventory
            .ledger
            .lock()
            .extents
            .get(&installed.owners.0[1])
            .expect("data inventory extent")
            .frame;
        Self {
            live: Arc::clone(&installed.live.0),
            old_frame,
            allow_quiesce: false,
            serial: std::sync::atomic::AtomicU64::new(
                installed.snapshot.mm.get().saturating_mul(1_000),
            ),
            published: parking_lot::Mutex::new(None),
        }
    }

    fn next(&self) -> NonZeroU64 {
        NonZeroU64::new(
            self.serial
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        )
        .expect("foreign COW test identity")
    }
}

impl carrick_hal::FrameCowAuthority for TestForeignCowAuthority {
    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        if self.allow_quiesce {
            Ok(Box::new(()))
        } else {
            panic!("foreign backend must not reacquire frame-COW quiesce")
        }
    }

    fn reserve(
        &self,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_count: usize,
    ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
    {
        let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(self.next());
        let frames = (0..frame_candidates)
            .map(|_| carrick_hal::FrameId::from_kernel_allocation(self.next()))
            .collect();
        let mappings = (0..mapping_candidates)
            .map(|_| carrick_hal::MappingId::from_kernel_allocation(self.next()))
            .collect();
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x7a; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    transaction,
                    carrick_hal::FrameEventCapacity::for_event_count(event_count)?,
                )?,
                frames,
                mappings,
            ),
        )
    }

    fn apply(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let events = commit.batch().events();
        let mut removed = Vec::new();
        let mut prepared = Vec::new();
        for event in events {
            match *event {
                carrick_hal::FrameInventoryEvent::UnmapMapping { mapping, .. } => {
                    removed.push(mapping)
                }
                carrick_hal::FrameInventoryEvent::PrepareMapping {
                    frame,
                    mapping,
                    gpa,
                    length,
                    ..
                } => prepared.push((mapping, frame, gpa, length.raw())),
                _ => {}
            }
        }
        let new = prepared
            .iter()
            .copied()
            .find(|(_, frame, _, _)| *frame != self.old_frame)
            .expect("new private foreign COW mapping");
        let mut live = self.live.write();
        live.mapping_ids
            .retain(|mapping| !removed.contains(mapping));
        live.mapping_ids
            .extend(prepared.iter().map(|(mapping, _, _, _)| *mapping));
        live.mapping_ids.sort_unstable();
        live.mapping_ids.dedup();
        live.frame_inventory_revision =
            carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                live.frame_inventory_revision.raw_for_probe() + 1,
            );
        *self.published.lock() = Some(new);
        Ok(())
    }

    fn apply_with_receipt(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryApplyReceipt, Box<dyn std::error::Error + Send + Sync>>
    {
        let transaction = commit.batch().transaction();
        let mappings = commit
            .batch()
            .events()
            .iter()
            .filter_map(|event| match *event {
                carrick_hal::FrameInventoryEvent::PrepareMapping { mapping, frame, .. } => {
                    Some((mapping, frame))
                }
                _ => None,
            })
            .collect();
        self.apply(commit)?;
        let live = self.live.read();
        Ok(
            carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x7a; 32]),
                transaction,
                live.mm,
                live.frame_inventory_revision.raw_for_probe(),
                mappings,
            ),
        )
    }

    fn apply_foreign_cow(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
        _semantic_start: carrick_guest_mem::GuestVa,
        _semantic_len: std::num::NonZeroUsize,
        _mapping: carrick_hal::MappingId,
        _frame: carrick_hal::FrameId,
        gpa: Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<
        (
            carrick_hal::FrameInventoryApplyReceipt,
            carrick_hal::ForeignCowKernelProof,
            carrick_hal::ForeignOwnerGeneration,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let owner_generation = global_frame_host_owner_generation(gpa.raw(), length.raw());
        let owner_generation = std::num::NonZeroU64::new(owner_generation)
            .map(carrick_hal::ForeignOwnerGeneration::from_backend_counter)
            .ok_or_else(|| std::io::Error::other("test foreign COW owner is not live"))?;
        Ok((
            self.apply_with_receipt(commit)?,
            carrick_hal::ForeignCowKernelProof::from_runtime_authority(Box::new(())),
            owner_generation,
        ))
    }

    fn mapping_is_live(
        &self,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .published
            .lock()
            .as_ref()
            .is_some_and(|published| *published == (mapping, frame, gpa, length.raw())))
    }

    fn frame_mapping_count(
        &self,
        frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok((frame == self.old_frame).then_some(2))
    }
}

#[derive(Debug)]
struct TestInvalidator {
    expected: carrick_hal::ForeignMmBinding,
    calls: usize,
    fail_call: Option<usize>,
}

impl carrick_hal::ForeignMmInvalidator for TestInvalidator {
    fn invalidate_exact_asid(
        &mut self,
        binding: carrick_hal::ForeignMmBinding,
        _deadline: Instant,
    ) -> Result<(), carrick_hal::ForeignMmTransportError> {
        assert_eq!(binding, self.expected);
        self.calls += 1;
        if self.fail_call == Some(self.calls) {
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
        Ok(())
    }
}

fn nonzero(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).expect("nonzero fixture identity")
}

fn install_owner(ipa: u64, bytes: &[u8]) -> (u64, usize) {
    let length = bytes.len();
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        length,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("foreign-read owner backing");
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.as_ptr(), length);
    }
    let host_addr = mapping.as_ptr() as usize;
    let generation = next_global_frame_owner_generation();
    let owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(ipa, length as u64),
        mapping,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
        generation,
        ipa,
        length as u64,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(
                (ipa, length as u64),
                GlobalFrameOwnerEntry::Live(Arc::new(owner))
            )
            .is_none(),
        "fixture IPA must be unique"
    );
    (generation, host_addr)
}

fn install_mm(
    transport: &CarrierForeignMmTransport,
    ordinal: u64,
    root: u64,
    data_ipa: u64,
    bytes: [u8; 4],
) -> InstalledMm {
    install_mm_with_data_len(transport, ordinal, root, data_ipa, OWNER_LEN, &bytes)
}

fn install_mm_with_data_len(
    transport: &CarrierForeignMmTransport,
    ordinal: u64,
    root: u64,
    data_ipa: u64,
    data_len: usize,
    bytes: &[u8],
) -> InstalledMm {
    install_mm_sparse(
        transport, ordinal, root, data_ipa, data_len, data_len, bytes,
    )
}

fn install_mm_sparse(
    transport: &CarrierForeignMmTransport,
    ordinal: u64,
    root: u64,
    data_ipa: u64,
    data_len: usize,
    vma_len: usize,
    bytes: &[u8],
) -> InstalledMm {
    assert!(vma_len >= data_len, "vma_len must be at least data_len");
    assert!(data_len >= bytes.len(), "fixture bytes must fit data owner");
    assert_eq!(
        data_len as u64 % CowArmedRanges::COMPOUND_SIZE,
        0,
        "fixture owner must contain whole host compounds",
    );
    let mut tables = carrick_mem::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables.rebase(root, None).expect("rebase foreign test root");
    tables
        .map_aliased(TEST_VA, data_ipa, data_len as u64, false, None)
        .expect("map foreign test leaf");

    // The manager retains only populated bytes; the host owner must still
    // cover the full primary arena that the publication resolver pins.
    let mut table_bytes = tables.as_bytes().to_vec();
    table_bytes.resize(carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize, 0);
    let (table_generation, table_host) = install_owner(root, &table_bytes);
    let mut data_bytes = vec![0_u8; data_len];
    data_bytes[..bytes.len()].copy_from_slice(bytes);
    let (data_generation, data_host) = install_owner(data_ipa, &data_bytes);

    let table_mapping = carrick_hal::MappingId::from_kernel_allocation(nonzero(ordinal * 10));
    let data_mapping = carrick_hal::MappingId::from_kernel_allocation(nonzero(ordinal * 10 + 1));
    let table_frame = carrick_hal::FrameId::from_kernel_allocation(nonzero(ordinal * 10 + 2));
    let data_frame = carrick_hal::FrameId::from_kernel_allocation(nonzero(ordinal * 10 + 3));
    let mut inventory = HvpatchFrameInventory {
        initialized: true,
        ..HvpatchFrameInventory::default()
    };
    inventory.extents.insert(
        (root, table_bytes.len() as u64),
        InventoryExtent {
            frame: table_frame,
            mapping: table_mapping,
            backing: InventoryBackingIdentity::Private(ordinal * 10 + 4),
            stage2_base: root,
            stage2_length: table_bytes.len() as u64,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: table_host,
                generation: table_generation,
            },
        },
    );
    inventory.extents.insert(
        (data_ipa, data_len as u64),
        InventoryExtent {
            frame: data_frame,
            mapping: data_mapping,
            backing: InventoryBackingIdentity::Private(ordinal * 10 + 5),
            stage2_base: data_ipa,
            stage2_length: data_len as u64,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: data_host,
                generation: data_generation,
            },
        },
    );
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(table_frame, 1);
        frames.references.insert(data_frame, 1);
        frames
            .extent_references
            .insert((table_frame, root, table_bytes.len() as u64), 1);
        frames
            .extent_references
            .insert((data_frame, data_ipa, data_len as u64), 1);
        frames
            .stage2_references
            .insert((root, table_bytes.len() as u64), 1);
        frames
            .stage2_references
            .insert((data_ipa, data_len as u64), 1);
    }
    let asid = NonZeroU16::new(ordinal as u16).expect("nonzero test ASID");
    let binding = CarrierForeignMmBinding {
        asid: carrick_hal::ForeignAsid::from_kernel_allocation(asid),
        stage1_root: Gpa(root),
    };
    let snapshot = TestSnapshot {
        mm: nonzero(ordinal),
        asid,
        stage1_root: Gpa(root),
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(17),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(19),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
            23,
        ),
        mapping_ids: vec![table_mapping, data_mapping],
        executable_ranges: Vec::new(),
        readable_ranges: vec![
            carrick_hal::ForeignReadableRange::from_kernel_projection(
                GuestVa(TEST_VA),
                GuestVa(TEST_VA + vma_len as u64),
            )
            .unwrap(),
        ],
    };
    let state = MmAccessState::for_foreign_read_test(
        binding,
        carrick_aarch64::Stage1Authority::new_with_manager(Some(tables)),
        Arc::new(MemoryProtections::default()),
        Arc::new(parking_lot::Mutex::new(inventory)),
        &snapshot,
    );
    if vma_len > data_len {
        let deferred = Arc::new(carrick_guest_mem::DeferredAnonymousState::new());
        deferred
            .reserve_fresh(GuestVa(TEST_VA + data_len as u64), vma_len - data_len)
            .unwrap();
        *state.deferred_anonymous.write() = Some((
            carrick_hal::ForeignMmId::from_kernel_allocation(nonzero(ordinal)),
            deferred,
        ));
    }
    transport.register(&snapshot, &state);
    InstalledMm {
        live: TestLiveAuthority(Arc::new(parking_lot::RwLock::new(snapshot.clone()))),
        snapshot,
        state,
        owners: OwnerCleanup(vec![
            (root, table_bytes.len() as u64),
            (data_ipa, data_len as u64),
        ]),
    }
}

fn read_installed(
    transport: &CarrierForeignMmTransport,
    installed: &InstalledMm,
    dst: &mut [u8],
) -> Result<Box<dyn carrick_hal::ForeignMmReadReceipt>, carrick_hal::ForeignMmTransportError> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let lease = endpoint.retain(&installed.snapshot, deadline)?;
    lease.read(
        &installed.live,
        &installed.snapshot,
        GuestVa(TEST_VA),
        dst,
        deadline,
    )
}

fn prepare_foreign_cow(
    installed: &InstalledMm,
) -> (
    Arc<TestForeignCowAuthority>,
    carrick_hal::ForeignMmLeaseEndpoint,
    TestInvalidator,
) {
    let data_key = installed.owners.0[1];
    let (host_addr, generation) =
        global_frame_host_owner_identity(data_key.0, data_key.1).expect("foreign COW source owner");
    let backing = installed
        .state
        .frame_inventory
        .ledger
        .lock()
        .extents
        .get(&data_key)
        .expect("foreign COW source inventory")
        .backing;
    let root_key = installed.owners.0[0];
    let scope = Some(root_key);
    register_shared_alias(AliasBacking {
        start: TEST_VA,
        ipa: data_key.0,
        host_addr,
        size: data_key.1 as usize,
        physical_ipa: data_key.0,
        physical_host_addr: host_addr,
        physical_size: data_key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            scope,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    });
    installed
        .state
        .cow_armed
        .lock()
        .arm(&[carrick_aarch64::vmm::ForkCowRange {
            va: TEST_VA,
            len: data_key.1 as usize,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        }]);
    let authority = Arc::new(TestForeignCowAuthority::new(installed));
    installed.state.bind_cow_runtime(MmCowRuntimeBinding {
        authority: authority.clone(),
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: installed.snapshot.mm.get() as i32,
            linux_tid: installed.snapshot.mm.get() as i32,
            mm: installed.snapshot.mm.get(),
            asid: installed.snapshot.asid.get(),
        },
        mm_root_slot: scope,
        container_root: ContainerRootToken::ROOT,
        persistent_vm_lifecycle: true,
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    let endpoint =
        carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(CarrierForeignMmTransport {
            states: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::from([
                (
                    CarrierForeignMmSnapshot::capture(&installed.snapshot).binding,
                    Arc::downgrade(&installed.state),
                ),
            ]))),
            custody: Arc::clone(legacy_test_carrier_vm_custody_arc()),
        }));
    let lease = endpoint
        .retain(&installed.snapshot, deadline)
        .expect("retain foreign COW state");
    let invalidator = TestInvalidator {
        expected: carrick_hal::ForeignMmSnapshot::binding(&installed.snapshot),
        calls: 0,
        fail_call: None,
    };
    (authority, lease, invalidator)
}

fn foreign_cow_fingerprint(installed: &InstalledMm) -> (Vec<u8>, String, Vec<(u64, u64)>) {
    let tables = installed.state.page_tables_authority();
    let stage1 = tables
        .with_manager(|mgr| mgr.as_bytes().to_vec())
        .expect("foreign COW page tables");
    let inventory = format!("{:?}", *installed.state.frame_inventory.ledger.lock());
    let owners = global_frame_host_owners().lock().keys().copied().collect();
    (stage1, inventory, owners)
}

#[test]
fn sparse_replacement_failure_preserves_preimage_before_retirement() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external = ExternalAliasStateRestore::capture();
    for after_sync in [false, true] {
        let stub = ScopedStage2MapTestStub::enable();
        let transport = CarrierForeignMmTransport::new();
        let installed = install_mm(
            &transport,
            197,
            0x9a00_6000_0000,
            0x9b00_6000_0000,
            *b"kept",
        );
        let (_authority, _lease, _invalidator) = prepare_foreign_cow(&installed);
        let mut authority = TestForeignCowAuthority::new(&installed);
        authority.allow_quiesce = true;
        installed
            .state
            .cow_runtime
            .write()
            .as_mut()
            .unwrap()
            .authority = Arc::new(authority);
        let identity = installed
            .state
            .cow_runtime
            .read()
            .as_ref()
            .unwrap()
            .identity;
        let context = sparse_materialization::PublicationContext::for_local(
            installed.state.clone(),
            Arc::clone(legacy_test_carrier_vm_custody_arc()),
            identity,
        )
        .unwrap();
        let before = foreign_cow_fingerprint(&installed);
        let aliases_before = alias_registry().lock().ordered();
        let retired = std::cell::Cell::new(false);
        if after_sync {
            STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_sparse_publication_after_sync = true);
        } else {
            stub.set_fail_stage_mapping(true);
        }
        let result = sparse_materialization::publish_replacing(
            &context,
            TEST_VA,
            TEST_VA + 4096,
            SparseExtentBacking::SeededAnon { bytes: b"next" },
            &mut || Ok(()),
            &mut || retired.set(true),
        );
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("injected publication must fail"),
        };
        let expected = if after_sync {
            "injected sparse publication failure after sync"
        } else {
            "injected stage_mapping failure"
        };
        assert!(error.contains(expected), "wrong failure boundary: {error}");
        assert!(
            !retired.get(),
            "failed publication must not retire the preimage"
        );
        assert_eq!(foreign_cow_fingerprint(&installed), before);
        assert_eq!(alias_registry().lock().ordered(), aliases_before);
        let mut bytes = [0; 4];
        read_installed(&transport, &installed, &mut bytes).unwrap();
        assert_eq!(&bytes, b"kept");
        assert!(installed.state.cow_armed.lock().span_for(TEST_VA).is_some());
    }
}

#[test]
fn foreign_cow_write_keeps_the_shared_parent_owner_unchanged() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        121,
        0x9a00_1800_0000,
        0x9b00_1800_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);
    let cow = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("foreign child COW");
    assert_eq!(invalidator.calls, 1);
    let old_key = child.owners.0[1];
    let mut parent_bytes = [0_u8; 4];
    copy_from_pinned_owner(
        &RetainedForeignMmBacking {
            extents: vec![RetainedForeignExtent {
                key: old_key,
                owner: RetainedPhysicalOwner::Global(
                    global_frame_host_owners().lock()[&old_key]
                        .owner()
                        .pin()
                        .expect("pin shared parent owner"),
                ),
            }],
        },
        old_key.0,
        &mut parent_bytes,
    )
    .expect("read shared parent owner");
    assert_eq!(&parent_bytes, b"old!");
    let post = child.live.0.read().clone();
    let prepared = lease
        .prepare_write(
            &child.live,
            &post,
            cow.as_ref(),
            GuestVa(TEST_VA),
            b"new!",
            deadline,
        )
        .expect("prepare authenticated child owner write");
    assert_eq!(prepared.receipt().bytes_written(), 4);
    prepared.commit();
    assert_eq!(&parent_bytes, b"old!");
    let new_key = (cow.physical_base().raw(), cow.physical_len());
    let new_owner = global_frame_host_owners().lock()[&new_key].owner().clone();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(new_owner.as_ptr(), 4) },
        b"new!"
    );
    child.owners.0.push(new_key);
}

#[test]
fn ptrace_text_cow_accepts_unarmed_rx_mapping_and_preserves_peer_and_stage1_ap() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let request_va = TEST_VA + 0x100;
    let neighbor_va = TEST_VA + 0x800;
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        132,
        0x9a00_2300_0000,
        0x9b00_2300_0000,
        *b"old!",
    );
    child.snapshot.executable_ranges = vec![
        carrick_hal::ForeignExecutableRange::from_kernel_projection(
            GuestVa(TEST_VA),
            GuestVa(TEST_VA + 0x2000),
        )
        .expect("nonempty executable fixture range"),
    ];
    *child.live.0.write() = child.snapshot.clone();

    let old_key = child.owners.0[1];
    let (host_addr, generation) =
        global_frame_host_owner_identity(old_key.0, old_key.1).expect("RX COW source owner");
    let backing = child
        .state
        .frame_inventory
        .ledger
        .lock()
        .extents
        .get(&old_key)
        .expect("RX COW source inventory")
        .backing;
    let root_key = child.owners.0[0];
    let scope = Some(root_key);
    register_shared_alias(AliasBacking {
        start: TEST_VA,
        ipa: old_key.0,
        host_addr,
        size: old_key.1 as usize,
        physical_ipa: old_key.0,
        physical_host_addr: host_addr,
        physical_size: old_key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadExec),
        guest_writable: false,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            scope,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    });
    register_shared_alias(AliasBacking {
        start: TEST_VA + 0x4000,
        ipa: old_key.0 - 0x1000,
        host_addr,
        size: old_key.1 as usize,
        physical_ipa: old_key.0,
        physical_host_addr: host_addr,
        physical_size: old_key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            scope,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    });
    assert!(
        child.state.cow_armed.lock().span_for(TEST_VA).is_none(),
        "RX ptrace text must not depend on writable-fault COW arming",
    );

    let authority = Arc::new(TestForeignCowAuthority::new(&child));
    child.state.bind_cow_runtime(MmCowRuntimeBinding {
        authority: authority.clone(),
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: child.snapshot.mm.get() as i32,
            linux_tid: child.snapshot.mm.get() as i32,
            mm: child.snapshot.mm.get(),
            asid: child.snapshot.asid.get(),
        },
        mm_root_slot: scope,
        container_root: ContainerRootToken::ROOT,
        persistent_vm_lifecycle: true,
    });
    let endpoint =
        carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(CarrierForeignMmTransport {
            states: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::from([
                (
                    CarrierForeignMmSnapshot::capture(&child.snapshot).binding,
                    Arc::downgrade(&child.state),
                ),
            ]))),
            custody: Arc::clone(legacy_test_carrier_vm_custody_arc()),
        }));
    let deadline = Instant::now() + Duration::from_secs(1);
    let lease = endpoint
        .retain(&child.snapshot, deadline)
        .expect("retain RX ptrace text state");
    let ptrace_authority = TestPtraceTextAuthority {
        snapshot: child.snapshot.clone(),
        start: GuestVa(request_va),
        len: 4,
    };
    let plan = lease
        .prepare_ptrace_text_cow(&child.snapshot, &ptrace_authority)
        .expect("mint authenticated RX ptrace text plan");
    let page_tables = child.state.page_tables_authority();
    const AP_MASK: u64 = 0b11 << 6;
    let (before_ap, before_ipa) = page_tables
        .with_manager(|tables| {
            let ap =
                carrick_mem::page_table::terminal_descriptor(tables.debug_walk(TEST_VA)) & AP_MASK;
            let ipa = tables
                .translate_retained_output(TEST_VA)
                .expect("RX source translation");
            (ap, ipa)
        })
        .expect("RX page tables");
    assert!(
        alias_registry().lock().iter().any(|alias| {
            TEST_VA.checked_sub(alias.start).is_some_and(|offset| {
                offset < alias.size as u64 && alias.ipa.checked_add(offset) == Some(before_ipa)
            })
        }),
        "fixture must publish a semantic alias for source IPA 0x{before_ipa:x}",
    );
    let mut invalidator = TestInvalidator {
        expected: carrick_hal::ForeignMmSnapshot::binding(&child.snapshot),
        calls: 0,
        fail_call: None,
    };
    let cow = lease
        .break_cow_prepared_ptrace_text(
            &mut invalidator,
            &child.snapshot,
            GuestVa(request_va),
            4,
            &plan,
            deadline,
        )
        .expect("RX ptrace text must break COW without writable-fault arming");
    let after_ap = page_tables
        .with_manager(|mgr| carrick_mem::page_table::terminal_descriptor(mgr.debug_walk(TEST_VA)))
        .expect("post-COW RX page tables")
        & AP_MASK;
    assert_eq!(
        after_ap, before_ap,
        "a same-IPA alias at another semantic VA must not widen RX stage-1 AP",
    );
    assert_eq!(cow.range_start(), GuestVa(TEST_VA));
    assert_eq!(cow.range_len(), 0x2000);

    let new_key = (cow.physical_base().raw(), cow.physical_len());
    let owners = global_frame_host_owners().lock();
    let peer_owner = owners[&old_key].owner().clone();
    let child_owner = owners[&new_key].owner().clone();
    drop(owners);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(peer_owner.as_ptr(), 4) },
        b"old!",
        "shared peer must retain the pre-patch instruction bytes",
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(child_owner.as_ptr(), 4) },
        b"old!",
        "ptrace target must receive a private copy of the source bytes",
    );
    assert_eq!(
        page_tables
            .with_manager(|mgr| mgr.translate_retained_output(neighbor_va))
            .expect("post-COW RX page tables"),
        Some(cow.physical_base().raw() + 0x800),
        "the neighboring address in the repointed leaf must resolve into the private owner",
    );
    assert!(
        alias_registry().lock().iter().any(|alias| {
            alias.start <= neighbor_va
                && neighbor_va < alias.start.saturating_add(alias.size as u64)
                && alias.physical_ipa == cow.physical_base().raw()
                && !alias.guest_writable
        }),
        "alias authority must cover the neighboring address changed by stage-1 repointing",
    );
    child.owners.0.push(new_key);
}

#[test]
fn ptrace_text_cow_rejects_source_alias_shorter_than_authenticated_span() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        133,
        0x9a00_2400_0000,
        0x9b00_2400_0000,
        *b"old!",
    );
    child.snapshot.executable_ranges = vec![
        carrick_hal::ForeignExecutableRange::from_kernel_projection(
            GuestVa(TEST_VA),
            GuestVa(TEST_VA + 0x2000),
        )
        .expect("two-leaf executable fixture range"),
    ];
    *child.live.0.write() = child.snapshot.clone();

    let old_key = child.owners.0[1];
    let (host_addr, generation) =
        global_frame_host_owner_identity(old_key.0, old_key.1).expect("RX source owner");
    let backing = child
        .state
        .frame_inventory
        .ledger
        .lock()
        .extents
        .get(&old_key)
        .expect("RX source inventory")
        .backing;
    let root_key = child.owners.0[0];
    let scope = Some(root_key);
    register_shared_alias(AliasBacking {
        start: TEST_VA,
        ipa: old_key.0,
        host_addr,
        size: 0x1000,
        physical_ipa: old_key.0,
        physical_host_addr: host_addr,
        physical_size: old_key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadExec),
        guest_writable: false,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            scope,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    });
    let authority = Arc::new(TestForeignCowAuthority::new(&child));
    child.state.bind_cow_runtime(MmCowRuntimeBinding {
        authority: authority.clone(),
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: child.snapshot.mm.get() as i32,
            linux_tid: child.snapshot.mm.get() as i32,
            mm: child.snapshot.mm.get(),
            asid: child.snapshot.asid.get(),
        },
        mm_root_slot: scope,
        container_root: ContainerRootToken::ROOT,
        persistent_vm_lifecycle: true,
    });
    let endpoint =
        carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(CarrierForeignMmTransport {
            states: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::from([
                (
                    CarrierForeignMmSnapshot::capture(&child.snapshot).binding,
                    Arc::downgrade(&child.state),
                ),
            ]))),
            custody: Arc::clone(legacy_test_carrier_vm_custody_arc()),
        }));
    let deadline = Instant::now() + Duration::from_secs(1);
    let lease = endpoint
        .retain(&child.snapshot, deadline)
        .expect("retain short-alias RX state");
    let ptrace_authority = TestPtraceTextAuthority {
        snapshot: child.snapshot.clone(),
        start: GuestVa(TEST_VA + 0x100),
        len: 4,
    };
    let plan = lease
        .prepare_ptrace_text_cow(&child.snapshot, &ptrace_authority)
        .expect("mint two-leaf ptrace text plan");
    let page_tables = child.state.page_tables_authority();
    let before_second_leaf = page_tables
        .with_manager(|tables| tables.translate_retained_output(TEST_VA + 0x1000))
        .expect("short-alias RX page tables");
    let before = foreign_cow_fingerprint(&child);
    let mut invalidator = TestInvalidator {
        expected: carrick_hal::ForeignMmSnapshot::binding(&child.snapshot),
        calls: 0,
        fail_call: None,
    };
    let rejected = lease.break_cow_prepared_ptrace_text(
        &mut invalidator,
        &child.snapshot,
        GuestVa(TEST_VA + 0x100),
        4,
        &plan,
        deadline,
    );
    if let Ok(cow) = &rejected {
        child
            .owners
            .0
            .push((cow.physical_base().raw(), cow.physical_len()));
    }
    assert!(
        matches!(
            rejected,
            Err(carrick_hal::ForeignMmTransportError::OwnerStale)
        ),
        "an alias shorter than the authenticated two-leaf span must fail closed: {rejected:?}",
    );
    assert_eq!(invalidator.calls, 0, "rejection must precede publication");
    assert_eq!(foreign_cow_fingerprint(&child), before);
    assert_eq!(
        page_tables
            .with_manager(|mgr| mgr.translate_retained_output(TEST_VA + 0x1000))
            .expect("rejected RX page tables"),
        before_second_leaf,
        "the second source leaf must remain unchanged on rejection",
    );
}

#[test]
fn ptrace_text_cow_uses_authenticated_span_when_preexisting_arm_differs() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        134,
        0x9a00_2500_0000,
        0x9b00_2500_0000,
        *b"old!",
    );
    child.snapshot.executable_ranges = vec![
        carrick_hal::ForeignExecutableRange::from_kernel_projection(
            GuestVa(TEST_VA),
            GuestVa(TEST_VA + 0x2000),
        )
        .expect("two-leaf executable fixture range"),
    ];
    *child.live.0.write() = child.snapshot.clone();
    let old_key = child.owners.0[1];
    let (host_addr, generation) =
        global_frame_host_owner_identity(old_key.0, old_key.1).expect("RX source owner");
    let backing = child
        .state
        .frame_inventory
        .ledger
        .lock()
        .extents
        .get(&old_key)
        .expect("RX source inventory")
        .backing;
    let root_key = child.owners.0[0];
    let scope = Some(root_key);
    register_shared_alias(AliasBacking {
        start: TEST_VA,
        ipa: old_key.0,
        host_addr,
        size: old_key.1 as usize,
        physical_ipa: old_key.0,
        physical_host_addr: host_addr,
        physical_size: old_key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadExec),
        guest_writable: false,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            scope,
            ContainerRootToken::ROOT,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    });
    child
        .state
        .cow_armed
        .lock()
        .arm(&[carrick_aarch64::vmm::ForkCowRange {
            va: TEST_VA + 0x80,
            len: 0x1000,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        }]);
    let authority = Arc::new(TestForeignCowAuthority::new(&child));
    child.state.bind_cow_runtime(MmCowRuntimeBinding {
        authority: authority.clone(),
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: child.snapshot.mm.get() as i32,
            linux_tid: child.snapshot.mm.get() as i32,
            mm: child.snapshot.mm.get(),
            asid: child.snapshot.asid.get(),
        },
        mm_root_slot: scope,
        container_root: ContainerRootToken::ROOT,
        persistent_vm_lifecycle: true,
    });
    let endpoint =
        carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(CarrierForeignMmTransport {
            states: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::from([
                (
                    CarrierForeignMmSnapshot::capture(&child.snapshot).binding,
                    Arc::downgrade(&child.state),
                ),
            ]))),
            custody: Arc::clone(legacy_test_carrier_vm_custody_arc()),
        }));
    let deadline = Instant::now() + Duration::from_secs(1);
    let lease = endpoint
        .retain(&child.snapshot, deadline)
        .expect("retain mismatched-arm RX state");
    let ptrace_authority = TestPtraceTextAuthority {
        snapshot: child.snapshot.clone(),
        start: GuestVa(TEST_VA + 0x100),
        len: 4,
    };
    let plan = lease
        .prepare_ptrace_text_cow(&child.snapshot, &ptrace_authority)
        .expect("mint exact executable span plan");
    let mut invalidator = TestInvalidator {
        expected: carrick_hal::ForeignMmSnapshot::binding(&child.snapshot),
        calls: 0,
        fail_call: None,
    };
    let cow = lease
        .break_cow_prepared_ptrace_text(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA + 0x100),
            4,
            &plan,
            deadline,
        )
        .expect("an ordinary fork arm must not override the authenticated executable span");
    assert_eq!(cow.range_start(), GuestVa(TEST_VA));
    assert_eq!(cow.range_len(), 0x2000);
    assert_eq!(
        invalidator.calls, 1,
        "exact executable COW must publish once"
    );
    child
        .owners
        .0
        .push((cow.physical_base().raw(), cow.physical_len()));
}

#[test]
fn foreign_cow_one_compound_authorizes_distinct_subrange_writes() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        125,
        0x9a00_1c00_0000,
        0x9b00_1c00_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let old_key = child.owners.0[1];
    let deadline = Instant::now() + Duration::from_secs(1);
    let cow = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break the exact child compound once");
    let post = child.live.0.read().clone();

    lease
        .prepare_write(
            &child.live,
            &post,
            cow.as_ref(),
            GuestVa(TEST_VA),
            b"one!",
            deadline,
        )
        .expect("prepare first subrange")
        .commit();
    lease
        .prepare_write(
            &child.live,
            &post,
            cow.as_ref(),
            GuestVa(TEST_VA + 0x1000),
            b"two!",
            deadline,
        )
        .expect("one authenticated compound must authorize a later subrange")
        .commit();

    assert_eq!(invalidator.calls, 1, "one compound must COW exactly once");
    let old_owner = global_frame_host_owners().lock()[&old_key].owner().clone();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(old_owner.as_ptr(), 4) },
        b"old!",
        "subrange reuse must never write through the shared source owner",
    );
    let new_key = (cow.physical_base().raw(), cow.physical_len());
    let new_owner = global_frame_host_owners().lock()[&new_key].owner().clone();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(new_owner.as_ptr(), 4) },
        b"one!",
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(new_owner.as_ptr().add(0x1000), 4) },
        b"two!",
    );
    child.owners.0.push(new_key);
}

#[test]
fn retained_foreign_lease_advances_across_two_compound_cow_commits() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm_with_data_len(
        &transport,
        126,
        0x9a00_1d00_0000,
        0x9b00_1d00_0000,
        OWNER_LEN * 2,
        b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let initially_retained_data_mapping = child.snapshot.mapping_ids[1];
    let deadline = Instant::now() + Duration::from_secs(1);

    let first = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break first compound COW");
    let after_first = child.live.0.read().clone();
    assert!(
        !after_first
            .mapping_ids
            .contains(&initially_retained_data_mapping),
        "first COW must retire the mapping identity frozen into the retained lease",
    );
    lease
        .prepare_write(
            &child.live,
            &after_first,
            first.as_ref(),
            GuestVa(TEST_VA),
            b"one!",
            deadline,
        )
        .expect("prepare first compound write")
        .commit();

    let second_va = TEST_VA + CowArmedRanges::COMPOUND_SIZE;
    let second = lease
        .break_cow(
            &mut invalidator,
            &after_first,
            GuestVa(second_va),
            4,
            deadline,
        )
        .expect("the retained lease must accept its authenticated successor snapshot");
    let after_second = child.live.0.read().clone();
    lease
        .prepare_write(
            &child.live,
            &after_second,
            second.as_ref(),
            GuestVa(second_va),
            b"two!",
            deadline,
        )
        .expect("prepare second compound write")
        .commit();

    assert_eq!(invalidator.calls, 2, "each compound must COW exactly once");
    let first_key = (first.physical_base().raw(), first.physical_len());
    let second_key = (second.physical_base().raw(), second.physical_len());
    assert_ne!(first_key, second_key);
    let owners = global_frame_host_owners().lock();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owners[&first_key].owner().as_ptr(), 4) },
        b"one!",
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owners[&second_key].owner().as_ptr(), 4) },
        b"two!",
    );
    drop(owners);
    child.owners.0.extend([first_key, second_key]);
}

#[test]
fn retained_foreign_lease_rejects_unrelated_or_tampered_successor_snapshot() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm_with_data_len(
        &transport,
        127,
        0x9a00_1e00_0000,
        0x9b00_1e00_0000,
        OWNER_LEN * 2,
        b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);

    let first = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break first compound COW");
    let after_first = child.live.0.read().clone();

    let mut tampered = after_first.clone();
    tampered
        .mapping_ids
        .push(carrick_hal::MappingId::from_kernel_allocation(nonzero(
            999_999,
        )));

    let second_va = TEST_VA + CowArmedRanges::COMPOUND_SIZE;
    let tampered_break =
        lease.break_cow(&mut invalidator, &tampered, GuestVa(second_va), 4, deadline);
    assert!(
        matches!(
            tampered_break,
            Err(carrick_hal::ForeignMmTransportError::MissingBinding)
        ),
        "tampered successor snapshot must be rejected on break_cow: {tampered_break:?}"
    );

    let tampered_prepare = lease.prepare_write(
        &child.live,
        &tampered,
        first.as_ref(),
        GuestVa(TEST_VA),
        b"fail",
        deadline,
    );
    assert!(
        matches!(
            tampered_prepare,
            Err(carrick_hal::ForeignMmTransportError::LeaseStale)
        ),
        "tampered successor snapshot must be rejected on prepare_write: {tampered_prepare:?}"
    );

    let first_key = (first.physical_base().raw(), first.physical_len());
    child.owners.0.push(first_key);
}

#[test]
fn concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        128,
        0x9a00_1f00_0000,
        0x9b00_1f00_0000,
        *b"old!",
    );
    let (_authority, lease, _invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(2);
    let snapshot = child.snapshot.clone();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let lease_clone1 = lease.clone();
    let lease_clone2 = lease.clone();
    let barrier1 = std::sync::Arc::clone(&barrier);
    let barrier2 = std::sync::Arc::clone(&barrier);
    let snap1 = snapshot.clone();
    let snap2 = snapshot.clone();
    let expected_binding = carrick_hal::ForeignMmSnapshot::binding(&snapshot);

    let handle1 = std::thread::spawn(move || {
        barrier1.wait();
        let mut invalidator = TestInvalidator {
            expected: expected_binding,
            calls: 0,
            fail_call: None,
        };
        lease_clone1.break_cow(&mut invalidator, &snap1, GuestVa(TEST_VA), 4, deadline)
    });
    let handle2 = std::thread::spawn(move || {
        barrier2.wait();
        let mut invalidator = TestInvalidator {
            expected: expected_binding,
            calls: 0,
            fail_call: None,
        };
        lease_clone2.break_cow(&mut invalidator, &snap2, GuestVa(TEST_VA), 4, deadline)
    });

    let res1 = handle1.join().expect("thread 1 panic");
    let res2 = handle2.join().expect("thread 2 panic");

    let (winner, loser) = match (res1, res2) {
        (Ok(cow), Err(err)) => (cow, err),
        (Err(err), Ok(cow)) => (cow, err),
        (r1, r2) => {
            panic!("expected exactly one winner and one loser, got: r1={r1:?}, r2={r2:?}")
        }
    };
    assert!(
        matches!(loser, carrick_hal::ForeignMmTransportError::MissingBinding),
        "loser from stale S_n must fail with MissingBinding: {loser:?}"
    );
    let winner_key = (winner.physical_base().raw(), winner.physical_len());
    assert_eq!(winner.range_len(), CowArmedRanges::COMPOUND_SIZE as usize);
    let owners = global_frame_host_owners().lock();
    assert!(owners.contains_key(&winner_key));
    drop(owners);
    child.owners.0.push(winner_key);
}

#[test]
fn foreign_cow_failpoint_leaves_lease_at_sn_and_retry_succeeds() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        129,
        0x9a00_2800_0000,
        0x9b00_2800_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);

    // Set failpoint at phase 2 (after allocation, before commit)
    child.state.set_foreign_cow_failpoint(2);
    let failed = lease.break_cow(
        &mut invalidator,
        &child.snapshot,
        GuestVa(TEST_VA),
        4,
        deadline,
    );
    assert!(
        matches!(
            failed,
            Err(carrick_hal::ForeignMmTransportError::MutationFailed)
        ),
        "failpoint must fail the COW: {failed:?}"
    );

    // Clear failpoint and retry on the SAME lease from S_n
    child.state.set_foreign_cow_failpoint(0);
    let succeeded = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("retry from unchanged S_n must succeed");

    let post = child.live.0.read().clone();
    lease
        .prepare_write(
            &child.live,
            &post,
            succeeded.as_ref(),
            GuestVa(TEST_VA),
            b"new!",
            deadline,
        )
        .expect("prepare write after retry")
        .commit();

    let new_key = (succeeded.physical_base().raw(), succeeded.physical_len());
    let owners = global_frame_host_owners().lock();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owners[&new_key].owner().as_ptr(), 4) },
        b"new!"
    );
    drop(owners);
    child.owners.0.push(new_key);
}

#[test]
fn foreign_cow_prepare_write_rejects_in_span_leaf_discontinuity() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        130,
        0x9a00_2900_0000,
        0x9b00_2900_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);

    let cow = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break compound COW");
    let after_cow = child.live.0.read().clone();

    // Repoint the 2nd leaf in stage-1 tables to create a discontinuity across the 4 KiB boundary
    {
        let table_owner = global_frame_host_owners().lock()[&child.owners.0[0]]
            .owner()
            .clone();
        let page_tables = child.state.page_tables_authority();
        page_tables
            .edit(
                || Err(TrapError::Hypervisor("manager must be present".to_owned())),
                |editor| {
                    editor
                        .repoint_preserving_attributes(TEST_VA + 0x1000, 0x9900_0000_0000, 0x1000)
                        .unwrap();
                    unsafe {
                        editor
                            .sync_to_host((editor.base(), table_owner.as_ptr()))
                            .unwrap()
                    };
                    Ok::<(), TrapError>(())
                },
            )
            .unwrap();
    }

    // An 8 KiB write from TEST_VA crosses the 4 KiB leaf boundary into the discontinuous leaf
    let crossed_src = vec![0x42u8; 0x2000];
    let rejected = lease.prepare_write(
        &child.live,
        &after_cow,
        cow.as_ref(),
        GuestVa(TEST_VA),
        &crossed_src,
        deadline,
    );
    assert!(
        matches!(
            rejected,
            Err(carrick_hal::ForeignMmTransportError::OwnerStale)
        ),
        "crossing into discontinuous leaf must be rejected: {rejected:?}"
    );

    let cow_key = (cow.physical_base().raw(), cow.physical_len());
    let owners = global_frame_host_owners().lock();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owners[&cow_key].owner().as_ptr(), 4) },
        b"old!"
    );
    drop(owners);
    child.owners.0.push(cow_key);
}

#[test]
fn foreign_cow_prepare_write_rejects_semantic_span_end_plus_one() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        131,
        0x9a00_2a00_0000,
        0x9b00_2a00_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);

    let cow = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break compound COW");
    let after_cow = child.live.0.read().clone();

    // Attempt write extending 1 byte past 16 KiB span: start at TEST_VA + 0x3fff with len 2
    let end_plus_one_va = TEST_VA + CowArmedRanges::COMPOUND_SIZE - 1;
    let rejected = lease.prepare_write(
        &child.live,
        &after_cow,
        cow.as_ref(),
        GuestVa(end_plus_one_va),
        b"ab",
        deadline,
    );
    assert!(
        matches!(
            rejected,
            Err(carrick_hal::ForeignMmTransportError::MutationFailed)
        ),
        "write extending past span end must be rejected: {rejected:?}"
    );

    // Attempt write starting exactly at span end
    let at_end_va = TEST_VA + CowArmedRanges::COMPOUND_SIZE;
    let rejected_at_end = lease.prepare_write(
        &child.live,
        &after_cow,
        cow.as_ref(),
        GuestVa(at_end_va),
        b"a",
        deadline,
    );
    assert!(
        matches!(
            rejected_at_end,
            Err(carrick_hal::ForeignMmTransportError::MutationFailed)
        ),
        "write at span end must be rejected: {rejected_at_end:?}"
    );

    let cow_key = (cow.physical_base().raw(), cow.physical_len());
    child.owners.0.push(cow_key);
}

#[test]
fn foreign_cow_prepare_write_rejects_out_of_span_alias() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut child = install_mm(
        &transport,
        132,
        0x9a00_2b00_0000,
        0x9b00_2b00_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&child);
    let deadline = Instant::now() + Duration::from_secs(1);

    let cow = lease
        .break_cow(
            &mut invalidator,
            &child.snapshot,
            GuestVa(TEST_VA),
            4,
            deadline,
        )
        .expect("break compound COW");
    let after_cow = child.live.0.read().clone();
    let cow_key = (cow.physical_base().raw(), cow.physical_len());

    // Install a real stage-1 alias OUTSIDE cow.range_start..range_end that translates to the
    // SAME authenticated new physical owner.
    let alias_va = TEST_VA + 0x1_0000;
    {
        let table_owner = global_frame_host_owners().lock()[&child.owners.0[0]]
            .owner()
            .clone();
        let page_tables = child.state.page_tables_authority();
        page_tables
            .edit(
                || Err(TrapError::Hypervisor("manager must be present".to_owned())),
                |editor| {
                    editor
                        .map_aliased(alias_va, cow.physical_base().raw(), 0x1000, true)
                        .expect("map stage-1 alias outside compound span");
                    unsafe {
                        editor
                            .sync_to_host((editor.base(), table_owner.as_ptr()))
                            .unwrap()
                    };
                    Ok::<(), TrapError>(())
                },
            )
            .unwrap();
    }

    // Prove prepare_write rejects the alias specifically because semantic authority is
    // out of span, even though physical translation names the same live owner.
    let rejected = lease.prepare_write(
        &child.live,
        &after_cow,
        cow.as_ref(),
        GuestVa(alias_va),
        b"test",
        deadline,
    );
    assert!(
        matches!(
            rejected,
            Err(carrick_hal::ForeignMmTransportError::MutationFailed)
        ),
        "out-of-span alias targeting same physical owner must be rejected: {rejected:?}"
    );

    // Verify bytes and commit state remain completely unchanged.
    let owners = global_frame_host_owners().lock();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owners[&cow_key].owner().as_ptr(), 4) },
        b"old!",
        "target owner bytes must remain unmutated after rejected prepare_write",
    );
    drop(owners);
    child.owners.0.push(cow_key);
}

#[test]
fn foreign_cow_each_reversible_boundary_restores_exact_stage1_inventory_and_owner_set() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    for phase in 1..=5 {
        let transport = CarrierForeignMmTransport::new();
        let installed = install_mm(
            &transport,
            121 + u64::from(phase),
            0x9a00_2000_0000 + u64::from(phase) * 0x0200_0000,
            0x9b00_2000_0000 + u64::from(phase) * 0x0200_0000,
            *b"same",
        );
        let (_authority, lease, mut invalidator) = prepare_foreign_cow(&installed);
        installed.state.set_foreign_cow_failpoint(phase);
        let before = foreign_cow_fingerprint(&installed);
        let result = lease.break_cow(
            &mut invalidator,
            &installed.snapshot,
            GuestVa(TEST_VA),
            4,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            matches!(
                result,
                Err(carrick_hal::ForeignMmTransportError::MutationFailed)
            ),
            "phase {phase} must fail before commit"
        );
        assert_eq!(foreign_cow_fingerprint(&installed), before, "phase {phase}");
        assert!(installed.state.cow_armed.lock().span_for(TEST_VA).is_some());
        let expected_invalidations = if phase == 4 {
            2
        } else if phase == 3 {
            1
        } else {
            0
        };
        assert_eq!(invalidator.calls, expected_invalidations, "phase {phase}");
    }
}

#[test]
fn foreign_cow_invalidation_failure_rolls_back_and_republishes_the_old_stage1() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        130,
        0x9a00_3000_0000,
        0x9b00_3000_0000,
        *b"same",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&installed);
    invalidator.fail_call = Some(1);
    let before = foreign_cow_fingerprint(&installed);
    assert!(
        lease
            .break_cow(
                &mut invalidator,
                &installed.snapshot,
                GuestVa(TEST_VA),
                4,
                Instant::now() + Duration::from_secs(1),
            )
            .is_err()
    );
    assert_eq!(invalidator.calls, 2);
    assert_eq!(foreign_cow_fingerprint(&installed), before);
}

#[test]
fn foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let mut installed = install_mm(
        &transport,
        124,
        0x9a00_1b00_0000,
        0x9b00_1b00_0000,
        *b"old!",
    );
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&installed);
    let result = lease.break_cow(
        &mut invalidator,
        &installed.snapshot,
        GuestVa(TEST_VA),
        4,
        Instant::now() + Duration::from_secs(1),
    );

    let cow = result.expect("committed COW returned retryable failure");
    let cow_key = (cow.physical_base().raw(), cow.physical_len());
    installed.owners.0.push(cow_key);
}

#[test]
fn foreign_mm_read_walks_the_target_root_not_the_caller_root() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let caller = install_mm(
        &transport,
        101,
        0x9a00_0000_0000,
        0x9b00_0000_0000,
        *b"call",
    );
    let target = install_mm(
        &transport,
        102,
        0x9a00_0200_0000,
        0x9b00_0200_0000,
        *b"targ",
    );
    let mut bytes = [0_u8; 4];

    let receipt =
        read_installed(&transport, &target, &mut bytes).expect("target-root foreign read");

    assert_eq!(&bytes, b"targ");
    assert_ne!(&bytes, b"call");
    assert!(receipt.authenticates(&target.snapshot));
    assert_eq!(receipt.bytes_read(), bytes.len());
    assert!(!receipt.owner_generations().is_empty());
    drop(caller);
}

#[test]
fn foreign_mm_read_retries_each_stale_revision_domain() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        103,
        0x9a00_0400_0000,
        0x9b00_0400_0000,
        *b"live",
    );

    for domain in 0..3 {
        {
            let mut live = installed.live.0.write();
            match domain {
                0 => {
                    live.backend_revision =
                        carrick_hal::ForeignBackendRevision::from_authority_raw(18)
                }
                1 => live.vma_revision = carrick_hal::ForeignVmaRevision::from_authority_raw(20),
                _ => {
                    live.frame_inventory_revision =
                        carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(24)
                }
            }
        }
        let mut bytes = [0_u8; 4];
        assert!(matches!(
            read_installed(&transport, &installed, &mut bytes),
            Err(carrick_hal::ForeignMmTransportError::Retry)
        ));
        *installed.live.0.write() = installed.snapshot.clone();
    }
}

#[test]
fn foreign_mm_read_rejects_a_missing_descriptor_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        104,
        0x9a00_0600_0000,
        0x9b00_0600_0000,
        *b"live",
    );
    let table_key = installed.owners.0[0];
    global_frame_host_owners().lock().remove(&table_key);
    let mut bytes = [0_u8; 4];

    assert!(matches!(
        read_installed(&transport, &installed, &mut bytes),
        Err(carrick_hal::ForeignMmTransportError::OwnerStale)
    ));
}

#[test]
fn foreign_mm_retain_pins_covering_owner_for_cow_split_inventory_fragment() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        149,
        0x9a00_4a00_0000,
        0x9b00_4a00_0000,
        *b"live",
    );
    let owner_key = installed.owners.0[1];
    let fragment_key = (owner_key.0 + 0x1000, 0x1000);
    {
        let mut inventory = installed.state.frame_inventory.ledger.lock();
        let extent = inventory
            .extents
            .remove(&owner_key)
            .expect("full compound inventory extent");
        assert_eq!(
            (extent.stage2_base, extent.stage2_length),
            owner_key,
            "split logical mapping must retain its authenticated covering owner",
        );
        inventory.extents.insert(fragment_key, extent);
    }

    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let retained = endpoint.retain(&installed.snapshot, Instant::now() + Duration::from_secs(1));

    assert!(
        retained.is_ok(),
        "a COW-split logical fragment must pin its covering stage-2 owner: {retained:?}",
    );
}

#[test]
fn foreign_mm_read_rejects_reused_owner_generation() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        105,
        0x9a00_0800_0000,
        0x9b00_0800_0000,
        *b"old!",
    );
    let data_key = installed.owners.0[1];
    global_frame_host_owners().lock().remove(&data_key);
    let replacement = vec![b'n'; data_key.1 as usize];
    let _ = install_owner(data_key.0, &replacement);
    let mut bytes = [0_u8; 4];

    assert!(matches!(
        read_installed(&transport, &installed, &mut bytes),
        Err(carrick_hal::ForeignMmTransportError::OwnerStale)
    ));
    assert_ne!(&bytes, b"nnnn");
}

#[test]
fn foreign_mm_read_unmaterialized_remote_page_within_vma_reads_zeros_and_full_length() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let page_size = CowArmedRanges::COMPOUND_SIZE as usize;
    let vma_len = page_size * 2;
    let installed = install_mm_sparse(
        &transport,
        108,
        0x9600_0800_0000,
        0x9700_0800_0000,
        page_size,
        vma_len,
        b"hello world",
    );
    let mut dst = vec![0xaa_u8; vma_len];
    let receipt = read_installed(&transport, &installed, &mut dst)
        .expect("read sparse VMA spanning resident and unmaterialized pages");
    assert_eq!(receipt.bytes_read(), vma_len);
    assert_eq!(&dst[..11], b"hello world");
    assert!(dst[11..page_size].iter().all(|&b| b == 0));
    assert!(dst[page_size..vma_len].iter().all(|&b| b == 0));

    let mut beyond = vec![0xaa_u8; page_size];
    let deadline = Instant::now() + Duration::from_secs(1);
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let lease = endpoint
        .retain(&installed.snapshot, deadline)
        .expect("retain MM");
    let beyond_res = lease.read(
        &installed.live,
        &installed.snapshot,
        GuestVa(TEST_VA + vma_len as u64),
        &mut beyond,
        deadline,
    );
    assert!(matches!(
        beyond_res,
        Err(carrick_hal::ForeignMmTransportError::Translation(va)) if va == GuestVa(TEST_VA + vma_len as u64)
    ));
}

/// A page inside a readable VMA with NO stage-1 entry and NO pristine
/// recipe still reads as zeros, and the transfer runs to full length.
///
/// That combination is what the 64 KiB anonymous fault window produces:
/// it materializes zeroed backing across the whole window while installing
/// stage-1 only for the page that faulted, so the rest of the window is
/// backed (gone from `pristine`) yet invisible to a foreign stage-1 walk.
/// Refusing it ended `process_vm_readv` early — `processvmsparse` returned
/// short from the moment the wide window became the default (9ac383a69).
/// The fixture reproduces the state by dropping the deferred recipe after
/// install, which is exactly what materialization does.
#[test]
fn foreign_mm_read_backed_page_without_stage1_or_recipe_reads_zeros() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let page_size = CowArmedRanges::COMPOUND_SIZE as usize;
    let vma_len = page_size * 2;
    let installed = install_mm_sparse(
        &transport,
        118,
        0x9600_0900_0000,
        0x9700_0900_0000,
        page_size,
        vma_len,
        b"hello world",
    );
    // The fault window materialized the tail: backed, no longer pristine,
    // and stage-1 still only covers the first page.
    *installed.state.deferred_anonymous.write() = None;

    let mut dst = vec![0xaa_u8; vma_len];
    let receipt = read_installed(&transport, &installed, &mut dst)
        .expect("read a materialized-but-untranslated page inside a readable VMA");
    assert_eq!(receipt.bytes_read(), vma_len);
    assert_eq!(&dst[..11], b"hello world");
    assert!(dst[page_size..vma_len].iter().all(|&b| b == 0));

    // Past the readable VMA is still a hard translation failure.
    let mut beyond = vec![0xaa_u8; page_size];
    let deadline = Instant::now() + Duration::from_secs(1);
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let lease = endpoint
        .retain(&installed.snapshot, deadline)
        .expect("retain MM");
    let beyond_res = lease.read(
        &installed.live,
        &installed.snapshot,
        GuestVa(TEST_VA + vma_len as u64),
        &mut beyond,
        deadline,
    );
    assert!(matches!(
        beyond_res,
        Err(carrick_hal::ForeignMmTransportError::Translation(va))
            if va == GuestVa(TEST_VA + vma_len as u64)
    ));
}

#[test]
fn retained_old_token_drop_only_enqueues_before_the_executor_safe_point() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let InstalledMm {
        snapshot,
        live,
        state,
        owners,
    } = install_mm(
        &transport,
        106,
        0x9a00_0a00_0000,
        0x9b00_0a00_0000,
        *b"old!",
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let lease = endpoint.retain(&snapshot, deadline).expect("retain old MM");
    let extents = owners
        .0
        .iter()
        .map(|&(ipa, length)| {
            (
                (ipa, usize::try_from(length).expect("fixture extent length")),
                global_frame_host_owner_identity(ipa, length)
                    .map(|(host_addr, generation)| InventoryStage2OwnerIdentity {
                        host_addr,
                        generation,
                    })
                    .expect("fixture exact owner identity"),
            )
        })
        .collect();
    let mut cleanup = PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::new(),
        extents,
        predecessor_aliases: Vec::new(),
        frames: Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: None,
        mm_access: None,
        predecessor_identity: carrick_hal::ExecPredecessorIdentity {
            task_serial: 106,
            thread_serial: 106,
            linux_pid: 106,
            linux_tid: 106,
            mm: snapshot.mm.get(),
            asid: snapshot.asid.get(),
        },
        predecessor_mm: snapshot.mm.get(),
        shared_projection: false,
        armed: true,
    };
    cleanup
        .retire_with(&mut |_| {})
        .expect("production exec predecessor cleanup");
    for &(ipa, length) in &owners.0 {
        assert!(
            global_frame_host_owners()
                .lock()
                .get(&(ipa, length))
                .is_some_and(|e| e.is_pending()),
            "production cleanup must place each retained owner into pending retirement while foreign lease is active",
        );
    }
    drop(state);

    let replacement_snapshot = TestSnapshot {
        mm: nonzero(107),
        ..snapshot.clone()
    };
    let replacement_state = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        Arc::new(parking_lot::Mutex::new(Vec::new())),
    );
    transport.register(&replacement_snapshot, &replacement_state);

    let mut bytes = [0_u8; 4];
    let receipt = lease
        .read(&live, &snapshot, GuestVa(TEST_VA), &mut bytes, deadline)
        .expect("old retained token must keep exact carrier state readable");
    assert_eq!(&bytes, b"old!");
    assert!(receipt.authenticates(&snapshot));

    drop(lease);
    assert!(
        owners.0.iter().all(|key| global_frame_host_owners()
            .lock()
            .get(key)
            .is_some_and(|entry| entry.is_pending())),
        "foreign lease drop must release pins and enqueue retirement without backend unmap",
    );
    let turn = retry_pending_global_frame_retirements_at_idle_in_using(
        &transport.custody,
        &mut unmap_global_frame_stage2_record,
    );
    assert!(turn.inspected_directory <= 16);
    for _ in 0..2 {
        if owners
            .0
            .iter()
            .all(|key| !global_frame_host_owners().lock().contains_key(key))
        {
            break;
        }
        let _ = retry_pending_global_frame_retirements_at_idle_in_using(
            &transport.custody,
            &mut unmap_global_frame_stage2_record,
        );
    }
    assert!(
        owners
            .0
            .iter()
            .all(|key| !global_frame_host_owners().lock().contains_key(key))
    );
}

const CONTENDED_HOLD: Duration = Duration::from_millis(250);
const TEST_DEADLINE: Duration = Duration::from_millis(25);
const MAX_BOUNDED_RETURN: Duration = Duration::from_millis(150);

fn hold_lock_then_signal(
    hold: impl FnOnce(mpsc::Sender<()>) + Send + 'static,
) -> (mpsc::Receiver<()>, thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let holder = thread::spawn(move || hold(ready_tx));
    (ready_rx, holder)
}

fn assert_bounded_timeout<T>(
    result: Result<T, carrick_hal::ForeignMmTransportError>,
    elapsed: Duration,
    lock_name: &str,
) {
    assert!(
        matches!(result, Err(carrick_hal::ForeignMmTransportError::TimedOut)),
        "{lock_name} contention must fail closed with TimedOut",
    );
    assert!(
        elapsed < MAX_BOUNDED_RETURN,
        "{lock_name} contention exceeded the overall bound: {elapsed:?}",
    );
}

#[test]
fn foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        108,
        0x9a00_0e00_0000,
        0x9b00_0e00_0000,
        *b"lock",
    );
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));

    let states = Arc::clone(&transport.states);
    let (ready, holder) = hold_lock_then_signal(move |ready| {
        let _guard = states.write();
        ready.send(()).expect("signal directory lock acquisition");
        thread::sleep(CONTENDED_HOLD);
    });
    ready.recv().expect("directory lock holder ready");
    let started = Instant::now();
    let result = endpoint.retain(&installed.snapshot, started + TEST_DEADLINE);
    let elapsed = started.elapsed();
    holder.join().expect("directory lock holder");
    assert_bounded_timeout(result, elapsed, "carrier directory");

    let state = Arc::clone(&installed.state);
    let (ready, holder) = hold_lock_then_signal(move |ready| {
        let _guard = state.identity.write();
        ready.send(()).expect("signal MM identity lock acquisition");
        thread::sleep(CONTENDED_HOLD);
    });
    ready.recv().expect("MM identity lock holder ready");
    let started = Instant::now();
    let result = endpoint.retain(&installed.snapshot, started + TEST_DEADLINE);
    let elapsed = started.elapsed();
    holder.join().expect("MM identity lock holder");
    assert_bounded_timeout(result, elapsed, "MM identity");

    let ledger = installed.state.frame_inventory.shared_ledger();
    let (ready, holder) = hold_lock_then_signal(move |ready| {
        let _guard = ledger.lock();
        ready.send(()).expect("signal inventory lock acquisition");
        thread::sleep(CONTENDED_HOLD);
    });
    ready.recv().expect("inventory lock holder ready");
    let started = Instant::now();
    let result = endpoint.retain(&installed.snapshot, started + TEST_DEADLINE);
    let elapsed = started.elapsed();
    holder.join().expect("inventory lock holder");
    assert_bounded_timeout(result, elapsed, "frame inventory");

    let (ready, holder) = hold_lock_then_signal(|ready| {
        let _guard = global_frame_host_owners().lock();
        ready.send(()).expect("signal owner lock acquisition");
        thread::sleep(CONTENDED_HOLD);
    });
    ready.recv().expect("owner lock holder ready");
    let started = Instant::now();
    let result = endpoint.retain(&installed.snapshot, started + TEST_DEADLINE);
    let elapsed = started.elapsed();
    holder.join().expect("owner lock holder");
    assert_bounded_timeout(result, elapsed, "global owners");
}

#[test]
fn foreign_mm_read_deadline_bounds_mutation_coordinator_contention() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = CarrierForeignMmTransport::new();
    let installed = install_mm(
        &transport,
        109,
        0x9a00_1000_0000,
        0x9b00_1000_0000,
        *b"lock",
    );
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(transport.clone()));
    let lease = endpoint
        .retain(&installed.snapshot, Instant::now() + Duration::from_secs(1))
        .expect("retain contended MM");
    let state = Arc::clone(&installed.state);
    let (ready, holder) = hold_lock_then_signal(move |ready| {
        let _guard = state.mutation_coordinator.lock();
        ready
            .send(())
            .expect("signal mutation coordinator acquisition");
        thread::sleep(CONTENDED_HOLD);
    });
    ready.recv().expect("mutation coordinator holder ready");
    let started = Instant::now();
    let mut bytes = [0_u8; 4];
    let result = lease.read(
        &installed.live,
        &installed.snapshot,
        GuestVa(TEST_VA),
        &mut bytes,
        started + TEST_DEADLINE,
    );
    let elapsed = started.elapsed();
    holder.join().expect("mutation coordinator holder");
    assert_bounded_timeout(result, elapsed, "mutation coordinator");
}

#[test]
fn structural_backing_owner_lifecycle_and_retained_backing() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let size = 0x4000usize;
    let ipa = 0x8800_1000_0000u64;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let payload = *b"structural_extent_retention_payload!";
    unsafe {
        std::ptr::copy_nonoverlapping(payload.as_ptr(), mapping.as_ptr(), payload.len());
    }
    let ptr = mapping.as_ptr();
    let epoch = next_structural_epoch().expect("next structural epoch");
    let lease = GlobalFrameStage2Lease::fixed(ipa, size as u64);
    let owner = StructuralBackingOwner::new(mapping, lease, epoch, ipa, size)
        .expect("create structural backing owner");
    let identity = *owner.retained.record_identity.lock();
    assert_eq!(owner.len(), size);
    assert_eq!(owner.ptr(), ptr);
    assert_eq!(owner.epoch(), epoch);

    // RetainedPhysicalOwner::Structural wrapping and inspection
    let retained_owner = RetainedPhysicalOwner::Structural(Arc::clone(&owner));
    assert_eq!(retained_owner.ptr(), ptr);
    assert_eq!(retained_owner.len(), size);
    assert_eq!(retained_owner.generation(), epoch.raw());

    let extent = RetainedForeignExtent {
        key: (ipa, size as u64),
        owner: retained_owner,
    };
    let backing = RetainedForeignMmBacking {
        extents: vec![extent],
    };

    // Successful read via read_bytes
    let mut read_buf = [0u8; 36];
    let bytes_read = backing
        .read_bytes(ipa, 0, &mut read_buf)
        .expect("read_bytes from backing");
    assert_eq!(bytes_read, 36);
    assert_eq!(&read_buf, &payload);

    // Successful copy via copy_from_pinned_owner
    let mut dst = [0u8; 16];
    let owner_gen =
        copy_from_pinned_owner(&backing, ipa, &mut dst).expect("copy_from_pinned_owner");
    assert_eq!(&dst, &payload[..16]);
    assert_eq!(owner_gen.raw_for_probe(), epoch.raw());

    // Out-of-bounds offset rejected
    let mut oob_dst = vec![0u8; size + 1];
    let oob_res = copy_from_pinned_owner(&backing, ipa, &mut oob_dst);
    assert!(matches!(
        oob_res,
        Err(carrick_hal::ForeignMmTransportError::OwnerStale)
    ));

    // Non-retained IPA lookup fails
    let missing = backing.extent_for(ipa + 0x1_0000, size);
    assert!(missing.is_err());
    drop(backing);
    drop(owner);
    retry_structural_backing_identities_in_using(
        legacy_test_carrier_vm_custody(),
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("explicitly retire structural lifecycle fixture");
}

#[test]
fn structural_backing_owner_invalid_arguments_and_exact_drop_order() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let size = 0x4000usize;
    let ipa = 0x8800_2000_0000u64;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let epoch = next_structural_epoch().expect("next structural epoch");

    // Mismatched physical_size rejected
    let lease_bad_size = GlobalFrameStage2Lease::fixed(ipa, (size + 0x1000) as u64);
    let err_size = StructuralBackingOwner::new(mapping, lease_bad_size, epoch, ipa, size + 0x1000);
    assert!(err_size.is_err());

    // Mismatched lease IPA key rejected
    let mapping2 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let lease_bad_ipa = GlobalFrameStage2Lease::fixed(ipa + 0x1000, size as u64);
    let err_ipa = StructuralBackingOwner::new(mapping2, lease_bad_ipa, epoch, ipa, size);
    assert!(err_ipa.is_err());

    // Drop order verification: stage2 lease drops before host munmap
    let mapping3 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let host_addr = mapping3.as_ptr() as usize;
    let mut lease3 = GlobalFrameStage2Lease::fixed(ipa, size as u64);
    let observed_live = Arc::new(std::sync::atomic::AtomicBool::new(false));
    lease3.drop_backing_audit = Some((host_addr, Arc::clone(&observed_live)));
    let owner = StructuralBackingOwner::new(mapping3, lease3, epoch, ipa, size).unwrap();
    let identity = *owner.retained.record_identity.lock();
    assert!(alias_backing_is_live(host_addr));
    drop(owner);
    assert!(
        !observed_live.load(std::sync::atomic::Ordering::SeqCst),
        "structural owner Drop must not execute lease retirement"
    );
    assert!(
        alias_backing_is_live(host_addr),
        "custody must retain backing until the explicit safe point"
    );
    retry_structural_backing_identities_in_using(
        legacy_test_carrier_vm_custody(),
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("explicitly retire structural drop-order fixture");
    assert!(!alias_backing_is_live(host_addr));
}

#[test]
fn global_frame_host_owner_drop_does_no_hv_and_explicit_retirement_releases_backing() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let size = 0x4000usize;
    let ipa = 0x8800_2800_0000u64;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let host_addr = mapping.as_ptr() as usize;
    let mut lease = GlobalFrameStage2Lease::fixed(ipa, size as u64);
    assert_eq!(
        unsafe { inventory_hv_vm_map(mapping.as_ptr().cast(), ipa, size, 7) },
        0
    );
    lease.mark_mapped();
    let generation = register_global_frame_host_owner(lease, mapping, 7)
        .expect("register global frame host owner");
    let owner = global_frame_host_owners()
        .lock()
        .get(&(ipa, size as u64))
        .expect("published owner")
        .owner()
        .clone();
    assert!(alias_backing_is_live(host_addr));
    drop(owner);
    assert!(
        ScopedStage2MapTestStub::is_mapped(ipa, size),
        "dropping an owner Arc must not perform hypervisor retirement"
    );
    assert!(
        alias_backing_is_live(host_addr),
        "carrier directory custody must retain backing until explicit retirement"
    );
    assert!(matches!(
        retire_global_frame_host_owner_if_generation(ipa, size as u64, generation),
        GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
    ));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa, size));
    assert!(!alias_backing_is_live(host_addr));
}

#[test]
fn owner_structs_encode_their_required_retirement_authority_static_audit() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let source = concat!(
        include_str!("../../trap.rs"),
        include_str!("../global_frame.rs")
    );

    // 1. GlobalFrameHostOwner: carrier custody is the sole stage-2
    // retirement authority. The owner has no lease and no Drop path that
    // can issue hypervisor work.
    let gfho_hdr = concat!("\npub(crate) struct ", "GlobalFrameHostOwner {");
    let gfho = source
        .split(gfho_hdr)
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .expect("GlobalFrameHostOwner struct body");
    assert!(gfho.contains("mapping: std::sync::Arc<GlobalFrameSharedMapping>"));
    assert!(gfho.contains("custody: std::sync::Weak<CarrierVmCustody>"));
    assert!(gfho.contains("record_identity: CarrierStage2RecordIdentity"));
    assert!(!gfho.contains("GlobalFrameStage2Lease"));
    assert!(!source.contains(concat!("impl Drop for ", "GlobalFrameHostOwner")));
    assert!(!source.contains(concat!("Arc::", "strong_count")));

    // 2. StructuralBackingOwner: carrier custody owns the exact stage-2
    // record and retained backing; final owner Drop can only request.
    let sbo_hdr = concat!("\npub(crate) struct ", "StructuralBackingOwner {");
    let sbo = source
        .split(sbo_hdr)
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .expect("StructuralBackingOwner struct body");
    assert!(sbo.contains("custody: std::sync::Weak<CarrierVmCustody>"));
    assert!(sbo.contains("retained: std::sync::Arc<StructuralBackingCustodyEntry>"));
    assert!(!sbo.contains("GlobalFrameStage2Lease"));

    // 3. ProcessMappingDesc: stage2_lease before host
    let pmd_hdr = concat!("\nstruct ", "ProcessMappingDesc {");
    let pmd_delim = concat!("struct ", "ProcessInventoryDesc");
    let pmd = source
        .split(pmd_hdr)
        .nth(1)
        .and_then(|tail| tail.split(pmd_delim).next())
        .expect("ProcessMappingDesc struct body");
    let pmd_lease = pmd
        .find("stage2_lease: Option<GlobalFrameStage2Lease>")
        .expect("ProcessMappingDesc.stage2_lease exists");
    let pmd_host = pmd
        .find("host: ProcessMappingHost")
        .expect("ProcessMappingDesc.host exists");
    assert!(
        pmd_lease < pmd_host,
        "ProcessMappingDesc must declare stage2_lease before host for safe drop order"
    );
}

#[test]
fn all_foreign_mm_tests_acquire_test_lock_census_audit() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let source = include_str!("tests.rs");
    for block in source.split("#[test]").skip(1) {
        if !block.contains("fn ") {
            continue;
        }
        let fn_name = block
            .split("fn ")
            .nth(1)
            .and_then(|tail| tail.split('(').next())
            .unwrap_or("unknown")
            .trim();
        assert!(
            block.contains("FOREIGN_MM_TEST_LOCK.lock()"),
            "test `{fn_name}` in `foreign_mm_tests` must acquire FOREIGN_MM_TEST_LOCK at entry"
        );
    }
}

#[test]
fn copied_fork_child_activation_publishes_exact_foreign_mm_binding() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let mm = NonZeroU64::new(2).unwrap();
    let asid = NonZeroU16::new(5).unwrap();
    let stage1_root = Gpa(0x8800_0020_0000);
    let transaction =
        carrick_hal::KernelTransactionId::from_kernel_allocation(NonZeroU64::new(701).unwrap());
    let receipt = carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x44; 32]),
        transaction,
        NonZeroU64::new(1).unwrap(),
        0,
        Vec::new(),
    );
    let task_mm = Arc::new(HvpatchTaskMmAuthority {
        mappings: Vec::new(),
        foreign_mm_transport: Some(Arc::clone(&transport)),
        mm_root_slot: Some((stage1_root.raw(), 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        container_root: ContainerRootToken::from_raw(1),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::Active {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            receipt,
            retirement: None,
        }),
        kernel_mm: parking_lot::Mutex::new(Some(mm)),
        cow_armed: Some(Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()))),
        cow_deferred_publications: Some(Arc::new(parking_lot::Mutex::new(Vec::new()))),
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Registration),
        drop_order: None,
    });
    let prepared_mm_access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        task_mm
            .inventory
            .lock()
            .shared_runtime_ledger()
            .expect("prepared child inventory ledger"),
        Arc::clone(task_mm.cow_armed.as_ref().expect("prepared COW arms")),
        Arc::clone(
            task_mm
                .cow_deferred_publications
                .as_ref()
                .expect("prepared COW publications"),
        ),
    );
    *task_mm.mm_access.lock() = Some(Arc::clone(&prepared_mm_access));
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let mut registration = HvpatchTaskRegistration {
        directory,
        key: HvpatchCarrierTaskStateKey {
            directory_instance: NonZeroU64::new(1).unwrap(),
            task_serial: 102,
            thread_serial: 102,
            execution_generation: 1,
            nonce: NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 102,
            thread_serial: 102,
            execution_generation: 1,
            linux_pid: 102,
            linux_tid: 102,
            asid: asid.get(),
        },
        foreign_mm_registration: None,
        task_mm: Some(Arc::clone(&task_mm)),
        cow_authority: Some(Arc::new(
            super::task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 102,
            linux_tid: 102,
            mm: mm.get(),
            asid: asid.get(),
        }),
        cow_authority_identity: None,
        child_token_verifier,
    };
    let runtime_page_tables = carrick_aarch64::Stage1Authority::new_with_manager(Some(
        crate::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            stage1_root.raw(),
        ),
    ));
    let runtime = registration
        .runtime_task_state(
            runtime_page_tables.clone(),
            Arc::new(MemoryProtections::default()),
        )
        .expect("materialize executable copied child runtime state");
    let preserved_prepared_mm = Arc::ptr_eq(&runtime.mm_access, &prepared_mm_access);
    let live_page_tables_bound = runtime
        .mm_access
        .page_tables_authority()
        .shares_exact_authority(&runtime_page_tables);
    let runtime_cow = runtime.mm_access.cow_runtime.read().clone();
    let exact_cow_mm = runtime_cow.as_ref().map(|binding| binding.identity.mm);
    registration
        .register_foreign_mm(&runtime)
        .expect("publish exact copied-child foreign-MM binding");
    registration
        .activate()
        .expect("activate exact copied child");
    assert_eq!(runtime.cow_identity.unwrap().mm, mm.get());

    let snapshot = TestSnapshot {
        mm,
        asid,
        stage1_root,
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids: Vec::new(),
        executable_ranges: vec![
            carrick_hal::ForeignExecutableRange::from_kernel_projection(
                GuestVa(0x0040_0000),
                GuestVa(0x0040_4000),
            )
            .unwrap(),
        ],
        readable_ranges: Vec::new(),
    };
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(
        Arc::clone(&transport) as Arc<dyn carrick_hal::ForeignMmTransport>
    );
    let retained = endpoint.retain(&snapshot, Instant::now() + Duration::from_secs(1));
    *task_mm.inventory.lock() = HvpatchTaskInventoryAuthority::Retired;
    assert!(
        preserved_prepared_mm,
        "runtime must preserve the MM authority registered during child preparation",
    );
    assert!(
        live_page_tables_bound,
        "runtime materialization must bind live page-table authority into the registered MM",
    );
    assert_eq!(
        exact_cow_mm,
        Some(mm.get()),
        "runtime materialization must bind exact COW authority before foreign mutation",
    );
    assert!(
        retained.is_ok(),
        "an active copied child must publish its exact foreign-MM binding before execution: {retained:?}"
    );
}

#[derive(Debug)]
struct TestArenaSource {
    id: carrick_mem::page_table::TableArenaSourceId,
    available: std::sync::Arc<std::sync::Mutex<Vec<carrick_guest_mem::Gpa>>>,
    returned: std::sync::Arc<std::sync::Mutex<Vec<carrick_guest_mem::Gpa>>>,
}

impl carrick_mem::page_table::TableArenaSource for TestArenaSource {
    fn id(&self) -> carrick_mem::page_table::TableArenaSourceId {
        self.id
    }
    fn take_arena(&mut self) -> Option<carrick_guest_mem::Gpa> {
        self.available.lock().unwrap().pop()
    }
    fn return_arena(&mut self, base: carrick_guest_mem::Gpa) {
        self.returned.lock().unwrap().push(base);
    }
}

#[test]
fn production_manager_bound_through_runtime_task_state_grows_extension_arenas() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let mm = NonZeroU64::new(2).unwrap();
    let asid = NonZeroU16::new(5).unwrap();
    let stage1_root = Gpa(0x8800_0020_0000);
    let transaction =
        carrick_hal::KernelTransactionId::from_kernel_allocation(NonZeroU64::new(701).unwrap());
    let receipt = carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x44; 32]),
        transaction,
        NonZeroU64::new(1).unwrap(),
        0,
        Vec::new(),
    );
    let task_mm = Arc::new(HvpatchTaskMmAuthority {
        mappings: Vec::new(),
        foreign_mm_transport: Some(Arc::clone(&transport)),
        mm_root_slot: Some((stage1_root.raw(), 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        container_root: ContainerRootToken::from_raw(1),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::Active {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            receipt,
            retirement: None,
        }),
        kernel_mm: parking_lot::Mutex::new(Some(mm)),
        cow_armed: Some(Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()))),
        cow_deferred_publications: Some(Arc::new(parking_lot::Mutex::new(Vec::new()))),
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Registration),
        drop_order: None,
    });
    let prepared_mm_access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        task_mm
            .inventory
            .lock()
            .shared_runtime_ledger()
            .expect("prepared child inventory ledger"),
        Arc::clone(task_mm.cow_armed.as_ref().expect("prepared COW arms")),
        Arc::clone(
            task_mm
                .cow_deferred_publications
                .as_ref()
                .expect("prepared COW publications"),
        ),
    );
    *task_mm.mm_access.lock() = Some(Arc::clone(&prepared_mm_access));
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let registration = HvpatchTaskRegistration {
        directory,
        key: HvpatchCarrierTaskStateKey {
            directory_instance: NonZeroU64::new(1).unwrap(),
            task_serial: 102,
            thread_serial: 102,
            execution_generation: 1,
            nonce: NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 102,
            thread_serial: 102,
            execution_generation: 1,
            linux_pid: 102,
            linux_tid: 102,
            asid: asid.get(),
        },
        foreign_mm_registration: None,
        task_mm: Some(Arc::clone(&task_mm)),
        cow_authority: Some(Arc::new(
            super::task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 102,
            linux_tid: 102,
            mm: mm.get(),
            asid: asid.get(),
        }),
        cow_authority_identity: None,
        child_token_verifier,
    };

    let mut manager = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    manager
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            None,
        )
        .expect("reserve sparse arena");
    manager
        .rebase(stage1_root.raw(), None)
        .expect("rebase to stage1_root");
    let ext_base = carrick_guest_mem::Gpa(0xb0_0000_0000);
    let available = std::sync::Arc::new(std::sync::Mutex::new(vec![ext_base]));
    let returned = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let source = TestArenaSource {
        id: carrick_mem::page_table::TableArenaSourceId(stage1_root),
        available: std::sync::Arc::clone(&available),
        returned: std::sync::Arc::clone(&returned),
    };
    let runtime_page_tables = carrick_aarch64::Stage1Authority::new_with_manager(Some(manager));
    runtime_page_tables
        .install_source(Box::new(source))
        .unwrap();
    assert_eq!(
        runtime_page_tables.pool_stats().map(|s| s.3),
        Some(1),
        "starts with 1 primary arena"
    );

    let runtime = registration
        .runtime_task_state(runtime_page_tables, Arc::new(MemoryProtections::default()))
        .expect("materialize executable copied child runtime state");

    let pt_auth = runtime.page_tables_authority();
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut block = crate::memory::LINUX_MMAP_BASE + 64 * TWO_MIB;
    pt_auth
        .edit(
            || Err(TrapError::Hypervisor("manager must be present".to_owned())),
            |editor| {
                while editor.pool_stats().3 < 2 {
                    editor
                        .set_rw(block + 0x1000, 0x1000, false)
                        .expect("mapping succeeds");
                    block += TWO_MIB;
                }
                assert_eq!(editor.pool_stats().3, 2, "grew to 2 arenas past 448 tables");
                Ok::<(), TrapError>(())
            },
        )
        .unwrap();
    assert!(
        available.lock().unwrap().is_empty(),
        "source arena was taken"
    );
    *task_mm.inventory.lock() = HvpatchTaskInventoryAuthority::Retired;
}

#[test]
fn production_resolver_under_manager_lock_does_not_deadlock_on_multi_arena_sync() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let mm = NonZeroU64::new(3).unwrap();
    let asid = NonZeroU16::new(6).unwrap();
    let stage1_root = Gpa(0x8800_0040_0000);
    let transaction =
        carrick_hal::KernelTransactionId::from_kernel_allocation(NonZeroU64::new(702).unwrap());
    let receipt = carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x45; 32]),
        transaction,
        NonZeroU64::new(1).unwrap(),
        0,
        Vec::new(),
    );
    let task_mm = Arc::new(HvpatchTaskMmAuthority {
        mappings: Vec::new(),
        foreign_mm_transport: Some(Arc::clone(&transport)),
        mm_root_slot: Some((stage1_root.raw(), 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        container_root: ContainerRootToken::from_raw(1),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::Active {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            receipt,
            retirement: None,
        }),
        kernel_mm: parking_lot::Mutex::new(Some(mm)),
        cow_armed: Some(Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()))),
        cow_deferred_publications: Some(Arc::new(parking_lot::Mutex::new(Vec::new()))),
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Registration),
        drop_order: None,
    });
    let prepared_mm_access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        task_mm
            .inventory
            .lock()
            .shared_runtime_ledger()
            .expect("prepared child inventory ledger"),
        Arc::clone(task_mm.cow_armed.as_ref().expect("prepared COW arms")),
        Arc::clone(
            task_mm
                .cow_deferred_publications
                .as_ref()
                .expect("prepared COW publications"),
        ),
    );
    *task_mm.mm_access.lock() = Some(Arc::clone(&prepared_mm_access));
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let registration = HvpatchTaskRegistration {
        directory,
        key: HvpatchCarrierTaskStateKey {
            directory_instance: NonZeroU64::new(1).unwrap(),
            task_serial: 103,
            thread_serial: 103,
            execution_generation: 1,
            nonce: NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 103,
            thread_serial: 103,
            execution_generation: 1,
            linux_pid: 103,
            linux_tid: 103,
            asid: asid.get(),
        },
        foreign_mm_registration: None,
        task_mm: Some(Arc::clone(&task_mm)),
        cow_authority: Some(Arc::new(
            super::task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 103,
            linux_tid: 103,
            mm: mm.get(),
            asid: asid.get(),
        }),
        cow_authority_identity: None,
        child_token_verifier,
    };

    let mut manager = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    manager
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            None,
        )
        .expect("reserve sparse arena");
    manager
        .rebase(stage1_root.raw(), None)
        .expect("rebase to stage1_root");
    let ext_base = carrick_guest_mem::Gpa(0xc0_0000_0000);
    let available = std::sync::Arc::new(std::sync::Mutex::new(vec![ext_base]));
    let returned = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let source = TestArenaSource {
        id: carrick_mem::page_table::TableArenaSourceId(stage1_root),
        available: std::sync::Arc::clone(&available),
        returned: std::sync::Arc::clone(&returned),
    };
    let runtime_page_tables = carrick_aarch64::Stage1Authority::new_with_manager(Some(manager));
    runtime_page_tables
        .install_source(Box::new(source))
        .unwrap();

    let mut runtime = registration
        .runtime_task_state(runtime_page_tables, Arc::new(MemoryProtections::default()))
        .expect("materialize executable copied child runtime state");

    let mut primary_host = vec![0u8; carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize];
    let mut ext_host = vec![0u8; carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize];
    let mut ext_region = crate::trap::thread_sibling_tests::mapped_region(
        ext_base.0,
        ext_base.0 + carrick_mem::memory::LINUX_PAGE_TABLES_SIZE,
        ext_base.0,
    );
    ext_region.host_addr = ext_host.as_mut_ptr();
    runtime.mappings.insert(ext_region);

    // Run sync_to_host under the manager lock with a bounded wait to detect self-deadlock.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    struct SendTaskState(HvfTaskState);
    unsafe impl Send for SendTaskState {}
    let runtime_send = SendTaskState(runtime);
    let primary_host_addr = primary_host.as_mut_ptr() as usize;
    fn run_sync_worker(
        runtime_send: SendTaskState,
        primary_host_addr: usize,
        done_tx: std::sync::mpsc::Sender<()>,
    ) {
        let runtime = runtime_send.0;
        let primary_host_ptr = primary_host_addr as *mut u8;
        let pt_auth = runtime.page_tables_authority();

        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut block = crate::memory::LINUX_MMAP_BASE + 64 * TWO_MIB;
        pt_auth
            .edit(
                || Err(TrapError::Hypervisor("manager must be present".to_owned())),
                |editor| {
                    while editor.pool_stats().3 < 2 {
                        editor
                            .set_rw(block + 0x1000, 0x1000, false)
                            .expect("mapping succeeds");
                        block += TWO_MIB;
                    }
                    assert_eq!(editor.pool_stats().3, 2, "manager grew to 2 arenas");

                    let page_table_resolver =
                        runtime.page_table_resolver(editor.base(), Some(primary_host_ptr));
                    // SAFETY: primary_host and ext_host are valid for the test duration.
                    unsafe { editor.sync_to_host(page_table_resolver).unwrap() };
                    Ok::<(), TrapError>(())
                },
            )
            .unwrap();
        done_tx.send(()).unwrap();
    }
    let worker =
        std::thread::spawn(move || run_sync_worker(runtime_send, primary_host_addr, done_tx));

    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("sync_to_host under manager lock must not deadlock");
    worker.join().unwrap();

    // Verify that ext_host received synced descriptors from the extension arena.
    assert!(
        ext_host.iter().any(|&b| b != 0),
        "extension arena host memory was written by sync_to_host"
    );

    *task_mm.inventory.lock() = HvpatchTaskInventoryAuthority::Retired;
}

#[test]
fn child_fork_replicates_multi_arena_stage1_page_tables() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let mm = NonZeroU64::new(4).unwrap();
    let asid = NonZeroU16::new(7).unwrap();
    let stage1_root = Gpa(0x8800_0060_0000);
    let transaction =
        carrick_hal::KernelTransactionId::from_kernel_allocation(NonZeroU64::new(703).unwrap());
    let receipt = carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x46; 32]),
        transaction,
        NonZeroU64::new(1).unwrap(),
        0,
        Vec::new(),
    );
    let task_mm = Arc::new(HvpatchTaskMmAuthority {
        mappings: Vec::new(),
        foreign_mm_transport: Some(Arc::clone(&transport)),
        mm_root_slot: Some((stage1_root.raw(), 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        container_root: ContainerRootToken::from_raw(1),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::Active {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            receipt,
            retirement: None,
        }),
        kernel_mm: parking_lot::Mutex::new(Some(mm)),
        cow_armed: Some(Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()))),
        cow_deferred_publications: Some(Arc::new(parking_lot::Mutex::new(Vec::new()))),
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Registration),
        drop_order: None,
    });
    let prepared_mm_access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        task_mm
            .inventory
            .lock()
            .shared_runtime_ledger()
            .expect("prepared child inventory ledger"),
        Arc::clone(task_mm.cow_armed.as_ref().expect("prepared COW arms")),
        Arc::clone(
            task_mm
                .cow_deferred_publications
                .as_ref()
                .expect("prepared COW publications"),
        ),
    );
    *task_mm.mm_access.lock() = Some(Arc::clone(&prepared_mm_access));
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let registration = HvpatchTaskRegistration {
        directory,
        key: HvpatchCarrierTaskStateKey {
            directory_instance: NonZeroU64::new(1).unwrap(),
            task_serial: 104,
            thread_serial: 104,
            execution_generation: 1,
            nonce: NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 104,
            thread_serial: 104,
            execution_generation: 1,
            linux_pid: 104,
            linux_tid: 104,
            asid: asid.get(),
        },
        foreign_mm_registration: None,
        task_mm: Some(Arc::clone(&task_mm)),
        cow_authority: Some(Arc::new(
            super::task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 104,
            linux_tid: 104,
            mm: mm.get(),
            asid: asid.get(),
        }),
        cow_authority_identity: None,
        child_token_verifier,
    };

    let mut parent_manager = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    parent_manager
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            None,
        )
        .expect("reserve sparse arena");
    parent_manager
        .rebase(stage1_root.raw(), None)
        .expect("rebase to stage1_root");
    let ext_base = carrick_guest_mem::Gpa(0xd0_0000_0000);
    let available = std::sync::Arc::new(std::sync::Mutex::new(vec![ext_base]));
    let returned = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let source = TestArenaSource {
        id: carrick_mem::page_table::TableArenaSourceId(stage1_root),
        available: std::sync::Arc::clone(&available),
        returned: std::sync::Arc::clone(&returned),
    };
    let parent_authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(parent_manager));
    parent_authority.install_source(Box::new(source)).unwrap();

    // Grow parent page tables to 2 arenas by mapping enough blocks.
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut block = crate::memory::LINUX_MMAP_BASE + 64 * TWO_MIB;
    let mut mapped_vas = Vec::new();
    parent_authority
        .edit(
            || Err(TrapError::Hypervisor("parent manager present".to_owned())),
            |editor| {
                while editor.pool_stats().3 < 2 {
                    let va = block + 0x1000;
                    editor.set_rw(va, 0x1000, false).expect("mapping succeeds");
                    mapped_vas.push(va);
                    block += TWO_MIB;
                }
                assert_eq!(editor.pool_stats().3, 2, "parent grew to 2 arenas");
                Ok::<(), TrapError>(())
            },
        )
        .unwrap();

    let mut parent_runtime = registration
        .runtime_task_state(
            parent_authority.clone(),
            Arc::new(MemoryProtections::default()),
        )
        .expect("materialize parent runtime state");

    // Primary arena mapping in parent
    let mut primary_host = vec![0u8; carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize];
    let mut primary_region = crate::trap::thread_sibling_tests::mapped_region(
        crate::memory::LINUX_PAGE_TABLES_BASE,
        crate::memory::LINUX_PAGE_TABLES_BASE + carrick_mem::memory::LINUX_PAGE_TABLES_SIZE,
        stage1_root.raw(),
    );
    primary_region.host_addr = primary_host.as_mut_ptr();
    parent_runtime.mappings.insert(primary_region);

    // Extension arena mapping in parent
    let mut ext_host = vec![0u8; TWO_MIB as usize];
    let mut ext_region = crate::trap::thread_sibling_tests::mapped_region(
        ext_base.0,
        ext_base.0 + TWO_MIB,
        ext_base.0,
    );
    ext_region.host_addr = ext_host.as_mut_ptr();
    parent_runtime.mappings.insert(ext_region);

    // Prepare child page tables (cloned and rebased for child root slot)
    let child_root_base = 0x8800_0080_0000_u64;
    let mut child_page_tables = parent_authority.snapshot_image().unwrap();
    child_page_tables.declare_offline_private_image();
    let child_ext_base = carrick_guest_mem::Gpa(0xe0_0000_0000);
    let child_available = std::sync::Arc::new(std::sync::Mutex::new(vec![child_ext_base]));
    let child_returned = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut child_source = TestArenaSource {
        id: carrick_mem::page_table::TableArenaSourceId(Gpa(child_root_base)),
        available: child_available,
        returned: child_returned,
    };
    child_page_tables
        .rebase(child_root_base, Some(&mut child_source))
        .expect("rebase child page tables");

    let request = carrick_hal::ProcessForkRequest {
        entry: carrick_hal::GuestEntryRegs::default(),
        child_ttbr0: child_root_base,
        root_slot_base: child_root_base,
        root_slot_size: 0x20_0000,
        plan: carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 104,
            child_mm: 105,
            ranges: Arc::from([]),
        },
        child_tid: carrick_hal::ThreadId::synthetic_for_tests(105),
        forking_tid: carrick_hal::ThreadId::synthetic_for_tests(104),
        table_arena_source: None,
    };

    let plan = parent_runtime
        .build_process_plan(
            request,
            &mut child_page_tables,
            &[],
            Arc::new(MailboxSlotAllocator::new()),
            HvfSyscallTransport::Mailbox,
            Arc::clone(&transport),
        )
        .expect("build_process_plan succeeds for multi-arena stage1");

    // Verify child mappings contain the root page table and extension arena
    let child_root_mapping = plan
        .mappings
        .iter()
        .find(|m| m.start == crate::memory::LINUX_PAGE_TABLES_BASE)
        .expect("child has root page table mapping");
    assert_eq!(child_root_mapping.ipa, child_root_base);

    let child_ext_mapping = plan
        .mappings
        .iter()
        .find(|m| m.ipa == child_ext_base.0)
        .expect("child has extension arena mapping");
    assert_eq!(child_ext_mapping.size, TWO_MIB as usize);
    assert!(!child_ext_mapping.physical_host_addr.is_null());

    // Verify that child host memory was populated and resolves live translations
    let child_resolver = |base: u64| -> Option<*const u8> {
        plan.mappings
            .iter()
            .find(|m| m.ipa == base)
            .map(|m| m.physical_host_addr.cast_const())
    };
    for va in mapped_vas {
        let walk = unsafe {
            child_page_tables
                .debug_walk_host(carrick_mem::page_table::const_resolver(child_resolver), va)
                .expect("debug_walk_host succeeds on child host memory")
        };
        assert_eq!(
            walk,
            child_page_tables.debug_walk(va),
            "child host tables match shadow tables for VA 0x{va:x}"
        );
    }

    *task_mm.inventory.lock() = HvpatchTaskInventoryAuthority::Retired;
}

#[test]
fn initial_carrier_control_mapping_keeps_direct_unmap_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
    let len = carrick_mem::memory::LINUX_EL0_TRAMPOLINE_SIZE;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0xd6; len as usize]),
        private_file_backing: None,
    };

    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map initial carrier-control region");

    assert!(
        region.host_mapping.is_some(),
        "persistent carrier mappings must retain direct-unmap host ownership",
    );
    assert!(
        region.structural_owner.is_none(),
        "persistent carrier mappings must not also publish structural custody",
    );
    assert_eq!(region.owner_generation, 0);
}

#[test]
fn initial_fixed_mapping_publishes_exact_structural_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x0020_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x5a; len as usize]),
        private_file_backing: None,
    };

    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map initial fixed executable region");
    let owner = region
        .structural_owner
        .as_ref()
        .expect("initial fixed mapping must publish structural ownership");
    let identity = *owner.retained.record_identity.lock();

    assert!(region.host_mapping.is_none());
    assert_eq!(owner.ptr(), region.host_addr);
    assert_eq!(owner.physical_ipa, ipa);
    assert_eq!(owner.physical_size, len as usize);
    assert_eq!(region.owner_generation, owner.epoch().raw());

    drop(region);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire initial fixed mapping fixture");
}

/// A fork must not re-derive every source mapping's inherited-extent
/// status once per (candidate, overlay) PAIR.
///
/// Asserted on visited rows, not wall time, so it is deterministic under
/// load. The shape it pins was measured on 2026-08-30: with the overlay
/// question answered by a full rescan,
/// `fork_source_translation_has_overlay_owner` plus the O(1)
/// `thread_mapping_semantic_ipa_at` it calls were ~22% of all carrier CPU
/// under a fork/exit storm, because each of the M scans also recomputed a
/// mapping's inherited inventory extents — a fresh allocation and a full
/// inventory pass — giving O(M^2 * I) per fork.
#[test]
fn fork_overlay_owner_lookup_does_not_rescan_every_source_mapping() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    const MAPPINGS: usize = 512;
    // `owner_generation == 0` short-circuits the live-owner authentication
    // in `inherited_fork_inventory_extents_in`, so this fixture exercises
    // the SCAN shape without needing real stage-2 custody.
    let mut mappings = Vec::with_capacity(MAPPINGS);
    let mut inventory = std::collections::BTreeMap::new();
    for index in 0..MAPPINGS {
        let start = 0x1_0000_0000 + (index as u64) * 0x1_0000;
        let physical_ipa = 0x8_0000_0000 + (index as u64) * 0x1_0000;
        let mut desc = ThreadMappingDesc {
            start,
            ipa: 0x4_0000_0000 + (index as u64) * 0x1_0000,
            end: start + 0x4000,
            host_addr: std::ptr::null_mut(),
            size: 0x4000,
            physical_ipa,
            physical_host_addr: std::ptr::null_mut(),
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::RW,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
            structural_owner: None,
        };
        desc.end = desc.start + desc.size as u64;
        inventory.insert(
            (physical_ipa, desc.physical_size as u64),
            InventoryExtent {
                frame: carrick_hal::FrameId::from_kernel_allocation(
                    NonZeroU64::new(1 + index as u64).unwrap(),
                ),
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    NonZeroU64::new(1 + index as u64).unwrap(),
                ),
                backing: InventoryBackingIdentity::Private(1 + index as u64),
                stage2_base: physical_ipa,
                stage2_length: desc.physical_size as u64,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: 0,
                    generation: 0,
                },
            },
        );
        mappings.push(desc);
    }

    let before = hot_path_rows_scanned(HotPathScan::ForkMappings);
    let index = ForkOverlayOwnerIndex::build(
        legacy_test_carrier_vm_custody(),
        &mappings,
        &index_fork_inventory_by_stage2(&inventory),
    );
    // One query per mapping, exactly as the fork loop issues them.
    for (candidate, mapping) in mappings.iter().enumerate() {
        let translated = thread_mapping_semantic_ipa_at(mapping, mapping.start)
            .expect("fixture mapping translates its own base");
        assert!(
            !index.has_overlay_owner(&mappings, candidate, mapping.start, translated),
            "each fixture mapping is its own only owner, so no OTHER mapping \
                 may claim its translation"
        );
    }
    let scanned = hot_path_rows_scanned(HotPathScan::ForkMappings) - before;

    let rows = MAPPINGS as u64;
    assert!(
        scanned <= 4 * rows,
        "a fork over {rows} source mappings visited {scanned} mapping rows; \
             the overlay-owner question must be indexed once per fork, not \
             re-asked against every mapping per candidate (the rescan shape \
             visits {} rows)",
        rows * rows
    );
}

#[test]
fn structural_vvar_fork_inheritance_requires_exact_live_custody() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = crate::vdso::LINUX_VVAR_BASE;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: 0x1000,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: false,
        },
        shared: false,
        image: Arc::new(vec![0; 0x1000]),
        private_file_backing: None,
    };
    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map structural vvar fixture");
    let owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("structural vvar owner");
    let identity = *owner.retained.record_identity.lock();
    let desc = ThreadMappingDesc::from_region(&region);
    let exact_owner = InventoryStage2OwnerIdentity {
        host_addr: desc.physical_host_addr as usize,
        generation: desc.owner_generation,
    };
    let extent = InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(860).unwrap()),
        mapping: carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(861).unwrap()),
        backing: InventoryBackingIdentity::Private(862),
        stage2_base: desc.physical_ipa,
        stage2_length: desc.physical_size as u64,
        stage2_owner: exact_owner,
    };
    let inventory = std::collections::BTreeMap::from([(
        (desc.physical_ipa, desc.physical_size as u64),
        extent,
    )]);

    let inventory_index = index_fork_inventory_by_stage2(&inventory);
    let inherited =
        inherited_fork_inventory_extents_indexed(&transport.custody, &desc, &inventory_index);
    assert_eq!(
        inherited.len(),
        1,
        "an exact current structural vvar owner must remain a fork source",
    );
    assert_eq!(
        inherited[0].0,
        (desc.physical_ipa, desc.physical_size as u64),
    );
    assert_eq!(inherited[0].1.mapping, extent.mapping);

    let mut wrong_epoch = desc.clone();
    wrong_epoch.owner_generation = wrong_epoch.owner_generation.saturating_add(1);
    assert!(
        inherited_fork_inventory_extents_indexed(
            &transport.custody,
            &wrong_epoch,
            &inventory_index,
        )
        .is_empty(),
        "a drifted structural epoch must fail closed",
    );
    let mut wrong_host = desc.clone();
    wrong_host.physical_host_addr = wrong_host.physical_host_addr.wrapping_add(0x1000);
    assert!(
            inherited_fork_inventory_extents_indexed(
                &transport.custody,
                &wrong_host,
                &inventory_index,
            )
            .is_empty(),
            "a drifted structural host must fail closed",
        );
    let mut wrong_perms = desc.clone();
    wrong_perms.perms = applevisor::memory::MemPerms::ReadWrite;
    assert!(
        inherited_fork_inventory_extents_indexed(
            &transport.custody,
            &wrong_perms,
            &inventory_index,
        )
        .is_empty(),
        "drifted structural permissions must fail closed",
    );
    let mut missing_owner = desc.clone();
    missing_owner.structural_owner = None;
    assert!(
        inherited_fork_inventory_extents_indexed(
            &transport.custody,
            &missing_owner,
            &inventory_index,
        )
        .is_empty(),
        "a structural generation without its exact owner Arc must fail closed",
    );
    {
        let mut state = transport.custody.state.lock();
        state.lifecycle = CarrierVmLifecycle::Creating(CarrierVmGeneration(
            identity.vm_generation.0.wrapping_add(1),
        ));
    }
    assert!(
        inherited_fork_inventory_extents_indexed(&transport.custody, &desc, &inventory_index)
            .is_empty(),
        "a structural owner outside its custody generation must fail closed",
    );
    {
        let mut state = transport.custody.state.lock();
        state.lifecycle = CarrierVmLifecycle::Live(identity.vm_generation);
        state
            .stage2_records
            .get_mut(&identity.record_id)
            .expect("structural vvar custody record")
            .snapshot
            .terminalized_by_vm_destroy = true;
    }
    assert!(
        inherited_fork_inventory_extents_indexed(&transport.custody, &desc, &inventory_index)
            .is_empty(),
        "a terminal structural custody record must fail closed",
    );
    {
        let mut state = transport.custody.state.lock();
        state
            .stage2_records
            .get_mut(&identity.record_id)
            .expect("structural vvar custody record")
            .snapshot
            .terminalized_by_vm_destroy = false;
    }
    owner
        .retained
        .owner_retired
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(
        inherited_fork_inventory_extents_indexed(&transport.custody, &desc, &inventory_index)
            .is_empty(),
        "a retired structural owner must fail closed",
    );

    drop(desc);
    drop(region);
    drop(owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire structural vvar fork fixture");
}

#[test]
fn production_fork_plan_retains_structural_vvar_semantic_authority() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let vvar_ipa = crate::vdso::LINUX_VVAR_BASE;
    let vvar_len = 0x4000_u64;
    let vvar_mapping = GuestMapping {
        guest_start: vvar_ipa,
        ipa_start: vvar_ipa,
        mapped_size: vvar_len,
        offset_in_mapping: 0,
        payload_size: 0x1000,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: false,
        },
        shared: false,
        image: Arc::new(vec![0; 0x1000]),
        private_file_backing: None,
    };
    let vvar = map_region_raw_in(&transport.custody, &vvar_mapping, false, true)
        .expect("map production-shape structural vvar");
    let vvar_owner = vvar
        .structural_owner
        .as_ref()
        .cloned()
        .expect("production-shape vvar owner");
    let vvar_identity = *vvar_owner.retained.record_identity.lock();
    let overlay_ipa = vvar_ipa + vvar_len;
    let overlay_mapping = GuestMapping {
        guest_start: vvar_ipa,
        ipa_start: overlay_ipa,
        mapped_size: vvar_len,
        offset_in_mapping: 0,
        payload_size: 0x1000,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: false,
        },
        shared: false,
        image: Arc::new(vec![0; 0x1000]),
        private_file_backing: None,
    };
    let overlay = map_region_raw_in(&transport.custody, &overlay_mapping, false, true)
        .expect("map authenticated structural vvar overlay");
    let overlay_owner = overlay
        .structural_owner
        .as_ref()
        .cloned()
        .expect("production-shape vvar overlay owner");
    let overlay_identity = *overlay_owner.retained.record_identity.lock();
    let page_tables_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent page-table backing");
    let page_tables_host_addr = page_tables_host.as_ptr();
    let page_tables = HvfMappedRegion {
        start: crate::memory::LINUX_PAGE_TABLES_BASE,
        ipa: crate::memory::LINUX_PAGE_TABLES_BASE,
        physical_ipa: crate::memory::LINUX_PAGE_TABLES_BASE,
        end: crate::memory::LINUX_PAGE_TABLES_BASE + crate::memory::LINUX_PAGE_TABLES_SIZE,
        host_addr: page_tables_host_addr,
        size: crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
        physical_size: crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
        perms: applevisor::memory::MemPerms::ReadWrite,
        memory: None,
        host_mapping: Some(page_tables_host),
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let parent_inventory = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let initial_transaction =
        carrick_hal::KernelTransactionId::from_kernel_allocation(NonZeroU64::new(869).unwrap());
    let mut initial_reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x86; 32]),
        carrick_hal::FrameInventoryBatch::prepare(
            initial_transaction,
            carrick_hal::FrameEventCapacity::for_event_count(4)
                .expect("initial vvar inventory event capacity"),
        )
        .expect("prepare initial vvar inventory batch"),
        vec![
            carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(870).unwrap()),
            carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(873).unwrap()),
        ],
        vec![
            carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(871).unwrap()),
            carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(874).unwrap()),
        ],
    );
    let vvar_extent = {
        let mut inventory = parent_inventory.lock();
        let extent = HvfVmState::stage_mapping_in(
            &transport.custody,
            &mut inventory,
            &mut initial_reservation,
            InventoryMappingStage {
                gpa: vvar.physical_ipa,
                length: vvar.physical_size as u64,
                permissions: HvfVmState::region_permissions(&vvar),
                backing: InventoryBackingIdentity::Private(872),
                inherited_frame: None,
                stage2_lease: None,
                stage2_owner: mapped_region_stage2_owner_identity(&vvar)
                    .expect("initial vvar structural owner identity"),
            },
        )
        .expect("stage initial vvar inventory through production path");
        inventory.initialized = true;
        extent
    };
    let overlay_extent = {
        let mut inventory = parent_inventory.lock();
        HvfVmState::stage_mapping_in(
            &transport.custody,
            &mut inventory,
            &mut initial_reservation,
            InventoryMappingStage {
                gpa: overlay.physical_ipa,
                length: overlay.physical_size as u64,
                permissions: HvfVmState::region_permissions(&overlay),
                backing: InventoryBackingIdentity::Private(875),
                inherited_frame: None,
                stage2_lease: None,
                stage2_owner: mapped_region_stage2_owner_identity(&overlay)
                    .expect("authenticated overlay structural owner identity"),
            },
        )
        .expect("stage authenticated overlay through production path")
    };
    let initial_commit = initial_reservation.commit(());
    assert_eq!(
        initial_commit.batch().transaction(),
        initial_transaction,
        "the production initial inventory transaction must publish the vvar extent",
    );
    let published_vvar_extent = parent_inventory
        .lock()
        .extents
        .get(&(vvar.physical_ipa, vvar.physical_size as u64))
        .copied()
        .expect("published initial vvar inventory extent");
    assert_eq!(published_vvar_extent.mapping, vvar_extent.mapping);
    assert_eq!(published_vvar_extent.frame, vvar_extent.frame);
    assert_eq!(published_vvar_extent.stage2_owner, vvar_extent.stage2_owner);
    let mut parent = HvfTaskState {
        mappings: TaskMappingIndex::from_iter([page_tables, vvar, overlay]),
        mm_root_slot: Some((0x9a00_2000_0000, 0x20_0000)),
        container_root: ContainerRootToken::from_raw(1),
        pending_exec_mm_root_slot: None,
        pending_exec_asid: None,
        pending_exec_predecessor_identity: None,
        pending_exec_stage2_cleanup: None,
        shared_process_mm: false,
        mm_access: MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            Arc::new(MemoryProtections::default()),
            parent_inventory,
            Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            Arc::new(parking_lot::Mutex::new(Vec::new())),
        ),
        last_exit_class: 0,
        last_fault_esr: 0,
        is_forked_child: false,
        forked_no_exec: false,
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
        persistent_vm_lifecycle: true,
        cow_authority: Some(Arc::new(
            task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 870,
            linux_tid: 870,
            mm: 870,
            asid: 1,
        }),
        pending_fork_frame_receipts: Vec::new(),
        pending_process_aliases: Vec::new(),
        fail_next_begin_exec_inventory: false,
        cow_rollback_scratch: None,
        registration: None,
    };
    let root_slot_base = crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x40_0000;
    let root_slot_size = 0x20_0000_u64;
    let make_request = || carrick_hal::ProcessForkRequest {
        entry: carrick_hal::GuestEntryRegs::default(),
        child_ttbr0: root_slot_base,
        root_slot_base,
        root_slot_size,
        plan: carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 870,
            child_mm: 871,
            ranges: Arc::from([]),
        },
        child_tid: carrick_hal::ThreadId::synthetic_for_tests(871),
        forking_tid: carrick_hal::ThreadId::synthetic_for_tests(870),
        table_arena_source: None,
    };
    let make_child_page_tables = |translated_ipa| {
        let mut child_page_tables = crate::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
        );
        child_page_tables
            .map_aliased(vvar_ipa, translated_ipa, vvar_len, false, None)
            .expect("map child vvar translation");
        child_page_tables
            .rebase(root_slot_base, None)
            .expect("rebase child page tables");
        child_page_tables
    };
    let cow_ranges = [carrick_aarch64::vmm::ForkCowRange {
        va: vvar_ipa,
        len: vvar_len as usize,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    }];
    let generation_address = vvar_ipa + crate::vdso::VVAR_OFF_RNG_GENERATION as u64;
    let parent_generation_ptr = vvar_owner
        .ptr()
        .wrapping_add(crate::vdso::VVAR_OFF_RNG_GENERATION);
    let parent_generation_seed = 0x1122_3344_5566_7788_u64;
    unsafe {
        parent_generation_ptr
            .cast::<u64>()
            .write_unaligned(parent_generation_seed);
    }

    let parent_vvar = parent
        .mappings
        .iter_mut()
        .find(|mapping| mapping.start == vvar_ipa)
        .expect("parent vvar mapping");
    let exact_owner = parent_vvar
        .structural_owner
        .take()
        .expect("parent structural vvar owner");
    let mut overlay_child_page_tables = make_child_page_tables(overlay_ipa);
    let overlay_plan = parent
        .build_process_plan(
            make_request(),
            &mut overlay_child_page_tables,
            &cow_ranges,
            Arc::new(MailboxSlotAllocator::new()),
            HvfSyscallTransport::Mailbox,
            Arc::clone(&transport),
        )
        .expect("an authenticated stage-1 overlay must supersede the stale coarse vvar row");
    assert!(
        overlay_plan.mappings.iter().any(|mapping| {
            mapping.start == vvar_ipa
                && mapping.ipa == overlay_ipa
                && mapping.inherited_frame == Some(overlay_extent.frame)
        }),
        "fork planning must retain the exact authenticated overlay owner",
    );

    let mut arbitrary_child_page_tables = make_child_page_tables(overlay_ipa + vvar_len);
    let error = match parent.build_process_plan(
        make_request(),
        &mut arbitrary_child_page_tables,
        &cow_ranges,
        Arc::new(MailboxSlotAllocator::new()),
        HvfSyscallTransport::Mailbox,
        Arc::clone(&transport),
    ) {
        Ok(_) => {
            panic!("an arbitrary translated IPA without an overlay owner must fail closed")
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("has no authenticated inherited inventory extent"),
        "unexpected arbitrary translated-IPA failure: {error}",
    );
    assert!(
        error.to_string().contains("live_translation=Some")
            && error.to_string().contains("candidate_translation=Some")
            && error.to_string().contains("authenticated_overlay=false"),
        "fork refusal must report the exact stage-1/overlay discriminator: {error}",
    );

    let mut unauthenticated_child_page_tables = make_child_page_tables(vvar_ipa);
    let error = match parent.build_process_plan(
        make_request(),
        &mut unauthenticated_child_page_tables,
        &cow_ranges,
        Arc::new(MailboxSlotAllocator::new()),
        HvfSyscallTransport::Mailbox,
        Arc::clone(&transport),
    ) {
        Ok(_) => panic!("a live vvar PTE without its structural owner must fail closed"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("has no authenticated inherited inventory extent"),
        "unexpected unauthenticated vvar failure: {error}",
    );
    assert!(
        error.to_string().contains("live_translation=Some")
            && error.to_string().contains("candidate_translation=Some")
            && error.to_string().contains("authenticated_overlay=false"),
        "fork refusal must report the exact stage-1/overlay discriminator: {error}",
    );
    parent
        .mappings
        .iter_mut()
        .find(|mapping| mapping.start == vvar_ipa)
        .expect("parent vvar mapping")
        .structural_owner = Some(exact_owner);

    let mut child_page_tables = make_child_page_tables(vvar_ipa);
    let mut plan = parent
        .build_process_plan(
            make_request(),
            &mut child_page_tables,
            &cow_ranges,
            Arc::new(MailboxSlotAllocator::new()),
            HvfSyscallTransport::Mailbox,
            Arc::clone(&transport),
        )
        .expect("build child plan with structural vvar");
    assert!(
        plan.mappings
            .iter()
            .any(|mapping| mapping.start == vvar_ipa),
        "production fork planning must retain the vvar semantic descriptor",
    );
    let ids = std::sync::atomic::AtomicU64::new(880);
    plan.stage_with_reservation_factory(|frames, mappings, capacity| {
        let next =
            || NonZeroU64::new(ids.fetch_add(1, std::sync::atomic::Ordering::SeqCst)).unwrap();
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x88; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(next()),
                    capacity,
                )
                .unwrap(),
                (0..frames)
                    .map(|_| carrick_hal::FrameId::from_kernel_allocation(next()))
                    .collect(),
                (0..mappings)
                    .map(|_| carrick_hal::MappingId::from_kernel_allocation(next()))
                    .collect(),
            ),
        )
    })
    .expect("reserve child inventory");
    let (carrier, mut prepared) =
        HvfVmState::prepare_task_only_plan_for_test(plan).expect("prepare task-only child");
    let mut projected = HvfTaskState::neutral();
    projected.persistent_vm_lifecycle = true;
    projected.mappings = prepared
        .mappings
        .iter()
        .map(HvpatchTaskMappingState::unowned_runtime_region)
        .collect();
    assert!(
        projected.mappings.iter().any(|mapping| {
            mapping.contains_range(generation_address, core::mem::size_of::<u64>())
                && mapping
                    .structural_owner
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(owner, &vvar_owner))
        }),
        "task-only projection must resolve the child RNG-generation stamp",
    );
    let child_page_table_host = prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE)
        .expect("prepared child page-table mapping")
        .host_addr;
    unsafe {
        child_page_tables
            .sync_to_host((child_page_tables.base(), child_page_table_host))
            .unwrap();
    }
    let child_inventory = prepared
        .inventory
        .shared_runtime_ledger()
        .expect("prepared child inventory ledger");
    let child_cow_armed = prepared
        .cow_armed
        .as_ref()
        .cloned()
        .expect("prepared child COW arms");
    let child_deferred_publications = prepared
        .cow_deferred_publications
        .as_ref()
        .cloned()
        .expect("prepared child deferred COW publications");
    let child_page_tables_authority =
        carrick_aarch64::Stage1Authority::new_with_manager(Some(child_page_tables));
    let child_state = MmAccessState::new(
        child_page_tables_authority.clone(),
        Arc::new(MemoryProtections::default()),
        Arc::clone(&child_inventory),
        child_cow_armed,
        child_deferred_publications,
    );
    for mapping in &prepared.mappings {
        if let Some(owner) = &mapping.structural_owner {
            child_state.install_structural_owner(Arc::clone(owner));
        }
    }
    let child_snapshot = TestSnapshot {
        mm: NonZeroU64::new(871).unwrap(),
        asid: NonZeroU16::new(2).unwrap(),
        stage1_root: Gpa(root_slot_base),
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids: child_inventory
            .lock()
            .extents
            .values()
            .map(|extent| extent.mapping)
            .collect(),
        executable_ranges: Vec::new(),
        readable_ranges: Vec::new(),
    };
    let child_live = TestLiveAuthority(Arc::new(parking_lot::RwLock::new(child_snapshot.clone())));
    let cow_authority = Arc::new(TestForeignCowAuthority {
        live: Arc::clone(&child_live.0),
        old_frame: vvar_extent.frame,
        allow_quiesce: true,
        serial: std::sync::atomic::AtomicU64::new(871_000),
        published: parking_lot::Mutex::new(None),
    });
    child_state.bind_cow_runtime(MmCowRuntimeBinding {
        authority: cow_authority.clone(),
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: 871,
            linux_tid: 871,
            mm: 871,
            asid: 2,
        },
        mm_root_slot: prepared.mm_root_slot,
        container_root: prepared.container_root,
        persistent_vm_lifecycle: true,
    });
    let prepared_vvar = prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == vvar_ipa)
        .expect("prepared child vvar mapping");
    assert!(
        !prepared_vvar.guest_writable,
        "vvar must remain guest read-only"
    );
    const AP_MASK: u64 = 0b11 << 6;
    const AP_USER_RO: u64 = 0b11 << 6;
    assert_eq!(
        child_page_tables_authority
            .with_manager(|pt| pt.debug_walk(generation_address)[3] & AP_MASK)
            .expect("prepared child page tables"),
        AP_USER_RO,
        "prepared child vvar leaf must begin guest read-only",
    );
    let mut child_task = HvfTaskState {
        mappings: prepared
            .mappings
            .iter()
            .map(HvpatchTaskMappingState::unowned_runtime_region)
            .collect(),
        mm_root_slot: prepared.mm_root_slot,
        container_root: prepared.container_root,
        pending_exec_mm_root_slot: None,
        pending_exec_asid: None,
        pending_exec_predecessor_identity: None,
        pending_exec_stage2_cleanup: None,
        shared_process_mm: false,
        mm_access: Arc::clone(&child_state),
        last_exit_class: 0,
        last_fault_esr: 0,
        is_forked_child: false,
        forked_no_exec: false,
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
        persistent_vm_lifecycle: true,
        cow_authority: Some(cow_authority),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 871,
            linux_tid: 871,
            mm: 871,
            asid: 2,
        }),
        pending_fork_frame_receipts: Vec::new(),
        pending_process_aliases: Vec::new(),
        fail_next_begin_exec_inventory: false,
        cow_rollback_scratch: None,
        registration: None,
    };
    assert!(
        child_task
            .mapping_for_range_in(
                &transport.custody,
                generation_address,
                core::mem::size_of::<u64>(),
            )
            .is_some_and(|mapping| !mapping.guest_writable),
        "production mapping resolution must find the read-only prepared child vvar",
    );
    let mut flushes = 0;
    child_task
        .refresh_fork_process_state_in(&transport.custody, &mut || {
            flushes += 1;
            Ok(())
        })
        .expect("production privileged child vvar refresh");
    assert_eq!(flushes, 1, "child vvar refresh must publish stage-1 once");
    let parent_generation = unsafe { parent_generation_ptr.cast::<u64>().read_unaligned() };
    assert_eq!(
        parent_generation, parent_generation_seed,
        "child refresh must not mutate the parent's structural vvar bytes",
    );
    let refreshed = child_task
        .mapping_for_range_in(
            &transport.custody,
            generation_address,
            core::mem::size_of::<u64>(),
        )
        .expect("refreshed child-private vvar mapping");
    assert!(
        !refreshed.guest_writable,
        "vvar semantic mapping must stay read-only"
    );
    assert_eq!(
        child_page_tables_authority
            .with_manager(|pt| pt.debug_walk(generation_address)[3] & AP_MASK)
            .expect("refreshed child page tables"),
        AP_USER_RO,
        "privileged internal COW must preserve the guest read-only AP",
    );
    assert!(
        child_task
            .cow_armed
            .lock()
            .span_for(generation_address)
            .is_none(),
        "successful privileged refresh must disarm the child vvar span",
    );
    let child_private_key = (
        align_down(refreshed.ipa, CowArmedRanges::COMPOUND_SIZE),
        CowArmedRanges::COMPOUND_SIZE,
    );
    let child_private_owner = transport.custody.global_frame_host_owners.lock()[&child_private_key]
        .owner()
        .clone();
    let child_generation_offset = generation_address - refreshed.start;
    let child_generation = unsafe {
        child_private_owner
            .as_ptr()
            .add(child_generation_offset as usize)
            .cast::<u64>()
            .read_unaligned()
    };
    assert_ne!(child_generation, parent_generation_seed);
    assert_eq!(
        unsafe {
            child_private_owner
                .as_ptr()
                .add(child_generation_offset as usize)
                .cast::<u64>()
                .read_unaligned()
        },
        child_generation,
        "the fresh generation must land in the child-private COW owner",
    );
    let grandchild_root_slot = root_slot_base + root_slot_size;
    let mut grandchild_page_tables = child_page_tables_authority
        .snapshot_image()
        .expect("refreshed child page tables");
    grandchild_page_tables
        .rebase(grandchild_root_slot, None)
        .expect("rebase refreshed child page tables for grandchild");
    let grandchild_plan = child_task
        .build_process_plan(
            carrick_hal::ProcessForkRequest {
                entry: carrick_hal::GuestEntryRegs::default(),
                child_ttbr0: grandchild_root_slot,
                root_slot_base: grandchild_root_slot,
                root_slot_size,
                plan: carrick_hal::ForkProjectionPlan::Copied {
                    parent_mm: 871,
                    child_mm: 872,
                    ranges: Arc::from([]),
                },
                child_tid: carrick_hal::ThreadId::synthetic_for_tests(872),
                forking_tid: carrick_hal::ThreadId::synthetic_for_tests(871),
                table_arena_source: None,
            },
            &mut grandchild_page_tables,
            &cow_ranges,
            Arc::new(MailboxSlotAllocator::new()),
            HvfSyscallTransport::Mailbox,
            Arc::clone(&transport),
        )
        .expect("fork refreshed child-private vvar into grandchild");
    assert!(
        grandchild_plan.mappings.iter().any(|mapping| {
            mapping.start == vvar_ipa
                && mapping.physical_ipa == child_private_key.0
                && mapping.owner_generation == child_private_owner.generation()
                && mapping.inherited_frame.is_some()
        }),
        "the second fork must inherit the exact COW overlay owner",
    );
    assert!(
        grandchild_plan.inventory_mappings.iter().any(|mapping| {
            mapping.gpa == child_private_key.0
                && mapping.length == child_private_key.1
                && mapping.stage2_owner
                    == InventoryStage2OwnerIdentity {
                        host_addr: child_private_owner.as_ptr() as usize,
                        generation: child_private_owner.generation(),
                    }
        }),
        "the second fork must carry the COW overlay's exact inventory authority",
    );
    drop(child_task);
    prepared.inventory = HvpatchTaskInventoryAuthority::Absent;
    drop(child_state);
    drop(child_inventory);
    let retired = retire_global_frame_host_owner_if_generation_in(
        &transport.custody,
        child_private_key.0,
        child_private_key.1,
        child_private_owner.generation(),
    );
    assert!(
        retired.is_retired(),
        "retire child-private vvar COW fixture: {retired:?}",
    );
    drop(child_private_owner);
    carrier.abort().expect("retire child carrier fixture");
    drop(projected);
    drop(parent);
    drop(vvar_owner);
    drop(overlay_owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[vvar_identity, overlay_identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire production vvar fixture");
}

#[test]
fn current_generation_structural_owner_needs_no_replay_rebind() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x0030_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x52; len as usize]),
        private_file_backing: None,
    };
    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map current-generation structural region");
    let owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("current-generation structural owner");
    let identity = *owner.retained.record_identity.lock();
    let before = transport
        .custody
        .stage2_record_snapshot(identity.record_id)
        .expect("current-generation structural record");
    assert!(before.mapped);
    assert!(before.backend_map_installed);
    assert!(!before.retirement_requested);
    assert!(!before.terminalized_by_vm_destroy);

    let report = reconcile_global_frame_owners_after_replay_in(&transport.custody, &[], false)
        .expect("a current-generation backend-installed structural owner is already live");

    assert_eq!(report, GlobalFrameReplayReconcileReport::default());
    assert_eq!(
        transport.custody.stage2_record_snapshot(identity.record_id),
        Some(before),
        "current-generation reconciliation must not rebind or mutate custody",
    );
    assert_eq!(
        *owner.retained.record_identity.lock(),
        identity,
        "current-generation reconciliation must retain the exact owner record identity",
    );
    drop(region);
    drop(owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire current-generation reconciliation fixture");
}

#[test]
fn old_generation_structural_owner_still_requires_exact_replay() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x0034_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x63; len as usize]),
        private_file_backing: None,
    };
    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map G1 structural region");
    let owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("G1 structural owner");
    let g1_identity = *owner.retained.record_identity.lock();
    let host_addr = owner.ptr() as usize;
    let perms = u64::from(region.perms);

    destroy_vm_with_custody_using(&transport.custody, "structural G1 destroy", || 0, || {})
        .expect("destroy G1 structural fixture");
    let g2 = transport.custody.begin_create().expect("begin G2");
    let empty_error = reconcile_global_frame_owners_after_replay_in(&transport.custody, &[], false)
        .expect_err("an old-generation structural owner requires exact replay");
    assert!(empty_error.to_string().contains(
        "live structural backing IPA 0x340000 size 16384 was not replayed into the current VM"
    ));

    let drift_error = reconcile_global_frame_owners_after_replay_in(
        &transport.custody,
        &[GlobalFrameReplayExtent {
            ipa,
            length: len,
            host_addr,
            perms: perms ^ 1,
        }],
        false,
    )
    .expect_err("same-key structural replay with drifted permissions must fail closed");
    assert!(
        drift_error
            .to_string()
            .contains("structural backing replay identity drift"),
        "unexpected drift failure: {drift_error}",
    );
    assert_eq!(
        *owner.retained.record_identity.lock(),
        g1_identity,
        "rejected replay must not rebind the retained owner identity",
    );

    let report = reconcile_global_frame_owners_after_replay_in(
        &transport.custody,
        &[GlobalFrameReplayExtent {
            ipa,
            length: len,
            host_addr,
            perms,
        }],
        false,
    )
    .expect("exact structural replay rebinds G1 custody into G2");

    assert_eq!(report.rebound, 1);
    let g2_identity = *owner.retained.record_identity.lock();
    assert_ne!(g2_identity.record_id, g1_identity.record_id);
    assert_eq!(g2_identity.vm_generation, g2);
    transport
        .custody
        .commit_create(g2)
        .expect("publish G2 fixture");
    drop(region);
    drop(owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[g2_identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire G2 structural replay fixture");
}

#[test]
fn initial_structural_epoch_failure_does_not_publish_stage2() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x0024_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: ipa,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x3c; len as usize]),
        private_file_backing: None,
    };

    let error =
        map_region_raw_in_using_epoch_allocator(&transport.custody, &mapping, false, true, || {
            Err(TrapError::Hypervisor(
                "injected structural epoch failure".to_owned(),
            ))
        })
        .expect_err("injected structural epoch failure must abort initial mapping");

    assert!(
        error
            .to_string()
            .contains("injected structural epoch failure")
    );
    assert!(
        ScopedStage2MapTestStub::events().is_empty(),
        "fallible structural authority must be minted before publishing stage-2",
    );
}

#[test]
fn structural_alias_rejects_forged_semantic_host_projection() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x0028_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: 0x0040_0000,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x7a; len as usize]),
        private_file_backing: None,
    };
    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map structural alias source");
    let owner = region
        .structural_owner
        .as_ref()
        .expect("structural alias source owner");
    let identity = *owner.retained.record_identity.lock();
    let source = ThreadMappingDesc::from_region(&region);
    let forged = AliasBacking {
        start: region.start + 0x1000,
        ipa: region.physical_ipa + 0x1000,
        host_addr: source.physical_host_addr as usize + 0x2000,
        size: 0x1000,
        physical_ipa: region.physical_ipa,
        physical_host_addr: source.physical_host_addr as usize,
        physical_size: region.physical_size,
        perms: u64::from(region.perms),
        guest_writable: region.guest_writable,
        sharing: region.sharing,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: 0x9000_0000,
            size: 0x20_0000,
        },
        inventory_backing: InventoryBackingIdentity::Private(841),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: region.owner_generation,
    };

    let projected =
        ThreadMappingDesc::from_alias_with_structural_owner(forged, std::slice::from_ref(&source))
            .expect("decode forged alias metadata");

    assert!(
        projected.structural_owner.is_none(),
        "matching physical identity must not authenticate a forged semantic host projection",
    );
    drop(projected);
    drop(source);
    drop(region);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire forged semantic projection fixture");
}

#[test]
fn initial_fixed_mapping_composes_through_first_fork_preparation() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let ipa = 0x002c_0000;
    let len = 0x4000_u64;
    let mapping = GuestMapping {
        guest_start: 0x0040_0000,
        ipa_start: ipa,
        mapped_size: len,
        offset_in_mapping: 0,
        payload_size: len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        },
        shared: false,
        image: Arc::new(vec![0x6b; len as usize]),
        private_file_backing: None,
    };
    let region = map_region_raw_in(&transport.custody, &mapping, false, true)
        .expect("map production initial fixed region");
    let root_owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("production initial fixed owner");
    let identity = *root_owner.retained.record_identity.lock();
    let projected = ThreadMappingDesc::from_region(&region);
    let inherited_frame =
        carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(842).unwrap());
    let inherited_mapping =
        carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(843).unwrap());
    let mut plan = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: projected.start,
            ipa: projected.ipa,
            end: projected.end,
            stage2_lease: None,
            host: ProcessMappingHost::Borrowed {
                pointer: projected.physical_host_addr,
                structural_owner: projected.structural_owner.clone(),
            },
            size: projected.size,
            physical_ipa: projected.physical_ipa,
            physical_host_addr: projected.physical_host_addr,
            physical_size: projected.physical_size,
            inventory_backing: InventoryBackingIdentity::Private(844),
            perms: projected.perms,
            is_dynamic_alias: projected.is_dynamic_alias,
            sharing: projected.sharing,
            guest_writable: projected.guest_writable,
            inherited_frame: Some(inherited_frame),
            shared_key_base: projected.shared_key_base,
            shared_key_offset: projected.shared_key_offset,
            owner_generation: projected.owner_generation,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: projected.physical_ipa,
            length: projected.physical_size as u64,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: false,
                exec: true,
            },
            inherited_frame: Some(inherited_frame),
            inherited_mapping: Some(inherited_mapping),
            backing: InventoryBackingIdentity::Private(844),
            stage2_lease: (projected.physical_ipa, projected.physical_size as u64),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: projected.physical_host_addr as usize,
                generation: projected.owner_generation,
            },
            fork_frame_receipt_kind: Some(
                carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            ),
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (0x9000_0000, 0x20_0000),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    plan.stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x77; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(
                        NonZeroU64::new(845).unwrap(),
                    ),
                    capacity,
                )
                .unwrap(),
                (0..frame_candidates)
                    .map(|index| {
                        carrick_hal::FrameId::from_kernel_allocation(
                            NonZeroU64::new(846 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
                (0..mapping_candidates)
                    .map(|index| {
                        carrick_hal::MappingId::from_kernel_allocation(
                            NonZeroU64::new(856 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
            ),
        )
    })
    .expect("reserve first-fork inventory");
    let (carrier, mut child) = HvfVmState::prepare_task_only_plan_for_test(plan)
        .expect("prepare first child from production initial mapping");
    let child_mapping = child
        .mappings
        .iter()
        .find(|mapping| mapping.start == region.start)
        .expect("prepared first-fork fixed mapping");
    assert!(
        child_mapping
            .structural_owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &root_owner)),
        "first fork must preserve the exact owner created by map_region_raw_in",
    );
    child
        .rollback_unpublished_inventory()
        .expect("rollback first-fork inventory");
    carrier.abort().expect("retire first-fork fixture leases");
    drop(child);
    drop(projected);
    drop(region);
    drop(root_owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire first-fork composition fixture");
}

#[test]
fn private_overlay_publication_preserves_structural_owner_across_fork() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let root_slot = (0x7ee0_0000_0000_u64, 0x20_0000_u64);
    let overlay_base = crate::memory::LINUX_PRIVATE_OVERLAY_BASE;
    let overlay_size = crate::memory::LINUX_PRIVATE_OVERLAY_SIZE;
    let mapping = GuestMapping {
        guest_start: overlay_base,
        ipa_start: overlay_base,
        mapped_size: overlay_size,
        offset_in_mapping: 0,
        payload_size: 0,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: true,
            execute: false,
        },
        shared: false,
        image: Arc::new(Vec::new()),
        private_file_backing: None,
    };
    let mut region = prepare_exec_region_raw_in(&transport.custody, &mapping)
        .expect("prepare private overlay exec backing");
    let mut lease = GlobalFrameStage2Lease::fixed(overlay_base, overlay_size);
    lease.mark_test_mapped_without_backend();

    publish_exec_region_host_owner_in(&transport.custody, &mut region, lease, Some(root_slot))
        .expect("publish exec private overlay under structural custody");

    let parent_owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("exec private overlay publication must preserve its exact structural owner");
    assert_eq!(parent_owner.physical_ipa, overlay_base);
    assert_eq!(parent_owner.physical_size as u64, overlay_size);
    assert!(
        global_frame_host_owner_identity_in(&transport.custody, overlay_base, overlay_size)
            .is_none(),
        "fixed private overlay custody must not be hidden in the global-frame directory"
    );

    let identity = *parent_owner.retained.record_identity.lock();
    let projected = ThreadMappingDesc::from_region(&region);
    let inherited_frame =
        carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(890).unwrap());
    let inherited_mapping =
        carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(891).unwrap());
    let mut plan = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: projected.start,
            ipa: projected.ipa,
            end: projected.end,
            stage2_lease: None,
            host: ProcessMappingHost::Borrowed {
                pointer: projected.physical_host_addr,
                structural_owner: projected.structural_owner.clone(),
            },
            size: projected.size,
            physical_ipa: projected.physical_ipa,
            physical_host_addr: projected.physical_host_addr,
            physical_size: projected.physical_size,
            inventory_backing: InventoryBackingIdentity::Private(892),
            perms: projected.perms,
            is_dynamic_alias: projected.is_dynamic_alias,
            sharing: projected.sharing,
            guest_writable: projected.guest_writable,
            inherited_frame: Some(inherited_frame),
            shared_key_base: projected.shared_key_base,
            shared_key_offset: projected.shared_key_offset,
            owner_generation: projected.owner_generation,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: projected.physical_ipa,
            length: projected.physical_size as u64,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            inherited_frame: Some(inherited_frame),
            inherited_mapping: Some(inherited_mapping),
            backing: InventoryBackingIdentity::Private(892),
            stage2_lease: (projected.physical_ipa, projected.physical_size as u64),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: projected.physical_host_addr as usize,
                generation: projected.owner_generation,
            },
            fork_frame_receipt_kind: Some(
                carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            ),
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: root_slot,
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    plan.stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x77; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(
                        NonZeroU64::new(893).unwrap(),
                    ),
                    capacity,
                )
                .unwrap(),
                (0..frame_candidates)
                    .map(|index| {
                        carrick_hal::FrameId::from_kernel_allocation(
                            NonZeroU64::new(894 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
                (0..mapping_candidates)
                    .map(|index| {
                        carrick_hal::MappingId::from_kernel_allocation(
                            NonZeroU64::new(895 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
            ),
        )
    })
    .expect("reserve first-fork inventory");
    let (carrier, mut child) = HvfVmState::prepare_task_only_plan_for_test(plan)
        .expect("prepare first child from private overlay mapping");
    let child_mapping = child
        .mappings
        .iter()
        .find(|mapping| mapping.start == region.start)
        .expect("prepared first-fork private overlay mapping");
    assert!(
        child_mapping
            .structural_owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &parent_owner)),
        "first fork must preserve the exact private overlay structural owner",
    );

    let repoint_va = 0x0040_0000_u64;
    let repoint_len = 0x4000_usize;
    let alias = AliasBacking {
        start: repoint_va,
        ipa: overlay_base,
        host_addr: region.host_addr as usize,
        size: repoint_len,
        physical_ipa: overlay_base,
        physical_host_addr: region.host_addr as usize,
        physical_size: overlay_size as usize,
        perms: u64::from(region.perms),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            Some(root_slot),
            ContainerRootToken::from_raw(1),
        ),
        inventory_backing: InventoryBackingIdentity::Private(900),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: region.owner_generation,
    };
    let alias_desc = ThreadMappingDesc::from_alias_with_structural_owner(
        alias,
        std::slice::from_ref(&projected),
    )
    .expect("project private overlay alias descriptor");
    assert!(
        alias_desc
            .structural_owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &parent_owner)),
        "private overlay alias must retain exact structural owner from covering parent mapping",
    );

    child
        .rollback_unpublished_inventory()
        .expect("rollback first-fork inventory");
    carrier.abort().expect("retire first-fork fixture leases");
    drop(child);
    drop(projected);
    drop(region);
    drop(parent_owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire private overlay structural fixture");
}

#[test]
fn copied_fork_child_retain_preserves_borrowed_structural_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let physical_ipa = 0x8800_0060_0000;
    let len = 0x4000_u64;
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        len as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate borrowed structural owner");
    let host_addr = host.as_ptr();
    let mut source_lease = GlobalFrameStage2Lease::fixed(physical_ipa, len);
    source_lease.mark_test_mapped_without_backend();
    let owner = StructuralBackingOwner::new_in(
        &transport.custody,
        host,
        source_lease,
        u64::from(applevisor::memory::MemPerms::ReadExec),
        next_structural_epoch().expect("mint borrowed structural epoch"),
        physical_ipa,
        len as usize,
    )
    .expect("publish borrowed structural owner");
    let identity = *owner.retained.record_identity.lock();
    let owner_generation = owner.epoch().raw();
    let mut plan = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: 0x0040_0000,
            ipa: physical_ipa,
            end: 0x0040_0000 + len,
            stage2_lease: None,
            host: ProcessMappingHost::Borrowed {
                pointer: host_addr,
                structural_owner: Some(Arc::clone(&owner)),
            },
            size: len as usize,
            physical_ipa,
            physical_host_addr: host_addr,
            physical_size: len as usize,
            inventory_backing: InventoryBackingIdentity::Private(801),
            perms: applevisor::memory::MemPerms::ReadExec,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: false,
            inherited_frame: Some(carrick_hal::FrameId::from_kernel_allocation(
                NonZeroU64::new(802).unwrap(),
            )),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: physical_ipa,
            length: len,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: false,
                exec: true,
            },
            inherited_frame: Some(carrick_hal::FrameId::from_kernel_allocation(
                NonZeroU64::new(802).unwrap(),
            )),
            inherited_mapping: Some(carrick_hal::MappingId::from_kernel_allocation(
                NonZeroU64::new(803).unwrap(),
            )),
            backing: InventoryBackingIdentity::Private(801),
            stage2_lease: (physical_ipa, len),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: host_addr as usize,
                generation: owner_generation,
            },
            fork_frame_receipt_kind: Some(
                carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            ),
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (physical_ipa, len),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    plan.stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x55; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(
                        NonZeroU64::new(804).unwrap(),
                    ),
                    capacity,
                )
                .unwrap(),
                (0..frame_candidates)
                    .map(|index| {
                        carrick_hal::FrameId::from_kernel_allocation(
                            NonZeroU64::new(805 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
                (0..mapping_candidates)
                    .map(|index| {
                        carrick_hal::MappingId::from_kernel_allocation(
                            NonZeroU64::new(815 + index as u64).unwrap(),
                        )
                    })
                    .collect(),
            ),
        )
    })
    .expect("reserve copied-child inventory");
    let (carrier, mut prepared) = HvfVmState::prepare_task_only_plan_for_test(plan)
        .expect("prepare copied-child borrowed structural mapping");
    assert!(
        prepared.pending_aliases.iter().any(|alias| {
            alias.start == 0x0040_0000
                && alias.size == len as usize
                && alias.ipa == physical_ipa
                && alias.physical_ipa == physical_ipa
                && alias.physical_host_addr == host_addr as usize
                && alias.owner_generation == owner_generation
                && alias.ownership_scope
                    == AliasOwnershipScope::MmRootSlot {
                        base: physical_ipa,
                        size: len,
                    }
                && !alias.guest_writable
        }),
        "ordinary inherited private RX must publish exact child-scoped alias authority for foreign text COW",
    );

    let child_mapping = prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == 0x0040_0000)
        .expect("materialized child structural mapping");
    let child_source = ThreadMappingDesc {
        start: child_mapping.start,
        ipa: child_mapping.ipa,
        end: child_mapping.end,
        host_addr: child_mapping.host_addr,
        size: semantic_extent_size(child_mapping.start, child_mapping.end),
        physical_ipa: child_mapping.physical_ipa,
        physical_host_addr: child_mapping.physical_host_addr,
        physical_size: child_mapping.physical_size,
        perms: child_mapping.perms,
        is_dynamic_alias: child_mapping.is_dynamic_alias,
        sharing: child_mapping.sharing,
        guest_writable: child_mapping.guest_writable,
        shared_key_base: child_mapping.shared_key_base,
        shared_key_offset: child_mapping.shared_key_offset,
        owner_generation: child_mapping.owner_generation,
        structural_owner: child_mapping.structural_owner.clone(),
    };
    let child_publication = prepared
        .pending_aliases
        .iter()
        .copied()
        .find(|alias| alias.start == 0x0040_0000)
        .expect("child alias publication");
    let overlay_publication = AliasBacking {
        start: child_publication.start + 0x1000,
        ipa: child_publication.ipa + 0x1000,
        host_addr: child_publication.host_addr + 0x1000,
        size: 0x1000,
        ..child_publication
    };
    let grandchild_overlay = ThreadMappingDesc::from_alias_with_structural_owner(
        overlay_publication,
        std::slice::from_ref(&child_source),
    )
    .expect("plan grandchild overlay from child publication");
    assert!(
        grandchild_overlay
            .structural_owner
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &owner)),
        "grandchild overlay must retain the exact root structural owner Arc",
    );

    let mut grandchild_plan = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: grandchild_overlay.start,
            ipa: grandchild_overlay.ipa,
            end: grandchild_overlay.end,
            stage2_lease: None,
            host: ProcessMappingHost::Borrowed {
                pointer: grandchild_overlay.physical_host_addr,
                structural_owner: grandchild_overlay.structural_owner.clone(),
            },
            size: grandchild_overlay.size,
            physical_ipa: grandchild_overlay.physical_ipa,
            physical_host_addr: grandchild_overlay.physical_host_addr,
            physical_size: grandchild_overlay.physical_size,
            inventory_backing: overlay_publication.inventory_backing,
            perms: grandchild_overlay.perms,
            is_dynamic_alias: true,
            sharing: grandchild_overlay.sharing,
            guest_writable: grandchild_overlay.guest_writable,
            inherited_frame: Some(carrick_hal::FrameId::from_kernel_allocation(
                NonZeroU64::new(822).unwrap(),
            )),
            shared_key_base: grandchild_overlay.shared_key_base,
            shared_key_offset: grandchild_overlay.shared_key_offset,
            owner_generation: grandchild_overlay.owner_generation,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: physical_ipa,
            length: len,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: false,
                exec: true,
            },
            inherited_frame: Some(carrick_hal::FrameId::from_kernel_allocation(
                NonZeroU64::new(822).unwrap(),
            )),
            inherited_mapping: Some(carrick_hal::MappingId::from_kernel_allocation(
                NonZeroU64::new(823).unwrap(),
            )),
            backing: overlay_publication.inventory_backing,
            stage2_lease: (physical_ipa, len),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: host_addr as usize,
                generation: owner_generation,
            },
            fork_frame_receipt_kind: Some(
                carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            ),
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (physical_ipa + 0x20_0000, len),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    grandchild_plan
        .stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
            Ok(
                carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                    carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x66; 32]),
                    carrick_hal::FrameInventoryBatch::prepare(
                        carrick_hal::KernelTransactionId::from_kernel_allocation(
                            NonZeroU64::new(824).unwrap(),
                        ),
                        capacity,
                    )
                    .unwrap(),
                    (0..frame_candidates)
                        .map(|index| {
                            carrick_hal::FrameId::from_kernel_allocation(
                                NonZeroU64::new(825 + index as u64).unwrap(),
                            )
                        })
                        .collect(),
                    (0..mapping_candidates)
                        .map(|index| {
                            carrick_hal::MappingId::from_kernel_allocation(
                                NonZeroU64::new(835 + index as u64).unwrap(),
                            )
                        })
                        .collect(),
                ),
            )
        })
        .expect("reserve grandchild overlay inventory");
    let (grandchild_carrier, mut grandchild_prepared) =
        HvfVmState::prepare_task_only_plan_for_test(grandchild_plan)
            .expect("materialize grandchild structural overlay");
    let materialized_overlay = grandchild_prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == overlay_publication.start)
        .expect("materialized grandchild overlay");
    assert!(
        materialized_overlay
            .structural_owner
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &owner)),
        "grandchild materialization must preserve the exact owner Arc",
    );
    grandchild_prepared
        .rollback_unpublished_inventory()
        .expect("rollback grandchild fixture inventory");
    grandchild_carrier
        .abort()
        .expect("retire grandchild fixture leases");
    let (ledger, mapping_ids) = match &prepared.inventory {
        HvpatchTaskInventoryAuthority::ProcessPrepared { ledger, staged, .. } => (
            Arc::clone(ledger),
            staged
                .iter()
                .map(|(_, staged)| staged.mapping)
                .collect::<Vec<_>>(),
        ),
        other => panic!(
            "expected prepared child inventory, got {}",
            other.phase_name()
        ),
    };
    let state = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        ledger,
        Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        Arc::new(parking_lot::Mutex::new(Vec::new())),
    );
    for mapping in &prepared.mappings {
        if let Some(owner) = &mapping.structural_owner {
            state.install_structural_owner(Arc::clone(owner));
        }
    }
    let mm = carrick_hal::ForeignMmId::from_kernel_allocation(NonZeroU64::new(806).unwrap());
    let binding = CarrierForeignMmBinding {
        asid: carrick_hal::ForeignAsid::from_kernel_allocation(NonZeroU16::new(7).unwrap()),
        stage1_root: Gpa(physical_ipa),
    };
    transport.register_identity(mm, binding, &state);
    let snapshot = CarrierForeignMmSnapshot {
        mm,
        binding,
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids,
        executable_ranges: vec![
            carrick_hal::ForeignExecutableRange::from_kernel_projection(
                GuestVa(0x0040_0000),
                GuestVa(0x0040_4000),
            )
            .unwrap(),
        ],
        readable_ranges: Vec::new(),
    };
    let retained = carrick_hal::ForeignMmEndpoint::for_carrier(
        Arc::clone(&transport) as Arc<dyn carrick_hal::ForeignMmTransport>
    )
    .retain(&snapshot, Instant::now() + Duration::from_secs(1));
    prepared
        .rollback_unpublished_inventory()
        .expect("rollback copied-child fixture inventory");
    carrier.abort().expect("retire copied-child fixture leases");
    assert!(
        retained.is_ok(),
        "copied child must retain every authenticated borrowed structural owner: {retained:?}"
    );
    drop(retained);
    drop(state);
    drop(grandchild_prepared);
    drop(grandchild_overlay);
    drop(child_source);
    drop(prepared);
    drop(owner);
    retry_structural_backing_identities_in_using(
        &transport.custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire copied-child structural fixture");
    assert!(
        transport
            .custody
            .stage2_record_snapshot(identity.record_id)
            .is_none(),
        "copied-child fixture must not leak a retired structural record",
    );
}

#[test]
fn owned_foreign_mm_registration_teardown_is_exact_and_stale_safe() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let binding = CarrierForeignMmBinding {
        asid: carrick_hal::ForeignAsid::from_kernel_allocation(NonZeroU16::new(9).unwrap()),
        stage1_root: Gpa(0x8800_0040_0000),
    };
    let make_state = || {
        MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            Arc::new(MemoryProtections::default()),
            Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            Arc::new(parking_lot::Mutex::new(Vec::new())),
        )
    };
    let old_state = make_state();
    let new_state = make_state();
    let old_mm = carrick_hal::ForeignMmId::from_kernel_allocation(NonZeroU64::new(31).unwrap());
    let new_mm = carrick_hal::ForeignMmId::from_kernel_allocation(NonZeroU64::new(32).unwrap());
    let old = transport.register_owned_identity(old_mm, binding, &old_state);
    let current = transport.register_owned_identity(new_mm, binding, &new_state);

    drop(old);
    let current_snapshot = CarrierForeignMmSnapshot {
        mm: new_mm,
        binding,
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids: Vec::new(),
        executable_ranges: Vec::new(),
        readable_ranges: Vec::new(),
    };
    assert!(
        Arc::ptr_eq(
            &transport
                .state_for(&current_snapshot, Instant::now() + Duration::from_secs(1))
                .expect("stale teardown must preserve successor binding"),
            &new_state,
        ),
        "binding reuse must retain the exact successor state"
    );

    drop(current);
    assert!(matches!(
        transport.state_for(&current_snapshot, Instant::now() + Duration::from_secs(1),),
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));
}

#[test]
#[ignore = "requires a signed HVF test executable"]
fn production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let custody = Arc::new(CarrierVmCustody::new());
    let carrier_foreign_mm_transport = Arc::new(CarrierForeignMmTransport {
        custody: Arc::clone(&custody),
        ..CarrierForeignMmTransport::default()
    });
    let (vm, permit, creation) = create_vm_with_admission(
        VmCreateAdmission::Initial,
        &carrier_foreign_mm_transport.custody,
    )
    .expect("create custody-approved signed-test VM");
    drop(permit);
    let vm = SetupVmGuard::new(vm, true);
    creation
        .commit()
        .expect("commit signed-test VM creation transaction");
    let vm = std::mem::ManuallyDrop::new(vm.into_inner());
    let root_slot_base = crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x20_0000;
    let root_slot_size = 0x0020_0000usize;

    // 1. Setup parent page tables and mappings covering all 5 required dispositions:
    //    (a) IndependentPageTables
    //    (b) IndependentKernelState (EL1 vectors & Mailbox)
    //    (c) Shared Executable / RX (Code)
    //    (d) Shared Writable User (Data)
    //    (e) Private / COW User (Data)
    let _parent_pt = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );

    let parent_pt_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent pt host mapping");
    let parent_pt_addr = parent_pt_host.as_ptr();
    let pt_payload = *b"production_fork_kernel_pagetable_canary!";
    unsafe {
        std::ptr::copy_nonoverlapping(pt_payload.as_ptr(), parent_pt_addr, pt_payload.len());
    }

    let parent_el1_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        crate::memory::LINUX_EL1_VECTORS_SIZE as usize,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("parent el1 host mapping");
    let parent_el1_addr = parent_el1_host.as_ptr();
    let el1_payload = *b"production_fork_kernel_vectors_canary!";
    unsafe {
        std::ptr::copy_nonoverlapping(el1_payload.as_ptr(), parent_el1_addr, el1_payload.len());
    }

    let parent_mailbox_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE as usize,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("parent mailbox host mapping");
    let parent_mailbox_addr = parent_mailbox_host.as_ptr();
    let mailbox_payload = *b"production_fork_kernel_mailbox_canary!";
    unsafe {
        std::ptr::copy_nonoverlapping(
            mailbox_payload.as_ptr(),
            parent_mailbox_addr,
            mailbox_payload.len(),
        );
    }

    let parent_rx_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent rx host mapping");
    let parent_rx_addr = parent_rx_host.as_ptr();
    let rx_payload = *b"parent_shared_rx_code_segment_payload!";
    unsafe {
        std::ptr::copy_nonoverlapping(rx_payload.as_ptr(), parent_rx_addr, rx_payload.len());
    }
    let mut parent_rx_lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
        .expect("reserve parent rx global-frame IPA");
    let parent_rx_ipa = parent_rx_lease.base;
    let rc = unsafe { inventory_hv_vm_map(parent_rx_addr.cast(), parent_rx_ipa, 0x4000, 5) };
    assert_eq!(rc, 0);
    parent_rx_lease.mark_mapped();
    let parent_rx_gen = register_global_frame_host_owner_in(
        &carrier_foreign_mm_transport.custody,
        parent_rx_lease,
        parent_rx_host,
        5,
    )
    .expect("register parent rx owner");

    let parent_rw_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent rw host mapping");
    let parent_rw_addr = parent_rw_host.as_ptr();
    let rw_payload = *b"parent_shared_rw_data_segment_payload!";
    unsafe {
        std::ptr::copy_nonoverlapping(rw_payload.as_ptr(), parent_rw_addr, rw_payload.len());
    }
    let mut parent_rw_lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
        .expect("reserve parent rw global-frame IPA");
    let parent_rw_ipa = parent_rw_lease.base;
    let rc = unsafe { inventory_hv_vm_map(parent_rw_addr.cast(), parent_rw_ipa, 0x4000, 3) };
    assert_eq!(rc, 0);
    parent_rw_lease.mark_mapped();
    let parent_rw_gen = register_global_frame_host_owner_in(
        &carrier_foreign_mm_transport.custody,
        parent_rw_lease,
        parent_rw_host,
        3,
    )
    .expect("register parent rw owner");

    let parent_cow_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent cow host mapping");
    let parent_cow_addr = parent_cow_host.as_ptr();
    let cow_payload = *b"parent_private_cow_user_data_payload!";
    unsafe {
        std::ptr::copy_nonoverlapping(cow_payload.as_ptr(), parent_cow_addr, cow_payload.len());
    }
    let mut parent_cow_lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
        .expect("reserve parent COW global-frame IPA");
    let parent_cow_ipa = parent_cow_lease.base;
    let rc = unsafe { inventory_hv_vm_map(parent_cow_addr.cast(), parent_cow_ipa, 0x4000, 3) };
    assert_eq!(rc, 0);
    parent_cow_lease.mark_mapped();
    let parent_cow_gen = register_global_frame_host_owner_in(
        &carrier_foreign_mm_transport.custody,
        parent_cow_lease,
        parent_cow_host,
        3,
    )
    .expect("register parent cow owner");

    let parent_mappings = TaskMappingIndex::from_iter([
        HvfMappedRegion {
            start: crate::memory::LINUX_PAGE_TABLES_BASE,
            end: crate::memory::LINUX_PAGE_TABLES_BASE + crate::memory::LINUX_PAGE_TABLES_SIZE,
            ipa: 0x8800_0000_0000,
            physical_ipa: 0x8800_0000_0000,
            host_addr: parent_pt_addr,
            size: crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
            physical_size: crate::memory::LINUX_PAGE_TABLES_SIZE as usize,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_writable: true,
            memory: None,
            host_mapping: Some(parent_pt_host),
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 1,
        },
        HvfMappedRegion {
            start: crate::memory::LINUX_EL1_VECTORS_BASE,
            end: crate::memory::LINUX_EL1_VECTORS_BASE + crate::memory::LINUX_EL1_VECTORS_SIZE,
            ipa: 0x8800_1000_0000,
            physical_ipa: 0x8800_1000_0000,
            host_addr: parent_el1_addr,
            size: crate::memory::LINUX_EL1_VECTORS_SIZE as usize,
            physical_size: crate::memory::LINUX_EL1_VECTORS_SIZE as usize,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_writable: true,
            memory: None,
            host_mapping: Some(parent_el1_host),
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 1,
        },
        HvfMappedRegion {
            start: crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            end: crate::memory::LINUX_SYSCALL_MAILBOX_BASE
                + crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
            ipa: 0x8800_2000_0000,
            physical_ipa: 0x8800_2000_0000,
            host_addr: parent_mailbox_addr,
            size: crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE as usize,
            physical_size: crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE as usize,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_writable: true,
            memory: None,
            host_mapping: Some(parent_mailbox_host),
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 1,
        },
        HvfMappedRegion {
            start: 0x0040_0000,
            end: 0x0040_4000,
            ipa: parent_rx_ipa,
            physical_ipa: parent_rx_ipa,
            host_addr: parent_rx_addr,
            size: 0x4000,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadExec,
            guest_writable: false,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::GlobalShared,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: parent_rx_gen,
        },
        HvfMappedRegion {
            start: 0x0060_0000,
            end: 0x0060_4000,
            ipa: parent_rw_ipa,
            physical_ipa: parent_rw_ipa,
            host_addr: parent_rw_addr,
            size: 0x4000,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_writable: true,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::GlobalShared,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: parent_rw_gen,
        },
        HvfMappedRegion {
            start: 0x0080_0000,
            end: 0x0080_4000,
            ipa: parent_cow_ipa,
            physical_ipa: parent_cow_ipa,
            host_addr: parent_cow_addr,
            size: 0x4000,
            physical_size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_writable: true,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: parent_cow_gen,
        },
    ]);

    let parent_inventory = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory {
        initialized: true,
        extents: std::collections::BTreeMap::from([
            (
                (0x8800_0000_0000, crate::memory::LINUX_PAGE_TABLES_SIZE),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(1).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(1).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(1),
                    stage2_base: 0x8800_0000_0000,
                    stage2_length: crate::memory::LINUX_PAGE_TABLES_SIZE,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_pt_addr as usize,
                        generation: 1,
                    },
                },
            ),
            (
                (0x8800_1000_0000, crate::memory::LINUX_EL1_VECTORS_SIZE),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(2).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(2).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(2),
                    stage2_base: 0x8800_1000_0000,
                    stage2_length: crate::memory::LINUX_EL1_VECTORS_SIZE,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_el1_addr as usize,
                        generation: 1,
                    },
                },
            ),
            (
                (
                    0x8800_2000_0000,
                    crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
                ),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(3).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(3).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(3),
                    stage2_base: 0x8800_2000_0000,
                    stage2_length: crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_mailbox_addr as usize,
                        generation: 1,
                    },
                },
            ),
            (
                (parent_rx_ipa, 0x4000),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(4).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(4).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(4),
                    stage2_base: parent_rx_ipa,
                    stage2_length: 0x4000,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_rx_addr as usize,
                        generation: parent_rx_gen,
                    },
                },
            ),
            (
                (parent_rw_ipa, 0x4000),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(5).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(5).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(5),
                    stage2_base: parent_rw_ipa,
                    stage2_length: 0x4000,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_rw_addr as usize,
                        generation: parent_rw_gen,
                    },
                },
            ),
            (
                (parent_cow_ipa, 0x4000),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(6).unwrap(),
                    ),
                    mapping: carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(6).unwrap(),
                    ),
                    backing: InventoryBackingIdentity::Private(6),
                    stage2_base: parent_cow_ipa,
                    stage2_length: 0x4000,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: parent_cow_addr as usize,
                        generation: parent_cow_gen,
                    },
                },
            ),
        ]),
        ..HvpatchFrameInventory::default()
    }));

    let parent_task = HvfTaskState {
        mappings: parent_mappings,
        mm_root_slot: Some((0x8800_0000_0000, 0x0020_0000)),
        container_root: ContainerRootToken::from_raw(1),
        pending_exec_mm_root_slot: None,
        pending_exec_asid: None,
        pending_exec_predecessor_identity: None,
        pending_exec_stage2_cleanup: None,
        shared_process_mm: false,
        mm_access: MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            Arc::new(MemoryProtections::default()),
            parent_inventory,
            Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            Arc::new(parking_lot::Mutex::new(Vec::new())),
        ),
        last_exit_class: 0,
        last_fault_esr: 0,
        is_forked_child: false,
        forked_no_exec: false,
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
        persistent_vm_lifecycle: true,
        cow_authority: Some(Arc::new(
            task_only_carrier_directory_tests::TestCowAuthority,
        )),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 101,
            linux_tid: 101,
            mm: 1,
            asid: 1,
        }),
        pending_fork_frame_receipts: Vec::new(),
        pending_process_aliases: Vec::new(),
        fail_next_begin_exec_inventory: false,
        cow_rollback_scratch: None,
        registration: None,
    };

    // 2. Perform production parent -> child build_process_plan
    let request = carrick_hal::ProcessForkRequest {
        entry: carrick_hal::GuestEntryRegs::default(),
        child_ttbr0: root_slot_base,
        root_slot_base,
        root_slot_size: root_slot_size as u64,
        plan: carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 1,
            child_mm: 2,
            ranges: std::sync::Arc::from([]),
        },
        child_tid: carrick_hal::ThreadId::synthetic_for_tests(102),
        forking_tid: carrick_hal::ThreadId::synthetic_for_tests(101),
        table_arena_source: None,
    };

    let mut child_pt = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    child_pt
        .map_aliased(0x0040_0000, parent_rx_ipa, 0x4000, false, None)
        .expect("map child user aliased rx");
    child_pt
        .map_aliased(0x0060_0000, parent_rw_ipa, 0x4000, true, None)
        .expect("map child user aliased rw");
    child_pt
        .map_aliased(0x0080_0000, parent_cow_ipa, 0x4000, false, None)
        .expect("map child user aliased cow");
    child_pt
        .rebase(root_slot_base, None)
        .expect("rebase child page tables");

    let cow_ranges = vec![carrick_aarch64::vmm::ForkCowRange {
        va: 0x0080_0000,
        len: 0x4000,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    }];

    let mut plan = parent_task
        .build_process_plan(
            request,
            &mut child_pt,
            &cow_ranges,
            Arc::new(MailboxSlotAllocator::new()),
            HvfSyscallTransport::Mailbox,
            Arc::clone(&carrier_foreign_mm_transport),
        )
        .expect("build_process_plan for child");

    // Verify structural and user dispositions in plan
    let (pt_physical_ipa, pt_physical_size) = {
        let pt_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .expect("child pt mapping descriptor");
        assert_eq!(pt_desc.physical_ipa, root_slot_base);
        assert!(pt_desc.stage2_lease.is_some());
        (pt_desc.physical_ipa, pt_desc.physical_size)
    };

    let (el1_physical_ipa, el1_physical_size) = {
        let el1_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == crate::memory::LINUX_EL1_VECTORS_BASE)
            .expect("child el1 mapping descriptor");
        assert_eq!(el1_desc.perms, applevisor::memory::MemPerms::ReadWrite);
        assert_ne!(el1_desc.physical_ipa, 0);
        assert_ne!(el1_desc.physical_ipa, pt_physical_ipa);
        (el1_desc.physical_ipa, el1_desc.physical_size)
    };

    let (mailbox_physical_ipa, mailbox_physical_size) = {
        let mb_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == crate::memory::LINUX_SYSCALL_MAILBOX_BASE)
            .expect("child mailbox mapping descriptor");
        assert_eq!(mb_desc.perms, applevisor::memory::MemPerms::ReadWrite);
        assert_ne!(mb_desc.physical_ipa, 0);
        assert_ne!(mb_desc.physical_ipa, pt_physical_ipa);
        assert_ne!(mb_desc.physical_ipa, el1_physical_ipa);
        (mb_desc.physical_ipa, mb_desc.physical_size)
    };

    {
        let rx_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == 0x0040_0000)
            .expect("child rx mapping descriptor");
        assert_eq!(
            rx_desc.inherited_frame,
            Some(carrick_hal::FrameId::from_kernel_allocation(
                std::num::NonZeroU64::new(4).unwrap()
            ))
        );
        assert_eq!(rx_desc.owner_generation, parent_rx_gen);
    }

    {
        let rw_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == 0x0060_0000)
            .expect("child rw mapping descriptor");
        assert_eq!(
            rw_desc.inherited_frame,
            Some(carrick_hal::FrameId::from_kernel_allocation(
                std::num::NonZeroU64::new(5).unwrap()
            ))
        );
        assert_eq!(rw_desc.owner_generation, parent_rw_gen);
    }

    {
        let cow_desc = plan
            .mappings
            .iter()
            .find(|m| m.start == 0x0080_0000)
            .expect("child cow mapping descriptor");
        assert_eq!(
            cow_desc.inherited_frame,
            Some(carrick_hal::FrameId::from_kernel_allocation(
                std::num::NonZeroU64::new(6).unwrap()
            ))
        );
        assert_eq!(cow_desc.owner_generation, parent_cow_gen);
    }

    // 3. Stage frame inventory reservation for child
    let next_id = std::sync::atomic::AtomicU64::new(500);
    plan.stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
        let tx_raw = next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
            std::num::NonZeroU64::new(tx_raw).unwrap(),
        );
        let frames = (0..frame_candidates)
            .map(|_| {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(id).unwrap())
            })
            .collect();
        let mappings = (0..mapping_candidates)
            .map(|_| {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(id).unwrap(),
                )
            })
            .collect();
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x33; 32]),
                carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
                frames,
                mappings,
            ),
        )
    })
    .expect("stage child inventory reservation");

    // 4. Cross the real production ProcessSpec boundary with the VM clone;
    // the non-dropping root handle above keeps custody as the sole raw
    // destroy owner during exact signed-test cleanup.
    let spec = ProcessSpec::new((*vm).clone(), plan);
    let (carrier_state, prepared_task) = HvfVmState::prepare_task_only_process_spec(spec)
        .expect("prepare_task_only_process_spec for child");

    // The signed acceptance route must never weaken to the test-only lease
    // carrier used by host-only rollback tests.
    assert!(
        matches!(&carrier_state, HvpatchCarrierTaskState::Process { .. }),
        "expected concrete HvpatchCarrierTaskState::Process"
    );

    // Verify structural owners are populated on prepared mappings with nonzero distinct generations
    let prepared_pt = prepared_task
        .mappings
        .iter()
        .find(|m| m.physical_ipa == pt_physical_ipa)
        .expect("prepared pt mapping");
    assert!(prepared_pt.structural_owner.is_some());
    let pt_epoch = prepared_pt.structural_owner.as_ref().unwrap().epoch();
    assert_ne!(pt_epoch.raw(), 0);
    assert_eq!(prepared_pt.owner_generation, pt_epoch.raw());

    let el1_canary = *b"el1_vector_canary_payload_32_bytes";
    let prepared_el1 = prepared_task
        .mappings
        .iter()
        .find(|m| m.physical_ipa == el1_physical_ipa)
        .expect("prepared el1 mapping");
    assert_eq!(prepared_el1.perms, applevisor::memory::MemPerms::ReadWrite);
    assert_eq!(prepared_el1.physical_ipa, el1_physical_ipa);
    let el1_owner = custody
        .global_frame_host_owners
        .lock()
        .get(&(el1_physical_ipa, el1_physical_size as u64))
        .map(|e| Arc::clone(e.owner()))
        .expect("el1 global frame owner");
    let el1_gen = el1_owner.generation();
    assert_ne!(el1_gen, 0);
    assert_eq!(prepared_el1.owner_generation, el1_gen);
    unsafe {
        std::ptr::copy_nonoverlapping(el1_canary.as_ptr(), el1_owner.ptr(), el1_canary.len());
    }

    let mb_canary = *b"mailbox_arena_canary_payload_32_b";
    let prepared_mb = prepared_task
        .mappings
        .iter()
        .find(|m| m.physical_ipa == mailbox_physical_ipa)
        .expect("prepared mailbox mapping");
    assert_eq!(prepared_mb.perms, applevisor::memory::MemPerms::ReadWrite);
    assert_eq!(prepared_mb.physical_ipa, mailbox_physical_ipa);
    let mb_owner = custody
        .global_frame_host_owners
        .lock()
        .get(&(mailbox_physical_ipa, mailbox_physical_size as u64))
        .map(|e| Arc::clone(e.owner()))
        .expect("mailbox global frame owner");
    let mb_gen = mb_owner.generation();
    assert_ne!(mb_gen, 0);
    assert_eq!(prepared_mb.owner_generation, mb_gen);
    unsafe {
        std::ptr::copy_nonoverlapping(mb_canary.as_ptr(), mb_owner.ptr(), mb_canary.len());
    }

    let prepared_rx = prepared_task
        .mappings
        .iter()
        .find(|m| m.start == 0x0040_0000)
        .expect("prepared rx mapping");
    assert_eq!(prepared_rx.owner_generation, parent_rx_gen);
    assert_eq!(prepared_rx.perms, applevisor::memory::MemPerms::ReadExec);

    let prepared_rw = prepared_task
        .mappings
        .iter()
        .find(|m| m.start == 0x0060_0000)
        .expect("prepared rw mapping");
    assert_eq!(prepared_rw.owner_generation, parent_rw_gen);
    assert_eq!(prepared_rw.perms, applevisor::memory::MemPerms::ReadWrite);

    let prepared_cow = prepared_task
        .mappings
        .iter()
        .find(|m| m.start == 0x0080_0000)
        .expect("prepared cow mapping");
    assert_eq!(prepared_cow.owner_generation, parent_cow_gen);
    assert_eq!(prepared_cow.perms, applevisor::memory::MemPerms::ReadWrite);

    // Verify staged inventory row received the exact minted structural epoch
    if let HvpatchTaskInventoryAuthority::ProcessPrepared { staged, .. } = &prepared_task.inventory
    {
        let (_, pt_staged) = staged
            .iter()
            .find(|((ipa, _), _)| *ipa == pt_physical_ipa)
            .expect("staged pt inventory extent");
        assert_eq!(
            pt_staged.stage2_owner.generation,
            pt_epoch.raw(),
            "production pt inventory row MUST match minted structural epoch"
        );
        assert_eq!(
            pt_staged.stage2_owner.host_addr,
            prepared_pt.structural_owner.as_ref().unwrap().ptr() as usize
        );
    } else {
        panic!("expected ProcessPrepared authority");
    }

    // 5. Publish to directory and activate child task state
    let (issuer, verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::new(
        std::num::NonZeroU64::new(1).unwrap(),
        verifier,
    ));
    let identity = HvpatchCarrierTaskIdentity {
        task_serial: 102,
        thread_serial: 102,
        execution_generation: 1,
        linux_pid: 102,
        linux_tid: 102,
        asid: 5,
    };
    let mut backend_state = directory
        .publish(identity, carrier_state, prepared_task)
        .expect("publish child to directory");

    let child_cow_identity = carrick_hal::FrameCowIdentity {
        linux_pid: 102,
        linux_tid: 102,
        mm: 2,
        asid: 5,
    };
    let token = issuer.issue(
        102,
        102,
        1,
        child_cow_identity,
        std::num::NonZeroU64::new(1).unwrap(),
        Arc::new(task_only_carrier_directory_tests::TestCowAuthority),
    );
    backend_state
        .bind_child_kernel(token)
        .expect("bind child kernel token");
    backend_state
        .apply_inventory(|commit| {
            let mappings = commit
                .batch()
                .events()
                .iter()
                .filter_map(|event| match *event {
                    carrick_hal::FrameInventoryEvent::PrepareMapping { mapping, frame, .. } => {
                        Some((mapping, frame))
                    }
                    _ => None,
                })
                .collect();
            Ok(
                carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
                    carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x33; 32]),
                    commit.batch().transaction(),
                    std::num::NonZeroU64::new(2).unwrap(),
                    1,
                    mappings,
                ),
            )
        })
        .expect("apply child inventory");
    backend_state.activate().expect("activate child task state");

    let expected_pt_bytes = child_pt.as_bytes()[..40].to_vec();
    let child_task_state = backend_state
        .runtime_task_state(
            carrick_aarch64::Stage1Authority::new_with_manager(Some(child_pt)),
            Arc::new(MemoryProtections::default()),
        )
        .expect("materialize child runtime task state");

    // Verify structural owner was installed into child task MmAccessState
    let child_mm_access = Arc::clone(&child_task_state.mm_access);

    // 6. Retain structural physical backing via CarrierForeignMmTransport::retain
    let child_inventory = &child_mm_access.frame_inventory;
    let pt_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(pt_physical_ipa, pt_physical_size as u64))
        .expect("pt mapping id")
        .mapping;
    let el1_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(el1_physical_ipa, el1_physical_size as u64))
        .expect("el1 mapping id")
        .mapping;
    let mb_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(mailbox_physical_ipa, mailbox_physical_size as u64))
        .expect("mb mapping id")
        .mapping;
    let rx_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(parent_rx_ipa, 0x4000))
        .expect("rx mapping id")
        .mapping;
    let rw_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(parent_rw_ipa, 0x4000))
        .expect("rw mapping id")
        .mapping;
    let cow_mapping_id = child_inventory
        .lock()
        .extents
        .get(&(parent_cow_ipa, 0x4000))
        .expect("cow mapping id")
        .mapping;

    let child_snapshot = TestSnapshot {
        mm: std::num::NonZeroU64::new(102).unwrap(),
        asid: std::num::NonZeroU16::new(5).unwrap(),
        stage1_root: carrick_guest_mem::Gpa(root_slot_base),
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids: vec![
            pt_mapping_id,
            el1_mapping_id,
            mb_mapping_id,
            rx_mapping_id,
            rw_mapping_id,
            cow_mapping_id,
        ],
        executable_ranges: Vec::new(),
        readable_ranges: Vec::new(),
    };

    let child_captured = CarrierForeignMmSnapshot::capture(&child_snapshot);

    // Register child identity in carrier foreign MM transport
    carrier_foreign_mm_transport.register_identity(
        child_captured.mm,
        child_captured.binding,
        &child_task_state.mm_access,
    );

    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(Arc::clone(
        &carrier_foreign_mm_transport,
    )
        as Arc<dyn carrick_hal::ForeignMmTransport>);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);

    // Tampered ASID rejected via state_for / retain
    let bad_asid_snapshot = TestSnapshot {
        asid: std::num::NonZeroU16::new(99).unwrap(),
        ..child_snapshot.clone()
    };
    let bad_asid_res = endpoint.retain(&bad_asid_snapshot, deadline);
    assert!(matches!(
        bad_asid_res,
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));
    let bad_asid_captured = CarrierForeignMmSnapshot::capture(&bad_asid_snapshot);
    let bad_asid_state = carrier_foreign_mm_transport.state_for(&bad_asid_captured, deadline);
    assert!(matches!(
        bad_asid_state,
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));

    // Tampered stage1 root rejected via state_for / retain
    let bad_root_snapshot = TestSnapshot {
        stage1_root: carrick_guest_mem::Gpa(root_slot_base + 0x1000),
        ..child_snapshot.clone()
    };
    let bad_root_res = endpoint.retain(&bad_root_snapshot, deadline);
    assert!(matches!(
        bad_root_res,
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));
    let bad_root_captured = CarrierForeignMmSnapshot::capture(&bad_root_snapshot);
    let bad_root_state = carrier_foreign_mm_transport.state_for(&bad_root_captured, deadline);
    assert!(matches!(
        bad_root_state,
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));

    // Authentic snapshot succeeds via ForeignMmEndpoint / transport retain
    let _lease = endpoint
        .retain(&child_snapshot, deadline)
        .expect("CarrierForeignMmTransport::retain must succeed for authentic child");

    let retained = child_mm_access
        .retain_physical_backing_in(&custody, &child_captured, deadline)
        .expect("retain_physical_backing must succeed for authentic structural extents");

    // Verify structural and shared payload readback through retained physical owners across all 5 dispositions
    // (a) Independent page tables
    let mut read_pt = [0u8; 40];
    let read_gen = copy_from_pinned_owner(&retained, pt_physical_ipa, &mut read_pt)
        .expect("copy_from_pinned_owner for structural page tables");
    assert_eq!(&read_pt, expected_pt_bytes.as_slice());
    assert_eq!(read_gen.raw_for_probe(), pt_epoch.raw());

    // (b) Independent EL1 vector table canary
    let mut read_el1 = [0u8; 34];
    let read_el1_gen = copy_from_pinned_owner(&retained, el1_physical_ipa, &mut read_el1)
        .expect("copy_from_pinned_owner for structural el1 vectors");
    assert_eq!(&read_el1, &el1_canary);
    assert_eq!(read_el1_gen.raw_for_probe(), el1_gen);

    // (b2) Independent Syscall Mailbox canary
    let mut read_mb = [0u8; 33];
    let read_mb_gen = copy_from_pinned_owner(&retained, mailbox_physical_ipa, &mut read_mb)
        .expect("copy_from_pinned_owner for structural mailbox arena");
    assert_eq!(&read_mb, &mb_canary);
    assert_eq!(read_mb_gen.raw_for_probe(), mb_gen);

    // (c) Shared RX executable segment
    let mut read_rx = [0u8; 38];
    let read_rx_gen = copy_from_pinned_owner(&retained, parent_rx_ipa, &mut read_rx)
        .expect("copy_from_pinned_owner for shared rx");
    assert_eq!(&read_rx, &rx_payload);
    assert_eq!(read_rx_gen.raw_for_probe(), parent_rx_gen);

    // (d) Shared RW data segment
    let mut read_rw = [0u8; 38];
    let read_rw_gen = copy_from_pinned_owner(&retained, parent_rw_ipa, &mut read_rw)
        .expect("copy_from_pinned_owner for shared rw");
    assert_eq!(&read_rw, &rw_payload);
    assert_eq!(read_rw_gen.raw_for_probe(), parent_rw_gen);

    // (e) Private COW data segment
    let mut read_cow = [0u8; 37];
    let read_cow_gen = copy_from_pinned_owner(&retained, parent_cow_ipa, &mut read_cow)
        .expect("copy_from_pinned_owner for private cow");
    assert_eq!(&read_cow, &cow_payload);
    assert_eq!(read_cow_gen.raw_for_probe(), parent_cow_gen);

    // 7. Stale / tampered generation is rejected
    let mut stale_extents = child_inventory.lock().extents.clone();
    if let Some(inv_entry) = stale_extents.get_mut(&(pt_physical_ipa, pt_physical_size as u64)) {
        inv_entry.stage2_owner.generation = pt_epoch.raw() + 999;
    }
    let stale_inventory = HvpatchFrameInventory {
        initialized: true,
        extents: stale_extents,
        ..HvpatchFrameInventory::default()
    };
    let stale_mm_access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        Arc::new(parking_lot::Mutex::new(stale_inventory)),
        Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        Arc::new(parking_lot::Mutex::new(Vec::new())),
    );
    for mapping in &child_task_state.mappings {
        if let Some(owner) = &mapping.structural_owner {
            stale_mm_access.install_structural_owner(Arc::clone(owner));
        }
    }
    let stale_transport = Arc::new(CarrierForeignMmTransport::new());
    stale_transport.register_identity(child_captured.mm, child_captured.binding, &stale_mm_access);
    let stale_endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(
        stale_transport as Arc<dyn carrick_hal::ForeignMmTransport>,
    );
    let stale_res = stale_endpoint.retain(&child_snapshot, deadline);
    assert!(matches!(
        stale_res,
        Err(carrick_hal::ForeignMmTransportError::OwnerStale)
    ));

    // 8. Multi-holder lifetime retention:
    // RetainedForeignMmBacking holds an Arc<StructuralBackingOwner>.
    // Cleanly retire child inventory, then drop backend_state and child task.
    let unmap_ids: Vec<_> = child_inventory
        .lock()
        .extents
        .values()
        .map(|e| e.mapping)
        .collect();
    let expected_mappings: Vec<_> = child_inventory
        .lock()
        .extents
        .values()
        .map(|e| (e.mapping, e.frame))
        .collect();
    let retirement_commit =
        task_only_carrier_directory_tests::retirement_inventory_commit(105, &unmap_ids);
    backend_state
        .prepare_inventory_retirement(retirement_commit)
        .expect("prepare child retirement");
    backend_state
        .apply_inventory_retirement(|commit| {
            Ok(
                carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
                    task_only_carrier_directory_tests::test_kernel_apply(
                        commit,
                        105,
                        std::num::NonZeroU64::new(2).unwrap(),
                        2,
                        expected_mappings,
                    ),
                    true,
                ),
            )
        })
        .expect("apply child retirement");

    drop(backend_state);
    drop(child_task_state);
    drop(child_mm_access);

    // Retained backing can STILL read valid physical memory across all structural dispositions
    let mut read_after_child_drop = [0u8; 40];
    let read_gen_after =
        copy_from_pinned_owner(&retained, pt_physical_ipa, &mut read_after_child_drop)
            .expect("copy_from_pinned_owner survives child task drop");
    assert_eq!(&read_after_child_drop, expected_pt_bytes.as_slice());
    assert_eq!(read_gen_after.raw_for_probe(), pt_epoch.raw());

    let mut read_el1_after = [0u8; 34];
    let read_el1_after_gen =
        copy_from_pinned_owner(&retained, el1_physical_ipa, &mut read_el1_after)
            .expect("copy_from_pinned_owner for el1 survives child drop");
    assert_eq!(&read_el1_after, &el1_canary);
    assert_eq!(read_el1_after_gen.raw_for_probe(), el1_gen);

    let mut read_mb_after = [0u8; 33];
    let read_mb_after_gen =
        copy_from_pinned_owner(&retained, mailbox_physical_ipa, &mut read_mb_after)
            .expect("copy_from_pinned_owner for mailbox survives child drop");
    assert_eq!(&read_mb_after, &mb_canary);
    assert_eq!(read_mb_after_gen.raw_for_probe(), mb_gen);

    // Dropping final retained backing cleanly releases structural owner
    drop(retained);
    drop(_lease);

    destroy_vm_with_custody(
        &carrier_foreign_mm_transport.custody,
        "signed structural-retention acceptance cleanup",
    )
    .expect("destroy signed-test VM through exact custody");
    finalize_carrier_exit_global_frame_owners_in(&carrier_foreign_mm_transport.custody)
        .expect("finalize signed-test terminal stage-2 records");
}

#[test]
fn releasable_stage2_lease_lifecycle_and_deterministic_allocator_reuse() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let size = 0x4000usize;

    // 1. Reserve a releasable global frame stage-2 lease
    let mut lease = GlobalFrameStage2Lease::reserve(size as u64, size as u64)
        .expect("reserve releasable global frame stage-2 lease");
    assert!(
        lease.release_ipa,
        "reusable extent must have release_ipa = true"
    );
    let allocated_ipa = lease.base;

    // 2. Wrap in host mapping, map stage-2, and register global frame host owner
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for test");
    let host_addr = mapping.as_ptr() as usize;
    let payload = *b"releasable_global_extent_payload_v3!";
    unsafe {
        std::ptr::copy_nonoverlapping(payload.as_ptr(), mapping.as_ptr(), payload.len());
    }

    let rc = unsafe { inventory_hv_vm_map(mapping.as_ptr().cast(), allocated_ipa, size, 7) };
    assert_eq!(rc, 0);
    lease.mark_mapped();
    assert!(
        ScopedStage2MapTestStub::is_mapped(allocated_ipa, size),
        "stage-2 mapping must be recorded in backend audit state"
    );

    let generation = register_global_frame_host_owner(lease, mapping, 7)
        .expect("register global frame host owner");
    assert_ne!(generation, 0);

    // 3. Create multiple retained physical owners
    let owner = global_frame_host_owners()
        .lock()
        .get(&(allocated_ipa, size as u64))
        .cloned()
        .expect("global frame host owner must be registered");

    let holder1 =
        RetainedPhysicalOwner::Global(owner.owner().pin().expect("pin first retained owner"));
    let holder2 =
        RetainedPhysicalOwner::Global(owner.owner().pin().expect("pin second retained owner"));

    let extent1 = RetainedForeignExtent {
        key: (allocated_ipa, size as u64),
        owner: holder1,
    };
    let backing1 = RetainedForeignMmBacking {
        extents: vec![extent1],
    };
    let mut read_buf = [0u8; 36];
    copy_from_pinned_owner(&backing1, allocated_ipa, &mut read_buf)
        .expect("copy_from_pinned_owner with holder1");
    assert_eq!(&read_buf, &payload);

    // While multiple holders exist, a new reservation attempt MUST NOT return the retained IPA
    let probe1 = GlobalFrameStage2Lease::reserve(size as u64, size as u64)
        .expect("reserve probe lease while multiple holders exist");
    assert_ne!(
        probe1.base, allocated_ipa,
        "retained IPA cannot be returned by new reservation while multiple holders exist"
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(allocated_ipa, size),
        "retained IPA must remain mapped while multiple holders exist"
    );
    drop(probe1);

    // 4. Explicit retirement while typed pins exist must defer and keep the
    // directory entry, stage-2 mapping, backing, and IPA reservation.
    assert!(matches!(
        retire_global_frame_host_owner_if_generation(allocated_ipa, size as u64, generation),
        GlobalFrameRetirementOutcome::DeferredActivePins { .. }
    ));
    drop(owner);
    drop(backing1);

    // While holder2 remains live, a new reservation attempt STILL MUST NOT return the retained IPA
    let probe2 = GlobalFrameStage2Lease::reserve(size as u64, size as u64)
        .expect("reserve probe lease while holder2 remains live");
    assert_ne!(
        probe2.base, allocated_ipa,
        "retained IPA cannot be returned while holder2 remains live"
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(allocated_ipa, size),
        "retained IPA must remain mapped while holder2 is live"
    );
    drop(probe2);

    // 5. Holder2 still keeps the IPA alive, mapped in stage-2, and readable
    let extent2 = RetainedForeignExtent {
        key: (allocated_ipa, size as u64),
        owner: holder2,
    };
    let backing2 = RetainedForeignMmBacking {
        extents: vec![extent2],
    };
    let mut read_buf2 = [0u8; 36];
    copy_from_pinned_owner(&backing2, allocated_ipa, &mut read_buf2)
        .expect("copy_from_pinned_owner with holder2");
    assert_eq!(&read_buf2, &payload);
    assert!(
        ScopedStage2MapTestStub::is_mapped(allocated_ipa, size),
        "stage-2 mapping must persist while retained holder is live"
    );
    assert!(
        alias_backing_is_live(host_addr),
        "host mapping must remain live while retained holder is live"
    );

    // 6. The final typed pin only makes explicit retirement eligible; its
    // Drop itself performs no hypervisor work.
    drop(backing2);
    assert!(ScopedStage2MapTestStub::is_mapped(allocated_ipa, size));
    assert!(alias_backing_is_live(host_addr));
    assert!(matches!(
        retire_global_frame_host_owner_if_generation(allocated_ipa, size as u64, generation),
        GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
    ));

    // 7. Verify explicit retirement unmapped stage-2, released backing,
    // and returned the IPA for deterministic allocator reuse.
    assert!(
        !ScopedStage2MapTestStub::is_mapped(allocated_ipa, size),
        "stage-2 mapping must be unmapped after final holder drop"
    );
    assert!(
        !alias_backing_is_live(host_addr),
        "host mapping must be unmapped after final holder drop"
    );

    let events = ScopedStage2MapTestStub::events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Stage2BackendEvent::Map { ipa, .. } if *ipa == allocated_ipa)),
        "events must record stage-2 map"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Stage2BackendEvent::Unmap { ipa, .. } if *ipa == allocated_ipa)),
        "events must record stage-2 unmap"
    );

    let new_lease = GlobalFrameStage2Lease::reserve(size as u64, size as u64)
        .expect("reserve new global frame stage-2 lease");
    assert_eq!(
        new_lease.base, allocated_ipa,
        "allocator must deterministically reuse the released IPA range after final holder drop"
    );
    drop(new_lease);
}

#[test]
fn semantic_lookup_rejects_foreign_va_alias_at_same_live_ipa() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) =
        global_frame_host_owner_identity_in(&custody, key.0, key.1).expect("current owner");
    let root = task.mm_root_slot.expect("fixture MM");
    let own = AliasBacking {
        start: va,
        ipa: key.0,
        host_addr,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0,
            size: root.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    let foreign = AliasBacking {
        start: 0x4000_2f8000,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0 + root.1,
            size: root.1,
        },
        ..own
    };
    alias_registry().lock().extend([own, foreign]);
    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, key.0, key.1, false, None)
        .expect("stage-1 mapping");
    task.page_tables_authority().set_manager(tables);
    let selected = task
        .mapping_for_range_in(&custody, va + 0x1000, 16)
        .expect("own live mapping");
    // Retire the fixture even when the assertion below detects the old bug.
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,)
            .is_retired()
    );
    assert_eq!(
        selected.start, va,
        "an IPA-sharing peer must not replace the requested semantic VA"
    );
    assert_eq!(selected.end, va + OWNER_LEN as u64);
}

#[test]
fn shared_extent_repoint_subpage_resolves_covering_owner_and_repoints_leaf() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let size = 0x4000; // 16 KiB
    let mut lease = GlobalFrameStage2Lease::reserve(size as u64, size as u64)
        .expect("reserve global frame stage-2 lease");
    let extent_base = lease.base;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate backing");
    let host_addr = mapping.as_ptr() as usize;
    let rc = unsafe { inventory_hv_vm_map(mapping.as_ptr().cast(), extent_base, size, 7) };
    assert_eq!(rc, 0);
    lease.mark_mapped();
    let generation = register_global_frame_host_owner(lease, mapping, 7)
        .expect("register global frame host owner");

    let mut task = HvfTaskState::neutral();
    task.persistent_vm_lifecycle = true;
    task.mm_root_slot = Some((0x9a00_f000_0000, 0x20_0000));
    task.container_root = ContainerRootToken::from_raw(250);

    let own = AliasBacking {
        start: va,
        ipa: extent_base,
        host_addr,
        size,
        physical_ipa: extent_base,
        physical_host_addr: host_addr,
        physical_size: size,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::SharedFile {
            device: 1,
            inode: 2,
            offset: 0,
            length: size as u64,
        },
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    register_shared_alias(own);

    let region = HvfMappedRegion {
        start: va,
        ipa: extent_base,
        physical_ipa: extent_base,
        end: va + size as u64,
        host_addr: host_addr as *mut u8,
        size,
        physical_size: size,
        perms: applevisor::memory::MemPerms::ReadWrite,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: true,
        sharing: GuestMappingSharing::GlobalShared,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    task.mappings.insert(region);

    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, extent_base, size as u64, false, None)
        .expect("stage-1 mapping");
    task.page_tables_authority().set_manager(tables);

    let repoint_va = 0x6001_030000_u64;
    let repoint_len = 0x1000;

    // An unauthenticated disconnected semantic IPA (such as LINUX_ALIAS_IPA_BASE + 0x1000)
    // has no physical owner in the VMM's global frame stage-2 arena.
    let disconnected_ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x1000;
    let disconnected_err = task
        .publish_shared_repoint(repoint_va, disconnected_ipa, repoint_len)
        .unwrap_err();
    assert!(
        disconnected_err
            .to_string()
            .contains("has no physical owner"),
        "expected unauthenticated semantic IPA to fail physical owner lookup: {disconnected_err}"
    );

    // Repointing outside any extent still fails with "no physical owner".
    let outside_ipa = extent_base + (size as u64) + 0x1000;
    let outside_err = task
        .publish_shared_repoint(repoint_va, outside_ipa, repoint_len)
        .unwrap_err();
    assert!(
        outside_err.to_string().contains("has no physical owner"),
        "expected no physical owner error, got: {outside_err}"
    );

    // Authenticating through the live stage-1 translation yields the authoritative
    // physical leaf IPA (extent_base + 0x1000).
    let repoint_ipa = task
        .translate_va(va + 0x1000)
        .expect("translate source subpage through live stage-1 page table");
    assert_eq!(repoint_ipa, extent_base + 0x1000);

    // Repointing a 4 KiB sub-page at offset 0x1000 succeeds via the covering production mapping.
    task.publish_shared_repoint(repoint_va, repoint_ipa, repoint_len)
        .expect("repoint 4 KiB sub-page of covering shared extent");

    // translate_va on the repointed VA returns extent_base + 0x1000.
    assert_eq!(
        task.translate_va(repoint_va),
        Some(repoint_ipa),
        "stage-1 page table leaf must point to extent_base + 0x1000"
    );
    let repointed = task.mappings.last().expect("repointed mapping");
    assert_eq!(repointed.start, repoint_va);
    assert_eq!(repointed.ipa, repoint_ipa);
    assert_eq!(repointed.physical_ipa, extent_base);
    assert_eq!(repointed.size, repoint_len);
    assert_eq!(repointed.physical_size, size);
    assert_eq!(repointed.owner_generation, generation);

    assert!(
        retire_global_frame_host_owner_if_generation(extent_base, size as u64, generation)
            .is_retired()
    );
}

#[test]
fn semantic_lookup_isolates_same_va_in_different_mm() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let (task_a, custody, key_a, gen_a) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr_a, _) =
        global_frame_host_owner_identity_in(&custody, key_a.0, key_a.1).expect("owner a");
    let root_a = task_a.mm_root_slot.expect("task a MM");

    let mut lease_b = GlobalFrameStage2Lease::reserve(OWNER_LEN as u64, OWNER_LEN as u64)
        .expect("reserve lease b");
    let key_b = lease_b.key();
    let host_b = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        OWNER_LEN,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate host backing b");
    let host_addr_b = host_b.as_ptr() as usize;
    assert_eq!(
        unsafe { inventory_hv_vm_map(host_b.as_ptr().cast(), key_b.0, OWNER_LEN, 3) },
        0,
    );
    lease_b.mark_mapped();
    let gen_b = register_global_frame_host_owner_in(&custody, lease_b, host_b, 3)
        .expect("register owner b");

    let root_b = (root_a.0 + root_a.1, root_a.1);
    let mut task_b = HvfTaskState::neutral();
    task_b.persistent_vm_lifecycle = true;
    task_b.mm_root_slot = Some(root_b);
    task_b.container_root = task_a.container_root;

    let alias_a = AliasBacking {
        start: va,
        ipa: key_a.0,
        host_addr: host_addr_a,
        size: OWNER_LEN,
        physical_ipa: key_a.0,
        physical_host_addr: host_addr_a,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root_a.0,
            size: root_a.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: gen_a,
    };
    let alias_b = AliasBacking {
        start: va,
        ipa: key_b.0,
        host_addr: host_addr_b,
        physical_ipa: key_b.0,
        physical_host_addr: host_addr_b,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root_b.0,
            size: root_b.1,
        },
        owner_generation: gen_b,
        ..alias_a
    };
    alias_registry().lock().extend([alias_a, alias_b]);

    let mut tables_a = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables_a
        .map_aliased(va, key_a.0, key_a.1, false, None)
        .expect("stage-1 mapping a");
    task_a.page_tables_authority().set_manager(tables_a);

    let mut tables_b = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables_b
        .map_aliased(va, key_b.0, key_b.1, false, None)
        .expect("stage-1 mapping b");
    task_b.page_tables_authority().set_manager(tables_b);

    let sel_a = task_a
        .mapping_for_range_in(&custody, va + 0x1000, 16)
        .expect("task a mapping");
    assert_eq!(sel_a.ipa, key_a.0);
    assert_eq!(sel_a.host_addr, host_addr_a as *mut u8);

    let sel_b = task_b
        .mapping_for_range_in(&custody, va + 0x1000, 16)
        .expect("task b mapping");
    assert_eq!(sel_b.ipa, key_b.0);
    assert_eq!(sel_b.host_addr, host_addr_b as *mut u8);

    let mut task_c = HvfTaskState::neutral();
    task_c.persistent_vm_lifecycle = true;
    task_c.mm_root_slot = Some((root_b.0 + root_b.1, root_b.1));
    task_c.container_root = task_a.container_root;
    assert!(
        task_c.mapping_for_range_in(&custody, va, 16).is_none(),
        "unrelated task must not see foreign MM mapping at same VA"
    );

    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key_a.0, key_a.1, gen_a)
            .is_retired()
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key_b.0, key_b.1, gen_b)
            .is_retired()
    );
}

#[test]
fn semantic_lookup_rejects_overlapping_row_with_wrong_va_to_ipa_offset() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) =
        global_frame_host_owner_identity_in(&custody, key.0, key.1).expect("current owner");
    let root = task.mm_root_slot.expect("fixture MM");

    let alias = AliasBacking {
        start: va,
        ipa: key.0,
        host_addr,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0,
            size: root.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    alias_registry().lock().extend([alias]);

    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(
            va,
            key.0 + 0x2000,
            key.1.saturating_sub(0x2000),
            false,
            None,
        )
        .expect("stage-1 mapping with offset mismatch");
    task.page_tables_authority().set_manager(tables);

    assert!(
        task.mapping_for_range_in(&custody, va, 16).is_none(),
        "stage-1 IPA mismatch must reject the alias and not fall through to stale mapping"
    );

    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation)
            .is_retired()
    );
}

#[test]
fn semantic_lookup_rejects_stale_owner_generation_and_accepts_current() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) =
        global_frame_host_owner_identity_in(&custody, key.0, key.1).expect("current owner");
    let root = task.mm_root_slot.expect("fixture MM");

    let stale_gen = generation.wrapping_add(100);
    let stale_alias = AliasBacking {
        start: va,
        ipa: key.0,
        host_addr,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0,
            size: root.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: stale_gen,
    };
    alias_registry().lock().extend([stale_alias]);

    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, key.0, key.1, false, None)
        .expect("stage-1 mapping");
    task.page_tables_authority().set_manager(tables);

    assert!(
        task.mapping_for_range_in(&custody, va, 16).is_none(),
        "stale owner generation must be rejected by mapping_for_range_in"
    );

    let current_alias = AliasBacking {
        owner_generation: generation,
        ..stale_alias
    };
    alias_registry().lock().replace_all([current_alias]);
    assert!(
        task.mapping_for_range_in(&custody, va, 16).is_some(),
        "current owner generation must be accepted by mapping_for_range_in"
    );

    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation)
            .is_retired()
    );
    assert!(
        task.mapping_for_range_in(&custody, va, 16).is_none(),
        "retired global frame owner must be rejected"
    );
}

#[test]
fn semantic_lookup_enforces_exact_boundary_length_and_overflow_protection() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let size = OWNER_LEN;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) =
        global_frame_host_owner_identity_in(&custody, key.0, key.1).expect("current owner");
    let root = task.mm_root_slot.expect("fixture MM");

    let alias = AliasBacking {
        start: va,
        ipa: key.0,
        host_addr,
        size,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: size,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0,
            size: root.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    alias_registry().lock().extend([alias]);

    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, key.0, key.1, false, None)
        .expect("stage-1 mapping");
    task.page_tables_authority().set_manager(tables);

    assert!(task.mapping_for_range_in(&custody, va, size).is_some());
    assert!(task.mapping_for_range_in(&custody, va, 1).is_some());
    assert!(
        task.mapping_for_range_in(&custody, va + size as u64 - 1, 1)
            .is_some()
    );
    assert!(
        task.mapping_for_range_in(&custody, va + size as u64, 1)
            .is_none()
    );
    assert!(
        task.mapping_for_range_in(&custody, va + size as u64 - 1, 2)
            .is_none()
    );
    assert!(task.mapping_for_range_in(&custody, va - 1, 1).is_none());
    assert!(task.mapping_for_range_in(&custody, va, 0).is_some());
    assert!(
        task.mapping_for_range_in(&custody, va + 0x1000, 0)
            .is_some()
    );
    assert!(
        task.mapping_for_range_in(&custody, va, usize::MAX)
            .is_none()
    );
    assert!(
        task.mapping_for_range_in(&custody, u64::MAX - 8, 16)
            .is_none()
    );

    for offset in [0, 0x100, 0x1000, 0x2000, 0x3f00] {
        let max_valid_len = size - offset;
        assert!(
            task.mapping_for_range_in(&custody, va + offset as u64, max_valid_len)
                .is_some(),
            "offset {offset:#x} with max valid len {max_valid_len:#x} must succeed"
        );
        assert!(
            task.mapping_for_range_in(&custody, va + offset as u64, max_valid_len + 1)
                .is_none(),
            "offset {offset:#x} exceeding len by 1 must fail"
        );
    }

    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation)
            .is_retired()
    );
}

#[test]
fn semantic_lookup_preserves_map_shared_and_maintenance_fallback() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let va = 0x6001_020000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) =
        global_frame_host_owner_identity_in(&custody, key.0, key.1).expect("current owner");

    let shared_alias = AliasBacking {
        start: va,
        ipa: key.0,
        host_addr,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::Private(9_608),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation,
    };
    alias_registry().lock().extend([shared_alias]);

    assert!(task.translate_va_for_cow(va).is_none());

    let selected = task
        .mapping_for_range_in(&custody, va + 0x1000, 16)
        .expect("maintenance fallback finds global shared mapping");
    assert_eq!(selected.start, va);
    assert_eq!(selected.sharing, GuestMappingSharing::GlobalShared);

    let mut tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, key.0, key.1, false, None)
        .expect("stage-1 mapping");
    task.page_tables_authority().set_manager(tables);

    let selected_stage1 = task
        .mapping_for_range_in(&custody, va + 0x1000, 16)
        .expect("stage-1 path finds global shared mapping");
    assert_eq!(selected_stage1.start, va);
    assert_eq!(selected_stage1.sharing, GuestMappingSharing::GlobalShared);

    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation)
            .is_retired()
    );
}

#[test]
fn cow_source_falls_back_to_offset_logical_inventory_with_current_physical_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let semantic_va = 0x6001_020000_u64;
    let (mut task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::CurrentOffsetLogicalKey);
    let mut page_tables = crate::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        crate::memory::LINUX_PAGE_TABLES_BASE,
    );
    page_tables
        .map_aliased(semantic_va, key.0, key.1, false, None)
        .expect("publish live COW source stage-1 compound");
    task.page_tables_authority().set_manager(page_tables);
    task.mappings.insert(HvfMappedRegion {
        start: semantic_va,
        ipa: key.0 + key.1,
        physical_ipa: key.0 + key.1,
        end: semantic_va + key.1,
        host_addr: std::ptr::null_mut(),
        size: OWNER_LEN,
        physical_size: OWNER_LEN,
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
    });
    let live_ipa = task
        .translate_va_for_cow(semantic_va)
        .expect("live stage-1 translation must name current COW owner");
    assert_eq!(live_ipa, key.0);

    let source = task.physical_cow_source_in(&custody, semantic_va, live_ipa);
    assert!(
        source.is_some(),
        "live stage-1 plus exact inventory/current-owner authority must survive stale worker-local semantic rows",
    );
    drop(source);
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,)
            .is_retired(),
        "retire exact inventoried COW source fixture",
    );
}

#[test]
fn persistent_reusable_cow_alias_rejects_zero_owner_generation() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let semantic_va = 0x6004_000000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) = global_frame_host_owner_identity_in(&custody, key.0, key.1)
        .expect("current COW source owner identity");
    alias_registry().lock().push(AliasBacking {
        start: semantic_va,
        ipa: key.0,
        host_addr,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: task.mm_root_slot.expect("fixture root slot").0,
            size: task.mm_root_slot.expect("fixture root slot").1,
        },
        inventory_backing: InventoryBackingIdentity::Private(9_607),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    });

    assert!(
        task.physical_cow_source_in(&custody, semantic_va, key.0)
            .is_none(),
        "a persistent reusable alias must not wildcard-authenticate a recycled owner",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,)
            .is_retired(),
    );
}

#[test]
fn persistent_reusable_cow_mapping_rejects_zero_owner_generation() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let semantic_va = 0x6005_000000_u64;
    let (mut task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    let (host_addr, _) = global_frame_host_owner_identity_in(&custody, key.0, key.1)
        .expect("current COW source owner identity");
    task.mappings.insert(HvfMappedRegion {
        start: semantic_va,
        ipa: key.0,
        physical_ipa: key.0,
        end: semantic_va + key.1,
        host_addr: host_addr as *mut u8,
        size: OWNER_LEN,
        physical_size: OWNER_LEN,
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

    assert!(
        task.physical_cow_source_in(&custody, semantic_va, key.0)
            .is_none(),
        "a persistent reusable mapping must not wildcard-authenticate a recycled owner",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,)
            .is_retired(),
    );
}

#[test]
fn cow_source_inventory_fallback_rejects_absent_zero_mismatched_or_conflicting_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let semantic_va = 0x6002_0a8000_u64;

    let (absent_task, absent_custody, absent_key, absent_generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::Absent);
    assert!(
        absent_task
            .physical_cow_source_in(&absent_custody, semantic_va, absent_key.0)
            .is_none(),
        "case1's live stage-1 IPA without inventory must fail closed",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(
            &absent_custody,
            absent_key.0,
            absent_key.1,
            absent_generation,
        )
        .is_retired(),
    );

    let (zero_task, zero_custody, zero_key, zero_generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::ZeroGeneration);
    assert!(
        zero_task
            .physical_cow_source_in(&zero_custody, semantic_va, zero_key.0)
            .is_none(),
        "an unstamped inventory owner generation must fail closed",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(
            &zero_custody,
            zero_key.0,
            zero_key.1,
            zero_generation,
        )
        .is_retired(),
    );

    let (mismatch_task, mismatch_custody, mismatch_key, mismatch_generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::MismatchedGeneration);
    assert!(
        mismatch_task
            .physical_cow_source_in(&mismatch_custody, semantic_va, mismatch_key.0)
            .is_none(),
        "inventory from another owner generation must fail closed",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(
            &mismatch_custody,
            mismatch_key.0,
            mismatch_key.1,
            mismatch_generation,
        )
        .is_retired(),
    );

    let (conflict_task, conflict_custody, conflict_key, conflict_generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::ConflictingOwners);
    assert!(
        conflict_task
            .physical_cow_source_in(&conflict_custody, semantic_va, conflict_key.0)
            .is_none(),
        "logical inventory fragments that disagree on physical owner identity must fail closed",
    );
    assert!(
        retire_global_frame_host_owner_if_generation_in(
            &conflict_custody,
            conflict_key.0,
            conflict_key.1,
            conflict_generation,
        )
        .is_retired(),
    );
}

#[test]
fn cow_source_inventory_fallback_pins_backing_through_copy_window() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = ExternalAliasStateRestore::capture();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let semantic_va = 0x6003_000000_u64;
    let (task, custody, key, generation) =
        inventoried_cow_source_fixture(CowSourceInventoryFixture::CurrentOffsetLogicalKey);
    let source = task
        .physical_cow_source_in(&custody, semantic_va, key.0)
        .expect("retain exact inventoried COW source");

    assert!(matches!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,),
        GlobalFrameRetirementOutcome::DeferredActivePins { .. }
    ));
    let mut copied = vec![0_u8; OWNER_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(source.host_addr(), copied.as_mut_ptr(), OWNER_LEN);
    }
    assert!(
        copied.iter().all(|byte| *byte == 0xa5),
        "the pinned source backing must remain readable after retirement is requested",
    );
    drop(source);
    assert!(
        retire_global_frame_host_owner_if_generation_in(&custody, key.0, key.1, generation,)
            .is_retired(),
        "retirement may complete only after the COW source copy guard drops",
    );
}

#[test]
fn owned_global_frame_alias_uses_the_fresh_registered_owner_generation() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let len = 0x4000_u64;
    let lease =
        GlobalFrameStage2Lease::reserve(len, len).expect("reserve owned child global-frame IPA");
    let physical_ipa = lease.base;
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        len as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate owned child global-frame backing");
    let physical_host_addr = host.as_ptr();
    let semantic_va = 0x4000_438000_u64;
    let mut plan = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: semantic_va,
            ipa: physical_ipa,
            end: semantic_va + len,
            stage2_lease: Some(lease),
            host: ProcessMappingHost::Owned(host),
            size: len as usize,
            physical_ipa,
            physical_host_addr,
            physical_size: len as usize,
            inventory_backing: InventoryBackingIdentity::Private(930),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            inherited_frame: None,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: physical_ipa,
            length: len,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            inherited_frame: None,
            inherited_mapping: None,
            backing: InventoryBackingIdentity::Private(930),
            stage2_lease: (physical_ipa, len),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: physical_host_addr as usize,
                generation: 0,
            },
            fork_frame_receipt_kind: None,
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (0x9a00_6000_0000, 0x20_0000),
        container_root: ContainerRootToken::from_raw(2),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    let ids = std::sync::atomic::AtomicU64::new(931);
    plan.stage_with_reservation_factory(|frames, mappings, capacity| {
        let next =
            || NonZeroU64::new(ids.fetch_add(1, std::sync::atomic::Ordering::SeqCst)).unwrap();
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x93; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(next()),
                    capacity,
                )
                .unwrap(),
                (0..frames)
                    .map(|_| carrick_hal::FrameId::from_kernel_allocation(next()))
                    .collect(),
                (0..mappings)
                    .map(|_| carrick_hal::MappingId::from_kernel_allocation(next()))
                    .collect(),
            ),
        )
    })
    .expect("reserve owned child inventory");

    let (carrier, prepared) = HvfVmState::prepare_task_only_plan_for_test(plan)
        .expect("prepare owned child global frame");
    let mapping = prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == semantic_va)
        .expect("prepared owned global-frame mapping");
    let alias = prepared
        .pending_aliases
        .iter()
        .find(|alias| alias.start == semantic_va)
        .expect("pending owned global-frame alias");
    assert_ne!(mapping.owner_generation, 0);
    assert_eq!(
        alias.owner_generation, mapping.owner_generation,
        "alias publication must authenticate the owner generation minted during materialization"
    );

    abort_prepared_task_and_carrier(prepared, carrier)
        .expect("retire owned child global-frame fixture");
}

#[test]
fn full_vm_materializer_stamps_fresh_owner_before_alias_mapping_and_inventory() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let source = include_str!("../../trap.rs");
    let full_vm = source
        .split(concat!("pub(crate) fn from_process_", "spec("))
        .nth(1)
        .and_then(|body| {
            body.split(concat!("    fn global_frame_exec_", "plan("))
                .next()
        })
        .expect("full-VM process materializer body");
    let registration = full_vm
        .find(concat!(
            "let owner_generation = register_global_frame_host_",
            "owner_in("
        ))
        .expect("owned reusable mapping registers its exact owner");
    let alias = full_vm
        .find(concat!("let alias = Alias", "Backing {"))
        .expect("full-VM alias construction");
    let mapped = full_vm
        .find(concat!("mapped.insert(HvfMapped", "Region {"))
        .expect("full-VM mapping construction");
    let inventory = full_vm
        .find(concat!(
            "let stage2_owner = if is_reusable_global_frame_",
            "extent("
        ))
        .expect("full-VM inventory owner stamping");
    assert!(registration < alias && registration < mapped && registration < inventory);
    assert!(
        full_vm[alias..mapped].contains("owner_generation,"),
        "the alias must carry the generation returned by owner registration",
    );
    assert!(
        full_vm[mapped..inventory].contains("owner_generation,"),
        "the local mapping must carry the generation returned by owner registration",
    );
    let inventory_tail = &full_vm[inventory..];
    assert!(inventory_tail.contains(concat!("global_frame_host_owner_generation_", "in(")));
    assert!(inventory_tail.contains(concat!("generation: if generation != ", "0 {")));
}

/// A fork that is abandoned after `prepare` (the dispatcher install losing
/// sole exact-MM authority answers `EAGAIN`) must leave the PARENT's
/// reusable global frames exactly as they were. The prepared child borrows
/// those frames COW with the parent's live owner generation stamped on the
/// descriptor; retiring that owner on abort unmaps the parent's stage-2
/// backing under a live process, and its next write fails the
/// owner-liveness check (the go `os/exec` crash after a load-induced
/// `fork(2) = EAGAIN`).
#[test]
fn abort_prepared_child_preserves_borrowed_parent_global_frame_owner() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let custody = Arc::clone(&transport.custody);

    // The parent's live reusable global frame (a private heap arena).
    let parent_len = 0x4000u64;
    let parent_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        parent_len as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("parent heap host mapping");
    let parent_addr = parent_host.as_ptr();
    let mut parent_lease = GlobalFrameStage2Lease::reserve(parent_len, parent_len)
        .expect("reserve parent global-frame IPA");
    let parent_ipa = parent_lease.base;
    assert!(is_reusable_global_frame_extent(parent_ipa, parent_len));
    assert_eq!(
        unsafe { inventory_hv_vm_map(parent_addr.cast(), parent_ipa, parent_len as usize, 3) },
        0
    );
    parent_lease.mark_mapped();
    let parent_gen = register_global_frame_host_owner_in(&custody, parent_lease, parent_host, 3)
        .expect("register parent heap owner");
    assert_ne!(parent_gen, 0);

    // A prepared fork child: its own root slot plus a COW borrow of the
    // parent's heap frame, stamped with the parent's owner generation.
    let pt_ipa = 0x9a00_6000_0000u64;
    let pt_len = 0x20_0000u64;
    let pt_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        pt_len as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("child page-table host mapping");
    let pt_host_addr = pt_host.as_ptr();
    let parent_frame =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(41).unwrap());
    let parent_mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(42).unwrap());
    let mut plan = ProcessSpecPlan {
        mappings: vec![
            ProcessMappingDesc {
                start: crate::memory::LINUX_PAGE_TABLES_BASE,
                ipa: pt_ipa,
                end: pt_ipa + pt_len,
                stage2_lease: Some(GlobalFrameStage2Lease::fixed(pt_ipa, pt_len)),
                host: ProcessMappingHost::Owned(pt_host),
                size: pt_len as usize,
                physical_ipa: pt_ipa,
                physical_host_addr: pt_host_addr,
                physical_size: pt_len as usize,
                inventory_backing: InventoryBackingIdentity::Private(1),
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                inherited_frame: None,
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: 0,
            },
            ProcessMappingDesc {
                start: 0x0080_0000,
                ipa: parent_ipa,
                end: 0x0080_0000 + parent_len,
                stage2_lease: None,
                host: ProcessMappingHost::Borrowed {
                    pointer: parent_addr,
                    structural_owner: None,
                },
                size: parent_len as usize,
                physical_ipa: parent_ipa,
                physical_host_addr: parent_addr,
                physical_size: parent_len as usize,
                inventory_backing: InventoryBackingIdentity::Private(2),
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: false,
                inherited_frame: Some(parent_frame),
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: parent_gen,
            },
        ],
        inventory_mappings: vec![
            ProcessInventoryDesc {
                gpa: pt_ipa,
                length: pt_len,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: InventoryBackingIdentity::Private(1),
                stage2_lease: (pt_ipa, pt_len),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: pt_host_addr as usize,
                    generation: 0,
                },
                fork_frame_receipt_kind: None,
            },
            ProcessInventoryDesc {
                gpa: parent_ipa,
                length: parent_len,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: false,
                    exec: false,
                },
                inherited_frame: Some(parent_frame),
                inherited_mapping: Some(parent_mapping),
                backing: InventoryBackingIdentity::Private(2),
                stage2_lease: (parent_ipa, parent_len),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: parent_addr as usize,
                    generation: parent_gen,
                },
                fork_frame_receipt_kind: Some(
                    carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
                ),
            },
        ],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (pt_ipa, pt_len),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::clone(&transport),
    };
    let ids = std::sync::atomic::AtomicU64::new(900);
    plan.stage_with_reservation_factory(|frames, mappings, capacity| {
        let next = || {
            std::num::NonZeroU64::new(ids.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
                .unwrap()
        };
        Ok(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x91; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(next()),
                    capacity,
                )
                .unwrap(),
                (0..frames)
                    .map(|_| carrick_hal::FrameId::from_kernel_allocation(next()))
                    .collect(),
                (0..mappings)
                    .map(|_| carrick_hal::MappingId::from_kernel_allocation(next()))
                    .collect(),
            ),
        )
    })
    .expect("stage abandoned-fork child reservation");
    let (carrier, prepared) =
        HvfVmState::prepare_task_only_plan_for_test(plan).expect("prepare abandoned-fork child");
    let root_authority = prepared
        .mm_root_stage2
        .as_ref()
        .expect("task-only publication captures exact root custody");
    assert_eq!(root_authority.root_slot, (pt_ipa, pt_len));
    assert_eq!(root_authority.physical_extent, (pt_ipa, pt_len as usize));
    assert_eq!(root_authority.owner.ptr(), pt_host_addr);
    let borrowed = prepared
        .mappings
        .iter()
        .find(|mapping| mapping.start == 0x0080_0000)
        .expect("prepared borrowed heap mapping");
    assert_eq!(borrowed.owner_generation, parent_gen);
    assert!(borrowed.host_mapping.is_none());

    // The dispatcher install lost sole exact-MM authority: unwind the child.
    abort_prepared_task_and_carrier(prepared, carrier).expect("abort abandoned fork child");

    // The parent's frame must be untouched: live owner, same generation,
    // stage-2 still installed, host backing still live.
    let live = custody
        .global_frame_host_owners
        .lock()
        .get(&(parent_ipa, parent_len))
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .map(|owner| owner.generation());
    assert_eq!(
        live,
        Some(parent_gen),
        "abandoning a prepared fork child must not retire the parent's borrowed global frame owner",
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(parent_ipa, parent_len as usize),
        "parent stage-2 backing must survive the abandoned fork",
    );
    assert!(
        alias_backing_is_live(parent_addr as usize),
        "parent host backing must survive the abandoned fork",
    );
    assert!(
        !ScopedStage2MapTestStub::is_mapped(pt_ipa, pt_len as usize),
        "the child's own root slot must be unmapped by the abort",
    );

    // The parent retires its own frame exactly once, at its own exit.
    assert!(matches!(
        retire_global_frame_host_owner_if_generation_in(
            &custody, parent_ipa, parent_len, parent_gen
        ),
        GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
    ));
}

fn partial_structural_map_plan(root_ipa: u64) -> (ProcessSpecPlan, Arc<CarrierVmCustody>) {
    fn structural_mapping(start: u64, ipa: u64) -> ProcessMappingDesc {
        const SIZE: usize = 0x20_0000;
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            SIZE,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .expect("allocate structural failure fixture");
        let host_addr = host.as_ptr();
        ProcessMappingDesc {
            start,
            ipa,
            end: ipa + SIZE as u64,
            stage2_lease: Some(GlobalFrameStage2Lease::fixed(ipa, SIZE as u64)),
            host: ProcessMappingHost::Owned(host),
            size: SIZE,
            physical_ipa: ipa,
            physical_host_addr: host_addr,
            physical_size: SIZE,
            inventory_backing: InventoryBackingIdentity::Private(ipa),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            inherited_frame: None,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        }
    }

    let later_ipa = root_ipa + 0x20_0000;
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let custody = Arc::clone(&transport.custody);
    let plan = ProcessSpecPlan {
        mappings: vec![
            structural_mapping(crate::memory::LINUX_PAGE_TABLES_BASE, root_ipa),
            structural_mapping(crate::memory::LINUX_PAGE_TABLES_BASE + 0x20_0000, later_ipa),
        ],
        inventory_mappings: Vec::new(),
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (root_ipa, 0x20_0000),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: transport,
    };
    (plan, custody)
}

#[test]
fn task_only_partial_map_failure_retires_the_exact_structural_root() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let stage2_stub = ScopedStage2MapTestStub::enable();
    let root_ipa = 0x9a00_0000_0000u64;
    let later_ipa = root_ipa + 0x20_0000;
    let (plan, custody) = partial_structural_map_plan(root_ipa);
    let custody_records_before = custody.stage2_record_identities();
    let structural_records_before = custody
        .structural_backings
        .lock()
        .keys()
        .copied()
        .collect::<Vec<_>>();

    // The root row is installed and transferred to structural custody;
    // fail the next row before it can acquire an owner.
    stage2_stub.set_fail_map_on_call(Some(2));
    let result = HvfVmState::prepare_task_only_plan_for_test(plan);
    assert!(
        matches!(result, Err(TrapError::ChildMapFailed { guest_start, .. }) if guest_start == later_ipa),
        "second-row backend failure must propagate without publishing a child",
    );
    assert!(
        !ScopedStage2MapTestStub::is_mapped(root_ipa, 0x20_0000),
        "rollback must retire the exact already-mapped structural root before its slot can recycle",
    );
    let structural_records_after = custody
        .structural_backings
        .lock()
        .keys()
        .copied()
        .collect::<Vec<_>>();
    assert!(
        structural_records_after
            .iter()
            .all(|record| structural_records_before.contains(record)),
        "rollback must not retain the newly created structural custody entry",
    );
    let custody_records_after = custody.stage2_record_identities();
    assert!(
        custody_records_after
            .iter()
            .all(|record| custody_records_before.contains(record)),
        "rollback must terminalize the exact new structural stage-2 record",
    );

    let replacement = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate replacement root backing");
    assert_eq!(
        unsafe {
            inventory_hv_vm_map(
                replacement.as_ptr().cast(),
                root_ipa,
                0x20_0000,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
        },
        0,
        "the same numeric root slot must be reusable after exact rollback",
    );
    assert_eq!(unsafe { inventory_hv_vm_unmap(root_ipa, 0x20_0000) }, 0);
}

#[test]
fn task_only_partial_map_unmap_failure_fail_stops_before_root_slot_reuse() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let stage2_stub = ScopedStage2MapTestStub::enable();
    let root_ipa = 0x9a00_0200_0000u64;
    let (plan, custody) = partial_structural_map_plan(root_ipa);
    let records_before = custody.stage2_record_identities();

    stage2_stub.set_fail_map_on_call(Some(2));
    stage2_stub.set_fail_next_unmap(true);
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = HvfVmState::prepare_task_only_plan_for_test(plan);
    }));
    assert!(
        stopped.is_err(),
        "a nonterminal exact structural rollback must fail-stop instead of returning the root slot",
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(root_ipa, 0x20_0000),
        "the injected backend failure must leave the old mapping visibly occupied",
    );
    let new_records = custody
        .stage2_record_identities()
        .into_iter()
        .filter(|record| !records_before.contains(record))
        .collect::<Vec<_>>();
    assert_eq!(
        new_records.len(),
        1,
        "the failed rollback must retain exactly its authenticated custody record",
    );
    let snapshot = custody
        .stage2_record_snapshot(new_records[0].record_id)
        .expect("nonterminal exact rollback record");
    assert!(snapshot.mapped && snapshot.retry_pending.is_some());

    let replacement = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate prohibited replacement backing");
    assert_ne!(
        unsafe {
            inventory_hv_vm_map(
                replacement.as_ptr().cast(),
                root_ipa,
                0x20_0000,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
        },
        0,
        "the occupied slot cannot be reissued after the carrier fail-stop boundary",
    );

    retry_structural_backing_identities_in_using(
        &custody,
        &new_records,
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("test cleanup exact failed rollback record");
    assert!(!ScopedStage2MapTestStub::is_mapped(root_ipa, 0x20_0000));
}

#[test]
fn task_only_partial_map_rollback_ignores_unrelated_retry_pending_record() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let stage2_stub = ScopedStage2MapTestStub::enable();
    let root_ipa = 0x9a00_0400_0000u64;
    let (plan, custody) = partial_structural_map_plan(root_ipa);

    let sentinel_ipa = 0x9900_0000_0000u64;
    let sentinel_size = 0x4000usize;
    let sentinel_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        sentinel_size,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate unrelated structural sentinel");
    assert_eq!(
        unsafe {
            inventory_hv_vm_map(
                sentinel_host.as_ptr().cast(),
                sentinel_ipa,
                sentinel_size,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
        },
        0,
    );
    let mut sentinel_lease = GlobalFrameStage2Lease::fixed(sentinel_ipa, sentinel_size as u64);
    sentinel_lease.mark_mapped();
    let sentinel_owner = StructuralBackingOwner::new_in(
        &custody,
        sentinel_host,
        sentinel_lease,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
        next_structural_epoch().expect("sentinel epoch"),
        sentinel_ipa,
        sentinel_size,
    )
    .expect("register unrelated structural sentinel");
    let sentinel_identity = sentinel_owner.record_identity();
    drop(sentinel_owner);
    stage2_stub.set_fail_next_unmap(true);
    assert!(
        retry_structural_backing_identities_in_using(
            &custody,
            &[sentinel_identity],
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )
        .is_err(),
        "fixture must leave the unrelated sentinel retry-pending",
    );

    stage2_stub.set_fail_map_on_call(Some(2));
    let result = HvfVmState::prepare_task_only_plan_for_test(plan);
    assert!(matches!(result, Err(TrapError::ChildMapFailed { .. })));
    assert!(
        !ScopedStage2MapTestStub::is_mapped(root_ipa, 0x20_0000),
        "an unrelated retry-pending record must not block exact root rollback",
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(sentinel_ipa, sentinel_size),
        "exact root rollback must not mutate the unrelated sentinel",
    );
    assert!(
        custody
            .stage2_record_snapshot(sentinel_identity.record_id)
            .is_some_and(|snapshot| snapshot.retry_pending.is_some()),
    );

    retry_structural_backing_identities_in_using(
        &custody,
        &[sentinel_identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("cleanup unrelated retry-pending sentinel");
}

#[test]
fn full_vm_partial_map_failure_uses_exact_fail_stop_rollback_static_audit() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let source = include_str!("../../trap.rs");
    let from_process = source
        .rsplit(concat!("pub(crate) fn ", "from_process_spec"))
        .next()
        .and_then(|tail| tail.split(concat!("fn global_frame_", "exec_plan")).next())
        .expect("from_process_spec source body");
    assert!(from_process.contains("rollback_partial_process_stage2_authorities"));
    assert!(from_process.contains("&structural_identities"));
    assert!(from_process.contains("fail_stop_partial_process_stage2_rollback"));
    assert!(!from_process.contains("retry_structural_backing_retirements_in_using"));
}

#[test]
fn foreign_mm_failure_injection_at_composition_boundaries() {
    let _guard = FOREIGN_MM_TEST_LOCK.lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();

    // 1. Reversible stage-2 map failure through production ProcessSpec route with rollback
    let pt_ipa = 0x9a00_0000_0000u64;
    let pt_lease = GlobalFrameStage2Lease::fixed(pt_ipa, 0x20_0000);
    let pt_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let pt_host_addr = pt_host.as_ptr();

    let plan_map_fail = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: crate::memory::LINUX_PAGE_TABLES_BASE,
            ipa: pt_ipa,
            end: pt_ipa + 0x20_0000,
            stage2_lease: Some(pt_lease),
            host: ProcessMappingHost::Owned(pt_host),
            size: 0x20_0000,
            physical_ipa: pt_ipa,
            physical_host_addr: pt_host_addr,
            physical_size: 0x20_0000,
            inventory_backing: InventoryBackingIdentity::Private(1),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            inherited_frame: None,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        }],
        inventory_mappings: Vec::new(),
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (pt_ipa, 0x20_0000),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::new(CarrierForeignMmTransport::new()),
    };
    _stage2_stub.set_fail_next_map(true);
    let map_fail_res = HvfVmState::prepare_task_only_plan_for_test(plan_map_fail);
    assert!(
        matches!(map_fail_res, Err(TrapError::ChildMapFailed { .. })),
        "injected stage2 map failure must return ChildMapFailed"
    );
    assert_eq!(
        ScopedStage2MapTestStub::mapped_count(),
        0,
        "failed stage-2 mapping must roll back and leave zero live mappings"
    );

    // 2. Multi-row test injection at production stage_mapping / inventory staging boundary
    let pt_ipa2_row1 = 0x9a00_2000_0000u64;
    let pt_lease2_row1 = GlobalFrameStage2Lease::fixed(pt_ipa2_row1, 0x20_0000);
    let pt_host2_row1 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let pt_host_addr2_row1 = pt_host2_row1.as_ptr();

    let pt_ipa2_row2 = 0x9a00_2200_0000u64;
    let pt_lease2_row2 = GlobalFrameStage2Lease::fixed(pt_ipa2_row2, 0x20_0000);
    let pt_host2_row2 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let pt_host_addr2_row2 = pt_host2_row2.as_ptr();

    let sentinel_ipa = 0x7c00_0000_0000u64;
    let sentinel_len = 0x4000u64;
    let sentinel_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        sentinel_len as usize,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate authoritative rollback sentinel backing");
    assert_eq!(
        unsafe {
            inventory_hv_vm_map(
                sentinel_host.as_ptr().cast(),
                sentinel_ipa,
                sentinel_len as usize,
                3,
            )
        },
        0,
        "install authoritative rollback sentinel stage-2 mapping"
    );
    let sentinel_frame =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(91).unwrap());
    let sentinel_mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(92).unwrap());
    let sentinel_backing = InventoryBackingIdentity::Private(93);
    let sentinel_owner = InventoryStage2OwnerIdentity {
        host_addr: sentinel_host.as_ptr() as usize,
        generation: 0,
    };
    let sentinel_frames = Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry {
        shared: std::collections::BTreeMap::from([(sentinel_backing, sentinel_frame)]),
        references: std::collections::BTreeMap::from([(sentinel_frame, 3)]),
        extent_references: std::collections::BTreeMap::from([(
            (sentinel_frame, sentinel_ipa, sentinel_len),
            2,
        )]),
        stage2_references: std::collections::BTreeMap::from([((sentinel_ipa, sentinel_len), 4)]),
        authority_retained_stage2: std::collections::BTreeSet::from([(sentinel_ipa, sentinel_len)]),
    }));
    let inventory_shared = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory {
        initialized: true,
        extents: std::collections::BTreeMap::from([(
            (sentinel_ipa, sentinel_len),
            InventoryExtent {
                frame: sentinel_frame,
                mapping: sentinel_mapping,
                backing: sentinel_backing,
                stage2_base: sentinel_ipa,
                stage2_length: sentinel_len,
                stage2_owner: sentinel_owner,
            },
        )]),
        frames: sentinel_frames,
        ..HvpatchFrameInventory::default()
    }));
    let authoritative_preimage = inventory_fingerprint(&inventory_shared.lock());

    let mut plan_stage_fail = ProcessSpecPlan {
        mappings: vec![
            ProcessMappingDesc {
                start: crate::memory::LINUX_PAGE_TABLES_BASE,
                ipa: pt_ipa2_row1,
                end: pt_ipa2_row1 + 0x20_0000,
                stage2_lease: Some(pt_lease2_row1),
                host: ProcessMappingHost::Owned(pt_host2_row1),
                size: 0x20_0000,
                physical_ipa: pt_ipa2_row1,
                physical_host_addr: pt_host_addr2_row1,
                physical_size: 0x20_0000,
                inventory_backing: InventoryBackingIdentity::Private(1),
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                inherited_frame: None,
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: 0,
            },
            ProcessMappingDesc {
                start: crate::memory::LINUX_PAGE_TABLES_BASE + 0x20_0000,
                ipa: pt_ipa2_row2,
                end: pt_ipa2_row2 + 0x20_0000,
                stage2_lease: Some(pt_lease2_row2),
                host: ProcessMappingHost::Owned(pt_host2_row2),
                size: 0x20_0000,
                physical_ipa: pt_ipa2_row2,
                physical_host_addr: pt_host_addr2_row2,
                physical_size: 0x20_0000,
                inventory_backing: InventoryBackingIdentity::Private(2),
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                inherited_frame: None,
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: 0,
            },
        ],
        inventory_mappings: vec![
            ProcessInventoryDesc {
                gpa: pt_ipa2_row1,
                length: 0x20_0000,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: InventoryBackingIdentity::Private(1),
                stage2_lease: (pt_ipa2_row1, 0x20_0000),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: pt_host_addr2_row1 as usize,
                    generation: 0,
                },
                fork_frame_receipt_kind: None,
            },
            ProcessInventoryDesc {
                gpa: pt_ipa2_row2,
                length: 0x20_0000,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: InventoryBackingIdentity::Private(2),
                stage2_lease: (pt_ipa2_row2, 0x20_0000),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: pt_host_addr2_row2 as usize,
                    generation: 0,
                },
                fork_frame_receipt_kind: None,
            },
        ],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (pt_ipa2_row1, 0x20_0000),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::clone(&inventory_shared),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::new(CarrierForeignMmTransport::new()),
    };
    plan_stage_fail
        .stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
            let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
                std::num::NonZeroU64::new(601).unwrap(),
            );
            let frames = (0..frame_candidates)
                .map(|id| {
                    carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(id as u64 + 1).unwrap(),
                    )
                })
                .collect();
            let mappings = (0..mapping_candidates)
                .map(|id| {
                    carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(id as u64 + 1).unwrap(),
                    )
                })
                .collect();
            Ok(
                carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                    carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x33; 32]),
                    carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
                    frames,
                    mappings,
                ),
            )
        })
        .expect("stage reservation for stage_mapping failure test");
    // Inject failure on Row 2 (index 1) after Row 1 (index 0) has staged state
    _stage2_stub.set_fail_stage_mapping_on_row(Some(1));
    let stage_fail_res = HvfVmState::prepare_task_only_plan_for_test(plan_stage_fail);
    assert!(
        matches!(stage_fail_res, Err(TrapError::Hypervisor(msg)) if msg.contains("injected stage_mapping failure")),
        "injected stage_mapping failure must return Hypervisor error"
    );
    assert_eq!(
        ScopedStage2MapTestStub::mapped_count(),
        1,
        "stage_mapping failure must preserve only the authoritative sentinel mapping"
    );
    assert!(!ScopedStage2MapTestStub::is_mapped(pt_ipa2_row1, 0x20_0000));
    assert!(!ScopedStage2MapTestStub::is_mapped(pt_ipa2_row2, 0x20_0000));
    assert!(ScopedStage2MapTestStub::is_mapped(
        sentinel_ipa,
        sentinel_len as usize
    ));
    assert_eq!(
        inventory_fingerprint(&inventory_shared.lock()),
        authoritative_preimage,
        "row-2 failure must restore every authoritative inventory component exactly"
    );
    assert!(
        global_frame_host_owners().lock().is_empty(),
        "global frame owners must be empty"
    );
    assert!(
        alias_registry().lock().is_empty(),
        "alias registry must be empty"
    );
    assert_eq!(
        unsafe { inventory_hv_vm_unmap(sentinel_ipa, sentinel_len as usize) },
        0,
        "remove authoritative rollback sentinel mapping"
    );
    drop(sentinel_host);

    // 3. Real directory publication failure rollback with concrete Process state and dynamic alias
    let external_state_restore = ExternalAliasStateRestore::capture();
    let preexisting_alias = AliasBacking {
        start: 0x6000_7a00_0000,
        ipa: 0x7b00_0000_0000,
        host_addr: 0x1234_0000,
        size: 0x4000,
        physical_ipa: 0x7b00_0000_0000,
        physical_host_addr: 0x1234_0000,
        physical_size: 0x4000,
        perms: 3,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::SharedFile {
            device: 71,
            inode: 72,
            offset: 0,
            length: 0x4000,
        },
        shared_key_base: 0x6000_7a00_0000,
        shared_key_offset: 0,
        owner_generation: 73,
    };
    register_shared_alias(preexisting_alias);
    let alias_preimage = alias_registry().lock().ordered();
    let replay_preimage = replay_mappings().lock().clone();
    assert!(!alias_preimage.is_empty());
    assert!(!replay_preimage.is_empty());

    let pt_ipa3 = 0x9a00_4000_0000u64;
    let pt_lease3 = GlobalFrameStage2Lease::fixed(pt_ipa3, 0x20_0000);
    let pt_host3 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x20_0000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let pt_host_addr3 = pt_host3.as_ptr();

    let mut plan_pub_fail = ProcessSpecPlan {
        mappings: vec![ProcessMappingDesc {
            start: crate::memory::LINUX_PAGE_TABLES_BASE,
            ipa: pt_ipa3,
            end: pt_ipa3 + 0x20_0000,
            stage2_lease: Some(pt_lease3),
            host: ProcessMappingHost::Owned(pt_host3),
            size: 0x20_0000,
            physical_ipa: pt_ipa3,
            physical_host_addr: pt_host_addr3,
            physical_size: 0x20_0000,
            inventory_backing: InventoryBackingIdentity::Private(1),
            perms: applevisor::memory::MemPerms::ReadWrite,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            inherited_frame: None,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        }],
        inventory_mappings: vec![ProcessInventoryDesc {
            gpa: pt_ipa3,
            length: 0x20_0000,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            inherited_frame: None,
            inherited_mapping: None,
            backing: InventoryBackingIdentity::Private(1),
            stage2_lease: (pt_ipa3, 0x20_0000),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: pt_host_addr3 as usize,
                generation: 0,
            },
            fork_frame_receipt_kind: None,
        }],
        protections: Arc::new(MemoryProtections::default()),
        mailbox_slots: Arc::new(MailboxSlotAllocator::new()),
        syscall_transport: HvfSyscallTransport::Mailbox,
        persistent_vm_lifecycle: true,
        mm_root_slot: (pt_ipa3, 0x20_0000),
        container_root: ContainerRootToken::from_raw(1),
        frame_inventory: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        carrier_foreign_mm_transport: Arc::new(CarrierForeignMmTransport::new()),
    };
    plan_pub_fail
        .stage_with_reservation_factory(|frame_candidates, mapping_candidates, capacity| {
            let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
                std::num::NonZeroU64::new(701).unwrap(),
            );
            let frames = (0..frame_candidates)
                .map(|id| {
                    carrick_hal::FrameId::from_kernel_allocation(
                        std::num::NonZeroU64::new(id as u64 + 1).unwrap(),
                    )
                })
                .collect();
            let mappings = (0..mapping_candidates)
                .map(|id| {
                    carrick_hal::MappingId::from_kernel_allocation(
                        std::num::NonZeroU64::new(id as u64 + 1).unwrap(),
                    )
                })
                .collect();
            Ok(
                carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                    carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x33; 32]),
                    carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
                    frames,
                    mappings,
                ),
            )
        })
        .expect("stage reservation for directory rollback test");
    let (carrier_state_pub, prepared_task_pub) =
        HvfVmState::prepare_task_only_plan_for_test(plan_pub_fail)
            .expect("prepare_task_only_plan_for_test for directory rollback test");
    assert!(
        ScopedStage2MapTestStub::is_mapped(pt_ipa3, 0x20_0000),
        "stage-2 mapping must be installed after successful preparation"
    );
    assert!(
        !prepared_task_pub.pending_aliases.is_empty(),
        "pending aliases must contain dynamic alias"
    );

    let (_issuer_pub, verifier_pub) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let directory_pub = Arc::new(HvpatchCarrierTaskStateDirectory::new(
        std::num::NonZeroU64::new(1).unwrap(),
        verifier_pub,
    ));
    let identity_pub = HvpatchCarrierTaskIdentity {
        task_serial: 301,
        thread_serial: 301,
        execution_generation: 1,
        linux_pid: 301,
        linux_tid: 301,
        asid: 1,
    };
    let pub_res = directory_pub.publish_inner(
        identity_pub,
        carrier_state_pub,
        prepared_task_pub,
        1, // Injected failpoint after alias commit
    );
    assert!(
        pub_res.is_err(),
        "injected publish failpoint must return error"
    );
    assert!(
        directory_pub.inner.lock().states.is_empty(),
        "no task state must remain published in directory after failure"
    );
    assert_eq!(
        alias_registry().lock().ordered(),
        alias_preimage,
        "failed publication must restore the exact nonempty alias preimage"
    );
    assert_eq!(
        *replay_mappings().lock(),
        replay_preimage,
        "failed publication must restore the exact nonempty replay preimage"
    );
    assert_eq!(
        ScopedStage2MapTestStub::mapped_count(),
        0,
        "directory publish rollback must abort and unmap all stage2 leases"
    );
    drop(external_state_restore);

    // 4. Real retirement/unmap failure semantics via fallible retirement transaction
    let ipa_retire = 0x8800_9000_0000u64;
    let size_retire = 0x4000usize;
    let mut lease_retire = GlobalFrameStage2Lease::fixed(ipa_retire, size_retire as u64);
    let mapping_retire = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size_retire,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate host mapping for retirement failure test");
    let host_addr_retire = mapping_retire.as_ptr() as usize;
    let rc =
        unsafe { inventory_hv_vm_map(mapping_retire.as_ptr().cast(), ipa_retire, size_retire, 7) };
    assert_eq!(rc, 0);
    lease_retire.mark_mapped();
    let observed_live_retire = Arc::new(std::sync::atomic::AtomicBool::new(false));
    lease_retire.drop_backing_audit = Some((host_addr_retire, Arc::clone(&observed_live_retire)));

    let owner_retire = GlobalFrameHostOwner::new(
        lease_retire,
        mapping_retire,
        7,
        1,
        ipa_retire,
        size_retire as u64,
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(ipa_retire, size_retire),
        "owner extent must be mapped before retirement"
    );

    // Injected unmap failure must preserve mapped state and return error for caller retry
    _stage2_stub.set_fail_next_unmap(true);
    let unmap_err = owner_retire
        .try_retire()
        .expect_err("try_retire must fail when unmap fails");
    assert!(
        matches!(unmap_err, TrapError::Hypervisor(msg) if msg.contains("retry pending")),
        "try_retire must expose custody's retry-pending outcome"
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(ipa_retire, size_retire),
        "mapped extent MUST remain installed on unmap failure"
    );
    assert!(
            ScopedStage2MapTestStub::events().iter().any(
                |e| matches!(e, Stage2BackendEvent::UnmapAttemptFailed { ipa, .. } if *ipa == ipa_retire)
            ),
            "unmap attempt failure event must be recorded"
        );
    assert!(
        alias_backing_is_live(host_addr_retire),
        "host memory backing must remain live on failed retirement"
    );

    // Retrying retirement without unmap failure succeeds cleanly
    owner_retire
        .try_retire()
        .expect("retry try_retire must succeed");
    assert!(
        !ScopedStage2MapTestStub::is_mapped(ipa_retire, size_retire),
        "extent must be unmapped after successful retirement"
    );
    drop(owner_retire);
    assert!(
        !alias_backing_is_live(host_addr_retire),
        "host mapping must be unmapped after owner drop"
    );
    assert!(
        !observed_live_retire.load(std::sync::atomic::Ordering::SeqCst),
        "transferred legacy lease audit state must not drive owner retirement"
    );
    assert!(
        ScopedStage2MapTestStub::events()
            .iter()
            .any(|e| matches!(e, Stage2BackendEvent::Unmap { ipa, .. } if *ipa == ipa_retire)),
        "successful unmap event must be recorded"
    );

    // 5. Transport retain failure on missing binding
    let transport = Arc::new(CarrierForeignMmTransport::new());
    let endpoint = carrick_hal::ForeignMmEndpoint::for_carrier(
        transport as Arc<dyn carrick_hal::ForeignMmTransport>,
    );
    let missing_snapshot = TestSnapshot {
        mm: std::num::NonZeroU64::new(888).unwrap(),
        asid: std::num::NonZeroU16::new(1).unwrap(),
        stage1_root: carrick_guest_mem::Gpa(0x1000),
        backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
        vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
        mapping_ids: vec![],
        executable_ranges: Vec::new(),
        readable_ranges: Vec::new(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let retain_missing = endpoint.retain(&missing_snapshot, deadline);
    assert!(matches!(
        retain_missing,
        Err(carrick_hal::ForeignMmTransportError::MissingBinding)
    ));

    // 6. Transport retain failure on expired deadline
    let expired_deadline = std::time::Instant::now() - std::time::Duration::from_millis(10);
    let retain_expired = endpoint.retain(&missing_snapshot, expired_deadline);
    assert!(matches!(
        retain_expired,
        Err(carrick_hal::ForeignMmTransportError::TimedOut)
    ));
    ScopedStage2MapTestStub::clear_events();
}
