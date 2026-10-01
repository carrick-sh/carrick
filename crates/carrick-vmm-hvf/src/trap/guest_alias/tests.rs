//! Guest-lane alias publication over fixture tables, executed by the real
//! neutral descriptor executor (the code EL1 runs), never a fabricated
//! receipt. The host twin of each fixture is the same boot image edited by
//! the host editor's `map_aliased`, so every comparison is host lane vs
//! guest lane on identical inputs.

use super::*;
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorTxn, InlineJournal, PrimaryTableWords, TableMaintenance, VerifiedDescriptorReceipt,
    execute_descriptor_txn,
};
use carrick_mmu_core::aarch64::{HostArenaResolver, PageTableManager, terminal_entry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const BASE: u64 = carrick_mem::memory::LINUX_PAGE_TABLES_BASE;
const SIZE: usize = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
const PAGE: u64 = 4096;
const PA_MASK: u64 = 0x0000_ffff_ffff_f000;
const NON_GLOBAL: u64 = 1 << 11;

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).expect("nonzero fixture identity")
}

/// The hardware-visible table words of one fixture MM.
struct LiveWords(Box<[AtomicU64]>);

// SAFETY: the boxed words are resident, 8-byte aligned and live as long as
// every manager bound to this resolver (the fixture owns both).
unsafe impl HostArenaResolver for LiveWords {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        let offset = usize::try_from(base.checked_sub(BASE)?).ok()?;
        (offset.checked_add(len)? <= SIZE)
            .then(|| unsafe { self.0.as_ptr().cast::<u8>().cast_mut().add(offset) })
    }
    fn publish_user_executable(
        &self,
        _output: u64,
        _len: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
        // VM-free test backing: no instruction cache to maintain.
        Ok(())
    }
}

impl LiveWords {
    fn bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|word| word.load(Ordering::Relaxed).to_le_bytes())
            .collect()
    }
}

fn boot_image(tables: Vec<u8>) -> PageTableManager {
    PageTableManager::new(
        tables,
        BASE,
        carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
    )
}

/// One guest-owned MM over live fixture words, plus its host-lane twin.
struct GuestMm {
    words: Arc<LiveWords>,
    tables: carrick_aarch64::Stage1Authority,
    host: PageTableManager,
}

fn guest_mm(tables: fn() -> Vec<u8>) -> GuestMm {
    let image = boot_image(tables());
    let mut bytes = image.as_bytes().to_vec();
    bytes.resize(SIZE, 0);
    let words = Arc::new(LiveWords(
        bytes
            .chunks_exact(8)
            .map(|word| AtomicU64::new(u64::from_le_bytes(word.try_into().unwrap())))
            .collect(),
    ));
    let authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(image));
    // SAFETY: `words` outlives the authority (both owned by the fixture).
    unsafe { authority.bind_live_backing(words.clone()) };
    authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
    GuestMm {
        words,
        tables: authority,
        host: boot_image(tables()),
    }
}

/// `(level, leaf)` of the guest's live words at `va`: the hardware walk
/// (same rules as `walk_descriptors`), read straight from the words.
fn guest_leaf(mm: &GuestMm, va: u64) -> (usize, u64) {
    let mut table = BASE;
    for level in 0..4 {
        let index = (va >> (39 - 9 * level)) & 511;
        let word = ((table - BASE) / 8 + index) as usize;
        let leaf = mm.words.0[word].load(Ordering::Relaxed);
        if leaf & 1 == 0 || level == 3 || leaf & 0b10 == 0 {
            return (level, leaf);
        }
        table = leaf & PA_MASK;
    }
    unreachable!("a four-level walk always terminates")
}

/// What a TLB fill for `va` yields: output page and attributes. The block
/// vs page type bit is excluded: it records the leaf's level, which is not
/// a translation property.
fn effective(level: usize, leaf: u64, va: u64) -> (u64, u64) {
    let span = 1_u64 << (39 - 9 * level);
    let output = (leaf & PA_MASK & !(span - 1)) | (va & (span - 1) & !(PAGE - 1));
    (output, leaf & !PA_MASK & !0b10)
}

struct Maintenance;
impl TableMaintenance for Maintenance {
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

/// The driving-vCPU publication venue: runs the neutral executor over the
/// live words and settles exactly as the engine's venue does.
struct El1<'a> {
    mm: &'a GuestMm,
    log: Arc<parking_lot::Mutex<Vec<String>>>,
    refuse_map_alias: Option<usize>,
    map_aliases: Vec<(PageSpan, u64, AliasAccess, BackingIdentity)>,
}

impl<'a> El1<'a> {
    fn new(mm: &'a GuestMm, log: Arc<parking_lot::Mutex<Vec<String>>>) -> Self {
        Self {
            mm,
            log,
            refuse_map_alias: None,
            map_aliases: Vec::new(),
        }
    }
}

impl Stage1Services for El1<'_> {
    fn flush(&mut self) -> Result<(), TrapError> {
        panic!("guest alias publication must not use the host flush")
    }
    fn guest_publication_available(&self) -> bool {
        true
    }
    fn publish(
        &mut self,
        txn: &DescriptorTxn,
    ) -> Result<VerifiedDescriptorReceipt, carrick_aarch64::vmm::GuestPublishError> {
        match txn.op {
            DescriptorOp::MapAlias {
                access,
                span,
                target_ipa,
                backing,
            } => {
                let ordinal = self.map_aliases.len();
                self.map_aliases
                    .push((span, target_ipa.raw(), access, backing));
                if self.refuse_map_alias == Some(ordinal) {
                    // EL1 refused before its first store: grants return.
                    self.log.lock().push("el1:map-alias-refused".to_owned());
                    self.mm.tables.abandon_guest_descriptor_txn(txn).unwrap();
                    return Err(TrapError::Hypervisor("EL1 refused MapAlias".to_owned()).into());
                }
                self.log.lock().push("el1:map-alias".to_owned());
            }
            DescriptorOp::Terminal { .. } => self.log.lock().push("el1:terminal".to_owned()),
            other => panic!("unexpected guest alias descriptor op {other:?}"),
        }
        // SAFETY: the words are resident and cover the whole primary arena.
        let words = unsafe {
            PrimaryTableWords::new(
                self.mm.words.0.as_ptr().cast_mut(),
                BASE,
                SIZE,
                &Maintenance,
            )
        }
        .unwrap();
        let receipt =
            execute_descriptor_txn(&words, SubstrateGpa(BASE), txn, &mut InlineJournal::new());
        self.mm
            .tables
            .settle_guest_descriptor_receipt(txn, &receipt)
            .map_err(|error| {
                carrick_aarch64::vmm::GuestPublishError::from_settle(error, "model EL1 receipt")
            })
    }
}

/// Kernel inventory authority double that records the order of calls and
/// only authenticates a mapping it has applied.
struct Authority {
    log: Arc<parking_lot::Mutex<Vec<String>>>,
    mm: NonZeroU64,
    provenance: carrick_hal::FrameInventoryProvenance,
    revision: u64,
    owner_generation: u64,
    live: parking_lot::Mutex<Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>>,
}

impl carrick_hal::FrameCowAuthority for Authority {
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
        panic!("guest alias publication reserves nothing of its own")
    }

    fn apply(
        &self,
        _: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        panic!("a guest alias must be applied with a receipt")
    }

    fn apply_with_receipt(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryApplyReceipt, Box<dyn std::error::Error + Send + Sync>>
    {
        self.log.lock().push("kernel:apply".to_owned());
        let mappings: Vec<_> = commit
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
        self.live.lock().extend(mappings.iter().copied());
        Ok(
            carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
                self.provenance,
                commit.batch().transaction(),
                self.mm,
                self.revision,
                mappings,
            ),
        )
    }

    fn authenticate_frame_backing(
        &self,
        request: carrick_hal::FrameBackingAuthentication,
    ) -> Result<(NonZeroU64, BackingIdentity), Box<dyn std::error::Error + Send + Sync>> {
        self.log.lock().push("kernel:authenticate".to_owned());
        if !self.live.lock().contains(&(request.mapping, request.frame)) {
            return Err(Box::new(std::io::Error::other("mapping is not live")));
        }
        Ok((
            self.mm,
            BackingIdentity {
                frame_id: nz(request.frame.raw()),
                mapping_id: nz(request.mapping.raw()),
                owner_generation: nz(self.owner_generation),
                inventory_revision: nz(self.revision),
            },
        ))
    }

    fn mapping_is_live(
        &self,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        _: carrick_guest_mem::Gpa,
        _: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.live.lock().contains(&(mapping, frame)))
    }

    fn frame_mapping_count(
        &self,
        _: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    fn rollback_frame_grant(
        &self,
        receipt: &carrick_hal::FrameInventoryApplyReceipt,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.log.lock().push("kernel:rollback".to_owned());
        assert_eq!(receipt.mm(), self.mm);
        self.live
            .lock()
            .retain(|mapping| !receipt.mapping_set().contains(mapping));
        Ok(())
    }
}

/// A registered global-frame owner plus the alias inventory `add_alias`
/// stages for it (extent, reservation commit), in a fixture custody.
struct StagedAlias {
    custody: Arc<CarrierVmCustody>,
    ledger: parking_lot::Mutex<HvpatchFrameInventory>,
    gpa: u64,
    length: u64,
    extent: InventoryExtent,
    authority: Authority,
}

const PROVENANCE: [u8; 32] = [0x5a; 32];
const REVISION: u64 = 4242;

fn staged_alias(log: &Arc<parking_lot::Mutex<Vec<String>>>, length: u64, mm: u64) -> StagedAlias {
    let custody = Arc::new(CarrierVmCustody::new_live_fixture());
    let mut lease = GlobalFrameStage2Lease::reserve(length, length).unwrap();
    let (gpa, length) = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        length as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let host_addr = host.as_ptr() as usize;
    assert_eq!(
        unsafe { inventory_hv_vm_map(host.as_ptr().cast(), gpa, length as usize, 7) },
        0
    );
    lease.mark_mapped();
    let generation = register_global_frame_host_owner_in(&custody, lease, host, 7).unwrap();
    let provenance = carrick_hal::FrameInventoryProvenance::from_kernel_entropy(PROVENANCE);
    let mut reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        provenance,
        carrick_hal::FrameInventoryBatch::prepare(
            carrick_hal::KernelTransactionId::from_kernel_allocation(nz(mm * 100 + 1)),
            carrick_hal::FrameEventCapacity::for_event_count(2).unwrap(),
        )
        .unwrap(),
        vec![carrick_hal::FrameId::from_kernel_allocation(nz(
            mm * 100 + 2
        ))],
        vec![carrick_hal::MappingId::from_kernel_allocation(nz(
            mm * 100 + 3
        ))],
    );
    let mut inventory = HvpatchFrameInventory::default();
    let extent = HvfVmState::stage_mapping_in(
        &custody,
        &mut inventory,
        &mut reservation,
        InventoryMappingStage {
            gpa,
            length,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: true,
            },
            backing: HvfVmState::private_backing_identity(),
            inherited_frame: None,
            stage2_lease: None,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr,
                generation,
            },
        },
    )
    .unwrap();
    inventory.alias_staged.push(((gpa, length), extent));
    inventory.alias_commit = Some(reservation.commit(()));
    StagedAlias {
        custody,
        ledger: parking_lot::Mutex::new(inventory),
        gpa,
        length,
        extent,
        authority: Authority {
            log: log.clone(),
            mm: nz(mm),
            provenance,
            revision: REVISION,
            owner_generation: generation,
            live: parking_lot::Mutex::new(Vec::new()),
        },
    }
}

impl StagedAlias {
    fn context<'a>(&'a self, mm: &'a GuestMm) -> GuestAliasContext<'a> {
        GuestAliasContext {
            custody: &self.custody,
            ledger: &self.ledger,
            authority: &self.authority,
            tables: &mm.tables,
            mm: self.authority.mm,
        }
    }
}

/// A high alias VA 8 KiB below a 2 MiB boundary. The global-frame IPA is
/// 16 KiB aligned, so VA and IPA are never congruent mod 2 MiB and the
/// publication splits into two transactions at the boundary.
const STRADDLING_VA: u64 = 0x5000_0020_0000 - 0x2000;

#[test]
fn guest_host_alias_applies_inventory_before_naming_its_revision() {
    let _guard =
        crate::trap::frame_inventory_backend_tests::global_frame_allocator_test_lock().lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mut mm = guest_mm(carrick_mem::memory::stage1_hvpatch_page_tables);
    let staged = staged_alias(&log, 0x4000, 31);
    let mut el1 = El1::new(&mm, log.clone());
    staged
        .context(&mm)
        .publish_host_alias(STRADDLING_VA, staged.gpa, staged.length, false, &mut el1)
        .expect("guest alias publishes");
    let published = std::mem::take(&mut el1.map_aliases);
    drop(el1);

    assert_eq!(
        *log.lock(),
        [
            "kernel:apply",
            "kernel:authenticate",
            "el1:map-alias",
            "el1:map-alias"
        ],
        "the kernel must know the mapping before a MapAlias names it"
    );
    let expected_backing = BackingIdentity {
        frame_id: nz(staged.extent.frame.raw()),
        mapping_id: nz(staged.extent.mapping.raw()),
        owner_generation: nz(staged.extent.stage2_owner.generation),
        inventory_revision: nz(REVISION),
    };
    let mut covered = 0;
    for (span, target, access, backing) in &published {
        assert_eq!(*backing, expected_backing);
        assert_eq!(
            *access,
            AliasAccess::User {
                writable: false,
                executable: true
            }
        );
        assert_eq!(*target, staged.gpa + (span.va - STRADDLING_VA));
        covered += span.len;
    }
    assert_eq!(covered, staged.length);
    // The whole staging became the authority's: nothing is left to take.
    let ledger = staged.ledger.lock();
    assert!(ledger.alias_commit.is_none() && ledger.alias_staged.is_empty());
    assert!(ledger.extents.get(&(staged.gpa, staged.length)).is_some());
    drop(ledger);

    // Host lane on the identical image: the same translation, page for page.
    mm.host
        .map_aliased(STRADDLING_VA, staged.gpa, staged.length, false, None)
        .unwrap();
    for page in (0..staged.length).step_by(PAGE as usize) {
        let va = STRADDLING_VA + page;
        let (level, leaf) = guest_leaf(&mm, va);
        let (host_level, host_leaf) = terminal_entry(mm.host.try_debug_walk(va).unwrap());
        assert_eq!(
            effective(level, leaf, va),
            effective(host_level, host_leaf, va),
            "page {va:#x}: guest {leaf:#x} host {host_leaf:#x}"
        );
        assert_eq!(effective(level, leaf, va).0, staged.gpa + page);
    }
}

#[test]
fn refused_guest_host_alias_retires_span_before_rolling_back_the_grant() {
    let _guard =
        crate::trap::frame_inventory_backend_tests::global_frame_allocator_test_lock().lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mm = guest_mm(carrick_mem::memory::stage1_hvpatch_page_tables);
    let staged = staged_alias(&log, 0x4000, 32);
    let mut el1 = El1::new(&mm, log.clone());
    // The first chunk publishes; EL1 refuses the second.
    el1.refuse_map_alias = Some(1);
    let refusal = staged
        .context(&mm)
        .publish_host_alias(STRADDLING_VA, staged.gpa, staged.length, true, &mut el1)
        .expect_err("a refused chunk refuses the alias");
    drop(el1);
    assert!(
        matches!(refusal, GuestAliasRefusal::RolledBack(_)),
        "{refusal:?}"
    );
    assert_eq!(
        *log.lock(),
        [
            "kernel:apply",
            "kernel:authenticate",
            "el1:map-alias",
            "el1:map-alias-refused",
            "el1:terminal",
            "kernel:rollback",
        ],
        "every leaf must be retired before the authority forgets the mapping"
    );
    // The published first chunk and the refused second are both retired.
    for page in (0..staged.length).step_by(PAGE as usize) {
        let (_, leaf) = guest_leaf(&mm, STRADDLING_VA + page);
        assert_eq!(leaf & 1, 0, "page {page:#x} still valid: {leaf:#x}");
    }
    // Kernel and backend inventory are both back to never having seen it,
    // so the caller's unregister finds nothing to retire.
    assert!(staged.authority.live.lock().is_empty());
    let ledger = staged.ledger.lock();
    assert!(ledger.alias_commit.is_none() && ledger.alias_staged.is_empty());
    assert!(ledger.extents.is_empty());
    let frames = ledger.frames.lock();
    assert!(frames.references.is_empty());
    assert!(frames.extent_references.is_empty());
    assert!(frames.stage2_references.is_empty());
}

#[test]
fn guest_host_alias_in_the_excluded_window_refuses_before_inventory_or_submission() {
    let _guard =
        crate::trap::frame_inventory_backend_tests::global_frame_allocator_test_lock().lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mm = guest_mm(carrick_mem::memory::stage1_hvpatch_page_tables);
    let staged = staged_alias(&log, 0x4000, 33);
    let words_before = mm.words.bytes();
    let mut el1 = El1::new(&mm, log.clone());
    let gic = carrick_mem::memory::LINUX_GIC_WINDOW_BASE;
    let refusal = staged
        .context(&mm)
        .publish_host_alias(STRADDLING_VA, gic, staged.length, true, &mut el1)
        .expect_err("an output in the GIC window refuses");
    assert!(el1.map_aliases.is_empty(), "nothing reached EL1");
    drop(el1);
    let GuestAliasRefusal::BeforeInventory(error) = refusal else {
        panic!("excluded-window refusal must precede inventory: {refusal:?}")
    };
    assert!(error.to_string().contains("excluded IPA window"), "{error}");
    assert!(
        log.lock().is_empty(),
        "no kernel or EL1 call: {:?}",
        log.lock()
    );
    assert_eq!(mm.words.bytes(), words_before);
    // The staging stays armed for the caller's abandon, as on the host lane.
    let ledger = staged.ledger.lock();
    assert!(ledger.alias_commit.is_some());
    assert_eq!(ledger.alias_staged.len(), 1);
}

#[test]
fn guest_identity_restore_names_the_live_extent_for_a_subrange() {
    let _guard =
        crate::trap::frame_inventory_backend_tests::global_frame_allocator_test_lock().lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mut mm = guest_mm(carrick_mem::memory::stage1_hvpatch_page_tables);
    // A live (applied) boot-style extent whose IPA is its own VA.
    let staged = staged_alias(&log, 0x10000, 34);
    {
        let mut ledger = staged.ledger.lock();
        let commit = ledger.alias_commit.take().unwrap();
        ledger.alias_staged.clear();
        drop(ledger);
        carrick_hal::FrameCowAuthority::apply_with_receipt(&staged.authority, commit).unwrap();
    }
    // A repointed page inside the extent (the state identity restore undoes).
    let va = staged.gpa + PAGE;
    let len = 2 * PAGE;
    let mut el1 = El1::new(&mm, log.clone());
    staged
        .context(&mm)
        .restore_identity(va, len, &mut el1)
        .expect("identity restore publishes");
    let published = std::mem::take(&mut el1.map_aliases);
    drop(el1);
    // The sub-range is published; its backing names the WHOLE live extent.
    assert_eq!(published.len(), 1);
    let (span, target, access, backing) = published[0];
    assert_eq!((span.va, span.len, target), (va, len, va));
    assert_eq!(
        access,
        AliasAccess::User {
            writable: true,
            executable: true
        }
    );
    assert_eq!(backing.mapping_id.get(), staged.extent.mapping.raw());
    assert_eq!(backing.inventory_revision, nz(REVISION));
    mm.host.map_aliased(va, va, len, true, None).unwrap();
    for page in (va - PAGE..va + len + PAGE).step_by(PAGE as usize) {
        let (level, leaf) = guest_leaf(&mm, page);
        let (host_level, host_leaf) = terminal_entry(mm.host.try_debug_walk(page).unwrap());
        if leaf & 1 == 0 && host_leaf & 1 == 0 {
            continue;
        }
        assert_eq!(
            effective(level, leaf, page),
            effective(host_level, host_leaf, page),
            "page {page:#x}: guest {leaf:#x} host {host_leaf:#x}"
        );
    }
}

/// Publish `va -> ipa` with the production chunk plan through prepared
/// transactions and the real executor, with a synthetic backing identity
/// (EL1 never interprets it).
fn publish_raw(mm: &GuestMm, va: u64, ipa: u64, len: u64, writable: bool) -> usize {
    let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mut el1 = El1::new(mm, log);
    let backing = BackingIdentity {
        frame_id: nz(1),
        mapping_id: nz(2),
        owner_generation: nz(3),
        inventory_revision: nz(4),
    };
    let chunks = map_alias_chunks(va, ipa, len);
    for &(offset, count) in &chunks {
        let txn = mm
            .tables
            .prepare_guest_descriptor_txn(
                nz(9),
                DescriptorOp::MapAlias {
                    access: AliasAccess::User {
                        writable,
                        executable: true,
                    },
                    span: PageSpan::new(va + offset, count),
                    target_ipa: SubstrateGpa(ipa + offset),
                    backing,
                },
            )
            .unwrap_or_else(|error| panic!("chunk {offset:#x}+{count:#x}: {error:?}"));
        el1.publish(&txn).unwrap();
    }
    chunks.len()
}

/// Per-page translation parity of EL1 `MapAlias` and the host editor's
/// `map_aliased` for every alias shape the two writers produce: sub-block
/// pages, 2 MiB blocks, a 1 GiB-aligned gigabyte, read-only, a non-congruent
/// IPA, and replacement of already-valid leaves.
#[test]
fn guest_map_alias_matches_host_map_aliased_page_for_page() {
    const TWO_MIB: u64 = 1 << 21;
    const ONE_GIB: u64 = 1 << 30;
    let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
    assert_eq!(ipa % ONE_GIB, 0, "fixture IPA must admit 1 GiB blocks");
    // (va, ipa, len, writable)
    let shapes = [
        (0x5000_0000_3000, ipa + 0x3000, 5 * PAGE, true),
        (
            0x5000_0010_0000,
            ipa + 0x10_0000,
            3 * TWO_MIB + 7 * PAGE,
            true,
        ),
        (
            0x5000_0000_0000 + 2 * ONE_GIB,
            ipa,
            ONE_GIB + TWO_MIB,
            false,
        ),
        (0x5000_4000_1000, ipa + 0x2000, TWO_MIB + 3 * PAGE, true),
    ];
    for (index, &(va, ipa, len, writable)) in shapes.iter().enumerate() {
        let mut mm = guest_mm(carrick_mem::memory::stage1_hvpatch_page_tables);
        // Replacement: an older alias at the same VA onto other output.
        let stale = ipa + 4 * ONE_GIB;
        publish_raw(&mm, va, stale, len, true);
        mm.host.map_aliased(va, stale, len, true, None).unwrap();
        let transactions = publish_raw(&mm, va, ipa, len, writable);
        mm.host.map_aliased(va, ipa, len, writable, None).unwrap();
        if index == 2 {
            // One transaction per 1 GiB-aligned VA span, not per 2 MiB.
            assert_eq!(transactions, 2);
            // Documented shape difference: the host editor installs a 1 GiB
            // L1 block where the guest executor links an L2 table of 2 MiB
            // blocks (it never edits L1 terminals). Same translation.
            assert_eq!(terminal_entry(mm.host.try_debug_walk(va).unwrap()).0, 1);
            assert_eq!(guest_leaf(&mm, va).0, 2);
        }
        let stride = if len > 64 * TWO_MIB {
            TWO_MIB / 2
        } else {
            PAGE
        };
        let mut pages: Vec<u64> = (0..len).step_by(stride as usize).collect();
        pages.push(len - PAGE);
        for page in pages {
            let va = va + page;
            let (level, leaf) = guest_leaf(&mm, va);
            let (host_level, host_leaf) = terminal_entry(mm.host.try_debug_walk(va).unwrap());
            assert_ne!(leaf & 1, 0, "shape {index} page {va:#x} not valid");
            let guest = effective(level, leaf, va);
            assert_eq!(
                guest,
                effective(host_level, host_leaf, va),
                "shape {index} page {va:#x}: guest {leaf:#x} host {host_leaf:#x}"
            );
            assert_eq!(guest.0, ipa + page, "shape {index} output");
            assert_ne!(guest.1 & NON_GLOBAL, 0, "HVPatch leaves are ASID-scoped");
        }
    }
}

/// The only leaf difference between the lanes: on an image whose boot
/// leaves are global (not ASID-scoped) the host editor writes global alias
/// leaves, while EL1 `MapAlias` always writes nG. The guest lane exists only
/// on HVPatch MMs, whose images are ASID-scoped (asserted above), and nG only
/// narrows TLB reuse to the MM's ASID, so the guest's leaf is never broader.
#[test]
fn map_alias_differs_from_a_global_image_only_by_asid_scoping() {
    let mut mm = guest_mm(carrick_mem::memory::stage1_identity_page_tables);
    let va = 0x5000_0000_3000;
    let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x3000;
    publish_raw(&mm, va, ipa, 2 * PAGE, true);
    mm.host.map_aliased(va, ipa, 2 * PAGE, true, None).unwrap();
    let (level, leaf) = guest_leaf(&mm, va);
    let (host_level, host_leaf) = terminal_entry(mm.host.try_debug_walk(va).unwrap());
    let (guest, host) = (
        effective(level, leaf, va),
        effective(host_level, host_leaf, va),
    );
    assert_eq!(guest.0, host.0);
    assert_eq!(guest.1 ^ host.1, NON_GLOBAL);
    assert_ne!(guest.1 & NON_GLOBAL, 0);
}

#[test]
fn chunks_follow_congruence_and_cover_the_span_exactly() {
    const TWO_MIB: u64 = 1 << 21;
    const ONE_GIB: u64 = 1 << 30;
    let covers = |chunks: &[(u64, u64)], len| {
        let mut next = 0;
        for &(offset, count) in chunks {
            assert_eq!(offset, next);
            assert!(count > 0);
            next += count;
        }
        assert_eq!(next, len);
    };
    // Congruent: pieces end at 1 GiB VA boundaries.
    let chunks = map_alias_chunks(ONE_GIB - TWO_MIB, 3 * ONE_GIB - TWO_MIB, 2 * ONE_GIB);
    covers(&chunks, 2 * ONE_GIB);
    assert_eq!(
        chunks,
        [
            (0, TWO_MIB),
            (TWO_MIB, ONE_GIB),
            (ONE_GIB + TWO_MIB, ONE_GIB - TWO_MIB)
        ]
    );
    // Incongruent: every piece stays inside one 2 MiB VA span.
    let chunks = map_alias_chunks(TWO_MIB - PAGE, 0x4000, 2 * TWO_MIB);
    covers(&chunks, 2 * TWO_MIB);
    assert_eq!(chunks.len(), 3);
    for (offset, count) in chunks {
        let start = TWO_MIB - PAGE + offset;
        assert_eq!(start / TWO_MIB, (start + count - 1) / TWO_MIB);
    }
}
