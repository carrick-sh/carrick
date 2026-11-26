#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    ForkLifecycleLoan, ForkStockExchange, ForkStockLoan, ForkStockRequest, ForkStockSettlement,
    Mapping, PortalOperation, ReservationGeneration, ReservationNodeFlags, SnapshotGeneration,
};
use carrick_guest_arch::{CpuId, KernelVa};
use carrick_hal::fork_stock::{ForkControlCapacity, GrantExecution, NoTableLedger, UntaggedRoots};

const CARRIER: NonZeroU64 = NonZeroU64::new(7).unwrap();
const SUCCESSOR: u64 = 12;
const ROOT_GENERATION: NonZeroU64 = NonZeroU64::new(5).unwrap();
const ENTRY: u64 = 0x40_1000;

/// A zeroed carrier region holding the zone and reservation table at their
/// real CPL0 offsets.
struct Region(carrick_test_support::ZeroedBox<carrick_test_support::TestEl1Region>);

impl Region {
    fn new() -> Self {
        Self(carrick_test_support::TestEl1Region::zeroed())
    }
    fn zone(&self) -> &X86Cpl0Zone {
        // SAFETY: the retained aligned region owns the zero-valid zone at its
        // real CPL0 offset for the fixture's life.
        unsafe {
            &*self
                .0
                .as_ptr()
                .add(carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize)
                .cast()
        }
    }
    fn roots(&self) -> &X86Cpl0Reservations {
        // SAFETY: as for `zone`.
        unsafe {
            &*self
                .0
                .as_ptr()
                .add(carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                .cast()
        }
    }
    /// The tables as the Exec service reaches them. The fixture's bootstrap
    /// arena is the region's EL1 one: it publishes no bank there.
    fn tables(&self) -> X86ExecTables<'_> {
        // SAFETY: the retained region spans the arena for the fixture's life.
        unsafe {
            X86ExecTables::new(
                self.roots(),
                self.zone(),
                core::ptr::NonNull::new(
                    self.0
                        .as_ptr()
                        .add(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize)
                        .cast_mut(),
                )
                .unwrap(),
            )
        }
    }
    /// Publish the closed, unadmitted root of `successor`, as the ring does
    /// before it asks for an exec.
    fn publish_successor(&self, successor: u64) {
        let index = self.zone().spaces.publish_closed(successor, 0, 0).unwrap();
        self.roots()
            .publish(
                index.index(),
                ReservationMm::new(successor).unwrap(),
                carrick_el1::memory::reservations::Layout {
                    heap: ReservationRange::new(0x1000_0000, 0x1100_0000).unwrap(),
                    arena: ReservationRange::new(0x4000_0000, 0x4400_0000).unwrap(),
                    brk: 0x1000_0000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
    }
}

/// The carrier frames, staged under the production inventory transaction
/// against a real frame inventory; only the GPA allocator is the fixture's.
struct TestFrames {
    authority: Arc<FrameInventoryAuthority>,
    inventory: Arc<dyn PhysicalFrameInventory>,
    next: u64,
    released: usize,
    written: std::collections::BTreeMap<u64, Vec<u8>>,
    cleared: usize,
    /// Release calls so far, and the ones (by that count) reported failed.
    release_calls: usize,
    fail_release: Vec<usize>,
    /// Report every table clear failed, clearing nothing.
    fail_clear: bool,
}

impl TestFrames {
    fn new() -> Self {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let inventory = authority.physical_projection(Arc::new(ObjectIdRegistry::new()));
        Self {
            authority,
            inventory,
            next: DYNAMIC_GRANT_GPA,
            released: 0,
            written: std::collections::BTreeMap::new(),
            cleared: 0,
            release_calls: 0,
            fail_release: Vec::new(),
            fail_clear: false,
        }
    }
    fn mapped(&self) -> usize {
        self.authority.snapshot().mappings.len()
    }
}

struct TestData {
    inventory: InitialInventory,
    grants: Vec<X86InitialBootGrant>,
}

impl X86ExecData for TestData {
    fn grants(&self) -> &[X86InitialBootGrant] {
        &self.grants
    }
}

impl X86ExecFrames for TestFrames {
    type Data = TestData;
    fn stage(
        &mut self,
        pages: usize,
        owner: carrick_hal::GuestFrameOwner,
    ) -> Result<TestData, TrapError> {
        let base = self.next;
        self.next += pages as u64 * 4096;
        let (inventory, grants) = InitialInventory::stage(
            Arc::default(),
            Arc::clone(&self.inventory),
            (0..pages as u64).map(|page| FrameGpa::new(base + page * 4096)),
            0,
            4096,
            owner,
        )?;
        Ok(TestData { inventory, grants })
    }
    fn release(&mut self, mut data: TestData) -> Result<(), TrapError> {
        data.inventory
            .rollback()
            .map_err(|error| fail(error.to_string()))?;
        let call = self.release_calls;
        self.release_calls += 1;
        if self.fail_release.contains(&call) {
            return Err(fail("injected release failure"));
        }
        self.released += 1;
        Ok(())
    }
    fn write(&mut self, data: &TestData, bytes: &[u8]) -> Result<(), TrapError> {
        self.written
            .insert(data.grants.first().unwrap().gpa, bytes.to_vec());
        Ok(())
    }
    fn read(&self, data: &TestData, len: usize) -> Result<Vec<u8>, TrapError> {
        let mut bytes = self.written[&data.grants.first().unwrap().gpa].clone();
        bytes.resize(len, 0);
        Ok(bytes)
    }
    fn clear_tables(&mut self, tables: &[RootGpa]) -> Result<(), TrapError> {
        if self.fail_clear {
            return Err(fail("injected clear failure"));
        }
        self.cleared += tables.len();
        Ok(())
    }
}

struct Fixture {
    region: Region,
    stock: ForkStock<UntaggedRoots>,
    frames: TestFrames,
    preparations: ExecPreparations<X86ExecPreparation<TestData>, X86ExecRequest>,
    receipt: Option<ExecAdoptionReceipt>,
}

/// The ring's exec request of a fork child on this carrier, as its ticket
/// names it.
fn child_identity() -> carrick_core_abi::service::ServiceIdentity {
    use carrick_core_abi::service::{ServiceBirth, ServiceIdentity, ServiceOrigin};
    use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
    ServiceIdentity {
        birth: ServiceBirth {
            origin: ServiceOrigin::Descendant,
            process: TaskKey {
                id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(2).unwrap()),
                serial: TaskSerial::from_registry_allocation(NonZeroU64::MIN),
            },
            thread: EntryThreadGeneration::from_raw(1),
            record: carrick_sched_core::RecordRef {
                id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
                incarnation: 1,
            },
            // SAFETY: a synthetic predecessor identity for this fixture; it
            // authorizes no memory operation.
            mm: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    CARRIER,
                    ReservationMm::new(3).unwrap(),
                    NonZeroU64::MIN,
                )
            },
        },
        execution: SnapshotGeneration::from_raw(1),
        sequence: NonZeroU64::MIN,
    }
}

impl Fixture {
    /// A carrier whose fork stock holds `pages` tables, with the closed,
    /// unadmitted successor root the ring publishes before it asks.
    fn new(pages: u64) -> Self {
        let region = Region::new();
        region.publish_successor(SUCCESSOR);
        let mut stock = ForkStock::new(
            CARRIER,
            ForkControlCapacity::unused(0x1_0000_0000),
            UntaggedRoots,
        );
        stock
            .install(
                (0..pages)
                    .map(|n| RootGpa::page_aligned(FrameGpa::new(0x20_0000 + n * 4096)).unwrap())
                    .collect(),
                carrick_hal::fork_stock::TableReserve::EMPTY,
                vec![
                    ForkLifecycleLoan::new_for_base(
                        EL1_DYNAMIC_METADATA_BASE,
                        KernelVa::new(EL1_DYNAMIC_METADATA_BASE + 0x4000),
                        KernelVa::new(EL1_DYNAMIC_METADATA_BASE + 0x5000),
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
        Self {
            region,
            stock,
            frames: TestFrames::new(),
            preparations: ExecPreparations::default(),
            receipt: None,
        }
    }

    /// The live claimed row, or a new claim reserving its receipt.
    fn claimed(&mut self) -> ExecAdoptionReceipt {
        if let Some(receipt) = self.receipt
            && self.preparations.claim_of(receipt).is_some()
        {
            return receipt;
        }
        let receipt = self
            .preparations
            .claim(
                child_identity(),
                ReservationMm::new(SUCCESSOR).unwrap(),
                ROOT_GENERATION,
            )
            .unwrap()
            .receipt();
        self.receipt = Some(receipt);
        receipt
    }

    fn stage(&mut self, request: X86ExecRequest) -> X86ExecStage {
        self.stage_waking(request, StockReleaseWake::new(|| {}))
    }

    fn stage_waking(&mut self, request: X86ExecRequest, wake: StockReleaseWake) -> X86ExecStage {
        let receipt = self.claimed();
        stage_x86_exec(
            CpuId::new(0),
            receipt,
            request,
            &mut self.preparations,
            &mut self.stock,
            &mut self.frames,
            self.region.tables(),
            wake,
            [9; 16],
        )
        .unwrap()
    }

    fn root(&self) -> SuccessorRoot<'_> {
        SuccessorRoot {
            tables: self.region.tables(),
            successor: ReservationMm::new(SUCCESSOR).unwrap(),
        }
    }

    /// Bytes imported into the still unadmitted successor root.
    fn imported(&self) -> u64 {
        self.root()
            .locked(|model| Ok(model.charges().bytes))
            .unwrap()
    }

    /// Admit the successor root as its adopter does (`prepare_adoption`),
    /// then read the node covering each of `addresses`.
    fn admit_and_read(&self, addresses: &[u64]) -> Vec<Option<Mapping>> {
        let index = self.region.zone().spaces.find(SUCCESSOR).unwrap();
        let release = SpaceReleaseVenue {
            zone: self.region.zone(),
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &|_, _, owned| {
                    let (_, effects) =
                        owned.deliver_handbacks(&mut |_| panic!("no waiter on a closed successor"));
                    assert_eq!(effects, carrick_sched_core::WakeEffects::default());
                },
            ),
        };
        let mut model = X86Cpl0RootReleaseVenue::new(self.region.roots(), release)
            .unwrap()
            .lock(
                index.index(),
                ReservationMm::new(SUCCESSOR).unwrap(),
                &NoRootWait,
            )
            .unwrap();
        model.finish_import().unwrap();
        addresses
            .iter()
            .map(|address| model.node(*address).map(|(mapping, _)| mapping))
            .collect()
    }
}

/// A static ET_EXEC x86-64 ELF: one R+X PT_LOAD from file offset 0 (so it
/// maps its own program headers) at 0x400000, three pages in memory, entry
/// at 0x401000.
fn static_x86_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 0x1004];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&ENTRY.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x40_0000_u64.to_le_bytes());
    elf[ph + 24..ph + 32].copy_from_slice(&0x40_0000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&0x1004_u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x3000_u64.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    // exit_group(0)
    elf[0x1000..0x1004].copy_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    elf
}

fn image(argv: Vec<Vec<u8>>, env: Vec<Vec<u8>>) -> Result<X86ExecImage, LinuxErrno> {
    let bytes = static_x86_elf();
    let program = ElfProgram::load(&bytes, 62, &|_| None).unwrap();
    X86ExecImage::from_program(&program, argv, env)
}

fn request(image: X86ExecImage) -> X86ExecRequest {
    X86ExecRequest {
        image: Box::new(image),
        successor: ReservationMm::new(SUCCESSOR).unwrap(),
        root_generation: ROOT_GENERATION,
    }
}

fn argv() -> Vec<Vec<u8>> {
    vec![b"/bin/successor".to_vec()]
}

/// #1093 S4c slice c: the host Exec service loads a static successor and,
/// before the arm, reserves exactly the tables and data frames the CPL0
/// build takes, imports the image and stack rows into the closed successor
/// root, retains the preparation and answers what the manifest seals.
#[test]
fn exec_service_stages_a_static_successor() {
    let mut fixture = Fixture::new(16);
    let successor_image = image(argv(), vec![b"A=1".to_vec()]).unwrap();
    let demand = successor_image.demand();
    // Three image pages and the sixteen-page built stack; the root, the
    // 512 GiB, 1 GiB and 2 MiB tables of the image and of the stack (which
    // sits in its own 512 GiB slot, above every arena), and the COW copy
    // branch.
    assert_eq!(
        demand,
        ImageFrameDemand {
            tables: 10,
            data: 19
        }
    );
    let expected_sp = build_initial_stack(&InitialStackSpec {
        entry: ENTRY,
        interpreter_base: 0,
        phdr: 0x40_0040,
        phent: 56,
        phnum: 1,
        argv: &[b"/bin/successor"],
        envp: &[b"A=1"],
        random: [0x5a; 16],
        stack_top: INITIAL_STACK_TOP,
        stack_size: INITIAL_STACK_SIZE,
        vdso: None,
    })
    .unwrap()
    .rsp;

    let X86ExecStage::Staged(backing, entry, build) = fixture.stage(request(successor_image))
    else {
        panic!("a static successor with stock to spare stages");
    };
    let successor = ReservationMm::new(SUCCESSOR).unwrap();
    let (_, preparation) = fixture.preparations.staged_for(successor).unwrap();
    assert_eq!(preparation.tables().len(), 10);
    assert_eq!(fixture.stock.table_stock().len(), 16 - 10);
    assert_eq!(
        backing.root,
        preparation.tables()[0],
        "the first table is the root"
    );
    assert_eq!(backing.asid, carrick_guest_arch::Asid::x86_untagged());
    assert_eq!(backing.asid_generation, ROOT_GENERATION);
    assert_eq!(entry.entry.raw(), ENTRY);
    assert_eq!(entry.stack_pointer.raw(), expected_sp);
    assert_eq!(preparation.data().grants().len(), 19);
    // #2235: the build extent the manifest seals is the preparation's own
    // staged frames, encoded with the shared layout.
    assert_eq!(build.base.raw(), preparation.build().grants()[0].gpa);
    let pages = build.pages.get() as usize;
    assert_eq!(preparation.build().grants().len(), pages);
    assert_eq!(
        fixture.frames.written[&build.base.raw()][..8],
        carrick_el1::isa::x86_exec_build::X86_EXEC_BUILD_MAGIC.to_le_bytes()
    );
    assert_eq!(fixture.frames.mapped(), 19 + pages);

    // The image pages and the whole stack reservation are imported, not
    // admitted: the adopter finishes the import.
    assert_eq!(fixture.imported(), 0x3000 + INITIAL_STACK_RESERVATION);

    // An unused preparation returns whole.
    let receipt = fixture.receipt.unwrap();
    let ExecRetained::Staged(preparation) = fixture
        .preparations
        .retire(receipt, ExecRetireReason::Refused)
        .unwrap()
        .held
    else {
        panic!("the staged row holds its preparation");
    };
    release_x86_exec(
        preparation,
        &mut fixture.stock,
        &mut fixture.frames,
        fixture.region.tables(),
    )
    .unwrap();
    assert_eq!(fixture.stock.table_stock().len(), 16);
    assert_eq!(fixture.frames.released, 2, "data frames and build extent");
    assert_eq!(fixture.frames.mapped(), 0);
    assert_eq!(fixture.imported(), 0);

    // Staged again, the rows admit as boot's do: the image root-editable
    // private memory, the built stack the carrier's, the rest growable.
    let again = image(argv(), vec![b"A=1".to_vec()]).unwrap();
    assert!(matches!(
        fixture.stage(request(again)),
        X86ExecStage::Staged(..)
    ));
    let [text, built, grown] = fixture
        .admit_and_read(&[
            0x40_0000,
            INITIAL_STACK_TOP - 8,
            INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION,
        ])
        .try_into()
        .unwrap();
    let text = text.expect("image row");
    assert_eq!(
        text.range,
        ReservationRange::new(0x40_0000, 0x40_3000).unwrap()
    );
    assert_eq!(text.protection.bits(), 0b101);
    assert_eq!(
        text.flags,
        ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::IMAGE)
    );
    assert_eq!(
        built.expect("built stack row").flags,
        ReservationNodeFlags::PRIVATE.union(ReservationNodeFlags::GROWSDOWN)
    );
    assert_eq!(
        grown.expect("growable stack row").flags,
        ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::GROWSDOWN)
    );
}

/// execve(2): E2BIG (7) when argv and envp exceed Linux's charge, checked
/// before the image as Linux does; ENOEXEC (8) for an image the x86 build
/// cannot map. Arguments Linux accepts but the built stack cannot hold are
/// a carrier limit, left unrouted (38), never a false E2BIG.
#[test]
fn exec_service_refuses_with_exact_execve_errnos() {
    let errno = |result: Result<X86ExecImage, LinuxErrno>| result.unwrap_err().get();
    let at_limit = vec![b'a'; carrick_core_abi::service::MAX_ARG_STRLEN];
    assert_eq!(errno(image(vec![at_limit], vec![])), 7, "MAX_ARG_STRLEN");
    let many = vec![vec![b'e'; 128 * 1024 - 1]; 17];
    assert_eq!(errno(image(argv(), many.clone())), 7, "ARG_MAX");

    let elf = static_x86_elf();
    let mut arm = elf.clone();
    arm[18..20].copy_from_slice(&183_u16.to_le_bytes());
    let arm = ElfProgram::load(&arm, 183, &|_| None).unwrap();
    assert_eq!(
        errno(X86ExecImage::from_program(&arm, argv(), vec![])),
        8,
        "another machine's image"
    );
    assert_eq!(
        errno(X86ExecImage::from_program(&arm, argv(), many)),
        7,
        "E2BIG before ENOEXEC"
    );
    // Program headers outside every PT_LOAD: the editor cannot hand the
    // successor AT_PHDR.
    let mut unmapped = elf;
    unmapped[64 + 8..64 + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    unmapped[64 + 16..64 + 24].copy_from_slice(&0x40_1000_u64.to_le_bytes());
    unmapped[64 + 24..64 + 32].copy_from_slice(&0x40_1000_u64.to_le_bytes());
    unmapped[64 + 32..64 + 40].copy_from_slice(&4_u64.to_le_bytes());
    let unmapped = ElfProgram::load(&unmapped, 62, &|_| None).unwrap();
    assert_eq!(
        errno(X86ExecImage::from_program(&unmapped, argv(), vec![])),
        8,
        "unmapped program headers"
    );

    let past_stack = vec![vec![b's'; 32 * 1024]; 3];
    assert_eq!(errno(image(argv(), past_stack)), 38);
}

/// The contract's own shape, "Busy once, then success": a pending fork
/// holds the stock the successor needs, so the exec parks with nothing
/// reserved, no errno and its wake enrolled on the stock's release. The
/// fork's abort, on another thread, delivers that wake; nothing probes the
/// parked exec until it is woken, then one probe hands the operation back
/// and the rerun stages it.
#[test]
fn a_pending_fork_parks_the_exec_until_its_release_wakes_it_then_stages() {
    let mut fixture = Fixture::new(11);
    let parent = GrantExecution::new(
        CpuId::new(1),
        ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(301),
            thread_generation: EntryThreadGeneration::from_raw(101),
        },
        AddressContext {
            mm: MmGeneration::new(NonZeroU64::new(301).unwrap()),
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        },
    );
    let mut exchange = ForkStockExchange::new(ForkStockRequest {
        binding: parent.binding,
        context: parent.context,
        operation: PortalOperation {
            carrier: CARRIER,
            mm: ReservationMm::new(301).unwrap(),
            incarnation: NonZeroU64::MIN,
            sequence: NonZeroU64::new(2).unwrap(),
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_mm: ReservationMm::new(302).unwrap(),
        child_bytes: 2 * 4096,
        parent_bytes: 4096,
    })
    .unwrap();
    let fork: ForkStockLoan = fixture
        .stock
        .loan(&mut NoTableLedger, parent, &mut exchange, |_| true)
        .unwrap();
    assert_eq!(fixture.stock.table_stock().len(), 8);

    // The carrier's owner parks the claimed row on the stock's release: the
    // row keeps the receipt reserved at claim.
    let receipt = fixture.claimed();
    let (woken, wake) = ExecParkWake::new();
    let X86ExecStage::Parked(parked) =
        fixture.stage_waking(request(image(argv(), vec![]).unwrap()), wake)
    else {
        panic!("the fork holds the tables: not now");
    };
    fixture.preparations.park(receipt, parked, woken).unwrap();
    // Nothing is reserved while the exec waits.
    assert_eq!(fixture.stock.table_stock().len(), 8);
    assert_eq!(fixture.stock.counters().successor_table_refusals, 1);
    assert!(fixture.preparations.staged(receipt).is_none());
    assert_eq!(fixture.preparations.parked(), vec![receipt]);
    assert_eq!(fixture.frames.mapped(), 0);
    assert_eq!(fixture.imported(), 0, "the import was aborted");
    assert_eq!(
        fixture.stock.release_waiters(),
        1,
        "enrolled on the holder's release"
    );
    let never_cancelled = |_: &X86ExecRequest| Ok::<_, ()>(false);
    assert!(matches!(
        fixture
            .preparations
            .probe_parked(receipt, &fixture.stock, never_cancelled)
            .unwrap(),
        ParkedProbe::Still
    ));

    let stock = &mut fixture.stock;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let mut abort = ForkStockSettlement::abort(fork);
            stock
                .settle(
                    &mut NoTableLedger,
                    parent,
                    &mut abort,
                    |_| true,
                    |_| true,
                    |_| true,
                )
                .unwrap();
        });
    });
    assert_eq!(fixture.stock.release_waiters(), 0, "woken once");
    let ParkedProbe::Rerun(claim, rerun) = fixture
        .preparations
        .probe_parked(receipt, &fixture.stock, never_cancelled)
        .unwrap()
    else {
        panic!("the fork's abort reruns the parked exec");
    };
    assert_eq!(claim.receipt(), receipt);
    let X86ExecStage::Staged(backing, _, _) = fixture.stage(rerun) else {
        panic!("the released stock grants the rerun");
    };
    let successor = ReservationMm::new(SUCCESSOR).unwrap();
    assert_eq!(
        backing.root,
        fixture.preparations.staged(receipt).unwrap().tables()[0]
    );
    assert_eq!(fixture.stock.table_stock().len(), 1);
    // The seal reuses the receipt reserved before the park.
    assert_eq!(
        fixture.preparations.seal(receipt).unwrap().receipt(),
        receipt
    );
    assert_eq!(
        fixture
            .preparations
            .staged_for(successor)
            .unwrap()
            .0
            .receipt(),
        receipt
    );
    let census = fixture.preparations.census();
    assert_eq!(
        (census.reserved, census.parked, census.reruns, census.sealed),
        (1, 1, 1, 1)
    );
    assert_eq!(fixture.stock.counters().successor_table_refusals, 1);
}

/// #2826: the carrier's exit drain is the last chance any row has, so one
/// row's failed release must not keep the rows after it. Two staged rows are
/// live at the exit, a sealed one (returned as a ring cancellation) and an
/// unsealed one (returned as a refusal); the sealed row's build extent
/// reports a failed release. The drain still returns the unsealed row's
/// tables, data frames and build extent, and its result is that first
/// failure. The fork stock and the frame inventory end at their baseline.
#[test]
fn the_carrier_exit_drain_releases_every_row_and_reports_the_first_failure() {
    const SECOND: u64 = 13;
    let mut fixture = Fixture::new(32);
    assert!(matches!(
        fixture.stage(request(image(argv(), vec![]).unwrap())),
        X86ExecStage::Staged(..)
    ));
    let sealed = fixture.receipt.unwrap();
    fixture.preparations.seal(sealed).unwrap();

    fixture.region.publish_successor(SECOND);
    let second = ReservationMm::new(SECOND).unwrap();
    let unsealed = fixture
        .preparations
        .claim(child_identity(), second, ROOT_GENERATION)
        .unwrap()
        .receipt();
    assert!(unsealed.raw() > sealed.raw(), "the sealed row drains first");
    let staged = stage_x86_exec(
        CpuId::new(0),
        unsealed,
        X86ExecRequest {
            image: Box::new(image(argv(), vec![]).unwrap()),
            successor: second,
            root_generation: ROOT_GENERATION,
        },
        &mut fixture.preparations,
        &mut fixture.stock,
        &mut fixture.frames,
        fixture.region.tables(),
        StockReleaseWake::new(|| {}),
        [9; 16],
    )
    .unwrap();
    assert!(matches!(staged, X86ExecStage::Staged(..)));
    assert_eq!(fixture.stock.table_stock().len(), 32 - 2 * 10);
    assert_ne!(fixture.frames.mapped(), 0);

    // The sealed row's second release, its build extent, reports a failure.
    fixture.frames.fail_release = vec![1];
    let error = drain_at_carrier_exit(&mut fixture).unwrap_err();
    assert!(
        format!("{error:?}").contains("injected release failure"),
        "the drain reports the first failure: {error:?}"
    );
    assert_eq!(
        fixture.frames.release_calls, 4,
        "both rows' data frames and build extents were released"
    );
    assert_eq!(fixture.frames.released, 3, "all but the injected failure");
    assert_eq!(fixture.frames.cleared, 10, "the sealed row's tables");
    assert_eq!(
        fixture.stock.table_stock().len(),
        32,
        "the stock's baseline"
    );
    assert_eq!(fixture.frames.mapped(), 0, "the inventory's baseline");
    assert_eq!(fixture.preparations.census().carrier_exit, 2);
    assert_eq!(fixture.preparations.census().unretired(), 0);
}

/// Stage one row on `fixture` and leave it live for the carrier's exit,
/// sealed (a ring cancellation returns it) or not (a refusal does).
fn one_row_at_carrier_exit(fixture: &mut Fixture, sealed: bool) {
    assert!(matches!(
        fixture.stage(request(image(argv(), vec![]).unwrap())),
        X86ExecStage::Staged(..)
    ));
    if sealed {
        fixture.preparations.seal(fixture.receipt.unwrap()).unwrap();
    }
    assert_eq!(fixture.stock.table_stock().len(), 32 - 10);
    assert_ne!(fixture.frames.mapped(), 0);
}

fn drain_at_carrier_exit(fixture: &mut Fixture) -> Result<usize, TrapError> {
    release_x86_execs_at_carrier_exit(
        Ok(fixture.region.tables()),
        &mut fixture.preparations,
        &mut fixture.stock,
        &mut fixture.frames,
    )
}

/// #2826 (review of #2868): the exec tables resolve before the drain retires
/// a row. A carrier whose tables are missing reports that, and keeps its
/// rows: none is retired, so the owner's census still names it, and what it
/// holds stays out of the stock. A later drain with the tables returns it.
#[test]
fn a_drain_without_exec_tables_keeps_its_rows_unretired() {
    for sealed in [true, false] {
        let mut fixture = Fixture::new(32);
        one_row_at_carrier_exit(&mut fixture, sealed);
        let error = release_x86_execs_at_carrier_exit(
            Err(fail("exec reservation table")),
            &mut fixture.preparations,
            &mut fixture.stock,
            &mut fixture.frames,
        )
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("exec reservation table"),
            "sealed={sealed}: the drain reports the missing tables: {error:?}"
        );
        let census = fixture.preparations.census();
        assert_eq!(census.carrier_exit, 0, "sealed={sealed}: nothing retired");
        assert_eq!(census.unretired(), 1, "sealed={sealed}: the row is kept");
        assert_eq!(fixture.frames.release_calls, 0, "sealed={sealed}");
        assert_eq!(
            fixture.stock.table_stock().len(),
            32 - 10,
            "sealed={sealed}"
        );

        assert_eq!(drain_at_carrier_exit(&mut fixture).unwrap(), 1);
        assert_eq!(fixture.preparations.census().unretired(), 0);
        assert_eq!(fixture.frames.mapped(), 0, "sealed={sealed}");
        assert_eq!(fixture.stock.table_stock().len(), 32, "sealed={sealed}");
    }
}

/// #2826 (review of #2868): a step that fails inside one row must not keep
/// that row's later steps either, since the drain is the row's last chance.
/// A sealed and an unsealed row each report their data frames' release
/// failed; each still returns its build extent and its tables, and the
/// failure is the drain's result.
#[test]
fn a_row_whose_data_release_fails_still_returns_its_build_extent_and_tables() {
    for sealed in [true, false] {
        let mut fixture = Fixture::new(32);
        one_row_at_carrier_exit(&mut fixture, sealed);
        fixture.frames.fail_release = vec![0];
        let error = drain_at_carrier_exit(&mut fixture).unwrap_err();
        assert!(
            format!("{error:?}").contains("injected release failure"),
            "sealed={sealed}: the drain reports the failure: {error:?}"
        );
        assert_eq!(
            fixture.frames.release_calls, 2,
            "sealed={sealed}: the build extent was released after the data failed"
        );
        assert_eq!(
            fixture.frames.mapped(),
            0,
            "sealed={sealed}: inventory baseline"
        );
        assert_eq!(
            fixture.stock.table_stock().len(),
            32,
            "sealed={sealed}: stock baseline"
        );
        assert_eq!(fixture.preparations.census().unretired(), 0);
    }
}

/// A sealed row whose tables fail to clear still returns its data frames and
/// build extent. Its tables stay out of the stock, whose pages must be zero:
/// a build may have written them.
#[test]
fn a_sealed_row_whose_tables_fail_to_clear_returns_its_frames_but_withholds_its_tables() {
    let mut fixture = Fixture::new(32);
    one_row_at_carrier_exit(&mut fixture, true);
    fixture.frames.fail_clear = true;
    let error = drain_at_carrier_exit(&mut fixture).unwrap_err();
    assert!(
        format!("{error:?}").contains("injected clear failure"),
        "the drain reports the clear failure: {error:?}"
    );
    assert_eq!(
        fixture.frames.release_calls, 2,
        "data frames and build extent"
    );
    assert_eq!(fixture.frames.released, 2);
    assert_eq!(fixture.frames.mapped(), 0, "the inventory's baseline");
    assert_eq!(
        fixture.stock.table_stock().len(),
        32 - 10,
        "uncleared tables never return to the stock"
    );
}

/// Every failure counts: the drain's result is the first failure, and names
/// how many steps failed after it.
#[test]
fn the_carrier_exit_drain_counts_the_failures_after_the_first() {
    let mut fixture = Fixture::new(32);
    one_row_at_carrier_exit(&mut fixture, true);
    fixture.frames.fail_release = vec![0, 1];
    let error = drain_at_carrier_exit(&mut fixture).unwrap_err();
    let text = format!("{error}");
    assert!(
        text.contains("injected release failure") && text.contains("1 more"),
        "the first failure, and the count after it: {text}"
    );
}

/// #3017 review P0-1: when no returnable custody holds tables, exec staging
/// refuses immediately with ENOMEM instead of parking forever; and when an
/// in-flight fork holds the tables and commits 100% of them, the parked exec
/// wakes once and reruns to ENOMEM.
#[test]
fn terminal_table_exhaustion_refuses_exec_with_enomem_and_committed_fork_wakes_parked_exec() {
    let mut fixture = Fixture::new(8);
    let _ = fixture.claimed();
    let (_, wake) = ExecParkWake::new();
    assert!(
        matches!(
            fixture.stage_waking(request(image(argv(), vec![]).unwrap()), wake),
            X86ExecStage::Refused(errno) if errno.get() == 12
        ),
        "zero returnable tables answers ENOMEM without parking"
    );
    assert_eq!(fixture.stock.release_waiters(), 0);
    assert_eq!(fixture.imported(), 0);

    // Now install 11 tables, hold 3 in a pending fork loan, park exec, and
    // commit 100% of the fork's tables so zero pages return.
    let mut fixture = Fixture::new(11);
    let parent = GrantExecution::new(
        CpuId::new(1),
        ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(301),
            thread_generation: EntryThreadGeneration::from_raw(101),
        },
        AddressContext {
            mm: MmGeneration::new(NonZeroU64::new(301).unwrap()),
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        },
    );
    let mut exchange = ForkStockExchange::new(ForkStockRequest {
        binding: parent.binding,
        context: parent.context,
        operation: PortalOperation {
            carrier: CARRIER,
            mm: ReservationMm::new(301).unwrap(),
            incarnation: NonZeroU64::MIN,
            sequence: NonZeroU64::new(2).unwrap(),
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_mm: ReservationMm::new(302).unwrap(),
        child_bytes: 2 * 4096,
        parent_bytes: 4096,
    })
    .unwrap();
    let fork: ForkStockLoan = fixture
        .stock
        .loan(&mut NoTableLedger, parent, &mut exchange, |_| true)
        .unwrap();
    let receipt = fixture.claimed();
    let (woken, wake) = ExecParkWake::new();
    let X86ExecStage::Parked(parked) =
        fixture.stage_waking(request(image(argv(), vec![]).unwrap()), wake)
    else {
        panic!("pending fork holds returnable tables: not now");
    };
    fixture.preparations.park(receipt, parked, woken).unwrap();
    assert_eq!(fixture.stock.release_waiters(), 1);

    // Commit 100% of the fork's tables (2 child, 1 parent): zero unused pages
    // return, yet returnable_tables drops to 0 and wakes the parked exec.
    let child_handle = unsafe {
        carrick_el1_abi::El1MmHandle::from_admitted_owner(
            CARRIER,
            ReservationMm::new(302).unwrap(),
            NonZeroU64::MIN,
        )
    };
    let completion = carrick_el1_abi::PortalForkCompletion {
        request: fork.request,
        child: child_handle,
        parent_generation: ReservationGeneration::new(2).unwrap(),
        child_tables_used: 2 * 4096,
        parent_tables_used: 4096,
    };
    let mut reserve =
        ForkStockSettlement::reserve(fork, completion, carrick_guest_arch::KernelVa::new(0), 0)
            .unwrap();
    fixture
        .stock
        .reserve_custody(parent, &mut reserve, |_| true, |_| true, |_, _, _| Ok(()))
        .unwrap();
    let mut commit_settlement = ForkStockSettlement::commit_reserved(fork, completion).unwrap();
    fixture
        .stock
        .settle(
            &mut NoTableLedger,
            parent,
            &mut commit_settlement,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert_eq!(fixture.stock.returnable_tables(), 0);
    assert_eq!(fixture.stock.release_waiters(), 0, "woken on exhaustion");
    let ParkedProbe::Rerun(_claim, rerun) = fixture
        .preparations
        .probe_parked(receipt, &fixture.stock, |_: &X86ExecRequest| {
            Ok::<_, ()>(false)
        })
        .unwrap()
    else {
        panic!("100%-committed fork wakes parked exec to rerun");
    };
    assert!(matches!(
        fixture.stage(rerun),
        X86ExecStage::Refused(errno) if errno.get() == 12
    ));
}
