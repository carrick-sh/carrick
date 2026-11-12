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
struct Region {
    ptr: NonNull<u8>,
    layout: std::alloc::Layout,
}

impl Region {
    fn new() -> Self {
        let layout =
            std::alloc::Layout::from_size_align(carrick_el1_abi::EL1_REGION_SIZE as usize, 64)
                .unwrap();
        // SAFETY: a nonzero layout; the region frees it on drop.
        let ptr = NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).unwrap();
        Self { ptr, layout }
    }
    fn zone(&self) -> &X86Cpl0Zone {
        // SAFETY: the retained aligned region owns the zero-valid zone at its
        // real CPL0 offset for the fixture's life.
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize)
                .cast()
        }
    }
    fn roots(&self) -> &X86Cpl0Reservations {
        // SAFETY: as for `zone`.
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                .cast()
        }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with exactly this layout.
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// The carrier frames, staged under the production inventory transaction
/// against a real frame inventory; only the GPA allocator is the fixture's.
struct TestFrames {
    authority: Arc<FrameInventoryAuthority>,
    inventory: Arc<dyn PhysicalFrameInventory>,
    next: u64,
    released: usize,
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
        self.released += 1;
        Ok(())
    }
}

struct Fixture {
    region: Region,
    stock: ForkStock<UntaggedRoots>,
    frames: TestFrames,
    preparations: X86ExecPreparations<TestData>,
}

impl Fixture {
    /// A carrier whose fork stock holds `pages` tables, with the closed,
    /// unadmitted successor root the ring publishes before it asks.
    fn new(pages: u64) -> Self {
        let region = Region::new();
        let mm = ReservationMm::new(SUCCESSOR).unwrap();
        let index = region
            .zone()
            .spaces
            .publish_closed(SUCCESSOR, 0, 0)
            .unwrap();
        region
            .roots()
            .publish(
                index.index(),
                mm,
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
            preparations: X86ExecPreparations::default(),
        }
    }

    fn stage(&mut self, request: X86ExecRequest) -> X86ExecStage {
        stage_x86_exec(
            CpuId::new(0),
            request,
            &mut self.preparations,
            &mut self.stock,
            &mut self.frames,
            self.region.roots(),
            self.region.zone(),
        )
        .unwrap()
    }

    fn root(&self) -> SuccessorRoot<'_> {
        SuccessorRoot {
            roots: self.region.roots(),
            zone: self.region.zone(),
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
        image,
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
    // Three image pages and the sixteen-page built stack; the root, one
    // 512 GiB table, the 1 GiB tables of the image and the stack, their
    // 2 MiB tables, and the COW copy branch.
    assert_eq!(
        demand,
        ImageFrameDemand {
            tables: 9,
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
    })
    .unwrap()
    .rsp;

    let X86ExecStage::Staged(backing, entry) = fixture.stage(request(successor_image)) else {
        panic!("a static successor with stock to spare stages");
    };
    let successor = ReservationMm::new(SUCCESSOR).unwrap();
    let preparation = fixture.preparations.get(successor).unwrap();
    assert_eq!(preparation.tables().len(), 9);
    assert_eq!(fixture.stock.table_stock().len(), 16 - 9);
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
    assert_eq!(fixture.frames.mapped(), 19);

    // The image pages and the whole stack reservation are imported, not
    // admitted: the adopter finishes the import.
    assert_eq!(fixture.imported(), 0x3000 + INITIAL_STACK_RESERVATION);

    // An unused preparation returns whole.
    let preparation = fixture.preparations.take(successor).unwrap();
    release_x86_exec(
        preparation,
        &mut fixture.stock,
        &mut fixture.frames,
        fixture.region.roots(),
        fixture.region.zone(),
    )
    .unwrap();
    assert_eq!(fixture.stock.table_stock().len(), 16);
    assert_eq!(fixture.frames.released, 1);
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
/// reserved and no errno; the fork's abort is the release it enrolled on,
/// one probe hands the operation back, and the rerun stages it.
#[test]
fn a_pending_fork_parks_the_exec_until_its_release_then_stages() {
    let mut fixture = Fixture::new(10);
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
    assert_eq!(fixture.stock.table_stock().len(), 7);

    let X86ExecStage::Parked(parked) = fixture.stage(request(image(argv(), vec![]).unwrap()))
    else {
        panic!("the fork holds the tables: not now");
    };
    // Nothing is reserved while the exec waits.
    assert_eq!(fixture.stock.table_stock().len(), 7);
    assert_eq!(fixture.stock.counters().successor_table_refusals, 1);
    assert!(fixture.preparations.is_empty());
    assert_eq!(fixture.frames.mapped(), 0);
    assert_eq!(fixture.imported(), 0, "the import was aborted");
    // Probed before the holder releases: still parked.
    let parked = parked.probe(&fixture.stock).unwrap_err();

    let mut abort = ForkStockSettlement::abort(fork);
    fixture
        .stock
        .settle(
            &mut NoTableLedger,
            parent,
            &mut abort,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    let rerun = parked.probe(&fixture.stock).unwrap();
    let X86ExecStage::Staged(backing, _) = fixture.stage(rerun) else {
        panic!("the released stock grants the rerun");
    };
    let successor = ReservationMm::new(SUCCESSOR).unwrap();
    assert_eq!(
        backing.root,
        fixture.preparations.get(successor).unwrap().tables()[0]
    );
    assert_eq!(fixture.stock.table_stock().len(), 1);
    assert_eq!(fixture.stock.counters().successor_table_refusals, 1);
}
