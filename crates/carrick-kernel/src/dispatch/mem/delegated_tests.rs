//! S1b: an MM whose shared EL1 reservation root is admitted has ONE owner for
//! anonymous-private placement and VMA facts: the root. Host-forwarded
//! `mmap`/`munmap`/`mprotect` and a guest-venue edit applied to the root are
//! the same authority; file, shared and attributed mappings are opaque root
//! nodes (placement obstacles) whose rows the host keeps.

use super::tests::{CountingMmapMemory, install_host_file_fd, returned};
use super::*;
use crate::dispatch::mem::el1_reservations::{HostReservationProvider, PreparedHostReservations};
use crate::linux_abi::LINUX_PAGE_SIZE;
use crate::memory::LINUX_MMAP_BASE;
use carrick_el1::memory::reservations::{
    Decision, Layout, Placement, Refusal, Reservations, SharedReservations,
};
use carrick_el1_abi::{
    ReservationBackingReceipt, ReservationCompletion, ReservationMm, ReservationProtection,
    ReservationRange,
};

const SYS_BRK: u64 = 214;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const SYS_MPROTECT: u64 = 226;
const PAGE: u64 = LINUX_PAGE_SIZE;
const FILE_FD: i32 = 40;

pub(in crate::dispatch) struct Root {
    table: Arc<SharedReservations>,
    pub(in crate::dispatch) mm: ReservationMm,
}

struct View(Arc<SharedReservations>, ReservationMm);
impl PreparedHostReservations for View {
    fn lock(&self, mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
        if mm != self.1 {
            return Err(Refusal::Stale);
        }
        self.0.lock(0, mm)
    }
}
struct Provider(Arc<SharedReservations>, ReservationMm);
impl HostReservationProvider for Provider {
    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
        Ok(Box::new(View(Arc::clone(&self.0), self.1)))
    }
}

/// Mock substrate: this VM-free fixture has no descriptors or frames.
fn commit(root: &mut Reservations<'_>, decision: Decision) -> u64 {
    match decision {
        Decision::Complete(value) => value,
        Decision::Work(request) => {
            let completion = unsafe {
                ReservationCompletion::after_descriptor_and_backing_commit(
                    request,
                    ReservationBackingReceipt {
                        receipt: 1,
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
            }
            .unwrap();
            root.complete(completion).unwrap()
        }
    }
}

impl Root {
    /// Publish this dispatcher MM's root, install the carrier provider and
    /// delegate its anonymous memory (the conformance-fixture admission).
    pub(in crate::dispatch) fn admit(dispatcher: &SyscallDispatcher) -> Self {
        // Same zeroed-region initialization as EL1 bootstrap.
        let ptr =
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        let table: Arc<SharedReservations> =
            Arc::from(unsafe { Box::<SharedReservations>::from_raw(ptr.cast()) });
        let mm = ReservationMm::new(dispatcher.mm_authority().mm_id.raw()).unwrap();
        let layout = dispatcher.mem().lock().layout;
        table
            .publish(
                0,
                mm,
                Layout {
                    heap: ReservationRange::new(
                        layout.heap_base,
                        layout.heap_base + layout.heap_size,
                    )
                    .unwrap(),
                    arena: ReservationRange::new(
                        layout.mmap_base,
                        layout.mmap_base + layout.mmap_size,
                    )
                    .unwrap(),
                    brk: layout.heap_base,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        dispatcher
            .install_reservation_provider(Arc::new(Provider(Arc::clone(&table), mm)))
            .unwrap();
        dispatcher.mem_view().delegate_anonymous_for_test().unwrap();
        Self { table, mm }
    }

    pub(in crate::dispatch) fn lock(&self) -> Reservations<'_> {
        self.table.lock(0, self.mm).unwrap()
    }

    /// What guest EL1 does for `brk` on its own venue.
    pub(in crate::dispatch) fn guest_brk(&self, requested: u64) -> u64 {
        let mut root = self.lock();
        let decision = root.brk(requested).unwrap();
        commit(&mut root, decision)
    }

    /// What guest EL1 does for an anonymous private `mmap` on its own venue.
    fn guest_mmap(
        &self,
        placement: Placement,
        len: u64,
        prot: ReservationProtection,
    ) -> Result<u64, Refusal> {
        let mut root = self.lock();
        let decision = root.mmap(placement, len, prot)?;
        Ok(commit(&mut root, decision))
    }

    /// What guest EL1 does for `mprotect` of anonymous memory on its own venue.
    fn guest_mprotect(&self, start: u64, len: u64, prot: ReservationProtection) {
        let mut root = self.lock();
        let decision = root
            .mprotect(ReservationRange::new(start, start + len).unwrap(), prot)
            .unwrap();
        commit(&mut root, decision);
    }
}

fn call(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    number: u64,
    args: [u64; 6],
) -> DispatchOutcome {
    dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(number, SyscallArgs(args)),
            memory,
            &CompatReporter::default(),
        )
        .expect("memory syscall dispatch")
}

fn host_mmap(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    address: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i32,
) -> DispatchOutcome {
    call(
        dispatcher,
        memory,
        SYS_MMAP,
        [address, len, prot, flags, fd as i64 as u64, 0],
    )
}

fn arena_memory() -> CountingMmapMemory {
    CountingMmapMemory::new(LINUX_MMAP_BASE, (32 * PAGE) as usize)
}

const READ: ReservationProtection = match ReservationProtection::from_bits(1) {
    Some(prot) => prot,
    None => panic!(),
};

/// The /proc/<pid>/maps rows the dispatcher projects for this MM.
fn proc_rows(dispatcher: &SyscallDispatcher) -> Vec<ProcMapsEntry> {
    let context = dispatcher.capture_one_task_context().unwrap();
    let mut rows = dispatcher
        .synthetic_proc_context(&context)
        .address_space_regions
        .unwrap_or_default();
    rows.sort_by_key(|row| row.start);
    rows
}

fn proc_row_at(dispatcher: &SyscallDispatcher, address: u64) -> Option<ProcMapsEntry> {
    proc_rows(dispatcher)
        .into_iter()
        .find(|row| row.start <= address && address < row.end)
}

#[test]
fn delegated_el1_mmap_then_host_file_mmap_anywhere_never_overlap() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
    let mut memory = arena_memory();

    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        0,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE,
        FILE_FD,
    )) as u64;
    assert!(
        file + PAGE <= guest || guest + 2 * PAGE <= file,
        "host file mapping {file:#x} overlaps the EL1 reservation {guest:#x}+2 pages"
    );
    let obstacle = root
        .lock()
        .mapping(file)
        .expect("the host file mapping is a root placement obstacle");
    assert!(!obstacle.anonymous);
    // The guest venue now places around it as well.
    let next = root
        .guest_mmap(Placement::Anywhere, PAGE, ReservationProtection::READ_WRITE)
        .unwrap();
    assert!(next + PAGE <= file || file + PAGE <= next);
}

#[test]
fn delegated_host_map_fixed_over_an_el1_reservation_replaces_it() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();

    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            3 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    // mmap(2) MAP_FIXED: "any overlapped part of the existing mapping(s)
    // will be discarded"; the new mapping has the new protection.
    let fixed = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        guest + PAGE,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
        -1,
    )) as u64;
    assert_eq!(fixed, guest + PAGE);
    let mut view = root.lock();
    let middle = view.mapping(guest + PAGE).expect("replacement mapping");
    assert_eq!(middle.protection, READ);
    assert_eq!(
        middle.range,
        ReservationRange::new(guest + PAGE, guest + 2 * PAGE).unwrap()
    );
    for outer in [guest, guest + 2 * PAGE] {
        let kept = view.mapping(outer).expect("untouched neighbour");
        assert_eq!(kept.protection, ReservationProtection::READ_WRITE);
        assert!(kept.anonymous);
    }
    drop(view);
    // No second owner: the host holds no anonymous row for the range.
    assert!(
        !dispatcher
            .mem()
            .lock()
            .semantic_vmas
            .iter()
            .any(|vma| vma.start < guest + 3 * PAGE
                && guest < vma.end
                && vma.provenance.is_private_anonymous()),
        "the root, not MemState, owns the anonymous rows"
    );
}

#[test]
fn delegated_munmap_of_mixed_opaque_and_anonymous_retires_both() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
    let mut memory = arena_memory();

    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        guest + 2 * PAGE,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
        FILE_FD,
    )) as u64;
    assert_eq!(file, guest + 2 * PAGE);
    assert!(root.lock().mapping(file).is_some_and(|m| !m.anonymous));

    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MUNMAP,
            [guest, 3 * PAGE, 0, 0, 0, 0],
        )),
        0
    );
    let mut view = root.lock();
    for page in 0..3 {
        assert!(
            view.mapping(guest + page * PAGE).is_none(),
            "page {page} of the mixed munmap survived in the root"
        );
    }
    drop(view);
    assert!(
        proc_rows(&dispatcher)
            .iter()
            .all(|row| row.end <= guest || guest + 3 * PAGE <= row.start),
        "no /proc row may survive the munmap: {:?}",
        proc_rows(&dispatcher)
    );
    // The retired range is placeable again by the guest venue.
    assert_eq!(
        root.guest_mmap(
            Placement::Fixed(guest),
            3 * PAGE,
            ReservationProtection::READ_WRITE
        ),
        Ok(guest)
    );
}

#[test]
fn delegated_mprotect_is_visible_to_proc_maps_from_the_root() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();

    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            3 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let row = proc_row_at(&dispatcher, guest).expect("the EL1 mapping is a /proc row");
    assert!(row.read && row.write && !row.execute);

    // Host-forwarded mprotect edits the root.
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MPROTECT,
            [guest, PAGE, LINUX_PROT_READ, 0, 0, 0],
        )),
        0
    );
    assert_eq!(root.lock().mapping(guest).unwrap().protection, READ);
    let row = proc_row_at(&dispatcher, guest).unwrap();
    assert!(row.read && !row.write, "host mprotect is visible: {row:?}");
    assert_eq!((row.start, row.end), (guest, guest + PAGE));

    // An EL1-served mprotect (guest venue) is visible from the same
    // authority, with no MemState update at all.
    root.guest_mprotect(guest + 2 * PAGE, PAGE, ReservationProtection::NONE);
    let row = proc_row_at(&dispatcher, guest + 2 * PAGE).unwrap();
    assert!(!row.read && !row.write && !row.execute, "{row:?}");
    let middle = proc_row_at(&dispatcher, guest + PAGE).unwrap();
    assert!(middle.read && middle.write);
}

#[test]
fn delegated_rlimit_as_counts_every_mapping_exactly_once() {
    let mut dispatcher = SyscallDispatcher::new();
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; 2 * PAGE as usize]);
    let mut memory = arena_memory();
    // A host-owned file mapping made before admission: an opaque root node.
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        0,
        2 * PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE,
        FILE_FD,
    )) as u64;
    let root = Root::admit(&dispatcher);
    assert!(root.lock().mapping(file).is_some_and(|m| !m.anonymous));

    let context = dispatcher.capture_one_task_context().unwrap();
    let committed = committed_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                committed + PAGE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_AS");

    let heap = dispatcher.mem().lock().layout.heap_base;
    let mut heap_memory = CountingMmapMemory::new(heap, (4 * PAGE) as usize);
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut heap_memory,
            SYS_BRK,
            [heap + PAGE, 0, 0, 0, 0, 0],
        )) as u64,
        heap + PAGE,
        "one page of headroom: the file mapping must not be charged twice"
    );
    assert_eq!(
        root.guest_mmap(Placement::Anywhere, PAGE, ReservationProtection::READ_WRITE),
        Err(Refusal::Limit),
        "the root then has no headroom left"
    );
    assert_eq!(
        host_mmap(
            &mut dispatcher,
            &mut memory,
            0,
            PAGE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
            -1,
        ),
        DispatchOutcome::errno(LINUX_ENOMEM)
    );
}

#[test]
fn delegated_fork_child_owns_the_parents_rows_in_host_setup() {
    let dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let first = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let gap = first + 2 * PAGE;
    let second = root
        .guest_mmap(
            Placement::Fixed(gap + PAGE),
            PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();

    let child_mm = crate::kernel::MmId::from_registry_allocation(
        std::num::NonZeroU64::new(root.mm.raw() + 1).unwrap(),
    );
    let child = dispatcher.mm_authority().fork_private(child_mm);
    let arena = child
        .lock()
        .host_arena()
        .expect("a fork child is in host setup")
        .clone();
    assert_eq!(arena.mmap_next, second + PAGE);
    assert_eq!(arena.free_regions, vec![(gap, PAGE)]);
    let row = |authority: &crate::dispatch::mm_authority::DispatchMmAuthority, at: u64| {
        authority.lock().semantic_vmas.find(at).cloned()
    };
    assert!(
        row(&child, first).is_some_and(|vma| vma.provenance.is_private_anonymous() && vma.write),
        "the child owns the parent's anonymous rows"
    );
    // The child's rows are its own: the parent's root moves on alone.
    let mut view = root.lock();
    let decision = view
        .munmap(ReservationRange::new(first, first + 2 * PAGE).unwrap())
        .unwrap();
    commit(&mut view, decision);
    drop(view);
    assert!(row(&child, first).is_some());
    assert!(root.lock().mapping(first).is_none());
}

// S1d: every host reader of placement on a delegated MM answers from the
// root, merged with the host's opaque rows. Each test runs one sequence on a
// host-setup MM (every edit a host syscall) and on a delegated MM (the
// root-owned edits made by the guest venue) and compares the reader.

impl Root {
    /// What guest EL1 does for `munmap` of anonymous memory on its own venue.
    fn guest_munmap(&self, start: u64, len: u64) {
        let mut root = self.lock();
        let decision = root
            .munmap(ReservationRange::new(start, start + len).unwrap())
            .unwrap();
        commit(&mut root, decision);
    }
}

fn reservation_prot(prot: u64) -> ReservationProtection {
    ReservationProtection::from_bits(prot).unwrap()
}

/// One sequence, two MMs: `host` is in host setup, `delegated` has an
/// admitted root.
struct Twin {
    host: SyscallDispatcher,
    host_memory: CountingMmapMemory,
    delegated: SyscallDispatcher,
    delegated_memory: CountingMmapMemory,
    root: Root,
}

impl Twin {
    fn new() -> Self {
        let host = SyscallDispatcher::new();
        let delegated = SyscallDispatcher::new();
        let root = Root::admit(&delegated);
        for dispatcher in [&host, &delegated] {
            install_host_file_fd(dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
        }
        Self {
            host,
            host_memory: arena_memory(),
            delegated,
            delegated_memory: arena_memory(),
            root,
        }
    }

    fn both(&mut self, mut step: impl FnMut(&mut SyscallDispatcher, &mut CountingMmapMemory)) {
        step(&mut self.host, &mut self.host_memory);
        step(&mut self.delegated, &mut self.delegated_memory);
    }

    /// Anonymous private memory at `address`: a host `mmap(MAP_FIXED)` on
    /// the host-setup MM, a guest-venue root edit on the delegated MM.
    fn anonymous(&mut self, address: u64, len: u64, prot: u64) {
        assert_eq!(
            returned(host_mmap(
                &mut self.host,
                &mut self.host_memory,
                address,
                len,
                prot,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                -1,
            )) as u64,
            address
        );
        assert_eq!(
            self.root
                .guest_mmap(Placement::Fixed(address), len, reservation_prot(prot)),
            Ok(address)
        );
    }

    /// Host-venue anonymous `mmap(MAP_FIXED)` on both MMs.
    fn host_anonymous(&mut self, address: u64, len: u64, prot: u64) {
        self.both(|dispatcher, memory| {
            assert_eq!(
                returned(host_mmap(
                    dispatcher,
                    memory,
                    address,
                    len,
                    prot,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    -1,
                )) as u64,
                address
            );
        });
    }

    /// A host private file mapping at `address` on both MMs.
    fn file(&mut self, address: u64) {
        self.both(|dispatcher, memory| {
            assert_eq!(
                returned(host_mmap(
                    dispatcher,
                    memory,
                    address,
                    PAGE,
                    LINUX_PROT_READ,
                    LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
                    FILE_FD,
                )) as u64,
                address
            );
        });
    }

    fn mprotect(&mut self, address: u64, len: u64, prot: u64) {
        assert_eq!(
            returned(call(
                &mut self.host,
                &mut self.host_memory,
                SYS_MPROTECT,
                [address, len, prot, 0, 0, 0],
            )),
            0
        );
        self.root
            .guest_mprotect(address, len, reservation_prot(prot));
    }

    fn host_mprotect(&mut self, address: u64, len: u64, prot: u64) {
        self.both(|dispatcher, memory| {
            assert_eq!(
                returned(call(
                    dispatcher,
                    memory,
                    SYS_MPROTECT,
                    [address, len, prot, 0, 0, 0],
                )),
                0
            );
        });
    }

    fn munmap(&mut self, address: u64, len: u64) {
        assert_eq!(
            returned(call(
                &mut self.host,
                &mut self.host_memory,
                SYS_MUNMAP,
                [address, len, 0, 0, 0, 0],
            )),
            0
        );
        self.root.guest_munmap(address, len);
    }

    /// The first touch of `page` on both MMs, through the host fault path.
    fn touch(&mut self, page: u64) {
        self.both(|dispatcher, _| {
            dispatcher.with_resident_fault_plan_for_test(page, |plan| {
                dispatcher.commit_resident_fault(plan)
            });
        });
    }

    /// Assert `reader` answers the same on both MMs.
    fn same<T: PartialEq + std::fmt::Debug>(
        &self,
        what: &str,
        reader: impl Fn(&SyscallDispatcher, &CountingMmapMemory) -> T,
    ) {
        assert_eq!(
            reader(&self.delegated, &self.delegated_memory),
            reader(&self.host, &self.host_memory),
            "{what}: the delegated MM (left) must answer as the host-setup MM (right)"
        );
    }
}

/// Every fault-planning answer for `pages`: the trap classifier, the
/// first-touch plan and the bulk frame-grant plan.
type FaultAnswer = (bool, Option<u64>, Option<(u64, u64, u64)>);

fn fault_answers(dispatcher: &SyscallDispatcher, pages: &[u64]) -> Vec<FaultAnswer> {
    pages
        .iter()
        .map(|&page| {
            (
                dispatcher.fault_requires_mm_mutation(page),
                dispatcher.with_resident_fault_plan_for_test(page, |plan| plan.prot()),
                dispatcher.with_resident_frame_grant_plan_for_test(page, 4 * PAGE, |plan| {
                    (plan.start(), plan.len(), plan.prot())
                }),
            )
        })
        .collect()
}

fn mincore(
    dispatcher: &SyscallDispatcher,
    memory: &CountingMmapMemory,
    address: u64,
    pages: u64,
) -> Option<Vec<u8>> {
    dispatcher.mincore_residency_vector(memory, address, pages, PAGE)
}

const RW: u64 = LINUX_PROT_READ | LINUX_PROT_WRITE;

#[test]
fn delegated_fault_on_a_root_owned_page_is_planned_from_the_root() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.anonymous(base, 2 * PAGE, RW);
    twin.file(base + 2 * PAGE);
    let pages = [base, base + PAGE, base + 2 * PAGE, base + 3 * PAGE];
    let answers = |twin: &Twin, what: &str| {
        twin.same(what, |dispatcher, _| fault_answers(dispatcher, &pages));
    };
    answers(&twin, "a fresh root-owned mapping beside a file mapping");
    assert!(
        twin.delegated.fault_requires_mm_mutation(base),
        "a root-owned page's first touch is the host's to serve"
    );

    twin.mprotect(base + PAGE, PAGE, LINUX_PROT_READ);
    answers(&twin, "after an mprotect of one root-owned page");

    twin.touch(base + PAGE);
    answers(&twin, "after the first touch of the read-only page");

    twin.munmap(base, PAGE);
    answers(&twin, "after an munmap of a root-owned page");
}

#[test]
fn delegated_host_venue_arming_follows_guest_venue_edits() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    // Host venue: the host armed first touch at read-write.
    twin.host_anonymous(base, 2 * PAGE, RW);
    let pages = [base, base + PAGE, base + 2 * PAGE];
    twin.same("host-venue mapping", |d, _| fault_answers(d, &pages));
    // The guest venue then narrows and retires it without the host.
    twin.mprotect(base, PAGE, LINUX_PROT_READ);
    twin.same("after a guest-venue mprotect", |d, _| {
        fault_answers(d, &pages)
    });
    twin.munmap(base + PAGE, PAGE);
    twin.same("after a guest-venue munmap", |d, _| {
        fault_answers(d, &pages)
    });
}

#[test]
fn delegated_mincore_across_root_and_file_mappings_reads_the_root() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.anonymous(base, 2 * PAGE, RW);
    twin.file(base + 2 * PAGE);
    twin.same(
        "untouched anonymous pages beside a loaded file page",
        |d, m| mincore(d, m, base, 3),
    );
    assert_eq!(
        mincore(&twin.delegated, &twin.delegated_memory, base, 3),
        Some(vec![0, 0, 1])
    );
    twin.touch(base + PAGE);
    twin.same("after the first touch of one anonymous page", |d, m| {
        mincore(d, m, base, 3)
    });
}

#[test]
fn delegated_remap_after_a_guest_venue_munmap_starts_fresh() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.host_anonymous(base, 2 * PAGE, RW);
    twin.touch(base);
    twin.same("touched page", |d, m| mincore(d, m, base, 2));
    // The guest venue retires the mapping; the host never saw it go.
    twin.munmap(base, 2 * PAGE);
    // A new (hinted, not MAP_FIXED) mapping at the same address holds none of
    // the old pages.
    twin.both(|dispatcher, memory| {
        assert_eq!(
            returned(host_mmap(
                dispatcher,
                memory,
                base,
                2 * PAGE,
                RW,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                -1,
            )) as u64,
            base
        );
    });
    twin.same("a fresh mapping over retired pages", |d, m| {
        mincore(d, m, base, 2)
    });
    twin.same("its first touch", |d, _| {
        fault_answers(d, &[base, base + PAGE])
    });
}

#[test]
fn delegated_demotion_hands_first_touch_to_the_host() {
    const SYS_MADVISE: u64 = 233;
    const MADV_DONTFORK: u64 = 10;
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.anonymous(base, 2 * PAGE, RW);
    twin.touch(base);
    // A policy edit the root cannot express makes the rows host-owned.
    twin.both(|dispatcher, memory| {
        assert_eq!(
            returned(call(
                dispatcher,
                memory,
                SYS_MADVISE,
                [base, 2 * PAGE, MADV_DONTFORK, 0, 0, 0],
            )),
            0
        );
    });
    twin.same("first touch of demoted pages", |d, _| {
        fault_answers(d, &[base, base + PAGE])
    });
    twin.same("mincore of demoted pages", |d, m| mincore(d, m, base, 2));
}

#[test]
fn delegated_host_mprotect_keeps_untouched_root_pages_observable() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.anonymous(base, 2 * PAGE, RW);
    twin.touch(base);
    twin.both(|_, memory| memory.protect_log.borrow_mut().clear());
    // A host-served mprotect of root-owned memory: the untouched page's leaf
    // must go back to invalid so its first touch is still observed.
    twin.host_mprotect(base, 2 * PAGE, LINUX_PROT_READ);
    twin.same("leaf edits of the host mprotect", |_, memory| {
        memory.protect_log.borrow().clone()
    });
    twin.same("first touch after the mprotect", |d, _| {
        fault_answers(d, &[base, base + PAGE])
    });
}

#[test]
fn delegated_stack_growth_stops_at_a_root_owned_mapping() {
    let mut twin = Twin::new();
    let stack = LINUX_MMAP_BASE + 16 * PAGE;
    twin.both(|dispatcher, memory| {
        assert_eq!(
            returned(host_mmap(
                dispatcher,
                memory,
                stack,
                PAGE,
                RW,
                LINUX_MAP_PRIVATE
                    | LINUX_MAP_ANONYMOUS
                    | LINUX_MAP_FIXED
                    | carrick_abi::LINUX_MAP_GROWSDOWN,
                -1,
            )) as u64,
            stack
        );
    });
    // A root-owned mapping inside the stack's growth window.
    twin.anonymous(stack - 4 * PAGE, PAGE, RW);
    for page in [stack - PAGE, stack - 6 * PAGE] {
        twin.same("the grow-down plan", |d, _| {
            d.with_mmap_growdown_fault_plan_for_test(page, |plan| (plan.start(), plan.len()))
        });
    }
    assert_eq!(
        twin.delegated
            .with_mmap_growdown_fault_plan_for_test(stack - 6 * PAGE, |plan| plan.start()),
        None,
        "the stack cannot grow over a root-owned mapping"
    );
}

#[test]
fn delegated_exec_leaves_no_root_row_in_the_new_image() {
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.anonymous(base, 2 * PAGE, RW);
    twin.file(base + 2 * PAGE);
    twin.touch(base);
    for (index, dispatcher) in [&twin.host, &twin.delegated].into_iter().enumerate() {
        let replacement = crate::kernel::MmId::from_registry_allocation(
            std::num::NonZeroU64::new(dispatcher.mm_authority().mm_id.raw() + 100 + index as u64)
                .unwrap(),
        );
        dispatcher
            .publish_exec_image_state(replacement, Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .commit();
        assert!(dispatcher.mem().lock().delegated_root().is_none());
    }
    let pages = [base, base + PAGE, base + 2 * PAGE];
    twin.same("fault planning in the new image", |d, _| {
        fault_answers(d, &pages)
    });
    twin.same("/proc/self/maps of the new image", |d, _| proc_rows(d));
    twin.same("placement in the new image", |d, _| {
        d.mem_view()
            .next_mmap_address(
                0,
                PAGE,
                RW,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                MmapGrantCongruence::Any,
                true,
            )
            .unwrap()
    });
}

// ---------------------------------------------------------------------------
// S1c: mremap, madvise and mlock of root-owned anonymous memory stay in the
// root; /proc merges the root projection with host rows exactly once.
// ---------------------------------------------------------------------------

const SYS_MLOCK: u64 = 228;
const SYS_MUNLOCK: u64 = 229;
const SYS_MLOCKALL: u64 = 230;
const SYS_MUNLOCKALL: u64 = 231;
const SYS_MADVISE: u64 = 233;
const MCL_CURRENT: u64 = 1;
const ANON: u64 = LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS;

impl Root {
    /// The committed root node at `address`: (start, end, anonymous, flags).
    fn node(&self, address: u64) -> Option<(u64, u64, bool, u32)> {
        self.lock().mapping(address).map(|mapping| {
            (
                mapping.range.start(),
                mapping.range.end(),
                mapping.anonymous,
                mapping.flags.bits(),
            )
        })
    }
}

fn anon_mmap(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    address: u64,
    len: u64,
) -> u64 {
    returned(host_mmap(dispatcher, memory, address, len, RW, ANON, -1)) as u64
}

/// No private anonymous row is host-owned for `[start, end)`.
fn host_owns_no_anonymous_row(dispatcher: &SyscallDispatcher, start: u64, end: u64) -> bool {
    let authority = dispatcher.mem();
    let mem = authority.lock();
    !mem.semantic_vmas
        .iter()
        .any(|vma| vma.start < end && start < vma.end && vma.provenance.is_private_anonymous())
        && !mem
            .dynamic_maps
            .iter()
            .any(|row| row.start < end && start < row.end)
}

fn locked_memory(dispatcher: &SyscallDispatcher) -> Vec<(u64, u64)> {
    let context = dispatcher.capture_one_task_context().unwrap();
    dispatcher
        .synthetic_proc_context(&context)
        .locked_memory
        .iter()
        .map(|range| (range.start().raw(), range.end().raw()))
        .collect()
}

const ANON_FLAGS: u32 = carrick_el1_abi::ReservationNodeFlags::ANONYMOUS_PRIVATE.bits();
const LOCKED: u32 = carrick_el1_abi::ReservationNodeFlags::LOCKED.bits();
const DONTFORK: u32 = carrick_el1_abi::ReservationNodeFlags::DONTFORK.bits();

#[test]
fn delegated_madvise_attributes_stay_on_the_root_node() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, 2 * PAGE);
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        a + 2 * PAGE,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
        FILE_FD,
    )) as u64;
    // One madvise over the root anonymous mapping and the file mapping.
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MADVISE,
            [
                a + PAGE,
                2 * PAGE,
                carrick_abi::LINUX_MADV_DONTFORK,
                0,
                0,
                0
            ],
        )),
        0
    );
    assert_eq!(root.node(a), Some((a, a + PAGE, true, ANON_FLAGS)));
    assert_eq!(
        root.node(a + PAGE),
        Some((a + PAGE, a + 2 * PAGE, true, ANON_FLAGS | DONTFORK)),
        "madvise must not demote the root-owned range"
    );
    assert!(host_owns_no_anonymous_row(&dispatcher, a, a + 2 * PAGE));
    assert!(
        dispatcher
            .mem()
            .lock()
            .semantic_vmas
            .find(file)
            .is_some_and(|vma| vma.fork_policy.copy == carrick_abi::VmaForkCopyPolicy::Omit),
        "the host file row takes the advice"
    );
    // The guest venue still edits the attributed range.
    root.guest_mprotect(a + PAGE, PAGE, ReservationProtection::NONE);
    assert_eq!(
        root.node(a + PAGE).map(|node| node.3),
        Some(ANON_FLAGS | DONTFORK)
    );
    // The fork child omits it (MADV_DONTFORK) and keeps the rest.
    let child_mm = crate::kernel::MmId::from_registry_allocation(
        std::num::NonZeroU64::new(root.mm.raw() + 1).unwrap(),
    );
    let (projection_revision, projection) = dispatcher
        .mm_authority()
        .fork_projection_with_revision()
        .unwrap();
    let _ = (child_mm, projection_revision);
    assert!(
        projection.iter().any(|range| range.va == a + PAGE
            && range.disposition == carrick_hal::ForkLeafDisposition::Omit)
    );
    assert!(
        projection.iter().any(|range| range.va == a
            && range.disposition == carrick_hal::ForkLeafDisposition::Preserve)
    );
}

#[test]
fn delegated_mlock_is_a_root_attribute_visible_to_proc_and_lock_readers() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, 2 * PAGE);
    let file = returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        a + 2 * PAGE,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
        FILE_FD,
    )) as u64;
    // mlock across the root mapping and the file mapping.
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MLOCK,
            [a + PAGE, 2 * PAGE, 0, 0, 0, 0]
        )),
        0
    );
    assert_eq!(
        root.node(a + PAGE),
        Some((a + PAGE, a + 2 * PAGE, true, ANON_FLAGS | LOCKED))
    );
    assert_eq!(locked_memory(&dispatcher), [(a + PAGE, file + PAGE)]);
    assert!(
        dispatcher
            .mem()
            .lock()
            .locked_ranges
            .iter()
            .all(|range| range.start().raw() >= file),
        "the host lock table holds only host-owned ranges"
    );
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            SYS_MADVISE,
            [a + PAGE, PAGE, carrick_abi::LINUX_MADV_DONTNEED, 0, 0, 0],
        ),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    // A guest-venue munmap of the locked page retires the lock with it.
    root.guest_munmap(a + PAGE, PAGE);
    assert_eq!(locked_memory(&dispatcher), [(file, file + PAGE)]);
    // munlock of the file, then mlockall(MCL_CURRENT) locks every mapping,
    // root-owned ones included.
    returned(call(
        &mut dispatcher,
        &mut memory,
        SYS_MUNLOCK,
        [file, PAGE, 0, 0, 0, 0],
    ));
    assert!(locked_memory(&dispatcher).is_empty());
    returned(call(
        &mut dispatcher,
        &mut memory,
        SYS_MLOCKALL,
        [MCL_CURRENT, 0, 0, 0, 0, 0],
    ));
    assert_eq!(root.node(a).map(|node| node.3), Some(ANON_FLAGS | LOCKED));
    assert!(
        locked_memory(&dispatcher)
            .iter()
            .any(|(start, end)| *start <= a && a + PAGE <= *end),
        "mlockall(MCL_CURRENT) missed the root mapping"
    );
    returned(call(&mut dispatcher, &mut memory, SYS_MUNLOCKALL, [0; 6]));
    assert!(locked_memory(&dispatcher).is_empty());
    assert_eq!(root.node(a).map(|node| node.3), Some(ANON_FLAGS));
}

#[test]
fn delegated_proc_rows_merge_the_root_heap_with_boot_regions_once() {
    let mut dispatcher = SyscallDispatcher::new();
    let layout = dispatcher.mem().lock().layout;
    let heap_end = layout.heap_base + layout.heap_size;
    let region = |start: u64, end: u64| ProcMapsEntry {
        start,
        end,
        read: true,
        write: true,
        execute: false,
        sharing: carrick_vfs::ProcMapSharing::Private,
        path: String::new(),
    };
    dispatcher.mem().lock().address_space_regions = Some(vec![
        region(layout.heap_base, heap_end),
        region(layout.mmap_base, layout.mmap_base + layout.mmap_size),
    ]);
    let root = Root::admit(&dispatcher);
    let brk = root.guest_brk(layout.heap_base + 2 * PAGE);
    assert_eq!(brk, layout.heap_base + 2 * PAGE);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, PAGE);
    let rows = proc_rows(&dispatcher);
    let covering = |address: u64| {
        rows.iter()
            .filter(|row| row.start <= address && address < row.end)
            .count()
    };
    // The heap and the anonymous mapping are each described once (the
    // hidden arena reservation is carrick's own backing row).
    assert_eq!(covering(layout.heap_base), 1, "{rows:?}");
    assert_eq!(
        covering(brk + PAGE),
        0,
        "no row may describe the heap past the break: {rows:?}"
    );
    assert!(covering(a) >= 1);
    let _ = dispatcher;
}
