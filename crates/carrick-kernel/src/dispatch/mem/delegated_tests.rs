//! S1b: an MM whose shared EL1 reservation root is admitted has ONE owner for
//! anonymous-private placement and VMA facts: the root. Host-forwarded
//! `mmap`/`munmap`/`mprotect` and a guest-venue edit applied to the root are
//! the same authority; file, shared and attributed mappings are opaque root
//! nodes (placement obstacles) whose rows the host keeps.

use super::tests::{CountingMmapMemory, install_host_file_fd, returned};
use super::*;
use crate::dispatch::mem::el1_reservations::{
    El1Admission, El1AdmissionOrigin, HostReservationProvider, PreparedHostReservations,
};
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

/// The carrier's reservation table and its published roots, slot by slot
/// (the zone's `AddressSpaces` index of each MM key).
#[derive(Clone)]
struct Carrier {
    table: Arc<SharedReservations>,
    slots: Arc<std::sync::Mutex<Vec<ReservationMm>>>,
}

impl Carrier {
    fn new() -> Self {
        // Same zeroed-region initialization as EL1 bootstrap.
        let ptr =
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        Self {
            table: Arc::from(unsafe { Box::<SharedReservations>::from_raw(ptr.cast()) }),
            slots: Arc::default(),
        }
    }

    fn slot(&self, mm: ReservationMm) -> Result<usize, Refusal> {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .position(|published| *published == mm)
            .ok_or(Refusal::Stale)
    }

    /// Publish `dispatcher`'s MM root as the carrier does at address-space
    /// publication (`mm_occupancy::publish_in_with_layout`).
    fn publish(&self, dispatcher: &SyscallDispatcher) -> ReservationMm {
        let mm = ReservationMm::new(dispatcher.mm_authority().mm_id.raw()).unwrap();
        let layout = dispatcher.mem().lock().layout;
        let index = {
            let mut slots = self.slots.lock().unwrap();
            slots.push(mm);
            slots.len() - 1
        };
        self.table
            .publish(
                index,
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
        mm
    }
}

pub(in crate::dispatch) struct Root {
    carrier: Carrier,
    pub(in crate::dispatch) mm: ReservationMm,
}

struct View(Carrier);
impl PreparedHostReservations for View {
    fn lock(&self, mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
        self.0.table.lock(self.0.slot(mm)?, mm)
    }
}
struct Provider(Carrier);
impl HostReservationProvider for Provider {
    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
        Ok(Box::new(View(self.0.clone())))
    }
}

/// `dispatcher`'s production admission under its own MM permit.
fn admit(
    dispatcher: &SyscallDispatcher,
    origin: El1AdmissionOrigin<'_, '_>,
    enabled: bool,
) -> Result<El1Admission, Refusal> {
    crate::dispatch::mm_mutation::test_support::with_permit(
        dispatcher.mm_mutation_coordinator(),
        |permit| {
            dispatcher
                .mem_view()
                .admit_el1_reservations(permit, origin, enabled)
        },
    )
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
    /// admit it (the production bind admission).
    pub(in crate::dispatch) fn admit(dispatcher: &SyscallDispatcher) -> Self {
        let root = Self::publish(dispatcher);
        assert_eq!(
            admit(dispatcher, El1AdmissionOrigin::Bind, true),
            Ok(El1Admission::Delegated)
        );
        root
    }

    /// Publish this dispatcher MM's root and install the carrier provider,
    /// leaving the MM in host setup.
    fn publish(dispatcher: &SyscallDispatcher) -> Self {
        let carrier = Carrier::new();
        let mm = carrier.publish(dispatcher);
        dispatcher
            .install_reservation_provider(Arc::new(Provider(carrier.clone())))
            .unwrap();
        Self { carrier, mm }
    }

    /// Publish a fork child's root in this carrier (its provider is the
    /// parent's, inherited by the fork).
    fn publish_child(&self, child: &SyscallDispatcher) -> Self {
        Self {
            carrier: self.carrier.clone(),
            mm: self.carrier.publish(child),
        }
    }

    pub(in crate::dispatch) fn lock(&self) -> Reservations<'_> {
        let slot = self.carrier.slot(self.mm).unwrap();
        self.carrier.table.lock(slot, self.mm).unwrap()
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

/// Fork preparation (before the child's root is published): the child's
/// host-setup twin holds the parent root's rows as its own host facts.
#[test]
fn delegated_fork_twin_owns_the_parents_rows_until_its_fork_commit() {
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
        .expect("a fork twin is in host setup until its fork commit")
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

const SYS_MREMAP: u64 = 216;
const SYS_MSYNC: u64 = 227;
const SYS_MLOCK: u64 = 228;
const SYS_MUNLOCK: u64 = 229;
const SYS_MLOCKALL: u64 = 230;
const SYS_MUNLOCKALL: u64 = 231;
const SYS_MADVISE: u64 = 233;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;
const MCL_CURRENT: u64 = 1;
const MS_INVALIDATE: u64 = 2;
const ANON: u64 = LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS;

impl Root {
    /// The committed Linux mapping at `address` (adjacent nodes of one
    /// mapping, whatever their incarnations): (start, end, anonymous, flags).
    fn node(&self, address: u64) -> Option<(u64, u64, bool, u32)> {
        let mut found = None;
        self.lock()
            .observe_mappings(&mut |mapping| {
                if mapping.range.start() <= address && address < mapping.range.end() {
                    found = Some((
                        mapping.range.start(),
                        mapping.range.end(),
                        mapping.anonymous,
                        mapping.flags.bits(),
                    ));
                }
            })
            .unwrap();
        found
    }
}

fn mremap(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    args: [u64; 5],
) -> DispatchOutcome {
    call(
        dispatcher,
        memory,
        SYS_MREMAP,
        [args[0], args[1], args[2], args[3], args[4], 0],
    )
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
fn delegated_mremap_shapes_stay_root_owned() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, 4 * PAGE);
    memory.write_bytes(a, b"root").unwrap();

    // Shrink retires the tail in the root.
    assert_eq!(
        returned(mremap(
            &mut dispatcher,
            &mut memory,
            [a, 4 * PAGE, 2 * PAGE, 0, 0]
        )) as u64,
        a
    );
    assert_eq!(root.node(a), Some((a, a + 2 * PAGE, true, ANON_FLAGS)));
    assert_eq!(root.node(a + 2 * PAGE), None);
    // In-place growth into the freed hole extends the root node.
    assert_eq!(
        returned(mremap(
            &mut dispatcher,
            &mut memory,
            [a, 2 * PAGE, 3 * PAGE, 0, 0]
        )) as u64,
        a
    );
    assert_eq!(root.node(a), Some((a, a + 3 * PAGE, true, ANON_FLAGS)));
    // A MAYMOVE move relocates the root node with its contents. (The
    // blocker is read-only so it stays a separate mapping.)
    let blocker = root
        .guest_mmap(Placement::Fixed(a + 3 * PAGE), PAGE, READ)
        .unwrap();
    assert_eq!(blocker, a + 3 * PAGE);
    let moved = returned(mremap(
        &mut dispatcher,
        &mut memory,
        [a, 3 * PAGE, 5 * PAGE, MREMAP_MAYMOVE, 0],
    )) as u64;
    assert_ne!(moved, a);
    assert_eq!(memory.read_bytes(moved, 4).unwrap(), b"root");
    assert_eq!(root.node(a), None);
    assert_eq!(
        root.node(moved),
        Some((moved, moved + 5 * PAGE, true, ANON_FLAGS))
    );
    // MREMAP_FIXED to a named destination.
    let fixed = returned(mremap(
        &mut dispatcher,
        &mut memory,
        [moved, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, a],
    )) as u64;
    assert_eq!(fixed, a);
    assert_eq!(memory.read_bytes(a, 4).unwrap(), b"root");
    assert_eq!(root.node(a), Some((a, a + PAGE, true, ANON_FLAGS)));
    assert_eq!(root.node(moved), None);
    assert_eq!(
        root.node(moved + PAGE),
        Some((moved + PAGE, moved + 5 * PAGE, true, ANON_FLAGS))
    );
    // MREMAP_DONTUNMAP keeps the source (zeroed) and adds a destination.
    let kept = returned(mremap(
        &mut dispatcher,
        &mut memory,
        [a, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0],
    )) as u64;
    assert_ne!(kept, a);
    assert_eq!(memory.read_bytes(kept, 4).unwrap(), b"root");
    assert_eq!(memory.read_bytes(a, 4).unwrap(), [0; 4]);
    // Both stay root mappings (they may coalesce when placed adjacent).
    assert_eq!(root.node(a).map(|node| (node.0, node.2)), Some((a, true)));
    assert_eq!(root.node(kept).map(|node| node.2), Some(true));
    assert!(
        host_owns_no_anonymous_row(&dispatcher, LINUX_MMAP_BASE, LINUX_MMAP_BASE + 32 * PAGE),
        "mremap demoted root rows into host rows"
    );
}

#[test]
fn delegated_mremap_growth_stops_at_an_adjacent_host_file_mapping() {
    // Two mappings: a root anonymous page and, right after a one-page
    // hole, a host-owned file mapping. mremap(2): growth that would reach
    // the file mapping fails in place (ENOMEM) and moves with MAYMOVE;
    // growth that fits the hole succeeds in place.
    for delegated in [false, true] {
        let mut dispatcher = SyscallDispatcher::new();
        let root = delegated.then(|| Root::admit(&dispatcher));
        install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
        let mut memory = arena_memory();
        let a = anon_mmap(&mut dispatcher, &mut memory, 0, PAGE);
        let file = returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            a + 2 * PAGE,
            PAGE,
            LINUX_PROT_READ,
            LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
            FILE_FD,
        )) as u64;
        assert_eq!(file, a + 2 * PAGE);
        assert_eq!(
            mremap(&mut dispatcher, &mut memory, [a, PAGE, 3 * PAGE, 0, 0]),
            DispatchOutcome::errno(LINUX_ENOMEM),
            "delegated={delegated}: the file mapping is in the way"
        );
        let Some(root) = root else {
            // Host setup grows only at its bump cursor, so this hole below
            // the cursor answers ENOMEM there although nothing is in the
            // way: a host-setup divergence from mremap(2), recorded here
            // rather than asserted.
            continue;
        };
        assert_eq!(
            mremap(&mut dispatcher, &mut memory, [a, PAGE, 2 * PAGE, 0, 0]),
            DispatchOutcome::Returned { value: a as i64 },
            "the hole fits exactly"
        );
        let moved = returned(mremap(
            &mut dispatcher,
            &mut memory,
            [a, 2 * PAGE, 3 * PAGE, MREMAP_MAYMOVE, 0],
        )) as u64;
        assert!(
            moved + 3 * PAGE <= file || file + PAGE <= moved,
            "delegated={delegated}: the move must not overlap the file mapping"
        );
        let file_row = proc_row_at(&dispatcher, file).expect("the file mapping survives");
        assert_eq!((file_row.start, file_row.end), (file, file + PAGE));
        assert_eq!(root.node(moved).map(|node| node.2), Some(true));
        assert!(root.node(file).is_some_and(|node| !node.2));
        assert!(host_owns_no_anonymous_row(
            &dispatcher,
            moved,
            moved + 3 * PAGE
        ));
        // MREMAP_FIXED onto the file mapping discards it (like MAP_FIXED):
        // the destination becomes the root's anonymous mapping, once.
        memory.write_bytes(moved, b"move").unwrap();
        assert_eq!(
            mremap(
                &mut dispatcher,
                &mut memory,
                [moved, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, file],
            ),
            DispatchOutcome::Returned { value: file as i64 }
        );
        assert_eq!(memory.read_bytes(file, 4).unwrap(), b"move");
        assert_eq!(root.node(file), Some((file, file + PAGE, true, ANON_FLAGS)));
        let row = proc_row_at(&dispatcher, file).unwrap();
        assert!(row.write && row.path.is_empty(), "{row:?}");
        assert!(host_owns_no_anonymous_row(&dispatcher, file, file + PAGE));
        assert_rows_ordered_and_disjoint(&dispatcher);
    }
}

/// The attributes (r, w, x, path) of the /proc row covering one page.
type ProcPage = Option<(bool, bool, bool, String)>;

/// Every page of the arena window: the attributes of the /proc row covering
/// it, if any.
fn proc_pages(dispatcher: &SyscallDispatcher, base: u64, pages: u64) -> Vec<ProcPage> {
    let rows = proc_rows(dispatcher);
    (0..pages)
        .map(|page| {
            let address = base + page * PAGE;
            rows.iter()
                .find(|row| row.start <= address && address < row.end)
                .map(|row| (row.read, row.write, row.execute, row.path.clone()))
        })
        .collect()
}

fn assert_rows_ordered_and_disjoint(dispatcher: &SyscallDispatcher) {
    let rows = proc_rows(dispatcher);
    for pair in rows.windows(2) {
        assert!(
            pair[0].end <= pair[1].start,
            "overlapping /proc rows {:?} and {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn delegated_mremap_madvise_mlock_sequence_matches_a_host_setup_mm() {
    fn run(delegated: bool) -> (Vec<DispatchOutcome>, Vec<ProcPage>) {
        let mut dispatcher = SyscallDispatcher::new();
        let _root = delegated.then(|| Root::admit(&dispatcher));
        install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
        let mut memory = arena_memory();
        let a = anon_mmap(&mut dispatcher, &mut memory, 0, 4 * PAGE);
        let file = a + 4 * PAGE;
        returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            file,
            PAGE,
            LINUX_PROT_READ,
            LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
            FILE_FD,
        ));
        memory.write_bytes(a, b"data").unwrap();
        let mut outcomes = vec![
            // mremap validation shapes, in the served path's precedence.
            mremap(&mut dispatcher, &mut memory, [a, PAGE, 0, 0, 0]),
            mremap(&mut dispatcher, &mut memory, [a, PAGE, PAGE, 1 << 20, 0]),
            mremap(&mut dispatcher, &mut memory, [a + 1, PAGE, PAGE, 0, 0]),
            mremap(&mut dispatcher, &mut memory, [a, 0, PAGE, 0, 0]),
            mremap(
                &mut dispatcher,
                &mut memory,
                [a, PAGE, PAGE, MREMAP_FIXED, a + 8 * PAGE],
            ),
            mremap(
                &mut dispatcher,
                &mut memory,
                [a, PAGE, PAGE, MREMAP_DONTUNMAP, 0],
            ),
            mremap(
                &mut dispatcher,
                &mut memory,
                [a, PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0],
            ),
            mremap(
                &mut dispatcher,
                &mut memory,
                [
                    a,
                    PAGE,
                    PAGE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    a + 8 * PAGE + 1,
                ],
            ),
            mremap(
                &mut dispatcher,
                &mut memory,
                [
                    a,
                    2 * PAGE,
                    2 * PAGE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    a + PAGE,
                ],
            ),
            mremap(&mut dispatcher, &mut memory, [a, u64::MAX, PAGE, 0, 0]),
            // A source spanning the anonymous mapping and the file mapping.
            mremap(
                &mut dispatcher,
                &mut memory,
                [a + 3 * PAGE, 2 * PAGE, PAGE, 0, 0],
            ),
            // A source in an unmapped hole.
            mremap(
                &mut dispatcher,
                &mut memory,
                [a + 6 * PAGE, PAGE, PAGE, 0, 0],
            ),
            // Growth into the file mapping without MAYMOVE.
            mremap(&mut dispatcher, &mut memory, [a, 4 * PAGE, 5 * PAGE, 0, 0]),
            // Shrink, then attributes, then locks.
            mremap(&mut dispatcher, &mut memory, [a, 4 * PAGE, 3 * PAGE, 0, 0]),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MADVISE,
                [a, 4 * PAGE, carrick_abi::LINUX_MADV_DONTFORK, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MLOCK,
                [a + PAGE, PAGE, 0, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MADVISE,
                [a, 2 * PAGE, carrick_abi::LINUX_MADV_DONTNEED, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MSYNC,
                [a, 2 * PAGE, MS_INVALIDATE, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MUNLOCK,
                [a, 5 * PAGE, 0, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MADVISE,
                [a, 2 * PAGE, carrick_abi::LINUX_MADV_DONTNEED, 0, 0, 0],
            ),
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MPROTECT,
                [a, PAGE, LINUX_PROT_READ, 0, 0, 0],
            ),
        ];
        outcomes.push(DispatchOutcome::Returned {
            value: i64::from(dispatcher.mem_view().vma_dump_omitted_for_test(a, PAGE)),
        });
        if delegated {
            assert!(
                host_owns_no_anonymous_row(&dispatcher, a, file),
                "the sequence demoted root rows into host rows"
            );
        }
        assert_rows_ordered_and_disjoint(&dispatcher);
        (outcomes, proc_pages(&dispatcher, a, 8))
    }
    let (host_outcomes, host_pages) = run(false);
    let (root_outcomes, root_pages) = run(true);
    for (index, (host, root)) in host_outcomes.iter().zip(&root_outcomes).enumerate() {
        assert_eq!(host, root, "outcome {index} differs");
    }
    assert_eq!(host_pages, root_pages, "/proc rows differ page for page");
}

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

#[test]
fn delegated_mremap_carries_the_lock_with_the_mapping() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, PAGE);
    returned(call(
        &mut dispatcher,
        &mut memory,
        SYS_MLOCK,
        [a, PAGE, 0, 0, 0, 0],
    ));
    // In-place growth of a locked mapping extends the locked VMA.
    assert_eq!(
        returned(mremap(
            &mut dispatcher,
            &mut memory,
            [a, PAGE, 2 * PAGE, 0, 0]
        )) as u64,
        a
    );
    assert_eq!(
        root.node(a),
        Some((a, a + 2 * PAGE, true, ANON_FLAGS | LOCKED))
    );
    assert_eq!(locked_memory(&dispatcher), [(a, a + 2 * PAGE)]);
    // A move takes the lock along; the old range holds none.
    let moved = returned(mremap(
        &mut dispatcher,
        &mut memory,
        [
            a,
            2 * PAGE,
            2 * PAGE,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            a + 4 * PAGE,
        ],
    )) as u64;
    assert_eq!(moved, a + 4 * PAGE);
    assert_eq!(locked_memory(&dispatcher), [(moved, moved + 2 * PAGE)]);
    assert!(dispatcher.mem().lock().locked_ranges.is_empty());
}

fn mincore_page(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    address: u64,
) -> u8 {
    let vec = LINUX_MMAP_BASE + 31 * PAGE;
    assert_eq!(
        returned(call(dispatcher, memory, 232, [address, PAGE, vec, 0, 0, 0])),
        0
    );
    memory.read_bytes(vec, 1).unwrap()[0]
}

#[test]
fn delegated_mremap_growth_over_a_guest_unmapped_page_is_not_resident() {
    // The host venue makes a page resident, the guest venue unmaps it
    // without the host, then a host-venue mremap grows back over it: the
    // grown page is fresh memory (mincore(2) 0), exactly as when every step
    // is a host syscall.
    for delegated in [false, true] {
        let mut dispatcher = SyscallDispatcher::new();
        let root = delegated.then(|| Root::admit(&dispatcher));
        let mut memory = arena_memory();
        let a = anon_mmap(&mut dispatcher, &mut memory, 0, 2 * PAGE);
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MLOCK,
            [a + PAGE, PAGE, 0, 0, 0, 0],
        ));
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MUNLOCK,
            [a + PAGE, PAGE, 0, 0, 0, 0],
        ));
        assert_eq!(mincore_page(&mut dispatcher, &mut memory, a + PAGE), 1);
        match &root {
            Some(root) => root.guest_munmap(a + PAGE, PAGE),
            None => {
                returned(call(
                    &mut dispatcher,
                    &mut memory,
                    SYS_MUNMAP,
                    [a + PAGE, PAGE, 0, 0, 0, 0],
                ));
            }
        }
        assert_eq!(
            returned(mremap(
                &mut dispatcher,
                &mut memory,
                [a, PAGE, 2 * PAGE, 0, 0]
            )) as u64,
            a
        );
        assert_eq!(
            mincore_page(&mut dispatcher, &mut memory, a + PAGE),
            0,
            "delegated={delegated}: the grown page is fresh"
        );
    }
}

#[test]
fn delegated_heap_mremap_and_mlockall_match_a_host_setup_mm() {
    // Readers S1d found still reading host rows only: the mremap source
    // metadata (a heap source is host-served) and mlockall(MCL_CURRENT).
    fn run(delegated: bool) -> (Vec<DispatchOutcome>, Vec<(u64, u64)>) {
        let mut dispatcher = SyscallDispatcher::new();
        let _root = delegated.then(|| Root::admit(&dispatcher));
        let heap = dispatcher.mem().lock().layout.heap_base;
        let mut heap_memory = CountingMmapMemory::new(heap, (8 * PAGE) as usize);
        let mut memory = arena_memory();
        let outcomes = vec![
            call(
                &mut dispatcher,
                &mut heap_memory,
                SYS_BRK,
                [heap + 3 * PAGE, 0, 0, 0, 0, 0],
            ),
            mremap(
                &mut dispatcher,
                &mut heap_memory,
                [heap, 3 * PAGE, 2 * PAGE, 0, 0],
            ),
            mremap(
                &mut dispatcher,
                &mut heap_memory,
                [heap + 2 * PAGE, PAGE, PAGE, 0, 0],
            ),
            DispatchOutcome::Returned {
                value: anon_mmap(&mut dispatcher, &mut memory, 0, 2 * PAGE) as i64,
            },
            call(
                &mut dispatcher,
                &mut memory,
                SYS_MLOCKALL,
                [MCL_CURRENT, 0, 0, 0, 0, 0],
            ),
        ];
        (outcomes, locked_memory(&dispatcher))
    }
    let host = run(false);
    let root = run(true);
    assert_eq!(host.0, root.0, "outcomes differ");
    assert_eq!(host.1, root.1, "mlockall locked different memory");
}

// ---------------------------------------------------------------------------
// S2: a host residency fact names the root node incarnation it was observed
// on. A guest-venue munmap/mmap retires that incarnation without the host, so
// the fact is dead by construction; nothing tells the host.
// ---------------------------------------------------------------------------

/// Every residency answer the host gives for `pages`: mincore(2) and the
/// fault-planning answers.
fn residency_answers(
    dispatcher: &SyscallDispatcher,
    memory: &CountingMmapMemory,
    base: u64,
    pages: u64,
) -> (Option<Vec<u8>>, Vec<FaultAnswer>) {
    let list: Vec<u64> = (0..pages).map(|page| base + page * PAGE).collect();
    (
        mincore(dispatcher, memory, base, pages),
        fault_answers(dispatcher, &list),
    )
}

#[test]
fn delegated_guest_venue_munmap_then_mmap_retires_host_residency() {
    // Host-venue first touch, then guest-venue munmap and guest-venue mmap
    // at the same address: the host never sees the guest steps. Linux: the
    // new mapping holds none of the old pages (mincore(2) 0, first touch
    // still pending).
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.host_anonymous(base, 2 * PAGE, RW);
    twin.touch(base);
    twin.same("the host-venue touch", |d, m| {
        residency_answers(d, m, base, 2)
    });
    twin.munmap(base, 2 * PAGE);
    twin.anonymous(base, 2 * PAGE, RW);
    twin.same("a guest-venue remap of a host-touched page", |d, m| {
        residency_answers(d, m, base, 2)
    });
    assert_eq!(
        mincore(&twin.delegated, &twin.delegated_memory, base, 2),
        Some(vec![0, 0])
    );
    // The new incarnation's own first touch is observed and reported.
    twin.touch(base + PAGE);
    twin.same("the new incarnation's first touch", |d, m| {
        residency_answers(d, m, base, 2)
    });
}

#[test]
fn delegated_residency_of_two_adjacent_mappings_survives_only_where_unretired() {
    // Adversarial: two adjacent mappings touched by the host; the guest
    // venue retires and recreates only the first, whose new node would
    // coalesce with its untouched-by-the-guest neighbour. The neighbour's
    // fact stays live; the recreated page's fact is dead.
    let mut twin = Twin::new();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    twin.host_anonymous(base, 2 * PAGE, RW);
    twin.host_anonymous(base + 2 * PAGE, 2 * PAGE, RW);
    twin.touch(base);
    twin.touch(base + 2 * PAGE);
    twin.munmap(base, 2 * PAGE);
    twin.anonymous(base, 2 * PAGE, RW);
    twin.same("a recreated mapping beside a live touched one", |d, m| {
        residency_answers(d, m, base, 4)
    });
    assert_eq!(
        mincore(&twin.delegated, &twin.delegated_memory, base, 4),
        Some(vec![0, 0, 1, 0])
    );
    // A middle hole recreated between two touched pages of one mapping:
    // mprotect splits keep residency, the retired page loses it.
    twin.touch(base + 3 * PAGE);
    twin.mprotect(base + 2 * PAGE, PAGE, LINUX_PROT_READ);
    twin.mprotect(base + 2 * PAGE, PAGE, RW);
    twin.munmap(base + 3 * PAGE, PAGE);
    twin.anonymous(base + 3 * PAGE, PAGE, RW);
    twin.same("split, rejoined and partly recreated", |d, m| {
        residency_answers(d, m, base, 4)
    });
    assert_eq!(
        mincore(&twin.delegated, &twin.delegated_memory, base, 4),
        Some(vec![0, 0, 1, 0])
    );
}

// ---------------------------------------------------------------------------
// S2 cost contract: a delegated reader's root work scales with the range it
// names, never with how many OTHER root nodes the MM holds. The instrument is
// root node reads (`DelegatedRoot::node_reads`), a deterministic
// architectural work unit.
// ---------------------------------------------------------------------------

/// Root node populations the budget compares: a toy process and one holding
/// hundreds of unrelated, non-coalescing anonymous mappings.
const FEW_NODES: u64 = 16;
const MANY_NODES: u64 = 512;

/// One small query's root node reads, on an MM holding `population`
/// unrelated root nodes far from the queried page.
fn delegated_reader_reads(population: u64) -> Vec<(&'static str, usize)> {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    // The unrelated population: alternating protection so nothing coalesces.
    let far = LINUX_MMAP_BASE + 64 * PAGE;
    for index in 0..population {
        let prot = if index % 2 == 0 {
            ReservationProtection::READ_WRITE
        } else {
            READ
        };
        root.guest_mmap(Placement::Fixed(far + index * 2 * PAGE), PAGE, prot)
            .unwrap();
    }
    // A finite RLIMIT_AS: every proposal charges the whole MM.
    dispatcher
        .capture_one_task_context()
        .unwrap()
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                1 << 46,
                LINUX_RLIM_INFINITY,
            ))
        })
        .unwrap();
    let base = LINUX_MMAP_BASE + 4 * PAGE;
    let delegated = dispatcher.mem().lock().delegated_root().cloned().unwrap();
    let mut out = Vec::new();
    let mut measure =
        |name: &'static str,
         dispatcher: &mut SyscallDispatcher,
         memory: &mut CountingMmapMemory,
         query: &mut dyn FnMut(&mut SyscallDispatcher, &mut CountingMmapMemory)| {
            let before = delegated.node_reads();
            query(dispatcher, memory);
            out.push((name, delegated.node_reads() - before));
        };
    measure("mmap", &mut dispatcher, &mut memory, &mut |d, m| {
        assert_eq!(
            returned(host_mmap(
                d,
                m,
                base,
                2 * PAGE,
                RW,
                ANON | LINUX_MAP_FIXED,
                -1
            )) as u64,
            base
        );
    });
    measure("fault plan", &mut dispatcher, &mut memory, &mut |d, _| {
        fault_answers(d, &[base]);
    });
    measure("first touch", &mut dispatcher, &mut memory, &mut |d, _| {
        d.with_resident_fault_plan_for_test(base, |plan| d.commit_resident_fault(plan));
    });
    measure("mincore", &mut dispatcher, &mut memory, &mut |d, m| {
        assert_eq!(mincore(d, m, base, 2), Some(vec![1, 0]));
    });
    measure("mprotect", &mut dispatcher, &mut memory, &mut |d, m| {
        assert_eq!(
            returned(call(
                d,
                m,
                SYS_MPROTECT,
                [base, PAGE, LINUX_PROT_READ, 0, 0, 0]
            )),
            0
        );
    });
    measure(
        "madvise range",
        &mut dispatcher,
        &mut memory,
        &mut |d, _| {
            d.mem_view().madvise_range_meta(base, base + PAGE);
        },
    );
    measure("mlock", &mut dispatcher, &mut memory, &mut |d, m| {
        assert_eq!(returned(call(d, m, SYS_MLOCK, [base, PAGE, 0, 0, 0, 0])), 0);
    });
    measure(
        "arena high water",
        &mut dispatcher,
        &mut memory,
        &mut |d, _| {
            d.mmap_arena_high_water();
        },
    );
    measure("munmap", &mut dispatcher, &mut memory, &mut |d, m| {
        assert_eq!(
            returned(call(d, m, SYS_MUNMAP, [base, 2 * PAGE, 0, 0, 0, 0])),
            0
        );
    });
    out
}

#[test]
fn delegated_readers_cost_the_queried_range_not_the_root_population() {
    let few = delegated_reader_reads(FEW_NODES);
    let many = delegated_reader_reads(MANY_NODES);
    // A balanced root descends in O(log n): 32x the nodes roughly doubles
    // the height (log2 16 + 1 = 5 levels, log2 512 + 1 = 10). A query that
    // makes a fixed number of descents may therefore about double; a query
    // that visits the unrelated population grows with it (32x).
    const GROWTH_BOUND: usize = 3;
    let walked: Vec<_> = few
        .iter()
        .zip(&many)
        .filter(|((_, small), (_, large))| *large > GROWTH_BOUND * small)
        .map(|((name, small), (_, large))| (*name, *small, *large))
        .collect();
    assert!(
        walked.is_empty(),
        "(query, root node reads at {FEW_NODES} nodes, at {MANY_NODES}) for queries that walk \
         the unrelated population: {walked:?}; all: {few:?} vs {many:?}"
    );
}

// ---------------------------------------------------------------------------
// S2 fencing: a root-owned anonymous mmap the runtime installs as a host
// alias (`MapHostAlias`) holds its root proposal until the install commits.
// A failed install leaves the root exactly as it was.
// ---------------------------------------------------------------------------

/// Every committed root mapping, in address order.
fn root_mappings(root: &Root) -> Vec<(u64, u64, u64, u32)> {
    let mut seen = Vec::new();
    root.lock()
        .observe_mappings(&mut |mapping| {
            seen.push((
                mapping.range.start(),
                mapping.range.end(),
                mapping.protection.bits(),
                mapping.flags.bits(),
            ))
        })
        .unwrap();
    seen
}

/// A root-eligible `mmap(MAP_FIXED)` the host serves with a host alias: a
/// heap address above the break has no identity backing.
fn alias_mmap(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut CountingMmapMemory,
    address: u64,
) -> crate::dispatch::HostAliasTransaction {
    match host_mmap(
        dispatcher,
        memory,
        address,
        2 * PAGE,
        RW,
        ANON | LINUX_MAP_FIXED,
        -1,
    ) {
        DispatchOutcome::MapHostAlias {
            transaction, va, ..
        } => {
            assert_eq!(va, GuestVa(address));
            transaction
        }
        other => panic!("expected a host-alias install, got {other:?}"),
    }
}

#[test]
fn delegated_failed_alias_install_leaves_the_root_exactly_as_it_was() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let heap = dispatcher.mem().lock().layout.heap_base;
    let hole = heap + 64 * PAGE;
    let owned = heap + 96 * PAGE;
    // A root-owned mapping the second MAP_FIXED would replace.
    root.guest_mmap(Placement::Fixed(owned), 2 * PAGE, READ)
        .unwrap();
    for address in [hole, owned] {
        let before = (
            root_mappings(&root),
            proc_rows(&dispatcher),
            root.lock().generation(),
        );
        let transaction = alias_mmap(&mut dispatcher, &mut memory, address);
        // The runtime could not install it: the transaction is dropped.
        drop(transaction);
        assert_eq!(
            (
                root_mappings(&root),
                proc_rows(&dispatcher),
                root.lock().generation()
            ),
            before,
            "{address:#x}: an aborted alias install must leave no trace"
        );
        // The range is free to be placed exactly as before.
        let refused = root.guest_mmap(
            Placement::NoReplace(address),
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        );
        assert_eq!(
            refused.is_ok(),
            address == hole,
            "{address:#x}: {refused:?}"
        );
        if address == hole {
            root.guest_munmap(hole, 2 * PAGE);
        }
    }
}

#[test]
fn delegated_committed_alias_install_replaces_the_range_with_its_host_row() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let mut memory = arena_memory();
    let heap = dispatcher.mem().lock().layout.heap_base;
    let owned = heap + 96 * PAGE;
    root.guest_mmap(Placement::Fixed(owned), 2 * PAGE, READ)
        .unwrap();
    let transaction = alias_mmap(&mut dispatcher, &mut memory, owned);
    transaction
        .with_claim_for_test(|install| dispatcher.commit_host_alias_install(install))
        .expect("claim")
        .expect("commit");
    let node = root.lock().mapping(owned).unwrap();
    assert!(!node.anonymous, "the alias mapping is host-owned");
    assert_eq!(node.protection, ReservationProtection::READ_WRITE);
    assert_eq!(
        node.range,
        ReservationRange::new(owned, owned + 2 * PAGE).unwrap()
    );
    let row = proc_row_at(&dispatcher, owned).expect("a /proc row");
    assert!(row.read && row.write);
    assert_eq!((row.start, row.end), (owned, owned + 2 * PAGE));
}

// ---------------------------------------------------------------------------
// S2 fencing: root node exhaustion is a typed, recoverable outcome. A host
// syscall that may need root metadata after its backend work secures it
// first, or answers ENOMEM (Linux's answer when a mapping edit would exceed
// the map count) before touching anything.
// ---------------------------------------------------------------------------

/// (start, end, protection bits) of one row or node.
type Row = (u64, u64, u64);

/// The root's opaque (host-owned) nodes and the host's rows in
/// `[start, end)`: after every host syscall the first mirrors the second.
fn host_rows_and_mirror(
    dispatcher: &SyscallDispatcher,
    root: &Root,
    start: u64,
    end: u64,
) -> (Vec<Row>, Vec<Row>) {
    let rows = dispatcher
        .mem()
        .lock()
        .semantic_vmas
        .overlapping(start, end)
        .map(|vma| {
            let prot =
                u64::from(vma.read) | (u64::from(vma.write) << 1) | (u64::from(vma.execute) << 2);
            (vma.start, vma.end, prot)
        })
        .collect();
    let mut mirror = Vec::new();
    root.lock()
        .observe_nodes(
            ReservationRange::new(start, end).unwrap(),
            &mut |mapping, _| {
                if !mapping.anonymous {
                    mirror.push((
                        mapping.range.start(),
                        mapping.range.end(),
                        mapping.protection.bits(),
                    ));
                }
            },
        )
        .unwrap();
    (rows, mirror)
}

#[test]
fn delegated_node_exhaustion_answers_enomem_or_succeeds_never_aborts() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let pages = 8u64;
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; (8 * PAGE) as usize]);
    let mut memory = arena_memory();
    let file = LINUX_MMAP_BASE + 4 * PAGE;
    assert_eq!(
        returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            file,
            pages * PAGE,
            LINUX_PROT_READ,
            LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
            FILE_FD,
        )) as u64,
        file
    );
    // Exhaust the shared node pool from the guest venue.
    let far = LINUX_MMAP_BASE + 64 * PAGE;
    let mut index = 0;
    loop {
        let prot = if index % 2 == 0 {
            ReservationProtection::READ_WRITE
        } else {
            READ
        };
        match root.guest_mmap(Placement::Fixed(far + index * 2 * PAGE), PAGE, prot) {
            Ok(_) => index += 1,
            Err(Refusal::MetadataRequired) => break,
            Err(other) => panic!("unexpected refusal {other:?}"),
        }
    }
    // Host-served edits that split host rows need nodes after their
    // backend work: each one succeeds or answers ENOMEM, and the root
    // mirrors the host rows exactly either way.
    let mut answers = Vec::new();
    for page in (1..pages).step_by(2) {
        let outcome = call(
            &mut dispatcher,
            &mut memory,
            SYS_MPROTECT,
            [file + page * PAGE, PAGE, 0, 0, 0, 0],
        );
        assert!(
            outcome == DispatchOutcome::Returned { value: 0 }
                || outcome == DispatchOutcome::errno(LINUX_ENOMEM),
            "{outcome:?}"
        );
        answers.push(outcome);
        let (rows, mirror) = host_rows_and_mirror(&dispatcher, &root, file, file + pages * PAGE);
        assert_eq!(rows, mirror, "the root mirrors the host rows");
    }
    assert!(
        answers.contains(&DispatchOutcome::errno(LINUX_ENOMEM)),
        "an exhausted pool must eventually refuse: {answers:?}"
    );
    // A root-owned anonymous mmap with no node to propose from: ENOMEM.
    assert_eq!(
        host_mmap(&mut dispatcher, &mut memory, 0, PAGE, RW, ANON, -1),
        DispatchOutcome::errno(LINUX_ENOMEM)
    );
    // Unmapping whole mappings needs no node, so an exhausted process can
    // always recover: the freed nodes refill the host reserve and a
    // splitting edit is admitted again.
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MUNMAP,
            [file, pages * PAGE, 0, 0, 0, 0],
        )),
        0
    );
    let (rows, mirror) = host_rows_and_mirror(&dispatcher, &root, file, file + pages * PAGE);
    assert!(rows.is_empty() && mirror.is_empty(), "{rows:?} {mirror:?}");
    root.guest_munmap(far, 2 * PAGE);
    assert_eq!(
        returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            file,
            3 * PAGE,
            LINUX_PROT_READ,
            LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
            FILE_FD,
        )) as u64,
        file
    );
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut memory,
            SYS_MPROTECT,
            [file + PAGE, PAGE, 0, 0, 0, 0],
        )),
        0
    );
    let (rows, mirror) = host_rows_and_mirror(&dispatcher, &root, file, file + 3 * PAGE);
    assert_eq!(rows, mirror);
    assert_eq!(rows.len(), 3);
}

// ---------------------------------------------------------------------------
// S2: one move backend for root and host mremap relocations. A source the
// backend cannot reclaim fails the move before anything is published: the
// destination is rolled back and the source keeps its contents (mremap(2)
// fails with ENOMEM and changes nothing), never a retry and a carrier abort.
// ---------------------------------------------------------------------------

#[test]
fn mremap_move_with_an_unreclaimable_source_fails_without_a_second_owner() {
    for delegated in [false, true] {
        let mut dispatcher = SyscallDispatcher::new();
        let root = delegated.then(|| Root::admit(&dispatcher));
        let mut memory = arena_memory();
        let a = anon_mmap(&mut dispatcher, &mut memory, 0, 2 * PAGE);
        memory.write_bytes(a, b"keep").unwrap();
        // A read-only neighbour forces a move.
        let blocker = returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            a + 2 * PAGE,
            PAGE,
            LINUX_PROT_READ,
            ANON | LINUX_MAP_FIXED,
            -1,
        )) as u64;
        assert_eq!(blocker, a + 2 * PAGE);
        memory.set_fail_unmap_at(Some(a));
        let before = proc_rows(&dispatcher);
        assert_eq!(
            mremap(
                &mut dispatcher,
                &mut memory,
                [a, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0]
            ),
            DispatchOutcome::errno(LINUX_ENOMEM),
            "delegated={delegated}"
        );
        memory.set_fail_unmap_at(None);
        assert_eq!(proc_rows(&dispatcher), before, "delegated={delegated}");
        assert_eq!(memory.read_bytes(a, 4).unwrap(), b"keep");
        if let Some(root) = &root {
            let node = root.node(a).expect("the source stays a root mapping");
            assert_eq!((node.0, node.1, node.2), (a, a + 2 * PAGE, true));
        }
        // The move then succeeds once the source can be reclaimed.
        let moved = returned(mremap(
            &mut dispatcher,
            &mut memory,
            [a, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0],
        )) as u64;
        assert_ne!(moved, a);
        assert_eq!(memory.read_bytes(moved, 4).unwrap(), b"keep");
    }
}

/// The fixture `el1_delegated_root_concurrent_vma_ops` in miniature: the
/// pre-fork region, then A (protect the middle, cut its tail), B (punch a
/// hole), with the protect and unmap served by the guest venue. Every step
/// must read back from /proc exactly as on a host-setup MM, which is the
/// Linux answer (adjacent same-flag anonymous VMAs merge).
#[test]
fn delegated_served_mprotect_and_munmap_read_back_as_linux_rows() {
    let arena = |d: &SyscallDispatcher, _: &CountingMmapMemory| {
        proc_rows(d)
            .into_iter()
            .filter(|r| r.start >= LINUX_MMAP_BASE && r.start < LINUX_MMAP_BASE + 64 * PAGE)
            .map(|r| (r.start, r.end, r.read, r.write, r.execute, r.path))
            .collect::<Vec<_>>()
    };
    let mut twin = Twin::new();
    let shared = LINUX_MMAP_BASE + 5 * PAGE;
    let a = shared + 8 * PAGE;
    let b = a + 8 * PAGE;
    twin.host_anonymous(shared, 8 * PAGE, RW);
    for page in 0..8 {
        twin.touch(shared + page * PAGE);
    }
    twin.same("shared", arena);
    // Protect one page of the pre-fork region and restore it.
    twin.mprotect(shared + PAGE, PAGE, LINUX_PROT_READ);
    twin.same("protect shared page", arena);
    twin.mprotect(shared + PAGE, PAGE, RW);
    twin.same("restore shared page", arena);
    assert_eq!(
        arena(&twin.delegated, &twin.delegated_memory)
            .iter()
            .map(|r| (r.0, r.1))
            .collect::<Vec<_>>(),
        vec![(shared, shared + 8 * PAGE)],
        "one merged row after the restore"
    );
    twin.host_anonymous(a, 8 * PAGE, RW);
    twin.same("map A", arena);
    twin.mprotect(a + 3 * PAGE, 2 * PAGE, LINUX_PROT_READ);
    twin.same("protect A middle", arena);
    twin.host_anonymous(b, 4 * PAGE, RW);
    twin.munmap(b + PAGE, 2 * PAGE);
    twin.same("hole in B", arena);
    twin.munmap(a + 7 * PAGE, PAGE);
    twin.same("unmap A tail", arena);
    twin.mprotect(shared + 2 * PAGE, PAGE, LINUX_PROT_READ);
    twin.same("protect shared page again", arena);
    twin.mprotect(shared + 2 * PAGE, PAGE, RW);
    twin.same("restore shared page again", arena);
}

/// After a fork both MMs see the pre-fork region: an mprotect and restore of
/// one page must leave ONE row in the parent (root rows) and in the child
/// (host-setup rows).
#[test]
fn delegated_fork_then_protect_restore_leaves_one_row_in_both_mms() {
    use carrick_abi::LinuxProtFlags;
    let dispatcher = SyscallDispatcher::new();
    let root = Root::admit(&dispatcher);
    let shared = root
        .guest_mmap(
            Placement::Anywhere,
            8 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let child_mm = crate::kernel::MmId::from_registry_allocation(
        std::num::NonZeroU64::new(root.mm.raw() + 1).unwrap(),
    );
    let child = dispatcher.mm_authority().fork_private(child_mm);
    let rows = |regions: Vec<ProcMapsEntry>| {
        regions
            .into_iter()
            .filter(|r| r.start >= shared && r.start < shared + 8 * PAGE)
            .map(|r| (r.start, r.end))
            .collect::<Vec<_>>()
    };
    let whole = vec![(shared, shared + 8 * PAGE)];
    assert_eq!(rows(child.lock().proc_regions().unwrap()), whole);
    for prot in [
        LinuxProtFlags::READ,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    ] {
        child
            .lock()
            .set_mapping_prot(shared + PAGE, shared + 2 * PAGE, prot);
    }
    assert_eq!(
        rows(child.lock().proc_regions().unwrap()),
        whole,
        "child after protect+restore"
    );
    root.guest_mprotect(shared + PAGE, PAGE, READ);
    root.guest_mprotect(shared + PAGE, PAGE, ReservationProtection::READ_WRITE);
    assert_eq!(
        rows(proc_rows(&dispatcher)),
        whole,
        "parent after protect+restore"
    );
}

// S3 T4: the ONE production admission (`admit_el1_reservations`) at bind
// and at fork commit.

/// A copied-MM fork of `dispatcher` through the production prepare/commit
/// pair: the child dispatcher, its root not yet published.
fn fork_child(dispatcher: &SyscallDispatcher) -> SyscallDispatcher {
    let parent_mm = dispatcher.mm_authority().mm_id;
    let child_mm = crate::kernel::MmId::from_registry_allocation(
        std::num::NonZeroU64::new(parent_mm.raw() + 1).unwrap(),
    );
    let prepared = dispatcher
        .prepare_fork_mm(parent_mm, child_mm, crate::kernel::CloneObjectMode::Copy)
        .unwrap();
    dispatcher
        .fork_clone_with_prepared_mm(parent_mm, child_mm, 100, 101, prepared)
        .ok()
        .unwrap()
}

/// The fork-commit admission of `child`, holding both MM permits.
fn fork_commit(
    parent: &SyscallDispatcher,
    child: &SyscallDispatcher,
) -> Result<El1Admission, Refusal> {
    crate::dispatch::mm_mutation::test_support::with_permit(
        parent.mm_mutation_coordinator(),
        |parent_permit| {
            crate::dispatch::mm_mutation::test_support::with_permit(
                child.mm_mutation_coordinator(),
                |permit| {
                    child.mem_view().admit_el1_reservations(
                        permit,
                        El1AdmissionOrigin::ForkCommit {
                            parent,
                            parent_permit,
                        },
                        true,
                    )
                },
            )
        },
    )
}

/// Every placement, `/proc` and charge answer an MM gives. `/proc` is read
/// per page over the image and the arena: host setup coalesces adjacent
/// rows whose lock or dump attributes differ, where Linux (and the root)
/// keeps separate VMAs, and host setup renders the loader's whole heap
/// backing row where the root renders `[heap]` up to the break (asserted
/// separately).
#[derive(Debug, PartialEq)]
struct MmAnswers {
    proc: Vec<ProcPage>,
    committed: u64,
    data: u64,
    locked: u64,
    brk: u64,
    high_water: u64,
}

const IMAGE: u64 = 0x40_0000;

fn mm_answers(dispatcher: &SyscallDispatcher, a: u64) -> MmAnswers {
    let authority = dispatcher.mem();
    let mem = authority.lock();
    let answers = MmAnswers {
        proc: Vec::new(),
        committed: committed_va_bytes(&mem),
        data: data_va_bytes(&mem),
        locked: mem.locked_bytes(),
        brk: mem.program_break(),
        high_water: mem.arena_high_water(),
    };
    drop(mem);
    let mut proc = proc_pages(dispatcher, IMAGE, 2);
    proc.extend(proc_pages(dispatcher, a, 6));
    MmAnswers { proc, ..answers }
}

const MADV_DONTDUMP: u64 = 16;

/// A mixed host-setup MM: anonymous rows (one mprotected, one locked, one
/// `MADV_DONTDUMP`), a heap, a private file mapping and a boot image region
/// outside the heap/arena layout.
fn populated_host_setup_mm() -> (SyscallDispatcher, CountingMmapMemory, u64) {
    let mut dispatcher = SyscallDispatcher::new();
    install_host_file_fd(&dispatcher, FILE_FD, &[0x5a; PAGE as usize]);
    let layout = dispatcher.mem().lock().layout;
    let region = |start: u64, end: u64, path: &str| ProcMapsEntry {
        start,
        end,
        read: true,
        write: true,
        execute: false,
        sharing: carrick_vfs::ProcMapSharing::Private,
        path: path.to_owned(),
    };
    // The boot image and the heap backing row the loader publishes.
    dispatcher.mem().lock().address_space_regions = Some(vec![
        region(IMAGE, IMAGE + 2 * PAGE, "/bin/image"),
        region(layout.heap_base, layout.heap_base + layout.heap_size, ""),
    ]);
    let mut memory = arena_memory();
    let a = anon_mmap(&mut dispatcher, &mut memory, 0, 4 * PAGE);
    returned(host_mmap(
        &mut dispatcher,
        &mut memory,
        a + 4 * PAGE,
        PAGE,
        LINUX_PROT_READ,
        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
        FILE_FD,
    ));
    for (number, args) in [
        (SYS_MPROTECT, [a + PAGE, PAGE, LINUX_PROT_READ, 0, 0, 0]),
        (SYS_MLOCK, [a + 2 * PAGE, PAGE, 0, 0, 0, 0]),
        (SYS_MADVISE, [a + 3 * PAGE, PAGE, MADV_DONTDUMP, 0, 0, 0]),
    ] {
        assert_eq!(
            returned(call(&mut dispatcher, &mut memory, number, args)),
            0
        );
    }
    let heap = dispatcher.mem().lock().layout.heap_base;
    let mut heap_memory = CountingMmapMemory::new(heap, (4 * PAGE) as usize);
    assert_eq!(
        returned(call(
            &mut dispatcher,
            &mut heap_memory,
            SYS_BRK,
            [heap + 2 * PAGE, 0, 0, 0, 0, 0],
        )) as u64,
        heap + 2 * PAGE
    );
    (dispatcher, memory, a)
}

#[test]
fn delegated_bind_admission_is_exact_against_its_host_setup_twin() {
    let (twin, twin_memory, a) = populated_host_setup_mm();
    let (live, live_memory, b) = populated_host_setup_mm();
    assert_eq!(a, b);
    let before = mm_answers(&live, a);
    assert_eq!(before, mm_answers(&twin, a));

    let root = Root::admit(&live);
    assert!(live.mem().lock().delegated_root().is_some());
    // The anonymous rows left the host; the root owns them with their
    // protections and attributes.
    assert!(host_owns_no_anonymous_row(&live, a, a + 4 * PAGE));
    assert_eq!(
        root.node(a + PAGE),
        Some((a + PAGE, a + 2 * PAGE, true, ANON_FLAGS))
    );
    assert_eq!(
        root.node(a + 2 * PAGE),
        Some((a + 2 * PAGE, a + 3 * PAGE, true, ANON_FLAGS | LOCKED))
    );
    assert!(
        root.lock()
            .mapping(a + 4 * PAGE)
            .is_some_and(|m| !m.anonymous)
    );
    assert_eq!(
        root.lock().mapping(a + PAGE).map(|m| m.protection),
        Some(READ)
    );
    // Every reader answers as the host-setup twin: rows, /proc, charges.
    assert_eq!(mm_answers(&live, a), before);
    // The root renders the heap as Linux does: `[heap]` up to the break.
    let heap = live.mem().lock().layout.heap_base;
    let rw_heap = Some((true, true, false, "[heap]".to_owned()));
    assert_eq!(
        proc_pages(&live, heap, 4),
        [rw_heap.clone(), rw_heap, None, None]
    );
    assert_eq!(
        mincore(&live, &live_memory, a, 5),
        mincore(&twin, &twin_memory, a, 5)
    );
    let pages: Vec<u64> = (0..5).map(|page| a + page * PAGE).collect();
    assert_eq!(fault_answers(&live, &pages), fault_answers(&twin, &pages));
    // Idempotent for its own root.
    assert_eq!(
        admit(&live, El1AdmissionOrigin::Bind, true),
        Ok(El1Admission::Delegated)
    );
}

#[test]
fn delegated_bind_admission_seals_the_exact_external_charges() {
    let (dispatcher, _memory, a) = populated_host_setup_mm();
    let root = Root::publish(&dispatcher);
    assert_eq!(
        admit(&dispatcher, El1AdmissionOrigin::Bind, true),
        Ok(El1Admission::Delegated)
    );
    // The boot image is the only mapping the root does not hold: two
    // private writable pages of address space and of data.
    let layout = root.lock().layout();
    assert_eq!(
        (layout.external_address_bytes, layout.external_data_bytes),
        (2 * PAGE, 2 * PAGE)
    );
    let charges = root.lock().charges();
    let answers = mm_answers(&dispatcher, a);
    assert_eq!(
        charges.bytes + layout.external_address_bytes,
        answers.committed
    );
    assert_eq!(charges.data + layout.external_data_bytes, answers.data);
}

#[test]
fn delegated_bind_admission_decides_against_a_finite_rlimit_from_its_first_proposal() {
    let (dispatcher, _memory, _) = populated_host_setup_mm();
    let root = Root::publish(&dispatcher);
    let committed = committed_va_bytes(&dispatcher.mem().lock());
    dispatcher
        .capture_one_task_context()
        .unwrap()
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                committed + PAGE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_AS");
    assert_eq!(
        admit(&dispatcher, El1AdmissionOrigin::Bind, true),
        Ok(El1Admission::Delegated)
    );
    // No host step ran since the admission: the guest venue's first
    // decisions see the whole MM's charges.
    assert_eq!(
        root.guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE
        ),
        Err(Refusal::Limit)
    );
    assert!(
        root.guest_mmap(Placement::Anywhere, PAGE, ReservationProtection::READ_WRITE)
            .is_ok()
    );
}

#[test]
fn delegated_admission_hatch_keeps_the_mm_in_host_setup() {
    let (dispatcher, _memory, a) = populated_host_setup_mm();
    let root = Root::publish(&dispatcher);
    let before = mm_answers(&dispatcher, a);
    // `CARRICK_EL1_RESERVATIONS=0`: the same entry point admits nothing.
    assert_eq!(
        admit(&dispatcher, El1AdmissionOrigin::Bind, false),
        Ok(El1Admission::HostSetup)
    );
    assert!(dispatcher.mem().lock().host_arena().is_some());
    assert!(!root.lock().is_admitted());
    assert!(root.lock().mapping(a).is_none());
    assert_eq!(mm_answers(&dispatcher, a), before);
    // A carrier without a provider is host setup too.
    let (bare, _bare_memory, _) = populated_host_setup_mm();
    assert_eq!(
        admit(&bare, El1AdmissionOrigin::Bind, true),
        Ok(El1Admission::HostSetup)
    );
}

#[test]
fn delegated_fork_commit_seeds_a_delegated_child_root_with_the_parents_rows() {
    let (parent, _memory, a) = populated_host_setup_mm();
    let root = Root::admit(&parent);
    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let before = mm_answers(&parent, a);

    let child = fork_child(&parent);
    // A fork twin is sealed only by its fork commit, never as a bind.
    let child_root = root.publish_child(&child);
    assert_eq!(
        admit(&child, El1AdmissionOrigin::Bind, true),
        Err(Refusal::Stale)
    );
    assert_eq!(fork_commit(&parent, &child), Ok(El1Admission::Delegated));

    // The child stays delegated, its root seeded with the parent's rows.
    assert!(child.mem().lock().delegated_root().is_some());
    assert!(host_owns_no_anonymous_row(&child, a, a + 4 * PAGE));
    assert!(host_owns_no_anonymous_row(&child, guest, guest + 2 * PAGE));
    for address in [a, a + PAGE, a + 2 * PAGE, a + 3 * PAGE, a + 4 * PAGE, guest] {
        assert_eq!(
            child_root.lock().mapping(address).map(|m| (
                m.range,
                m.protection,
                m.anonymous,
                m.flags
            )),
            root.lock()
                .mapping(address)
                .map(|m| (m.range, m.protection, m.anonymous, m.flags)),
            "child root node at {address:#x}"
        );
    }
    assert_eq!(mm_answers(&child, a), before);
    // Idempotent for its own root.
    assert_eq!(fork_commit(&parent, &child), Ok(El1Admission::Delegated));

    // Two live MMs: each root moves on alone.
    root.guest_munmap(guest, 2 * PAGE);
    assert!(child_root.lock().mapping(guest).is_some());
    child_root.guest_munmap(a, PAGE);
    assert!(root.lock().mapping(a).is_some());
    assert!(proc_row_at(&parent, a).is_some());
    assert!(proc_row_at(&child, a).is_none());
    assert!(proc_row_at(&child, guest).is_some());
}

#[test]
fn delegated_fork_commit_refuses_a_parent_that_moved_on() {
    let (parent, _memory, _) = populated_host_setup_mm();
    let root = Root::admit(&parent);
    let child = fork_child(&parent);
    let child_root = root.publish_child(&child);
    // The parent root's generation moved after the twin was taken.
    root.guest_mmap(Placement::Anywhere, PAGE, ReservationProtection::READ_WRITE)
        .unwrap();
    assert_eq!(fork_commit(&parent, &child), Err(Refusal::Stale));
    assert!(child.mem().lock().host_arena().is_some());
    assert!(!child_root.lock().is_admitted());
}

// S3 T4b: returns guest EL1 deferred are reconciled by the host venue in one
// transaction and acknowledged; a fork commit derives the child's authority
// and admits its root.

impl Root {
    /// What guest EL1 does for `munmap` of RESIDENT anonymous memory: retire
    /// its stage-1 terminals in place and journal the range as a return the
    /// host owes (`complete_deferring_return`), frames still in inventory.
    fn guest_munmap_resident(&self, start: u64, len: u64) {
        let mut root = self.lock();
        let range = ReservationRange::new(start, start + len).unwrap();
        let Decision::Work(request) = root.munmap(range).unwrap() else {
            panic!("a resident munmap carries work");
        };
        let slot = root.reserve_return(range).unwrap();
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete_deferring_return(completion, slot).unwrap();
    }

    /// The extents this root owes the host.
    fn owed(&self) -> Vec<(u64, u64)> {
        let mut owed = Vec::new();
        self.lock().observe_deferred_returns(&mut |entry| {
            owed.push((entry.range.start(), entry.range.end()));
        });
        owed
    }
}

/// `dispatcher`'s reconciliation at a host boundary, under its own permit.
fn reconcile(
    dispatcher: &SyscallDispatcher,
    memory: &mut CountingMmapMemory,
) -> Result<usize, crate::dispatch::mem::el1_reservations::El1ReturnError> {
    crate::dispatch::mm_mutation::test_support::with_permit(
        dispatcher.mm_mutation_coordinator(),
        |permit| dispatcher.reconcile_el1_deferred_returns(permit, memory),
    )
}

#[test]
fn delegated_el1_resident_munmap_reconciles_at_the_next_host_boundary() {
    let (dispatcher, mut memory, _) = populated_host_setup_mm();
    let root = Root::admit(&dispatcher);
    let first = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    let second = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    // Two EL1-served resident munmaps: both owed, VA not placeable again.
    root.guest_munmap_resident(first, 2 * PAGE);
    root.guest_munmap_resident(second + PAGE, PAGE);
    let owed = root.owed();
    assert_eq!(owed.len(), 2, "{owed:x?}");
    assert!(dispatcher.el1_returns_owed());
    assert_eq!(
        root.guest_mmap(
            Placement::Fixed(first),
            PAGE,
            ReservationProtection::READ_WRITE
        ),
        Err(Refusal::Busy)
    );

    // The next host boundary: ONE transaction retires every owed extent
    // through the backend (its frames return), then acknowledges.
    memory.unmap_log.borrow_mut().clear();
    assert_eq!(reconcile(&dispatcher, &mut memory).unwrap(), 2);
    let mut retired = memory.unmap_log.borrow().clone();
    retired.sort_unstable();
    let mut expected: Vec<(u64, usize)> = owed
        .iter()
        .map(|&(start, end)| (start, (end - start) as usize))
        .collect();
    expected.sort_unstable();
    assert_eq!(retired, expected, "each owed extent retired exactly once");
    assert!(root.owed().is_empty());
    assert!(!dispatcher.el1_returns_owed());
    // Acknowledged: the VAs are placeable again, by either venue.
    assert_eq!(
        root.guest_mmap(
            Placement::Fixed(first),
            PAGE,
            ReservationProtection::READ_WRITE
        ),
        Ok(first)
    );
    // Idempotent: nothing is owed, nothing retires again.
    memory.unmap_log.borrow_mut().clear();
    assert_eq!(reconcile(&dispatcher, &mut memory).unwrap(), 0);
    assert!(memory.unmap_log.borrow().is_empty());
}

#[test]
fn delegated_failed_return_reconciliation_acknowledges_nothing() {
    let (dispatcher, mut memory, _) = populated_host_setup_mm();
    let root = Root::admit(&dispatcher);
    let first = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    root.guest_munmap_resident(first, 2 * PAGE);
    memory.set_fail_unmap_at(Some(first));
    assert!(matches!(
        reconcile(&dispatcher, &mut memory),
        Err(crate::dispatch::mem::el1_reservations::El1ReturnError::Backend { .. })
    ));
    // Still owed: the frames stay unreusable until a retirement succeeds.
    assert_eq!(root.owed(), vec![(first, first + 2 * PAGE)]);
    memory.set_fail_unmap_at(None);
    assert_eq!(reconcile(&dispatcher, &mut memory).unwrap(), 1);
    assert!(root.owed().is_empty());
}

#[test]
fn delegated_host_mmap_over_an_owed_range_reconciles_first() {
    let (mut dispatcher, mut memory, _) = populated_host_setup_mm();
    let root = Root::admit(&dispatcher);
    let first = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    root.guest_munmap_resident(first, 2 * PAGE);
    // A host MAP_FIXED over the owed range: the host venue reconciles the
    // owed return before it plans, so the Prepare lands on settled memory.
    memory.unmap_log.borrow_mut().clear();
    assert_eq!(
        returned(host_mmap(
            &mut dispatcher,
            &mut memory,
            first,
            PAGE,
            RW,
            ANON | LINUX_MAP_FIXED,
            -1,
        )) as u64,
        first
    );
    assert!(root.owed().is_empty());
    assert_eq!(
        memory.unmap_log.borrow().first().copied(),
        Some((first, (2 * PAGE) as usize))
    );
    assert!(root.lock().mapping(first).is_some_and(|m| m.anonymous));
}

#[test]
fn delegated_final_settlement_drains_owed_returns() {
    let (dispatcher, _memory, _) = populated_host_setup_mm();
    let root = Root::admit(&dispatcher);
    let first = root
        .guest_mmap(
            Placement::Anywhere,
            4 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    root.guest_munmap_resident(first, 2 * PAGE);
    root.guest_munmap_resident(first + 3 * PAGE, PAGE);
    assert_eq!(root.owed().len(), 2);
    // Final-MM settlement (`mm_occupancy::retire_reservation_root`): owed
    // returns never make the root Busy; every extent is released with it.
    assert_eq!(
        crate::dispatch::mem::el1_reservations::settle_final_root(root.lock()),
        Ok(2)
    );
    let slot = root.carrier.slot(root.mm).unwrap();
    // The root is gone and its journal slots are free for another MM.
    assert_eq!(
        root.carrier.table.lock(slot, root.mm).err(),
        Some(Refusal::Stale)
    );
    let other = SyscallDispatcher::new();
    let other_root = Root {
        carrier: root.carrier.clone(),
        mm: root.carrier.publish(&other),
    };
    let model = other_root.lock();
    let mut owed = 0;
    model.observe_deferred_returns(&mut |_| owed += 1);
    assert_eq!(owed, 0);
}

/// The parent's fork transaction over `child`, as `commit_parent` holds it.
fn with_fork_commit<T>(
    parent: &SyscallDispatcher,
    child: &SyscallDispatcher,
    step: impl FnOnce(
        Result<
            crate::dispatch::mm_mutation::ForkCommit<'_>,
            crate::dispatch::mm_mutation::ForkCommitRefusal,
        >,
    ) -> T,
) -> T {
    crate::dispatch::mm_mutation::test_support::with_guard(
        parent.mm_mutation_coordinator(),
        |guard| {
            let topology = guard.begin_transaction();
            step(guard.fork_commit(&topology, child))
        },
    )
}

#[test]
fn fork_commit_admits_the_published_child_root() {
    let (parent, mut memory, a) = populated_host_setup_mm();
    let root = Root::admit(&parent);
    let guest = root
        .guest_mmap(
            Placement::Anywhere,
            2 * PAGE,
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    // An owed return before the fork: the fork boundary reconciles first,
    // so the child is seeded from settled memory.
    root.guest_munmap_resident(guest, PAGE);
    assert_eq!(reconcile(&parent, &mut memory).unwrap(), 1);
    let child = fork_child(&parent);
    let admitted = with_fork_commit(&parent, &child, |commit| {
        let commit = commit.expect("a fork commit over the parent's own twin");
        assert_eq!(commit.child_mm(), child.mm_authority().mm_id);
        // The carrier publishes the child's root (production:
        // `publish_child_address_space` from its `Stage1MmLease`).
        let child_root = root.publish_child(&child);
        (commit.admit_child_root(&parent), child_root)
    });
    let (admission, child_root) = admitted;
    assert_eq!(admission, Ok(El1Admission::Delegated));
    assert!(child.mem().lock().delegated_root().is_some());
    assert!(child_root.lock().mapping(a).is_some());
    assert!(child_root.lock().mapping(guest + PAGE).is_some());
    assert!(child_root.lock().mapping(guest).is_none());
}

#[test]
fn fork_commit_cannot_be_forged_outside_a_fork() {
    let (parent, _memory, _) = populated_host_setup_mm();
    let root = Root::admit(&parent);
    let child = fork_child(&parent);
    // The parent itself is no child.
    with_fork_commit(&parent, &parent, |commit| {
        assert_eq!(
            commit.err(),
            Some(crate::dispatch::mm_mutation::ForkCommitRefusal::SharedMm)
        );
    });
    // A transaction another MM's guard minted names no fork of this parent.
    let (stranger, _, _) = populated_host_setup_mm();
    crate::dispatch::mm_mutation::test_support::with_guard(
        parent.mm_mutation_coordinator(),
        |guard| {
            crate::dispatch::mm_mutation::test_support::with_guard(
                stranger.mm_mutation_coordinator(),
                |other| {
                    let foreign = other.begin_transaction();
                    assert_eq!(
                        guard.fork_commit(&foreign, &child).err(),
                        Some(crate::dispatch::mm_mutation::ForkCommitRefusal::ForeignTransaction)
                    );
                },
            );
        },
    );
    // Another parent's fork twin is not this parent's child.
    let stranger_root = Root::admit(&stranger);
    let strangers_child = fork_child(&stranger);
    with_fork_commit(&parent, &strangers_child, |commit| {
        assert_eq!(
            commit.err(),
            Some(crate::dispatch::mm_mutation::ForkCommitRefusal::NotThisParentsChild)
        );
    });
    drop(stranger_root);
    // An MM that published its address space may have run: no commit.
    child.mm_authority().seal_reservation_provider();
    with_fork_commit(&parent, &child, |commit| {
        assert_eq!(
            commit.err(),
            Some(crate::dispatch::mm_mutation::ForkCommitRefusal::ChildPublished)
        );
    });
    drop(root);
}
