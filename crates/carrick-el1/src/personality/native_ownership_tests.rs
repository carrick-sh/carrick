//! N0 red reduction of the *production* reservation admission path.
//! No replacement portal is simulated here: these receipts deliberately retain
//! the host proposal venue and identify it as a violation of exclusive ownership.
use crate::memory::reservations::{Layout, SharedReservations};
use crate::memory::{
    AnonymousBackingProbe, AnonymousPermissionEditor, AnonymousRetirementEditor,
    DelegatedAnonymous, Stage1Backing, classify_stage1_range, serve_delegated_anonymous,
};
use carrick_el1_abi::CurrentTask;
use carrick_el1_abi::{
    Counters, ReservationMm, ReservationProtection, ReservationRange, TrapFrame,
};
use carrick_mmu_core::aarch64::{
    GuestPermissionEdit, GuestPermissionEditError, GuestRetirementError, HostArenaResolver,
    PageTableError, PageTableLayoutConfig, PageTableManager,
};
use carrick_sched_core::AddressSpaces;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const VA: u64 = 0x100000;
const PAGE: u64 = 4096;
const SYS_MMAP: u64 = 222;
const SYS_MUNMAP: u64 = 215;

fn reservations() -> Box<SharedReservations> {
    // SAFETY: the production shared region is zero-initialized before publish;
    // atomics accept zero and unpublished State storage is MaybeUninit.
    let raw = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
    assert!(!raw.is_null());
    // SAFETY: allocation has precisely this layout and is exclusively owned.
    unsafe { Box::from_raw(raw.cast()) }
}

struct Mm {
    task: CurrentTask,
    key: ReservationMm,
    slot: usize,
    ttbr0: u64,
}

fn admit(table: &SharedReservations, spaces: &AddressSpaces, key: u64, unrelated: usize) -> Mm {
    let ttbr0 = 0x800000 + key * 0x100000;
    let index = spaces.publish_closed(key, ttbr0, ttbr0).unwrap();
    let key = ReservationMm::new(key).unwrap();
    table
        .publish(
            index.index(),
            key,
            Layout {
                heap: ReservationRange::new(PAGE, VA).unwrap(),
                arena: ReservationRange::new(VA, 0x10000000).unwrap(),
                brk: PAGE,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    let mut root = table.lock(index.index(), key).unwrap();
    for n in 0..unrelated {
        let address = 0x1000000 + n as u64 * PAGE * 2;
        root.import(
            ReservationRange::new(address, address + PAGE).unwrap(),
            ReservationProtection::READ_WRITE,
            true,
        )
        .unwrap();
    }
    root.finish_import().unwrap();
    drop(root);
    spaces.open(index);
    assert!(table.admitted(index.index(), key));
    let task = CurrentTask::new();
    task.task_id.store(key.raw() + 100, Ordering::Relaxed);
    task.thread_serial.store(1, Ordering::Relaxed);
    task.zone_mm.store(key.raw(), Ordering::Relaxed);
    Mm {
        task,
        key,
        slot: index.index(),
        ttbr0,
    }
}

struct TableBacking {
    base: u64,
    words: Box<[AtomicU64]>,
}
// SAFETY: stable, aligned atomic storage, retained by the manager Arc. This
// fixture never concurrently invokes the host editor and the descriptor reader.
unsafe impl HostArenaResolver for TableBacking {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        let offset = usize::try_from(base.checked_sub(self.base)?).ok()?;
        (offset.is_multiple_of(8) && offset.checked_add(len)? <= self.words.len() * 8).then(|| {
            self.words
                .as_ptr()
                .cast::<u8>()
                .wrapping_add(offset)
                .cast_mut()
        })
    }
    fn publish_user_executable(&self, _output: u64, _len: u64) -> Result<(), PageTableError> {
        Ok(()) // No executable publication in this VM-free lazy-map reduction.
    }
}

struct LiveProbe {
    tables: PageTableManager,
    visits: Cell<usize>,
    callbacks: usize,
    probes: usize,
    backing: Arc<TableBacking>,
}
impl LiveProbe {
    fn new(base: u64) -> Self {
        let backing = Arc::new(TableBacking {
            base,
            words: (0..65536).map(|_| AtomicU64::new(0)).collect(),
        });
        let mut tables = PageTableManager::new(
            vec![0; 524288],
            base,
            PageTableLayoutConfig::new(VA, 524288, 0, 0),
        );
        // SAFETY: resolver owns stable zeroed primary table storage.
        unsafe {
            tables.make_live(backing.clone());
        }
        assert!(tables.is_live());
        Self {
            tables,
            visits: Cell::new(0),
            callbacks: 0,
            probes: 0,
            backing,
        }
    }
}
impl AnonymousBackingProbe for LiveProbe {
    fn backing(&mut self, ttbr0: u64, va: u64, len: u64) -> Stage1Backing {
        assert_eq!(ttbr0, self.tables.base());
        self.probes += 1;
        classify_stage1_range(
            &|pa| {
                self.visits.set(self.visits.get() + 1);
                let offset = usize::try_from(pa.checked_sub(self.tables.base())?).ok()?;
                self.backing
                    .words
                    .get(offset / 8)
                    .map(|word| word.load(Ordering::Acquire))
            },
            ttbr0,
            va,
            len,
        )
    }
    fn stock_span(&mut self, _mm: u64, _va: u64) -> Option<(u64, u64)> {
        None
    }
}
impl AnonymousPermissionEditor for LiveProbe {
    fn protect_and_invalidate(
        &mut self,
        _ttbr0: u64,
        _edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError> {
        panic!("lazy-only witness must not invoke resident protection")
    }
}
impl AnonymousRetirementEditor for LiveProbe {
    fn retire_and_invalidate(
        &mut self,
        _ttbr0: u64,
        _address: u64,
        _len: u64,
    ) -> Result<(), GuestRetirementError> {
        panic!("lazy-only witness must not invoke resident retirement")
    }
}

fn syscall(
    mm: &Mm,
    table: &SharedReservations,
    spaces: &AddressSpaces,
    editor: &mut LiveProbe,
    nr: u64,
    pages: u64,
) {
    let mut frame = TrapFrame::default();
    frame.x[8] = nr;
    frame.x[0] = VA;
    frame.x[1] = pages * PAGE;
    frame.x[2] = 3;
    frame.x[3] = 0x32; // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    frame.x[4] = u64::MAX;
    assert_eq!(
        serve_delegated_anonymous(
            &mut frame,
            &Counters::default(),
            &mm.task,
            spaces,
            table,
            editor
        ),
        DelegatedAnonymous::Served
    );
    assert_eq!(frame.x[0], if nr == SYS_MMAP { VA } else { 0 });
}

fn require_exclusive_owner(host_callbacks: usize) -> Result<(), &'static str> {
    if host_callbacks == 0 {
        Ok(())
    } else {
        Err("red_until_n1_host_semantic_venue_survives_admission")
    }
}

#[test]
fn production_nonfork_admission_retains_host_semantic_venue() {
    for pages in [16, 64, 256] {
        for unrelated in [16, 512] {
            let (table, spaces) = (reservations(), AddressSpaces::new());
            let a = admit(&table, &spaces, 17, unrelated);
            // Peer stays live at the same VA with 16 unrelated nodes.
            // Two 512-node roots exceed the current bootstrap node pool.
            let b = admit(&table, &spaces, 18, 16);
            let (mut ea, mut eb) = (LiveProbe::new(a.ttbr0), LiveProbe::new(b.ttbr0));
            for (mm, editor) in [(&a, &mut ea), (&b, &mut eb)] {
                syscall(mm, &table, &spaces, editor, SYS_MMAP, pages);
                let mut root = table.lock(mm.slot, mm.key).unwrap();
                let old = root
                    .fault_plan(VA, PAGE, ReservationProtection::READ_WRITE)
                    .unwrap();
                assert!(root.authenticate_fault(old));
                // This is an actual production permission to make a host
                // semantic proposal, not a callback invented by the fixture.
                root.begin_host_proposal().unwrap();
                editor.callbacks += 1;
                drop(root);
                syscall(mm, &table, &spaces, editor, SYS_MUNMAP, pages);
                syscall(mm, &table, &spaces, editor, SYS_MMAP, pages);
                let mut root = table.lock(mm.slot, mm.key).unwrap();
                assert!(
                    !root.authenticate_fault(old),
                    "retired generation must stay dead"
                );
                assert!(
                    root.mapping(VA)
                        .unwrap()
                        .protection
                        .permits(ReservationProtection::READ_WRITE)
                );
                let before = root.work;
                let peer = if mm.key == a.key { b.key } else { a.key };
                let mut foreign = root
                    .fault_plan(VA, PAGE, ReservationProtection::READ_WRITE)
                    .unwrap();
                foreign.mm = peer;
                assert!(!root.authenticate_fault(foreign));
                let visits = root.work - before;
                let failure = require_exclusive_owner(editor.callbacks)
                    .expect_err("red_until_n1_production_host_authority");
                assert!(failure.starts_with("red_until_n1_"));
                let own_unrelated = if mm.key == a.key { unrelated } else { 16 };
                println!(
                    "n0 pages={pages} unrelated={own_unrelated} mm={} table_visits={} vma_auth_visits={visits} host_semantic_proposals={} descriptor_probe_calls={} transfer_pins=unbound capacity_crossings=unbound verdict=red",
                    mm.key.raw(),
                    editor.visits.get(),
                    editor.callbacks,
                    editor.probes
                );
            }
        }
    }
}

#[test]
fn production_admitted_fork_uses_exclusive_owner_without_host_semantic_venue() {
    // The production fork API accepts exact root identity and physical table
    // supply only. Exercise its live graph COW publication and complete undo;
    // no host VMA/protection proposal can enter this operation.
    crate::personality::mm_portal::tests::owner_fork_child_has_live_private_cow_and_parent_stays_unchanged_on_abort();
}
