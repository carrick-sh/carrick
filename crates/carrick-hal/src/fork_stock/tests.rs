#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, El1MmHandle, EntryGeneration, EntryMmKey, EntryTaskKey,
    EntryThreadGeneration, ForkStockRequest, PortalForkCompletion, PortalOperation,
    ReservationGeneration,
};
use carrick_guest_arch::{ContextGeneration, FrameGpa, KernelVa, MmGeneration};
use std::cell::RefCell;

const CARRIER: NonZeroU64 = NonZeroU64::new(7).unwrap();
const PARENT_MM: u64 = 301;

fn page(addr: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(addr)).unwrap()
}

fn mm(raw: u64) -> ReservationMm {
    ReservationMm::new(raw).unwrap()
}

fn execution(task: u64, cpu: u32, mm: u64, root: u64) -> GrantExecution {
    GrantExecution::new(
        CpuId::new(cpu),
        ExecutionBinding {
            task: EntryTaskKey::from_raw(task),
            generation: EntryGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(mm),
            thread_generation: EntryThreadGeneration::from_raw(101),
        },
        AddressContext {
            mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
            root: page(root),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        },
    )
}

fn parent() -> GrantExecution {
    execution(41, 0, PARENT_MM, 0x1000)
}

fn request(exec: GrantExecution, child_mm: u64, child: u64, parent: u64) -> ForkStockRequest {
    ForkStockRequest {
        binding: exec.binding,
        context: exec.context,
        operation: PortalOperation {
            carrier: CARRIER,
            mm: mm(exec.context.mm.raw().get()),
            incarnation: NonZeroU64::MIN,
            sequence: NonZeroU64::new(2).unwrap(),
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_mm: mm(child_mm),
        child_bytes: child * 4096,
        parent_bytes: parent * 4096,
    }
}

fn lifecycles(count: u64) -> Vec<ForkLifecycleLoan> {
    (0..count)
        .map(|n| {
            let page = EL1_DYNAMIC_METADATA_BASE + 0x4000 + n * 0x4000;
            ForkLifecycleLoan::new_for_base(
                EL1_DYNAMIC_METADATA_BASE,
                KernelVa::new(page),
                KernelVa::new(page + 0x1000),
            )
            .unwrap()
        })
        .collect()
}

fn stock<T: ChildAddressTags>(tags: T, pages: u64, records: u64) -> ForkStock<T> {
    let mut stock = ForkStock::new(CARRIER, 0x1_0000_0000, tags);
    stock
        .install(
            (0..pages).map(|n| page(0x20_0000 + n * 4096)).collect(),
            lifecycles(records),
        )
        .unwrap();
    stock
}

fn loan<T: ChildAddressTags>(
    stock: &mut ForkStock<T>,
    exec: GrantExecution,
    child_mm: u64,
    child: u64,
    parent: u64,
) -> Result<ForkStockLoan, ForkStockRefusal> {
    let mut exchange = ForkStockExchange::new(request(exec, child_mm, child, parent)).unwrap();
    stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| true)
}

fn commit<T: ChildAddressTags>(
    stock: &mut ForkStock<T>,
    exec: GrantExecution,
    loan: ForkStockLoan,
    child_used: u64,
    parent_used: u64,
) -> Result<(), ForkStockServiceError> {
    let completion = PortalForkCompletion {
        request: loan.request,
        // SAFETY: test receipt for the exact admitted loan.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, loan.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: child_used * 4096,
        parent_tables_used: parent_used * 4096,
    };
    let mut settlement =
        ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    stock.settle(
        &mut NoTableLedger,
        exec,
        &mut settlement,
        |_| true,
        |_| true,
        |_| true,
    )
}

/// The child's own execution: its root is the loaned child table base.
fn child_of(loan: ForkStockLoan, task: u64) -> GrantExecution {
    execution(
        task,
        1,
        loan.request.child_mm.raw(),
        loan.request.child_tables.base,
    )
}

fn retire<T: ChildAddressTags>(
    stock: &mut ForkStock<T>,
    child: GrantExecution,
) -> Result<(), ForkStockServiceError> {
    let mut record = NativeChildRetire::new(child.binding, child.context).unwrap();
    let result = stock.retire_child(child, &mut record);
    // The typed reply in the record always agrees with the result.
    assert_eq!(
        record.take(child.binding, child.context),
        Some(if result.is_ok() {
            Ok(())
        } else {
            Err(carrick_el1_abi::ChildRetireRefusal::Stale)
        })
    );
    result
}

/// Occupancy proof for a test where no slot installs anything.
fn absent(mm: ReservationMm) -> Option<SlotAbsence> {
    SlotAbsence::scan(mm, [])
}

fn reclaim<T: ChildAddressTags>(
    stock: &mut ForkStock<T>,
    safe: impl Fn(ReservationMm) -> bool,
    cleared: &RefCell<Vec<RootGpa>>,
) -> usize {
    stock
        .reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            |mm| {
                let installed = (!safe(mm)).then_some(mm.raw());
                SlotAbsence::scan(mm, installed)
            },
            |pages| {
                cleared.borrow_mut().extend_from_slice(pages);
                true
            },
            |_| true,
            |_| true,
        )
        .unwrap()
}

fn sequential_cycles_beyond_stock<T: ChildAddressTags>(tags: T) -> ForkStock<T> {
    let mut stock = stock(tags, 4, 1);
    let pages = stock.table_stock().len();
    let cleared = RefCell::new(Vec::new());
    let cycles = 2 * pages as u64 + 1;
    for cycle in 0..cycles {
        let child_mm = 302 + cycle;
        let granted = loan(&mut stock, parent(), child_mm, 1, 1)
            .unwrap_or_else(|refusal| panic!("cycle {cycle}: {refusal:?}"));
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
        assert!(!stock.lifecycle_available(), "one record, one live child");
        retire(&mut stock, child_of(granted, 900 + cycle)).unwrap();
        assert_eq!(reclaim(&mut stock, |_| true, &cleared), 1);
        assert_eq!(stock.table_stock().len(), pages);
        assert!(stock.lifecycle_available());
        assert_eq!(stock.live_children(), 0);
    }
    let counters = stock.counters();
    assert_eq!(counters.loans, cycles);
    assert_eq!(counters.quarantined_children, cycles);
    assert_eq!(counters.returned_children, cycles);
    assert_eq!(counters.capacity_refusals, 0);
    assert_eq!(cleared.borrow().len(), cycles as usize);
    stock
}

#[test]
fn untagged_sequential_fork_retire_cycles_exceed_stock() {
    sequential_cycles_beyond_stock(UntaggedRoots);
}

#[test]
fn asid_tagged_sequential_fork_retire_cycles_exceed_stock_and_tags() {
    let asids = AsidAllocator::with_limit_for_tests(2);
    let stock = sequential_cycles_beyond_stock(asids.clone());
    // Every child ASID was retired and acknowledged: two are reusable.
    let a = asids.allocate().unwrap();
    let b = asids.allocate().unwrap();
    assert_ne!(a.asid(), b.asid());
    assert_eq!(stock.tags().allocate(), Err(AsidError::Exhausted));
}

#[test]
fn quarantined_stock_is_never_reissued_while_its_mm_is_live() {
    let mut stock = stock(UntaggedRoots, 4, 2);
    let first = loan(&mut stock, parent(), 302, 3, 1).unwrap();
    commit(&mut stock, parent(), first, 3, 0).unwrap();
    let child = child_of(first, 900);
    retire(&mut stock, child).unwrap();
    let held = stock.quarantined_tables();
    assert_eq!(held.len(), 3);
    assert!(stock.is_quarantined(mm(302)));

    // A slot still has the child installed: nothing returns.
    let cleared = RefCell::new(Vec::new());
    assert_eq!(
        reclaim(&mut stock, |candidate| candidate != mm(302), &cleared),
        0
    );
    // The child itself is the servicing CPU's MM: nothing returns.
    assert_eq!(
        stock
            .reclaim(
                &mut NoTableLedger,
                mm(302),
                absent,
                |_| true,
                |_| true,
                |_| true
            )
            .unwrap(),
        0
    );
    assert!(cleared.borrow().is_empty());
    assert!(held.iter().all(|page| !stock.table_stock().contains(page)));

    // The next fork cannot borrow quarantined pages: counted EAGAIN.
    assert_eq!(
        loan(&mut stock, parent(), 303, 3, 1),
        Err(ForkStockRefusal::Capacity)
    );
    assert_eq!(stock.counters().capacity_refusals, 1);

    // Absent from every slot: cleared, then reusable.
    assert_eq!(reclaim(&mut stock, |_| true, &cleared), 1);
    assert_eq!(*cleared.borrow(), held);
    let second = loan(&mut stock, parent(), 303, 3, 1).unwrap();
    let reissued = stock.pending(CpuId::new(0)).unwrap().child_tables.clone();
    assert!(reissued.iter().all(|page| held.contains(page)));
    assert_eq!(second.request.child_mm, mm(303));
}

#[test]
fn exhaustion_with_live_children_is_a_counted_capacity_refusal() {
    let mut stock = stock(UntaggedRoots, 16, 2);
    for child_mm in [302, 303] {
        let granted = loan(&mut stock, parent(), child_mm, 1, 1).unwrap();
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
    }
    assert!(!stock.lifecycle_available());
    for attempt in 1..=3 {
        assert_eq!(
            loan(&mut stock, parent(), 304, 1, 1),
            Err(ForkStockRefusal::Capacity)
        );
        assert_eq!(stock.counters().capacity_refusals, attempt);
    }
    assert!(stock.pending(CpuId::new(0)).is_none());
    assert_eq!(stock.table_stock().len(), 14);
}

#[test]
fn retire_requires_the_exact_committed_child_once() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    // Not yet committed.
    assert_eq!(
        retire(&mut stock, child_of(granted, 900)),
        Err(ForkStockServiceError::StaleExecution)
    );
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    // Foreign root for the right MM.
    let mut foreign = child_of(granted, 900);
    foreign.context.root = page(0x9000);
    assert_eq!(
        retire(&mut stock, foreign),
        Err(ForkStockServiceError::StaleExecution)
    );
    // A record naming another binding.
    let child = child_of(granted, 900);
    let mut other = NativeChildRetire::new(child_of(granted, 901).binding, child.context).unwrap();
    assert_eq!(
        stock.retire_child(child, &mut other),
        Err(ForkStockServiceError::StaleExecution)
    );
    retire(&mut stock, child).unwrap();
    assert_eq!(
        retire(&mut stock, child),
        Err(ForkStockServiceError::StaleExecution)
    );
    assert_eq!(stock.counters().quarantined_children, 1);
    assert_eq!(stock.counters().retire_refusals, 4);
}

#[test]
fn abort_returns_cleared_lifecycle_and_untouched_tables() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 2, 1).unwrap();
    let mut abort = ForkStockSettlement::abort(granted);
    // An unclearable lifecycle record keeps the loan outstanding.
    assert_eq!(
        stock.settle(
            &mut NoTableLedger,
            parent(),
            &mut abort,
            |_| true,
            |_| true,
            |_| false
        ),
        Err(ForkStockServiceError::MemoryAccessFailed)
    );
    assert!(stock.pending(CpuId::new(0)).is_some());
    let cleared = RefCell::new(None);
    stock
        .settle(
            &mut NoTableLedger,
            parent(),
            &mut abort,
            |_| true,
            |_| true,
            |life| {
                *cleared.borrow_mut() = Some(life);
                true
            },
        )
        .unwrap();
    assert_eq!(*cleared.borrow(), Some(granted.lifecycle));
    assert_eq!(stock.table_stock().len(), 4);
    assert!(stock.lifecycle_available());
}

#[test]
fn commit_refuses_dirty_unused_tables() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 2, 1).unwrap();
    let completion = PortalForkCompletion {
        request: granted.request,
        // SAFETY: test receipt for the exact admitted loan.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut settlement =
        ForkStockSettlement::new(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    assert_eq!(
        stock.settle(
            &mut NoTableLedger,
            parent(),
            &mut settlement,
            |_| true,
            |_| false,
            |_| true
        ),
        Err(ForkStockServiceError::ExposedDirtyTable)
    );
    assert!(stock.pending(CpuId::new(0)).is_some());
}

#[test]
fn stale_lifecycle_record_refuses_without_consuming_stock() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let exec = parent();
    let mut exchange = ForkStockExchange::new(request(exec, 302, 1, 1)).unwrap();
    assert_eq!(
        stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| false),
        Err(ForkStockRefusal::Inventory)
    );
    assert_eq!(stock.table_stock().len(), 4);
    assert!(stock.lifecycle_available());
    assert!(stock.pending(CpuId::new(0)).is_none());
}

/// Host bytes of an x86 CPL0 metadata window, aligned like the retained
/// carrier mapping.
struct MetadataBytes {
    words: Vec<u64>,
}

const X86_METADATA_LEN: u64 = 0x10_0000;
const X86_FORK_LIFECYCLE_OFFSET: u64 = 0x8_8000;

impl MetadataBytes {
    fn new() -> Self {
        Self {
            words: vec![0; (X86_METADATA_LEN / 8) as usize],
        }
    }

    fn window(&mut self) -> LifecycleWindow {
        let host = core::ptr::NonNull::new(self.words.as_mut_ptr().cast::<u8>()).unwrap();
        // SAFETY: the vector outlives every use of the window in the test.
        unsafe {
            LifecycleWindow::new(
                host,
                carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE,
                X86_METADATA_LEN,
            )
        }
    }
}

fn x86_lifecycles(count: u64) -> Vec<ForkLifecycleLoan> {
    let base = carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE;
    lifecycle_slots(base, base + X86_FORK_LIFECYCLE_OFFSET, count).unwrap()
}

/// The guest initializes its census in the loaned record before any task.
fn guest_initializes(window: LifecycleWindow, lifecycle: ForkLifecycleLoan) {
    let ranges = window.ranges(lifecycle).unwrap();
    for (ptr, len) in ranges {
        // SAFETY: in-window test bytes.
        unsafe { core::ptr::write_bytes(ptr, 0xa5, len) };
    }
    assert!(!window.is_zero(lifecycle));
}

fn x86_loan(
    stock: &mut ForkStock<UntaggedRoots>,
    window: LifecycleWindow,
    child_mm: u64,
) -> Result<ForkStockLoan, ForkStockRefusal> {
    let exec = parent();
    let mut exchange = ForkStockExchange::new(request(exec, child_mm, 1, 1)).unwrap();
    stock.loan(&mut NoTableLedger, exec, &mut exchange, |life| {
        window.is_zero(life)
    })
}

#[test]
fn kvm_lifecycle_window_cycles_exceed_stock_with_cleared_records() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(CARRIER, 0x1_0000_0000, UntaggedRoots);
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(2),
        )
        .unwrap();
    let cleared = RefCell::new(Vec::new());
    for cycle in 0..9 {
        let child_mm = 302 + cycle;
        let granted = x86_loan(&mut stock, window, child_mm)
            .unwrap_or_else(|refusal| panic!("cycle {cycle}: {refusal:?}"));
        guest_initializes(window, granted.lifecycle);
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
        retire(&mut stock, child_of(granted, 900 + cycle)).unwrap();
        let returned = stock
            .reclaim(
                &mut NoTableLedger,
                mm(PARENT_MM),
                absent,
                |pages| {
                    cleared.borrow_mut().extend_from_slice(pages);
                    true
                },
                |life| window.clear(life),
                |_| true,
            )
            .unwrap();
        assert_eq!(returned, 1);
        assert!(window.is_zero(granted.lifecycle));
    }
    assert_eq!(stock.counters().returned_children, 9);
    assert_eq!(stock.counters().capacity_refusals, 0);
}

#[test]
fn kvm_unclearable_lifecycle_record_is_never_reissued_dirty() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(CARRIER, 0x1_0000_0000, UntaggedRoots);
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(1),
        )
        .unwrap();
    let granted = x86_loan(&mut stock, window, 302).unwrap();
    guest_initializes(window, granted.lifecycle);
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    // A reclaim that skips clearing returns a dirty record: the next loan
    // must refuse it as stale inventory rather than hand it to a child.
    stock
        .reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert_eq!(
        x86_loan(&mut stock, window, 303),
        Err(ForkStockRefusal::Inventory)
    );
    assert!(stock.lifecycle_available());
    assert!(window.clear(granted.lifecycle));
    x86_loan(&mut stock, window, 303).unwrap();
}

#[test]
fn kvm_live_children_beyond_lifecycle_records_are_counted_refusals() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(CARRIER, 0x1_0000_0000, UntaggedRoots);
    stock
        .install(
            (0..32).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(8),
        )
        .unwrap();
    for child_mm in 302..310 {
        let granted = x86_loan(&mut stock, window, child_mm).unwrap();
        guest_initializes(window, granted.lifecycle);
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
    }
    assert_eq!(
        x86_loan(&mut stock, window, 310),
        Err(ForkStockRefusal::Capacity)
    );
    assert_eq!(stock.counters().capacity_refusals, 1);
    assert_eq!(stock.live_children(), 8);
}

#[test]
fn lifecycle_window_refuses_records_outside_the_window() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let outside = lifecycle_slots(
        carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE,
        carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE + X86_METADATA_LEN,
        1,
    )
    .unwrap()[0];
    assert!(!window.is_zero(outside));
    assert!(!window.clear(outside));
}

/// Fork the next child while the previous one is quarantined but still
/// installed on a slot: the new loan may never contain its pages. Then the
/// previous child leaves its slot and only it is reclaimed.
fn interleaved_cycles<T: ChildAddressTags>(tags: T, cycles: u64) -> ForkStock<T> {
    let mut stock = stock(tags, 6, 2);
    let mut installed: Option<ReservationMm> = None;
    let cleared = RefCell::new(Vec::new());
    for cycle in 0..cycles {
        let child_mm = 302 + cycle;
        let held = stock.quarantined_tables();
        let granted = loan(&mut stock, parent(), child_mm, 1, 1)
            .unwrap_or_else(|refusal| panic!("cycle {cycle}: {refusal:?}"));
        let issued = stock.pending(CpuId::new(0)).unwrap().child_tables.clone();
        assert!(
            issued.iter().all(|page| !held.contains(page)),
            "cycle {cycle}: reissued a page of an installed quarantined MM"
        );
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
        retire(&mut stock, child_of(granted, 900 + cycle)).unwrap();
        // The new child is still installed; the previous one has left.
        let previous = installed.replace(mm(child_mm));
        let still = installed;
        let returned = reclaim(&mut stock, |candidate| Some(candidate) != still, &cleared);
        assert_eq!(returned, usize::from(previous.is_some()), "cycle {cycle}");
        assert!(stock.is_quarantined(mm(child_mm)));
        if let Some(previous) = previous {
            assert!(!stock.is_quarantined(previous));
        }
    }
    assert_eq!(stock.counters().returned_children, cycles - 1);
    assert_eq!(stock.counters().capacity_refusals, 0);
    stock
}

#[test]
fn interleaved_untagged_cycles_never_reissue_installed_quarantine() {
    interleaved_cycles(UntaggedRoots, 20);
}

#[test]
fn interleaved_asid_cycles_never_reissue_installed_quarantine() {
    // Two live children at a time: one installed in quarantine, one forking.
    interleaved_cycles(AsidAllocator::with_limit_for_tests(2), 20);
}

#[test]
fn refused_release_keeps_the_child_quarantined_and_its_stock_held() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    let released = RefCell::new(Vec::new());
    assert_eq!(
        stock.reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |_| true,
            |child| {
                released.borrow_mut().push(child);
                false
            },
        ),
        Err(ForkStockServiceError::ReleaseRefused)
    );
    assert_eq!(*released.borrow(), vec![mm(302)]);
    assert!(stock.is_quarantined(mm(302)));
    assert_eq!(stock.table_stock().len(), 3);
    assert!(!stock.lifecycle_available());
}

#[test]
fn slot_absence_is_minted_only_when_no_slot_installs_the_mm() {
    assert!(SlotAbsence::scan(mm(302), [0, 303, 301]).is_some());
    assert!(SlotAbsence::scan(mm(302), [0, 302]).is_none());
    // A proof for another MM never licenses this one's reclaim.
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    let foreign = stock.reclaim(
        &mut NoTableLedger,
        mm(PARENT_MM),
        |_| SlotAbsence::scan(mm(999), []),
        |_| true,
        |_| true,
        |_| true,
    );
    assert_eq!(foreign, Ok(0));
    assert!(stock.is_quarantined(mm(302)));
}
