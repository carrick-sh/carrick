#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, El1MmHandle, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
    ForkStockRequest, PortalForkCompletion, PortalOperation, ReservationGeneration,
    SnapshotGeneration,
};
use carrick_guest_arch::{ContextGeneration, FrameGpa, KernelVa, MmGeneration};
use std::cell::RefCell;

#[test]
fn committed_child_retains_physical_custody_through_quarantine() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct PhysicalPin(Arc<AtomicUsize>);
    impl Drop for PhysicalPin {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicUsize::new(0));
    let mut stock: ForkStock<UntaggedRoots, PhysicalPin> = ForkStock::new(
        CARRIER,
        ForkControlCapacity::exclusive(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            lifecycles(1),
        )
        .unwrap();
    let parent = parent();
    let mut exchange = ForkStockExchange::new(request(parent, 302, 2, 1)).unwrap();
    let loan = stock
        .loan(&mut NoTableLedger, parent, &mut exchange, |_| true)
        .unwrap();
    let completion = PortalForkCompletion {
        request: loan.request,
        // SAFETY: exact admitted child fixture.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, loan.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut reserve =
        ForkStockSettlement::reserve(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    stock
        .reserve_custody(
            parent,
            &mut reserve,
            |_| true,
            |_| true,
            |_, _, _| Ok(PhysicalPin(Arc::clone(&dropped))),
        )
        .unwrap();
    let mut settlement = ForkStockSettlement::commit_reserved(loan, completion).unwrap();
    stock
        .settle(
            &mut NoTableLedger,
            parent,
            &mut settlement,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    let child = child_of(loan, 43);
    let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
    stock.retire_child(child, &mut retire).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
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
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn committed_child_weak_pin_venue_drops_carrier_without_reclaim_and_releases_on_drain() {
    use std::sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct CarrierFixture {
        pin_count: AtomicUsize,
        stock: Mutex<ForkStock<UntaggedRoots, WeakCarrierPin>>,
    }

    #[derive(Debug)]
    struct WeakCarrierPin(Weak<CarrierFixture>);

    impl Drop for WeakCarrierPin {
        fn drop(&mut self) {
            if let Some(carrier) = self.0.upgrade() {
                carrier.pin_count.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    let make_carrier = || {
        let carrier = Arc::new(CarrierFixture {
            pin_count: AtomicUsize::new(0),
            stock: Mutex::new(ForkStock::new(
                CARRIER,
                ForkControlCapacity::exclusive(0x1_0000_0000),
                UntaggedRoots,
            )),
        });
        {
            let mut stock = carrier.stock.lock().unwrap();
            stock
                .install(
                    (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
                    lifecycles(1),
                )
                .unwrap();
        }
        carrier.pin_count.fetch_add(1, Ordering::SeqCst);
        let pin = WeakCarrierPin(Arc::downgrade(&carrier));
        assert_eq!(carrier.pin_count.load(Ordering::SeqCst), 1);
        let parent = parent();
        let mut exchange = ForkStockExchange::new(request(parent, 302, 2, 1)).unwrap();
        let loan = carrier
            .stock
            .lock()
            .unwrap()
            .loan(&mut NoTableLedger, parent, &mut exchange, |_| true)
            .unwrap();
        let completion = PortalForkCompletion {
            request: loan.request,
            // SAFETY: exact admitted child fixture.
            child: unsafe {
                El1MmHandle::from_admitted_owner(CARRIER, loan.request.child_mm, NonZeroU64::MIN)
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let mut reserve =
            ForkStockSettlement::reserve(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
                .unwrap();
        carrier
            .stock
            .lock()
            .unwrap()
            .reserve_custody(parent, &mut reserve, |_| true, |_| true, |_, _, _| Ok(pin))
            .unwrap();
        let mut settlement = ForkStockSettlement::commit_reserved(loan, completion).unwrap();
        carrier
            .stock
            .lock()
            .unwrap()
            .settle(
                &mut NoTableLedger,
                parent,
                &mut settlement,
                |_| true,
                |_| true,
                |_| true,
            )
            .unwrap();
        assert_eq!(carrier.stock.lock().unwrap().live_children(), 1);
        carrier
    };

    // 1. Dropping the carrier with a committed child still in stock drops the carrier immediately.
    let carrier = make_carrier();
    let weak = Arc::downgrade(&carrier);
    drop(carrier);
    assert!(
        weak.upgrade().is_none(),
        "committed child retaining a Weak pin venue must not cycle the carrier"
    );

    // 2. Draining fork stock on VM destroy releases the committed child's stage-2 pin.
    let carrier = make_carrier();
    assert_eq!(carrier.pin_count.load(Ordering::SeqCst), 1);
    let drained = std::mem::replace(
        &mut *carrier.stock.lock().unwrap(),
        ForkStock::new(CARRIER, None, UntaggedRoots),
    );
    drop(drained);
    assert_eq!(carrier.stock.lock().unwrap().live_children(), 0);
    assert_eq!(
        carrier.pin_count.load(Ordering::SeqCst),
        0,
        "draining fork stock at teardown must release committed-child stage-2 pins"
    );
}

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
            generation: SnapshotGeneration::from_raw(11),
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
    let mut stock = ForkStock::new(CARRIER, ForkControlCapacity::exclusive(0x1_0000_0000), tags);
    if records != 0 {
        stock
            .install_control_capacity(
                (0..records)
                    .map(|n| ForkControlCapacity::exclusive(0x1_0000_0000 + n * 0x20_0000).unwrap())
                    .collect(),
            )
            .unwrap();
    }
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
    let mut reserve =
        ForkStockSettlement::reserve(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    stock
        .reserve_custody(exec, &mut reserve, |_| true, |_| true, |_, _, _| Ok(()))
        .map_err(|_| ForkStockServiceError::InvalidRecord)?;
    let mut settlement = ForkStockSettlement::commit_reserved(loan, completion).unwrap();
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
fn arm_fork_children_receive_distinct_control_capacity() {
    let mut stock = stock(AsidAllocator::with_limit_for_tests(2), 8, 2);
    let first = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), first, 1, 0).unwrap();
    let second = loan(&mut stock, parent(), 303, 1, 1).unwrap();
    assert_ne!(
        first.request.child_tables.base,
        second.request.child_tables.base
    );
    assert_ne!(
        first.request.kernel_control_ipa, second.request.kernel_control_ipa,
        "two live children must not copy their identity pages into one physical control window"
    );
}

#[test]
fn arm_control_windows_scale_past_eight_live_children() {
    let mut stock = ForkStock::new(CARRIER, None, AsidAllocator::new());
    stock
        .install(
            (0..64).map(|n| page(0x20_0000 + n * 4096)).collect(),
            lifecycles(12),
        )
        .unwrap();
    let mut controls = std::collections::BTreeSet::new();
    for child in 0..12 {
        assert!(stock.needs_control_capacity());
        stock
            .provide_arm_control_capacity(0x1_0000_0000 + child * CONTROL_WINDOW_BYTES)
            .unwrap();
        let granted = loan(&mut stock, parent(), 302 + child, 1, 1).unwrap();
        assert!(controls.insert(granted.request.kernel_control_ipa));
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
    }
    assert_eq!(stock.live_children(), 12);
    assert_eq!(stock.counters().capacity_refusals, 0);
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
fn abort_settle_is_atomic_on_tag_release_failure() {
    struct FailingReleaseTags;
    impl ChildAddressTags for FailingReleaseTags {
        type Tag = ();
        fn allocate(&mut self) -> Option<()> {
            Some(())
        }
        fn wire((): ()) -> Option<carrick_guest_arch::Asid> {
            None
        }
        fn release_unpublished(&mut self, (): ()) -> Result<(), ForkStockServiceError> {
            Err(ForkStockServiceError::InvalidRecord)
        }
        fn retire(
            &mut self,
            _tag: ChildTag<()>,
            _absence: SlotAbsence,
        ) -> Result<(), ForkStockServiceError> {
            Ok(())
        }
    }

    let mut stock = stock(FailingReleaseTags, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 2, 1).unwrap();
    assert_eq!(stock.table_stock().len(), 1);
    assert!(!stock.lifecycle_available());

    let mut abort = ForkStockSettlement::abort(granted);
    let result = stock.settle(
        &mut NoTableLedger,
        parent(),
        &mut abort,
        |_| true,
        |_| true,
        |_| true,
    );
    assert_eq!(result, Err(ForkStockServiceError::InvalidRecord));
    assert_eq!(stock.table_stock().len(), 1);
    assert!(!stock.lifecycle_available());
    assert!(stock.pending(CpuId::new(0)).is_some());
}

#[test]
fn abort_refuses_dirty_tables_and_subsequent_loan_refuses_until_scrubbed_and_aborted() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let exec = parent();
    let granted = loan(&mut stock, exec, 302, 2, 1).unwrap();
    let mut abort = ForkStockSettlement::abort(granted);
    let is_clean = std::cell::Cell::new(false);

    let result = stock.settle(
        &mut NoTableLedger,
        exec,
        &mut abort,
        |_| true,
        |_| is_clean.get(),
        |_| true,
    );
    assert_eq!(result, Err(ForkStockServiceError::ExposedDirtyTable));
    assert!(stock.pending(CpuId::new(0)).is_some());

    let mut exchange = ForkStockExchange::new(request(exec, 302, 1, 1)).unwrap();
    assert_eq!(
        stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| true),
        Err(ForkStockRefusal::Capacity)
    );

    is_clean.set(true);
    let result = stock.settle(
        &mut NoTableLedger,
        exec,
        &mut abort,
        |_| true,
        |_| is_clean.get(),
        |_| true,
    );
    assert_eq!(result, Ok(()));
    assert!(stock.pending(CpuId::new(0)).is_none());

    let mut second_exchange = ForkStockExchange::new(request(exec, 302, 1, 1)).unwrap();
    assert!(
        stock
            .loan(&mut NoTableLedger, exec, &mut second_exchange, |_| true)
            .is_ok()
    );
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
    let mut reserve =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    assert_eq!(
        stock
            .reserve_custody(
                parent(),
                &mut reserve,
                |_| true,
                |_| false,
                |_, _, _| Ok(())
            )
            .unwrap_err(),
        ForkStockRefusal::Invalid
    );
    let mut settlement = ForkStockSettlement::commit_reserved(granted, completion).unwrap();
    assert_eq!(
        stock.settle(
            &mut NoTableLedger,
            parent(),
            &mut settlement,
            |_| true,
            |_| true,
            |_| true
        ),
        Err(ForkStockServiceError::InvalidRecord)
    );
    assert!(stock.pending(CpuId::new(0)).is_some());
}

#[test]
fn stale_lifecycle_record_is_withdrawn_and_refused_on_every_carrier() {
    // One hygiene policy for every carrier: a dirty record is refused with
    // a typed Inventory refusal and withdrawn, never reissued, never fatal.
    let mut stock = stock(UntaggedRoots, 4, 2);
    let exec = parent();
    let mut exchange = ForkStockExchange::new(request(exec, 302, 1, 1)).unwrap();
    assert_eq!(
        stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| false),
        Err(ForkStockRefusal::Inventory)
    );
    assert_eq!(stock.table_stock().len(), 4);
    assert_eq!(stock.lifecycle_stock().len(), 1, "dirty record withdrawn");
    assert_eq!(stock.counters().withdrawn_lifecycles, 1);
    assert!(stock.pending(CpuId::new(0)).is_none());
    // The next clean record serves the next fork.
    loan(&mut stock, exec, 302, 1, 1).unwrap();
}

/// Host bytes of an x86 CPL0 metadata window, aligned like the retained
/// carrier mapping.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct AlignedMetadataChunk([u64; 8]);

struct MetadataBytes {
    chunks: Vec<AlignedMetadataChunk>,
}

const X86_METADATA_LEN: u64 = 0x10_0000;
const X86_FORK_LIFECYCLE_OFFSET: u64 = 0x8_8000;

impl MetadataBytes {
    fn new() -> Self {
        Self {
            chunks: vec![AlignedMetadataChunk([0; 8]); (X86_METADATA_LEN / 64) as usize],
        }
    }

    fn window(&mut self) -> LifecycleWindow {
        let host = core::ptr::NonNull::new(self.chunks.as_mut_ptr().cast::<u8>()).unwrap();
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

/// The guest initializes its census in the loaned record before any task, and
/// releases its control custody before the MM's lifecycle window is reclaimed.
fn guest_initializes(window: LifecycleWindow, lifecycle: ForkLifecycleLoan) {
    let ranges = window.ranges(lifecycle).unwrap();
    // SAFETY: in-window test bytes.
    unsafe { core::ptr::write_bytes(ranges[0].0, 0xa5, ranges[0].1) };
    let control = unsafe { &*ranges[1].0.cast::<carrick_el1_abi::ThreadControlSlot>() };
    assert!(control.publish_visible_tid(42));
    let custody = carrick_el1_abi::MemberControlCustody::retain(control).unwrap();
    custody.commit_registration();
    drop(custody);
    assert!(!control.graph_referenced());
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
    let mut stock = ForkStock::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
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
fn lifecycle_window_clear_refuses_graph_referenced_control_and_defers_reclaim() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(1),
        )
        .unwrap();
    let granted = x86_loan(&mut stock, window, 302).unwrap();
    let ranges = window.ranges(granted.lifecycle).unwrap();
    // SAFETY: in-window test bytes aligned to 64 bytes.
    let control = unsafe { &*ranges[1].0.cast::<carrick_el1_abi::ThreadControlSlot>() };
    assert!(control.publish_visible_tid(42));
    let custody = carrick_el1_abi::MemberControlCustody::retain(control).unwrap();
    custody.commit_registration();
    assert!(control.graph_referenced());
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();

    // While the process graph still holds `MemberControlCustody` on the child's
    // loaned control slot, `window.clear` refuses to zero it and `reclaim`
    // defers the child rather than clobbering a referenced control slot.
    assert!(!window.clear(granted.lifecycle));
    let deferred = stock
        .reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |life| window.clear(life),
            |_| true,
        )
        .unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(stock.counters().reclaim_deferrals, 1);
    assert!(stock.is_quarantined(mm(302)));
    assert!(control.graph_referenced());

    // Once the graph drops its custody before reclaim, `window.clear` zeroes
    // the record and `reclaim` returns the child's stock.
    drop(custody);
    assert!(!control.graph_referenced());
    let returned = stock
        .reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |life| window.clear(life),
            |_| true,
        )
        .unwrap();
    assert_eq!(returned, 1);
    assert!(window.is_zero(granted.lifecycle));
}

#[test]
fn kvm_unclearable_lifecycle_record_is_never_reissued_dirty() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
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
    // Withdrawn, so even a later clear cannot bring the record back.
    assert!(!stock.lifecycle_available());
    assert!(window.clear(granted.lifecycle));
    assert_eq!(
        x86_loan(&mut stock, window, 303),
        Err(ForkStockRefusal::Capacity)
    );
}

#[test]
fn kvm_live_children_beyond_lifecycle_records_are_counted_refusals() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..32).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(8),
        )
        .unwrap();
    let mut granted = Vec::new();
    for child_mm in 302..310 {
        let loan = x86_loan(&mut stock, window, child_mm).unwrap();
        guest_initializes(window, loan.lifecycle);
        commit(&mut stock, parent(), loan, 1, 0).unwrap();
        granted.push(loan);
    }
    assert_eq!(
        x86_loan(&mut stock, window, 310),
        Err(ForkStockRefusal::Capacity)
    );
    assert_eq!(stock.counters().capacity_refusals, 1);
    assert_eq!(stock.live_children(), 8);
    // The limit counts live children, not forks: once one child is retired
    // and reclaimed, the refused fork is admitted.
    retire(&mut stock, child_of(granted[0], 900)).unwrap();
    let returned = stock
        .reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |life| window.clear(life),
            |_| true,
        )
        .unwrap();
    assert_eq!(returned, 1);
    assert!(x86_loan(&mut stock, window, 310).is_ok());
    assert_eq!(stock.counters().capacity_refusals, 1);
    assert!(
        stock
            .counters()
            .families()
            .contains(&("capacity_refusal", 1))
    );
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
            |absence| {
                released.borrow_mut().push(absence.mm());
                false
            },
        ),
        Ok(0)
    );
    assert_eq!(*released.borrow(), vec![mm(302)]);
    assert!(stock.is_quarantined(mm(302)));
    assert_eq!(stock.table_stock().len(), 3);
    assert!(!stock.lifecycle_available());
    // A refused release is a counted deferral, never a carrier fault; the
    // next drain retries it and returns the stock.
    assert_eq!(stock.counters().reclaim_deferrals, 1);
    assert!(
        stock
            .counters()
            .families()
            .contains(&("reclaim_deferral", 1))
    );
    assert_eq!(reclaim(&mut stock, |_| true, &RefCell::new(Vec::new())), 1);
    assert!(!stock.is_quarantined(mm(302)));
    assert!(stock.lifecycle_available());
}

/// A child whose release is refused does not hold back the children
/// behind it: each candidate is reclaimed or deferred on its own.
#[test]
fn deferred_candidate_does_not_block_later_candidates() {
    let mut stock = stock(UntaggedRoots, 8, 2);
    for child_mm in [302, 303] {
        let granted = loan(&mut stock, parent(), child_mm, 1, 1).unwrap();
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
        retire(&mut stock, child_of(granted, 600 + child_mm)).unwrap();
    }
    let result = stock.reclaim(
        &mut NoTableLedger,
        mm(PARENT_MM),
        absent,
        |_| true,
        |_| true,
        |absence| absence.mm() != mm(302),
    );
    assert_eq!(result, Ok(1));
    assert!(stock.is_quarantined(mm(302)));
    assert!(!stock.is_quarantined(mm(303)));
    assert_eq!(stock.counters().reclaim_deferrals, 1);
    assert_eq!(stock.counters().returned_children, 1);
}

/// A clear that fails after a successful release is retried without
/// releasing again.
#[test]
fn failed_clear_after_release_is_retried_without_a_second_release() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    let releases = core::cell::Cell::new(0);
    let clear_ok = core::cell::Cell::new(false);
    let attempt = |stock: &mut ForkStock<UntaggedRoots>| {
        stock.reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| clear_ok.get(),
            |_| true,
            |_| {
                releases.set(releases.get() + 1);
                true
            },
        )
    };
    assert_eq!(attempt(&mut stock), Ok(0));
    assert!(stock.is_quarantined(mm(302)));
    clear_ok.set(true);
    assert_eq!(attempt(&mut stock), Ok(1));
    assert_eq!(releases.get(), 1);
    assert_eq!(stock.counters().reclaim_deferrals, 1);
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

/// Tags whose release/retire can be made to fail once.
#[derive(Default)]
struct FlakyTags {
    fail_release: bool,
    fail_retire_once: core::cell::Cell<bool>,
}

impl ChildAddressTags for FlakyTags {
    type Tag = ();
    fn allocate(&mut self) -> Option<()> {
        Some(())
    }
    fn wire((): ()) -> Option<Asid> {
        None
    }
    fn release_unpublished(&mut self, (): ()) -> Result<(), ForkStockServiceError> {
        if self.fail_release {
            Err(ForkStockServiceError::InvalidRecord)
        } else {
            Ok(())
        }
    }
    fn retire(&mut self, _: ChildTag<()>, _: SlotAbsence) -> Result<(), ForkStockServiceError> {
        if self.fail_retire_once.replace(false) {
            Err(ForkStockServiceError::InvalidRecord)
        } else {
            Ok(())
        }
    }
}

#[test]
fn loan_refuses_the_exchange_even_when_restore_fails() {
    let mut stock = stock(
        FlakyTags {
            fail_release: true,
            ..FlakyTags::default()
        },
        4,
        1,
    );
    let exec = parent();
    let request = request(exec, 302, 1, 1);
    let mut exchange = ForkStockExchange::new(request).unwrap();
    assert!(
        stock
            .loan(&mut NoTableLedger, exec, &mut exchange, |_| false)
            .is_err()
    );
    // The guest always receives a typed refusal, never a silent record.
    assert!(matches!(exchange.take(request), Some(Err(_))));
}

#[test]
fn reclaim_releases_each_child_once_across_a_retire_failure() {
    let mut stock = stock(FlakyTags::default(), 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    stock.tags_mut_for_tests().fail_retire_once.set(true);
    let releases = core::cell::Cell::new(0);
    let attempt = |stock: &mut ForkStock<FlakyTags>| {
        stock.reclaim(
            &mut NoTableLedger,
            mm(PARENT_MM),
            absent,
            |_| true,
            |_| true,
            |_| {
                releases.set(releases.get() + 1);
                true
            },
        )
    };
    assert_eq!(attempt(&mut stock), Ok(0));
    assert!(stock.is_quarantined(mm(302)));
    assert_eq!(attempt(&mut stock), Ok(1));
    assert_eq!(releases.get(), 1, "release ran exactly once");
}

/// Release happens inside reclaim, per candidate, before that candidate's
/// stock is reissued: a later candidate's refusal neither skips nor undoes
/// an earlier candidate's completed release and return.
#[test]
fn second_candidate_refusal_keeps_first_candidate_released_and_returned() {
    let mut stock = stock(UntaggedRoots, 8, 2);
    for child_mm in [302, 303] {
        let granted = loan(&mut stock, parent(), child_mm, 1, 1).unwrap();
        commit(&mut stock, parent(), granted, 1, 0).unwrap();
        retire(&mut stock, child_of(granted, 600 + child_mm)).unwrap();
    }
    let order = RefCell::new(Vec::new());
    let result = stock.reclaim(
        &mut NoTableLedger,
        mm(PARENT_MM),
        absent,
        |_| {
            order.borrow_mut().push("clear");
            true
        },
        |_| true,
        |absence| {
            order.borrow_mut().push(if absence.mm() == mm(302) {
                "release 302"
            } else {
                "refuse 303"
            });
            absence.mm() == mm(302)
        },
    );
    assert_eq!(result, Ok(1));
    // 302 was released before its tables were cleared and returned.
    assert_eq!(*order.borrow(), vec!["release 302", "clear", "refuse 303"]);
    assert!(!stock.is_quarantined(mm(302)));
    assert!(stock.is_quarantined(mm(303)));
    assert_eq!(stock.counters().returned_children, 1);
}

#[test]
fn unreserved_commit_cannot_bypass_physical_custody_admission() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 2, 1).unwrap();
    let completion = PortalForkCompletion {
        request: granted.request,
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::new(2).unwrap(),
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut commit = ForkStockSettlement::commit_reserved(granted, completion).unwrap();
    assert_eq!(
        stock.settle(
            &mut NoTableLedger,
            parent(),
            &mut commit,
            |_| true,
            |_| true,
            |_| true,
        ),
        Err(ForkStockServiceError::InvalidRecord),
        "every Commit must consume pre-publication physical custody admission"
    );
    assert_eq!(stock.live_children(), 0);
    assert!(stock.pending(parent().cpu).is_some());
}

/// Reservation validates the whole completion before retaining physical custody,
/// and committing without an admitted reservation is refused.
#[test]
fn reserve_custody_refuses_invalid_completion_before_retaining_physical_custody() {
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
    let mut reserve_dirty =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    assert_eq!(
        stock
            .reserve_custody(
                parent(),
                &mut reserve_dirty,
                |_| true,
                |_| false,
                |_, _, _| panic!("retain_physical must not run when unused tables are dirty")
            )
            .unwrap_err(),
        ForkStockRefusal::Invalid
    );
    let mut reserve_unresolvable =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    assert_eq!(
        stock
            .reserve_custody(
                parent(),
                &mut reserve_unresolvable,
                |_| false,
                |_| true,
                |_, _, _| panic!("retain_physical must not run when tables are unresolvable")
            )
            .unwrap_err(),
        ForkStockRefusal::Inventory
    );
    assert!(stock.pending(CpuId::new(0)).is_some(), "nothing consumed");
    let mut unreserved_commit = ForkStockSettlement::commit_reserved(granted, completion).unwrap();
    assert_eq!(
        stock.commit_admitted(&mut NoTableLedger, parent(), &mut unreserved_commit),
        Err(ForkStockServiceError::InvalidRecord)
    );
    let mut reserve_ok =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 0)
            .unwrap();
    assert!(
        stock
            .reserve_custody(
                parent(),
                &mut reserve_ok,
                |_| true,
                |_| true,
                |_, _, _| Ok(())
            )
            .is_ok()
    );
}

/// Every loan refusal is counted by its typed reason and named, so a run
/// report says why a fork failed.
#[test]
fn every_refusal_reason_is_counted_and_named() {
    let mut stock = stock(UntaggedRoots, 4, 2);
    let exec = parent();
    // Stale: a request naming another binding.
    let mut foreign = exec;
    foreign.binding.task = EntryTaskKey::from_raw(999);
    let mut exchange = ForkStockExchange::new(request(foreign, 302, 1, 1)).unwrap();
    assert_eq!(
        stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| true),
        Err(ForkStockRefusal::Stale)
    );
    // Inventory: a dirty lifecycle record (withdrawn).
    let mut exchange = ForkStockExchange::new(request(exec, 302, 1, 1)).unwrap();
    assert_eq!(
        stock.loan(&mut NoTableLedger, exec, &mut exchange, |_| false),
        Err(ForkStockRefusal::Inventory)
    );
    // Capacity: more table pages than the stock holds.
    assert_eq!(
        loan(&mut stock, exec, 302, 8, 1),
        Err(ForkStockRefusal::Capacity)
    );
    let counters = stock.counters();
    assert_eq!(counters.stale_refusals, 1);
    assert_eq!(counters.inventory_refusals, 1);
    assert_eq!(counters.capacity_refusals, 1);
    assert_eq!(counters.withdrawn_lifecycles, 1);
    let families = counters.families();
    for (family, count) in [
        ("stale_refusal", 1),
        ("inventory_refusal", 1),
        ("capacity_refusal", 1),
        ("withdrawn_lifecycle", 1),
    ] {
        assert!(
            families.contains(&(family, count)),
            "{family} in {families:?}"
        );
    }
    assert!(families.iter().all(|(_, count)| *count != 0));
}

#[test]
fn refusal_reports_installed_quarantine_and_exact_lifecycle_resource() {
    let mut stock = stock(UntaggedRoots, 4, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    retire(&mut stock, child_of(granted, 900)).unwrap();
    let cleared = RefCell::new(Vec::new());
    assert_eq!(reclaim(&mut stock, |_| false, &cleared), 0);
    assert_eq!(
        loan(&mut stock, parent(), 303, 1, 1),
        Err(ForkStockRefusal::Capacity)
    );
    let refusal = stock.admission_refusal().unwrap();
    assert_eq!(refusal.resource, ForkCapacityResource::Lifecycle);
    assert_eq!(refusal.available_lifecycles, 0);
    assert_eq!(
        refusal.quarantine,
        vec![ForkQuarantineState {
            mm: 302,
            absent: false,
            carrier_released: false,
        }]
    );
    assert!(cleared.borrow().is_empty());
    assert_eq!(stock.counters().capacity_refusals, 1);
}

#[test]
fn reserve_custody_refuses_retired_munmap_backing_and_rolls_back_earlier_pins() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct PhysicalPin(Arc<AtomicUsize>);
    impl Drop for PhysicalPin {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dropped_first = Arc::new(AtomicUsize::new(0));
    let mut stock: ForkStock<UntaggedRoots, Vec<PhysicalPin>> = ForkStock::new(
        CARRIER,
        ForkControlCapacity::exclusive(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            lifecycles(1),
        )
        .unwrap();
    let exec = parent();
    let mut exchange = ForkStockExchange::new(request(exec, 302, 2, 1)).unwrap();
    let granted = stock
        .loan(&mut NoTableLedger, exec, &mut exchange, |_| true)
        .unwrap();
    let completion = PortalForkCompletion {
        request: granted.request,
        // SAFETY: exact admitted child fixture.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut reserve =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 2)
            .unwrap();
    let result = stock.reserve_custody(
        exec,
        &mut reserve,
        |_| true,
        |_| true,
        |_req, _addr, count| {
            assert_eq!(count, 2);
            let _pin = PhysicalPin(Arc::clone(&dropped_first));
            // Second mapping's stage-2 record entered RetirementRequested from concurrent munmap.
            Err(ForkStockRefusal::Inventory)
        },
    );
    assert_eq!(result.unwrap_err(), ForkStockRefusal::Inventory);
    assert_eq!(
        reserve.take(granted),
        Some(Err(ForkStockRefusal::Inventory))
    );
    assert_eq!(
        dropped_first.load(Ordering::SeqCst),
        1,
        "earlier pin in the batch must be dropped immediately when reservation refuses"
    );
    assert_eq!(stock.counters().inventory_refusals, 1);
    assert!(
        stock
            .pending(CpuId::new(0))
            .unwrap()
            .admitted_custody()
            .is_none()
    );
    assert_eq!(stock.live_children(), 0);

    // The guest scrubs and aborts the loan back to stock.
    let mut abort = ForkStockSettlement::abort(granted);
    stock
        .settle(
            &mut NoTableLedger,
            exec,
            &mut abort,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert!(stock.pending(CpuId::new(0)).is_none());
    assert_eq!(stock.table_stock().len(), 4);
    assert!(stock.lifecycle_available());
}

#[test]
fn admitted_custody_token_drops_reserved_pins_on_abort_and_consumes_infallibly_on_commit() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct PhysicalPin(Arc<AtomicUsize>);
    impl Drop for PhysicalPin {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicUsize::new(0));
    let mut stock: ForkStock<UntaggedRoots, Vec<PhysicalPin>> = ForkStock::new(
        CARRIER,
        ForkControlCapacity::exclusive(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            lifecycles(1),
        )
        .unwrap();
    let exec = parent();

    // 1. Reserve custody, then abort before commit: reserved pins drop on abort.
    let mut exchange = ForkStockExchange::new(request(exec, 302, 2, 1)).unwrap();
    let granted = stock
        .loan(&mut NoTableLedger, exec, &mut exchange, |_| true)
        .unwrap();
    let completion = PortalForkCompletion {
        request: granted.request,
        // SAFETY: exact admitted child fixture.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut reserve =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
            .unwrap();
    stock
        .reserve_custody(
            exec,
            &mut reserve,
            |_| true,
            |_| true,
            |_, _, _| Ok(vec![PhysicalPin(Arc::clone(&dropped))]),
        )
        .unwrap();
    assert_eq!(reserve.take(granted), Some(Ok(())));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    let mut abort = ForkStockSettlement::abort(granted);
    stock
        .settle(
            &mut NoTableLedger,
            exec,
            &mut abort,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "aborting a loan with reserved custody must drop its physical pins"
    );

    // 2. Reserve custody, then commit_admitted: consumes the admitted custody into CommittedChild.
    let mut exchange = ForkStockExchange::new(request(exec, 303, 2, 1)).unwrap();
    let granted = stock
        .loan(&mut NoTableLedger, exec, &mut exchange, |_| true)
        .unwrap();
    let completion = PortalForkCompletion {
        request: granted.request,
        // SAFETY: exact admitted child fixture.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 0,
    };
    let mut reserve =
        ForkStockSettlement::reserve(granted, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
            .unwrap();
    stock
        .reserve_custody(
            exec,
            &mut reserve,
            |_| true,
            |_| true,
            |_, _, _| Ok(vec![PhysicalPin(Arc::clone(&dropped))]),
        )
        .unwrap();
    let mut commit = ForkStockSettlement::commit_reserved(granted, completion).unwrap();
    stock
        .commit_admitted(&mut NoTableLedger, exec, &mut commit)
        .unwrap();
    assert_eq!(commit.take(granted), Some(Ok(())));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    let child = child_of(granted, 44);
    let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
    stock.retire_child(child, &mut retire).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
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
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}

#[derive(Default)]
struct RecordingLedger {
    live: std::collections::BTreeSet<(RootGpa, u64)>,
}

impl ForkTableLedger for RecordingLedger {
    fn grant(&mut self, page: RootGpa, mm: ReservationMm) -> bool {
        self.live.insert((page, mm.raw()))
    }

    fn give_back(&mut self, page: RootGpa, mm: ReservationMm) {
        assert!(
            self.live.remove(&(page, mm.raw())),
            "unexpected give_back {page:?} {mm:?}"
        );
    }
}

fn backing_txn(
    owner: El1MmHandle,
    root: RootGpa,
    generation: u64,
    tables: carrick_mmu_core::aarch64::descriptor_txn::TableGrants,
) -> carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};

    DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: NonZeroU64::new(owner.mm().raw()).unwrap(),
            generation: NonZeroU64::new(generation).unwrap(),
        },
        root: SubstrateGpa(root.address().raw()),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: 0x6000_0000 + generation * 0x1_0000,
                ipa: 0x8000_0000 + generation * 0x1_0000,
                len: 0x1_0000,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(0x6000_0000 + generation * 0x1_0000, 4096),
            backing: BackingIdentity {
                frame_id: NonZeroU64::new(generation).unwrap(),
                mapping_id: NonZeroU64::new(generation).unwrap(),
                owner_generation: NonZeroU64::MIN,
                inventory_revision: NonZeroU64::MIN,
            },
        },
        tables,
    }
}

fn applied_backing_receipt(
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    tables_linked: u8,
) -> carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorApplied, DescriptorOutcome, DescriptorReceipt, ReclaimedTables,
    };
    let carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp::Prepare {
        publication,
        resident,
        ..
    } = txn.op
    else {
        unreachable!()
    };
    DescriptorReceipt {
        id: txn.id,
        digest: txn.digest(),
        outcome: DescriptorOutcome::Applied(DescriptorApplied {
            pages: publication.len / 4096,
            resident,
            tables_linked,
            reclaimed: ReclaimedTables::NONE,
            live_stores: 1,
            flush_required: false,
        }),
    }
}

fn refused_backing_receipt(
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
) -> carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOutcome, DescriptorReceipt, DescriptorRefusal,
    };
    DescriptorReceipt {
        id: txn.id,
        digest: txn.digest(),
        outcome: DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot),
    }
}

#[test]
fn many_native_backing_supplies_return_unused_tables_across_two_children() {
    use carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS;

    let mut stock = stock(UntaggedRoots, 40, 2);
    let first = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), first, 1, 0).unwrap();
    let second = loan(&mut stock, parent(), 303, 1, 1).unwrap();
    commit(&mut stock, parent(), second, 1, 0).unwrap();
    let children = [child_of(first, 44), child_of(second, 45)];
    let before = stock.table_stock().len();
    let mut linked = 0;

    for generation in 1..=512 {
        let child = children[generation as usize % children.len()];
        let owner = stock.child_owner(mm(child.binding.mm.raw())).unwrap();
        let reservation = stock
            .reserve_native_descriptor_tables(
                &mut NoTableLedger,
                owner,
                child.context.root,
                MAX_TABLE_GRANTS,
            )
            .unwrap();
        let txn = backing_txn(
            owner,
            child.context.root,
            generation,
            reservation.descriptor_tables(),
        );
        stock
            .track_native_descriptor_tables(&mut NoTableLedger, reservation, txn)
            .unwrap();
        let refused = generation % 63 == 0;
        let tables_linked = u8::from(!refused && generation % 64 == 0);
        linked += usize::from(tables_linked);
        let receipt = if refused {
            refused_backing_receipt(&txn)
        } else {
            applied_backing_receipt(&txn, tables_linked)
        };
        stock
            .settle_native_descriptor_tables(
                &mut NoTableLedger,
                owner,
                child.context.root,
                &receipt,
            )
            .unwrap();
        assert_eq!(stock.table_stock().len(), before - linked);
    }

    assert_eq!(linked, 8);
    assert_eq!(stock.table_stock().len(), before - linked);

    let child = children[0];
    let owner = stock.child_owner(mm(child.binding.mm.raw())).unwrap();
    let reservation = stock
        .reserve_native_descriptor_tables(
            &mut NoTableLedger,
            owner,
            child.context.root,
            MAX_TABLE_GRANTS,
        )
        .unwrap();
    let txn = backing_txn(
        owner,
        child.context.root,
        513,
        reservation.descriptor_tables(),
    );
    stock
        .track_native_descriptor_tables(&mut NoTableLedger, reservation, txn)
        .unwrap();
    stock
        .cancel_submitted_native_descriptor_tables(
            &mut NoTableLedger,
            owner,
            child.context.root,
            txn.id.generation,
        )
        .unwrap();
    assert_eq!(stock.table_stock().len(), before - linked);

    for child in children {
        retire(&mut stock, child).unwrap();
    }
    let cleared = RefCell::new(Vec::new());
    assert_eq!(reclaim(&mut stock, |_| true, &cleared), 2);
    assert_eq!(cleared.borrow().len(), linked + children.len());
    assert_eq!(stock.table_stock().len(), 40);
}

#[test]
fn native_backing_table_exhaustion_is_counted_without_losing_stock() {
    use carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS;

    let mut stock = stock(UntaggedRoots, 8, 1);
    let granted = loan(&mut stock, parent(), 302, 1, 1).unwrap();
    commit(&mut stock, parent(), granted, 1, 0).unwrap();
    let child = child_of(granted, 44);
    let owner = stock.child_owner(granted.request.child_mm).unwrap();
    let before = stock.table_stock().to_vec();

    assert!(matches!(
        stock.reserve_native_descriptor_tables(
            &mut NoTableLedger,
            owner,
            child.context.root,
            MAX_TABLE_GRANTS,
        ),
        Err(ForkStockServiceError::DescriptorTableCapacity)
    ));
    assert_eq!(stock.table_stock(), before);
    assert_eq!(stock.counters().descriptor_capacity_refusals, 1);
}

#[derive(Debug)]
struct TestTableReservation(Vec<RootGpa>);

impl NativeForkTableReservation for TestTableReservation {
    fn arenas(&self) -> &[RootGpa] {
        &self.0
    }
}

struct DummyInventory;

#[allow(clippy::unimplemented)]
impl crate::PhysicalFrameInventory for DummyInventory {
    fn bind(&self, _owner: crate::GuestFrameOwner) -> std::sync::Arc<dyn crate::FrameCowAuthority> {
        unimplemented!()
    }

    fn allocate_backing_ids(
        &self,
    ) -> Result<(crate::FrameId, crate::MappingId), Box<dyn std::error::Error + Send + Sync>> {
        Err("unused in test".into())
    }

    fn retire_mm(
        &self,
        _mm: carrick_guest_arch::MmGeneration,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0)
    }
}

#[test]
fn second_root_reuses_carrier_fork_stock_after_first_root_exits() {
    let tables = std::sync::Arc::new(TestTableReservation(vec![page(0x9a00_0000_0000)]));
    let inventory: std::sync::Arc<dyn crate::PhysicalFrameInventory> =
        std::sync::Arc::new(DummyInventory);
    let first_resources = NativeForkStockResources {
        tables: tables.clone(),
        inventory: std::sync::Arc::clone(&inventory),
    };
    let second_resources = NativeForkStockResources {
        tables,
        inventory: std::sync::Arc::clone(&inventory),
    };
    let foreign_tables = NativeForkStockResources {
        tables: std::sync::Arc::new(TestTableReservation(vec![page(0x9a00_0040_0000)])),
        inventory: std::sync::Arc::clone(&inventory),
    };
    let foreign_inventory = NativeForkStockResources {
        tables: std::sync::Arc::new(TestTableReservation(vec![page(0x9a00_0000_0000)])),
        inventory: std::sync::Arc::new(DummyInventory),
    };
    assert!(first_resources.matches(&second_resources));
    assert!(!first_resources.matches(&foreign_tables));
    assert!(!first_resources.matches(&foreign_inventory));

    let mut stock = stock(UntaggedRoots, 2, 1);
    let mut ledger = RecordingLedger::default();
    let root1 = execution(41, 0, PARENT_MM, 0x1000);
    let mut exchange1 = ForkStockExchange::new(request(root1, 302, 1, 1)).unwrap();
    let granted1 = stock
        .loan(&mut ledger, root1, &mut exchange1, |_| true)
        .unwrap();
    let completion1 = PortalForkCompletion {
        request: granted1.request,
        // SAFETY: test receipt for the exact admitted loan.
        child: unsafe {
            El1MmHandle::from_admitted_owner(CARRIER, granted1.request.child_mm, NonZeroU64::MIN)
        },
        parent_generation: ReservationGeneration::INITIAL,
        child_tables_used: 4096,
        parent_tables_used: 4096,
    };
    let mut reserve1 = ForkStockSettlement::reserve(
        granted1,
        completion1,
        KernelVa::new(0xffff_8000_0001_0000),
        0,
    )
    .unwrap();
    stock
        .reserve_custody(root1, &mut reserve1, |_| true, |_| true, |_, _, _| Ok(()))
        .unwrap();
    let mut settlement1 = ForkStockSettlement::commit_reserved(granted1, completion1).unwrap();
    stock
        .settle(
            &mut ledger,
            root1,
            &mut settlement1,
            |_| true,
            |_| true,
            |_| true,
        )
        .unwrap();
    assert!(stock.table_stock().is_empty());

    retire(&mut stock, child_of(granted1, 900)).unwrap();
    stock.retire_exited_root(mm(PARENT_MM));
    assert!(stock.is_quarantined(mm(302)));
    assert!(stock.is_quarantined(mm(PARENT_MM)));

    let root2_mm = 401;
    let root2 = execution(51, 0, root2_mm, 0x2000);
    let released = RefCell::new(Vec::new());
    let reclaimed = stock
        .reclaim(
            &mut ledger,
            mm(root2_mm),
            absent,
            |_| true,
            |_| true,
            |absence| {
                released.borrow_mut().push(absence.mm());
                true
            },
        )
        .unwrap();
    assert_eq!(reclaimed, 2);
    assert_eq!(*released.borrow(), vec![mm(302)]);
    assert!(ledger.live.is_empty());
    assert_eq!(stock.table_stock().len(), 2);
    assert!(stock.lifecycle_available());

    let mut exchange2 = ForkStockExchange::new(request(root2, 402, 1, 1)).unwrap();
    let granted2 = stock
        .loan(&mut ledger, root2, &mut exchange2, |_| true)
        .unwrap();
    assert_eq!(granted2.request.child_mm, mm(402));
}

#[test]
fn accepted_cold_lifecycle_publishes_all_affinity_aliases_and_abort_scrubs_them() {
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let mut stock = ForkStock::<UntaggedRoots>::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            x86_lifecycles(1),
        )
        .unwrap();
    let mut exchange = ForkStockExchange::new(request(parent(), 302, 1, 1)).unwrap();
    let mut aliases = None;
    let granted = stock
        .loan(&mut NoTableLedger, parent(), &mut exchange, |life| {
            aliases = window.prepare_affinity_aliases(life);
            aliases.is_some()
        })
        .unwrap();
    assert!(
        window.is_zero(granted.lifecycle),
        "preparation must not dirty unaccepted stock"
    );
    aliases.unwrap().publish();
    let ranges = window.ranges(granted.lifecycle).unwrap();
    let controls = unsafe {
        core::slice::from_raw_parts(
            ranges[1].0.cast::<carrick_el1_abi::ThreadControlSlot>(),
            carrick_el1_abi::THREAD_POOL_ENTRIES + 1,
        )
    };
    for (index, control) in controls.iter().enumerate() {
        let source = control.affinity_source();
        let authority = core::ptr::from_ref(control.affinity_authority()).addr() as u64;
        let offset = authority - core::ptr::from_ref(control).addr() as u64;
        assert_eq!(source.raw_host(), authority);
        assert_eq!(
            source.raw_guest(),
            granted.lifecycle.controls.raw()
                + (index * core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>()) as u64
                + offset
        );
        assert!(source.is_guest_mapped());
        assert!(
            control
                .affinity_authority()
                .initialize_quiescent(if index % 2 == 0 { 1 } else { 2 })
        );
        assert_eq!(source.load(), Some(if index % 2 == 0 { 1 } else { 2 }));
    }
    assert!(!window.is_zero(granted.lifecycle));
    let mut abort = ForkStockSettlement::abort(granted);
    stock
        .settle(
            &mut NoTableLedger,
            parent(),
            &mut abort,
            |_| true,
            |_| true,
            |life| window.clear(life),
        )
        .unwrap();
    assert!(window.is_zero(granted.lifecycle));
    assert!(stock.pending(parent().cpu).is_none());
}

#[test]
fn lifecycle_alias_preparation_never_dirties_a_refused_loan() {
    struct Denied;
    impl ForkTableLedger for Denied {
        fn grant(&mut self, _: RootGpa, _: ReservationMm) -> bool {
            false
        }
        fn give_back(&mut self, _: RootGpa, _: ReservationMm) {}
    }
    let mut bytes = MetadataBytes::new();
    let window = bytes.window();
    let lifecycle = x86_lifecycles(1)[0];
    let mut stock = ForkStock::<UntaggedRoots>::new(
        CARRIER,
        ForkControlCapacity::unused(0x1_0000_0000),
        UntaggedRoots,
    );
    stock
        .install(
            (0..4).map(|n| page(0x20_0000 + n * 4096)).collect(),
            vec![lifecycle],
        )
        .unwrap();
    let mut exchange = ForkStockExchange::new(request(parent(), 302, 1, 1)).unwrap();
    let mut aliases = None;
    assert_eq!(
        stock.loan(&mut Denied, parent(), &mut exchange, |life| {
            aliases = window.prepare_affinity_aliases(life);
            aliases.is_some()
        }),
        Err(ForkStockRefusal::Capacity)
    );
    assert!(aliases.is_some());
    assert!(window.is_zero(lifecycle));
    assert!(stock.pending(parent().cpu).is_none());
    let control = unsafe {
        &*window.ranges(lifecycle).unwrap()[1]
            .0
            .cast::<carrick_el1_abi::ThreadControlSlot>()
    };
    assert!(control.publish_visible_tid(42));
    assert!(
        window.prepare_affinity_aliases(lifecycle).is_none(),
        "dirty stock cannot license alias publication"
    );
    assert!(!control.affinity_source().is_guest_mapped());
}

#[test]
fn maintenance_reclaim_requires_the_exact_nonzero_hardware_root() {
    assert!(ReclaimExecution::maintenance_root(page(0x1000), page(0x2000)).is_none());
    assert!(ReclaimExecution::maintenance_root(page(0), page(0)).is_none());
    assert!(ReclaimExecution::maintenance_root(page(0x2000), page(0x2000)).is_some());
}
