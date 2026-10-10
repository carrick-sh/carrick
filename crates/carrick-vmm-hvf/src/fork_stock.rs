//! Physical page-table stock loans and root-exit notifications for AArch64 EL1.
//!
//! On AArch64, this crossing is driven synchronously through `HVC #6` using operation
//! codes [`carrick_el1_abi::GRANT_OP_FORK_STOCK`], [`carrick_el1_abi::GRANT_OP_ROOT_EXIT`]
//! and [`carrick_el1_abi::GRANT_OP_CHILD_RETIRE`]. The stopped vCPU retains its exclusive
//! execution context and stack-allocated wire record ([`ForkStockExchange`],
//! [`ForkStockSettlement`], [`NativeRootExit`] or [`NativeChildRetire`]).
//!
//! The stock, loan, settlement and child quarantine state machine is the
//! ISA-neutral [`carrick_hal::fork_stock::ForkStock`]; this adapter supplies
//! only the HVF mechanics:
//! - the carrier [`AsidAllocator`] tags each child root;
//! - [`El1FrameGrantLedger`] accounts every loaned table page;
//! - boot stock geometry comes from carrier-owned metadata extents;
//! - `CarrierVmCustody` stage-2 records resolve guest records and pages.

use carrick_el1_abi::{
    ForkLifecycleLoan, ForkStockExchange, ForkStockLoan, ForkStockRefusal, ForkStockSettlement,
    NativeChildRetire, NativeRootExit, ReservationMm,
};
use carrick_guest_arch::{FrameGpa, RootGpa};
use carrick_hal::asid::{AsidAllocator, AsidGeneration};
use carrick_hal::fork_stock::{
    ForkStock, ForkTableLedger, LIFECYCLE_SLOT_STRIDE, LifecycleHygiene, SlotAbsence,
    lifecycle_slots,
};
use carrick_sched_core::process::LinuxWaitStatus;
use core::num::NonZeroU64;

pub use carrick_hal::fork_stock::{ForkStockServiceError, GrantExecution, take_fork_table_stock};

use crate::trap::{CarrierVmCustody, El1FrameGrantLedger, El1FrameGrantMm};

/// Outstanding physical table loan held by a stopped vCPU.
pub type PendingForkLoan = carrick_hal::fork_stock::PendingForkLoan<AsidGeneration>;

impl ForkTableLedger for El1FrameGrantLedger {
    fn grant(&mut self, page: RootGpa, mm: ReservationMm) -> bool {
        El1FrameGrantMm::new(mm.raw())
            .is_some_and(|owner| self.mark_grant(page.address().raw(), 4096, owner).is_ok())
    }

    fn give_back(&mut self, page: RootGpa, mm: ReservationMm) {
        if let Some(owner) = El1FrameGrantMm::new(mm.raw()) {
            self.mark_return(page.address().raw(), 4096, owner, false);
        }
    }
}

/// Host custody of physical table stock and pending loans for an AArch64 carrier.
#[derive(Debug)]
pub struct ForkStockHostCustody {
    stock: ForkStock<AsidAllocator>,
}

impl ForkStockHostCustody {
    pub fn new(carrier: NonZeroU64) -> Self {
        Self::with_asids(carrier, AsidAllocator::new())
    }

    pub fn with_asids(carrier: NonZeroU64, asids: AsidAllocator) -> Self {
        Self {
            stock: ForkStock::new(
                carrier,
                carrick_mem::memory::LINUX_KERNEL_REGION_BASE,
                asids,
            ),
        }
    }

    pub fn asids(&self) -> &AsidAllocator {
        self.stock.tags()
    }

    /// The shared stock, loan and quarantine state.
    pub fn stock(&self) -> &ForkStock<AsidAllocator> {
        &self.stock
    }

    /// Published count of children whose quarantined stock returned.
    pub fn returned_children(&self) -> u64 {
        self.stock.counters().returned_children
    }

    /// Seed the same bounded stock in production and VM-free witnesses. Both
    /// extents are carrier-owned, live stage-2 mappings admitted before guest
    /// entry by the metadata aperture; lifecycle and table pages are disjoint.
    pub fn install_boot_stock(
        &mut self,
        lifecycle_base: u64,
        table_base: u64,
    ) -> Result<(), ForkStockServiceError> {
        let extent = carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;
        let aperture = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE;
        let limit = aperture + carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE;
        let valid = |base: u64| {
            base >= aperture
                && base.is_multiple_of(extent)
                && base.checked_add(extent).is_some_and(|end| end <= limit)
        };
        if !valid(lifecycle_base) || !valid(table_base) || lifecycle_base == table_base {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let lifecycles = lifecycle_slots(
            aperture,
            lifecycle_base + LIFECYCLE_SLOT_STRIDE,
            HVF_FORK_LIFECYCLE_SLOTS,
        )
        .ok_or(ForkStockServiceError::InvalidRecord)?;
        let tables = (table_base..table_base + extent)
            .step_by(4096)
            .map(|ipa| RootGpa::page_aligned(FrameGpa::new(ipa)))
            .collect::<Option<Vec<_>>>()
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        self.stock.install(tables, lifecycles)
    }

    /// Service a stopped-vCPU loan request.
    pub(crate) fn service_loan(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        execution: GrantExecution,
        exchange: &mut ForkStockExchange,
        hygiene: &impl LifecycleHygiene,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        self.stock.loan(ledger, execution, exchange, |lifecycle| {
            hygiene.is_zero(lifecycle)
        })
    }

    /// Service a stopped-vCPU settlement (Commit or Abort).
    pub(crate) fn service_settlement(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        execution: GrantExecution,
        settlement: &mut ForkStockSettlement,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
        hygiene: &impl LifecycleHygiene,
    ) -> Result<(), ForkStockServiceError> {
        self.stock.settle(
            ledger,
            execution,
            settlement,
            is_resolvable,
            is_clean,
            |lifecycle| hygiene.clear(lifecycle),
        )
    }

    /// Service a container root exit notification.
    ///
    /// Validates the executing task binding against the record, retires the root's ASID
    /// generation exactly once through the shared allocator, and returns the Linux wait status.
    /// If the binding does not match, returns `Err(StaleExecution)` without modifying any ledger.
    pub(crate) fn service_root_exit(
        &mut self,
        binding: carrick_el1_abi::ExecutionBinding,
        root_exit: &NativeRootExit,
    ) -> Result<LinuxWaitStatus, ForkStockServiceError> {
        let status = root_exit
            .status_for(binding)
            .ok_or(ForkStockServiceError::StaleExecution)?;
        if let Some(mm) = ReservationMm::new(binding.mm.raw()) {
            self.stock.retire_exited_root(mm);
        }
        Ok(status)
    }

    pub(crate) fn service_child_retire(
        &mut self,
        execution: GrantExecution,
        retire: &mut NativeChildRetire,
    ) -> Result<(), ForkStockServiceError> {
        self.stock.retire_child(execution, retire)
    }

    /// Reclaim only MMs whose final guest execution has moved off their root.
    /// The caller authenticates absence from every live zone slot and clears
    /// physical table bytes before returned pages reenter the stock.
    pub(crate) fn reclaim_retired(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        active_mm: ReservationMm,
        occupancy: impl Fn(ReservationMm) -> Option<SlotAbsence>,
        clear_tables: impl Fn(&[RootGpa]) -> bool,
        hygiene: &impl LifecycleHygiene,
    ) -> Result<usize, ForkStockServiceError> {
        self.stock.reclaim(
            ledger,
            active_mm,
            occupancy,
            clear_tables,
            |lifecycle| hygiene.clear(lifecycle),
            |_| true,
        )
    }

    /// Read/write helper resolving GPA through CarrierVmCustody stage-2 mappings.
    pub(crate) fn resolve_record_ptr<T>(
        custody: &CarrierVmCustody,
        record_gpa: u64,
    ) -> Result<*mut T, ForkStockServiceError> {
        let size = core::mem::size_of::<T>();
        if !record_gpa.is_multiple_of(64) {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let identity = custody
            .stage2_record_covering(record_gpa, size)
            .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
        let state = custody.state.lock();
        let record = state
            .stage2_records
            .get(&identity.record_id)
            .ok_or(ForkStockServiceError::MemoryAccessFailed)?;
        if record.snapshot.host_addr == 0 {
            return Err(ForkStockServiceError::MemoryAccessFailed);
        }
        let offset = usize::try_from(
            record_gpa
                .checked_sub(record.snapshot.ipa)
                .ok_or(ForkStockServiceError::MemoryAccessFailed)?,
        )
        .map_err(|_| ForkStockServiceError::MemoryAccessFailed)?;
        let host_ptr = (record.snapshot.host_addr as *mut u8).wrapping_add(offset);
        Ok(host_ptr.cast::<T>())
    }
}

/// The HVF lifecycle hygiene: records live in carrier-owned metadata
/// extents whose kernel VAs equal their stage-2 IPAs, reached through the
/// carrier's stage-2 records.
pub(crate) struct StageTwoLifecycles<'a> {
    pub(crate) custody: &'a CarrierVmCustody,
}

impl StageTwoLifecycles<'_> {
    fn ranges(&self, lifecycle: ForkLifecycleLoan) -> Option<[(*mut u8, usize); 2]> {
        let page =
            ForkStockHostCustody::resolve_record_ptr::<carrick_el1_abi::ThreadLifecyclePage>(
                self.custody,
                lifecycle.page.raw(),
            )
            .ok()?;
        let controls = ForkStockHostCustody::resolve_record_ptr::<
            [carrick_el1_abi::ThreadControlSlot; carrick_el1_abi::THREAD_POOL_ENTRIES + 1],
        >(self.custody, lifecycle.controls.raw())
        .ok()?;
        Some([
            (
                page.cast::<u8>(),
                core::mem::size_of::<carrick_el1_abi::ThreadLifecyclePage>(),
            ),
            (
                controls.cast::<u8>(),
                core::mem::size_of::<
                    [carrick_el1_abi::ThreadControlSlot; carrick_el1_abi::THREAD_POOL_ENTRIES + 1],
                >(),
            ),
        ])
    }
}

impl LifecycleHygiene for StageTwoLifecycles<'_> {
    fn is_zero(&self, lifecycle: ForkLifecycleLoan) -> bool {
        self.ranges(lifecycle).is_some_and(|ranges| {
            ranges.iter().all(|(ptr, len)| {
                // SAFETY: resolved carrier-retained stage-2 bytes of a record
                // no task owns while its loan is decided.
                unsafe { core::slice::from_raw_parts(*ptr, *len) }
                    .iter()
                    .all(|byte| *byte == 0)
            })
        })
    }
    fn clear(&self, lifecycle: ForkLifecycleLoan) -> bool {
        self.ranges(lifecycle).is_some_and(|ranges| {
            for (ptr, len) in ranges {
                // SAFETY: as above; the record is aborted or reclaimed.
                unsafe { core::ptr::write_bytes(ptr, 0, len) };
            }
            true
        })
    }
}

#[cfg(test)]
impl ForkStockHostCustody {
    /// Seed table pages with the default ARM lifecycle record.
    pub(crate) fn seed_for_tests(&mut self, tables: Vec<RootGpa>) {
        self.seed_with_for_tests(
            tables,
            vec![carrick_el1_abi::ForkLifecycleLoan::ARM_DEFAULT],
        );
    }

    pub(crate) fn seed_with_for_tests(
        &mut self,
        tables: Vec<RootGpa>,
        lifecycles: Vec<carrick_el1_abi::ForkLifecycleLoan>,
    ) {
        assert_eq!(self.stock.install(tables, lifecycles), Ok(()));
    }

    pub(crate) fn set_carrier_for_tests(&mut self, carrier: NonZeroU64) {
        self.stock.set_carrier(carrier);
    }
}

/// Lifecycle records in the HVF stock: one metadata extent of 16 KiB slots,
/// the first left unused. Each live fork child holds one.
pub(crate) const HVF_FORK_LIFECYCLE_SLOTS: u64 =
    carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64 / LIFECYCLE_SLOT_STRIDE - 1;

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
        PortalForkCompletion, PortalOperation, ReservationGeneration, ReservationMm,
    };
    use carrick_guest_arch::{
        AddressContext, ContextGeneration, CpuId, FrameGpa, KernelVa, MmGeneration,
    };
    use carrick_hal::asid::AsidError;
    use core::num::NonZeroU64;

    /// A real lifecycle window over zeroed host bytes covering the ARM
    /// default record and the production boot stock extent.
    fn test_hygiene() -> carrick_hal::fork_stock::LifecycleWindow {
        let words = carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE / 8;
        let bytes: &'static mut [u64] = Box::leak(vec![0u64; words].into_boxed_slice());
        // SAFETY: the leaked buffer lives for the test process and backs
        // the first metadata extent's kernel VAs.
        unsafe {
            carrick_hal::fork_stock::LifecycleWindow::new(
                core::ptr::NonNull::new(bytes.as_mut_ptr().cast::<u8>()).unwrap(),
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
                carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            )
        }
    }

    fn page(addr: u64) -> RootGpa {
        RootGpa::page_aligned(FrameGpa::new(addr)).unwrap()
    }

    fn test_execution(task: u64, cpu: u32, mm: u64) -> GrantExecution {
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
                root: page(0x1000),
                generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
    }

    /// The child's own execution: its root is the loaned child table base.
    fn child_execution(task: u64, loan: &ForkStockLoan) -> GrantExecution {
        let mut child = test_execution(task, 0, loan.request.child_mm.raw());
        child.context.root = page(loan.request.child_tables.base);
        child
    }

    fn test_request(
        exec: GrantExecution,
        child_mm: u64,
        child_pages: u64,
        parent_pages: u64,
    ) -> carrick_el1_abi::ForkStockRequest {
        carrick_el1_abi::ForkStockRequest {
            binding: exec.binding,
            context: exec.context,
            operation: PortalOperation {
                carrier: NonZeroU64::new(7).unwrap(),
                mm: ReservationMm::new(exec.context.mm.raw().get()).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::new(2).unwrap(),
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_mm: ReservationMm::new(child_mm).unwrap(),
            child_bytes: child_pages * 4096,
            parent_bytes: parent_pages * 4096,
        }
    }

    /// A record whose host bytes are not zero (a dirty reissue).
    struct DirtyLifecycles;
    impl LifecycleHygiene for DirtyLifecycles {
        fn is_zero(&self, _: carrick_el1_abi::ForkLifecycleLoan) -> bool {
            false
        }
        fn clear(&self, _: carrick_el1_abi::ForkLifecycleLoan) -> bool {
            true
        }
    }

    #[test]
    fn dirty_lifecycle_record_is_withdrawn_not_reissued_on_hvf() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        custody.seed_for_tests((0..8).map(|i| page(0x20000 + i * 4096)).collect());
        let mut ledger = El1FrameGrantLedger::default();
        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange, &DirtyLifecycles),
            Err(ForkStockRefusal::Inventory)
        );
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Inventory)));
        assert!(custody.stock().lifecycle_stock().is_empty());
        assert_eq!(custody.stock().counters().withdrawn_lifecycles, 1);
        assert_eq!(custody.stock().table_stock().len(), 8);
        assert_eq!(ledger.snapshot().bytes_granted, 0);
    }

    #[test]
    fn table_stock_allocation_geometry() {
        let mut stock = vec![
            page(0x6000),
            page(0x2000),
            page(0x4000),
            page(0x1000),
            page(0x3000),
            page(0x5000),
        ];
        let (child, parent) = take_fork_table_stock(&mut stock, 12288, 8192).unwrap();
        assert_eq!(child.len(), 3);
        assert_eq!(parent.len(), 2);
        assert_eq!(stock.len(), 1);
        assert_eq!(stock[0], page(0x6000));
        assert!(
            child
                .windows(2)
                .all(|w| w[1].address().raw() == w[0].address().raw() + 4096)
        );
        assert!(
            parent
                .windows(2)
                .all(|w| w[1].address().raw() == w[0].address().raw() + 4096)
        );
        assert!(
            child
                .iter()
                .all(|c| !parent.contains(c) && !stock.contains(c))
        );

        // Unaligned requests fail
        let mut empty = Vec::new();
        assert!(take_fork_table_stock(&mut empty, 4095, 4096).is_none());
        assert!(take_fork_table_stock(&mut empty, 4096, 0).is_none());

        // Duplicate pages fail
        let mut dup = vec![page(0x1000), page(0x1000)];
        assert!(take_fork_table_stock(&mut dup, 4096, 4096).is_none());

        // Non-contiguous stock fails
        let mut holes = vec![page(0x1000), page(0x3000), page(0x5000)];
        assert!(take_fork_table_stock(&mut holes, 8192, 4096).is_none());
    }

    #[test]
    fn request_settlement_round_trip() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let mut ledger = El1FrameGrantLedger::default();

        // Seed 8 contiguous pages: 0x20000..0x28000
        custody.seed_for_tests((0..8).map(|i| page(0x20000 + i * 4096)).collect());
        let initial_stock_len = custody.stock().table_stock().len();

        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 4, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();

        // Service Loan
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange, &test_hygiene())
            .expect("loan should succeed");
        assert_eq!(custody.stock().table_stock().len(), initial_stock_len - 5);
        assert_eq!(loan.request.child_tables.base, 0x20000);
        assert_eq!(loan.request.child_tables.len, 4 * 4096);
        assert_eq!(loan.request.parent_tables.base, 0x24000);
        assert_eq!(loan.request.parent_tables.len, 4096);

        // Consume exchange
        let taken_loan = exchange.take(req).unwrap().unwrap();
        assert_eq!(taken_loan.id, loan.id);
        assert!(
            exchange.take(req).is_none(),
            "exchange must be consumed once"
        );

        // Verify ledger grants
        let child_mm = El1FrameGrantMm::new(302).unwrap();
        let parent_mm = El1FrameGrantMm::new(301).unwrap();
        let observer_ledger = std::sync::Arc::new(parking_lot::Mutex::new(ledger));
        let child_stats = observer_ledger.lock().snapshot_mm(child_mm).unwrap();
        let parent_stats = observer_ledger.lock().snapshot_mm(parent_mm).unwrap();
        assert_eq!(child_stats.bytes_granted, 4 * 4096);
        assert_eq!(parent_stats.bytes_granted, 4096);

        // Commit: child used 1 page (4096), parent used 1 page (4096)
        // 3 child pages (12288 bytes) are unused and returned!
        let completion = PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    req.operation.carrier,
                    req.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let mut settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0x2D_0800_4000), 0)
                .expect("settlement must be valid");

        let mut ledger = std::sync::Arc::try_unwrap(observer_ledger)
            .unwrap()
            .into_inner();
        custody
            .service_settlement(
                &mut ledger,
                exec,
                &mut settlement,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("settlement commit should succeed");

        // Unused 3 child pages returned to stock: initial (8) - 2 used = 6 remaining
        assert_eq!(custody.stock().table_stock().len(), 6);
        assert_eq!(
            ledger.snapshot_mm(child_mm).unwrap().bytes_returned,
            3 * 4096
        );

        // Settlement consumed once
        assert_eq!(settlement.take(loan), Some(Ok(())));
        assert!(settlement.take(loan).is_none());

        // Subsequent commit or abort fails (loan already settled)
        let mut second_settlement = ForkStockSettlement::abort(loan);
        assert_eq!(
            custody.service_settlement(
                &mut ledger,
                exec,
                &mut second_settlement,
                |_| true,
                |_| true,
                &test_hygiene()
            ),
            Err(ForkStockServiceError::NoPendingLoan)
        );
    }

    #[test]
    fn refusal_on_stale_or_foreign_custody() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let mut ledger = El1FrameGrantLedger::default();
        custody.seed_for_tests((0..8).map(|i| page(0x20000 + i * 4096)).collect());

        let exec = test_execution(41, 0, 301);

        // Case A: Foreign task binding
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(999);
        let req = test_request(foreign_exec, 302, 2, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let result = custody.service_loan(&mut ledger, exec, &mut exchange, &test_hygiene());
        assert_eq!(result, Err(ForkStockRefusal::Stale));
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));

        // Case B: Foreign context
        let mut foreign_context_exec = exec;
        foreign_context_exec.context.root = page(0x9000);
        let req = test_request(foreign_context_exec, 302, 2, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange, &test_hygiene()),
            Err(ForkStockRefusal::Stale)
        );

        // Case C: Foreign carrier
        let mut foreign_carrier_req = test_request(exec, 302, 2, 1);
        foreign_carrier_req.operation.carrier = NonZeroU64::new(99).unwrap();
        let mut exchange = ForkStockExchange::new(foreign_carrier_req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange, &test_hygiene()),
            Err(ForkStockRefusal::Stale)
        );

        // Case D: Capacity refusal when stock insufficient
        let huge_req = test_request(exec, 302, 100, 100);
        let mut exchange = ForkStockExchange::new(huge_req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange, &test_hygiene()),
            Err(ForkStockRefusal::Capacity)
        );

        // Verify stock and ledger were completely untouched across all refusals
        assert_eq!(custody.stock().table_stock().len(), 8);
        assert_eq!(ledger.snapshot().bytes_granted, 0);
    }

    #[test]
    fn rollback_returns_pages_exactly_once() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let mut ledger = El1FrameGrantLedger::default();
        custody.seed_for_tests((0..6).map(|i| page(0x20000 + i * 4096)).collect());
        assert_eq!(custody.stock().table_stock().len(), 6);

        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 3, 1); // 4 pages total
        let mut exchange = ForkStockExchange::new(req).unwrap();

        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange, &test_hygiene())
            .expect("loan succeeds");
        assert_eq!(custody.stock().table_stock().len(), 2);
        assert_eq!(ledger.snapshot().bytes_granted, 4 * 4096);
        assert_eq!(ledger.snapshot().bytes_returned, 0);

        // Abort the loan
        let mut abort_settlement = ForkStockSettlement::abort(loan);
        custody
            .service_settlement(
                &mut ledger,
                exec,
                &mut abort_settlement,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("abort succeeds");

        // All 4 pages restored to stock exactly once
        assert_eq!(custody.stock().table_stock().len(), 6);
        assert_eq!(ledger.snapshot().bytes_returned, 4 * 4096);
        assert_eq!(ledger.snapshot().returns_completed, 4); // 3 child + 1 parent

        // A second abort attempt must fail with NoPendingLoan and NOT return pages again
        assert_eq!(
            custody.service_settlement(
                &mut ledger,
                exec,
                &mut abort_settlement,
                |_| true,
                |_| true,
                &test_hygiene()
            ),
            Err(ForkStockServiceError::NoPendingLoan)
        );
        assert_eq!(custody.stock().table_stock().len(), 6);
        assert_eq!(ledger.snapshot().bytes_returned, 4 * 4096);

        // Dirty page verification: if pages were modified, abort fails closed
        let mut second_exchange = ForkStockExchange::new(test_request(exec, 303, 3, 1)).unwrap();
        let second_loan = custody
            .service_loan(&mut ledger, exec, &mut second_exchange, &test_hygiene())
            .unwrap();
        let mut dirty_abort = ForkStockSettlement::abort(second_loan);
        let result = custody.service_settlement(
            &mut ledger,
            exec,
            &mut dirty_abort,
            |_| true,
            |_| false,
            &test_hygiene(),
        );
        assert_eq!(result, Err(ForkStockServiceError::ExposedDirtyTable));
        custody
            .service_settlement(
                &mut ledger,
                exec,
                &mut dirty_abort,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("guest cleared the loan after refusal");
        let mut third_exchange = ForkStockExchange::new(test_request(exec, 304, 3, 1)).unwrap();
        custody
            .service_loan(&mut ledger, exec, &mut third_exchange, &test_hygiene())
            .expect("same CPU can fork after clean abort");
    }

    #[test]
    fn root_exit_refuses_stale_custody_and_leaves_ledger_unchanged() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let ledger = El1FrameGrantLedger::default();
        let initial_stats = ledger.snapshot();

        let exec = test_execution(41, 0, 301);
        let valid_status = LinuxWaitStatus::from_wait_encoding(42 << 8);
        let root_exit = NativeRootExit::new(exec.binding, valid_status).unwrap();

        // Foreign execution binding (wrong task ID)
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(99);
        let result = custody.service_root_exit(foreign_exec.binding, &root_exit);
        assert_eq!(result, Err(ForkStockServiceError::StaleExecution));

        // Foreign generation
        let mut foreign_gen_exec = exec;
        foreign_gen_exec.binding.generation = EntryGeneration::from_raw(99);
        assert_eq!(
            custody.service_root_exit(foreign_gen_exec.binding, &root_exit),
            Err(ForkStockServiceError::StaleExecution)
        );

        // Foreign MM
        let mut foreign_mm_exec = exec;
        foreign_mm_exec.binding.mm = EntryMmKey::from_raw(99);
        assert_eq!(
            custody.service_root_exit(foreign_mm_exec.binding, &root_exit),
            Err(ForkStockServiceError::StaleExecution)
        );

        // Assert that the ledger was left completely unchanged!
        assert_eq!(ledger.snapshot(), initial_stats);

        // Matching binding succeeds and still leaves ledger unchanged
        let exit_status = custody.service_root_exit(exec.binding, &root_exit).unwrap();
        assert_eq!(exit_status, valid_status);
        assert_eq!(ledger.snapshot(), initial_stats);
    }

    #[test]
    fn shared_asid_allocator_host_and_fork_stock_coexist() {
        let asid_allocator = AsidAllocator::with_limit_for_tests(2);
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::with_asids(carrier, asid_allocator.clone());
        let mut ledger = El1FrameGrantLedger::default();

        // 1. Allocate an ASID for a host-created MM through the production path
        let host_asid_gen = asid_allocator.allocate().expect("host MM ASID");
        let host_asid = host_asid_gen.asid();

        // 2. Fork through the fork-stock path and assert the child's ASID differs
        custody.seed_for_tests(
            (0..16)
                .map(|i| RootGpa::page_aligned(FrameGpa::new(0x2_0000 + i * 4096)).unwrap())
                .collect(),
        );
        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange, &test_hygiene())
            .expect("loan granted");

        let child_asid = loan.asid.expect("child ASID granted");
        assert_ne!(
            child_asid, host_asid,
            "child ASID must differ from host MM ASID"
        );

        // 3. Abort releases the ASID back to reusable pool
        let mut abort = ForkStockSettlement::abort(loan);
        custody
            .service_settlement(
                &mut ledger,
                exec,
                &mut abort,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("abort settlement");

        // The aborted ASID was released unpublished and can now be reallocated
        let reallocated_gen = asid_allocator.allocate().expect("allocate after abort");
        assert_eq!(
            reallocated_gen.asid(),
            child_asid,
            "aborted ASID should be released back to the allocator immediately"
        );
        asid_allocator.release_unpublished(reallocated_gen).unwrap();

        // 4. Now fork again, commit, and retire through root exit
        let req2 = test_request(exec, 303, 1, 1);
        let mut exchange2 = ForkStockExchange::new(req2).unwrap();
        let loan2 = custody
            .service_loan(&mut ledger, exec, &mut exchange2, &test_hygiene())
            .expect("loan 2 granted");
        let child_asid2 = loan2.asid.expect("child ASID 2");

        let completion = PortalForkCompletion {
            request: loan2.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    carrier,
                    req2.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let mut commit =
            ForkStockSettlement::new(loan2, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                .unwrap();
        custody
            .service_settlement(
                &mut ledger,
                exec,
                &mut commit,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("commit settlement");

        // Child exit marks the MM retired while its TTBR0 may still be live.
        let child_exec = child_execution(42, &loan2);
        let mut retire = NativeChildRetire::new(child_exec.binding, child_exec.context).unwrap();
        custody
            .service_child_retire(child_exec, &mut retire)
            .expect("child quarantine");

        assert!(
            custody
                .stock()
                .child_tag(ReservationMm::new(303).unwrap())
                .is_some()
        );
        assert_eq!(
            custody
                .reclaim_retired(
                    &mut ledger,
                    ReservationMm::new(exec.binding.mm.raw()).unwrap(),
                    |mm| SlotAbsence::scan(mm, []),
                    |_| true,
                    &test_hygiene()
                )
                .expect("reclaim after parent resumes"),
            1
        );
        // A second pass cannot reclaim the same child twice.
        assert_eq!(
            custody
                .reclaim_retired(
                    &mut ledger,
                    ReservationMm::new(exec.binding.mm.raw()).unwrap(),
                    |mm| SlotAbsence::scan(mm, []),
                    |_| true,
                    &test_hygiene()
                )
                .expect("exactly once"),
            0
        );
        assert!(
            custody
                .stock()
                .child_tag(ReservationMm::new(303).unwrap())
                .is_none()
        );

        // The retired and acknowledged ASID is now reusable in the allocator
        let reallocated_gen2 = asid_allocator
            .allocate()
            .expect("allocate after retirement");
        assert_eq!(
            reallocated_gen2.asid(),
            child_asid2,
            "retired ASID should be released back to the reusable pool"
        );
    }

    #[test]
    fn sequential_fork_wait_reuses_retired_stock_beyond_pool_size() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody =
            ForkStockHostCustody::with_asids(carrier, AsidAllocator::with_limit_for_tests(2));
        let mut ledger = El1FrameGrantLedger::default();
        custody
            .install_boot_stock(
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            )
            .expect("production boot stock");
        let pool_pages = custody.stock().table_stock().len();
        let lifecycle_slots = custody.stock().lifecycle_stock().len();
        let parent = test_execution(41, 0, 301);

        for cycle in 0..=pool_pages as u64 {
            let child_mm = 302 + cycle;
            let request = test_request(parent, child_mm, 1, 1);
            let mut exchange = ForkStockExchange::new(request).unwrap();
            let loan = custody
                .service_loan(&mut ledger, parent, &mut exchange, &test_hygiene())
                .expect("bounded stock serves each fork");
            let completion = PortalForkCompletion {
                request: loan.request,
                child: unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        carrier,
                        request.child_mm,
                        NonZeroU64::MIN,
                    )
                },
                parent_generation: ReservationGeneration::INITIAL,
                child_tables_used: 4096,
                parent_tables_used: 0,
            };
            let mut commit =
                ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                    .unwrap();
            custody
                .service_settlement(
                    &mut ledger,
                    parent,
                    &mut commit,
                    |_| true,
                    |_| true,
                    &test_hygiene(),
                )
                .expect("settle child and return unused parent page");
            let child = child_execution(42 + cycle, &loan);
            let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
            custody
                .service_child_retire(child, &mut retire)
                .expect("child quarantine");
            assert_eq!(
                custody
                    .reclaim_retired(
                        &mut ledger,
                        ReservationMm::new(parent.binding.mm.raw()).unwrap(),
                        |mm| SlotAbsence::scan(mm, []),
                        |_| true,
                        &test_hygiene()
                    )
                    .expect("parent has resumed"),
                1
            );
            assert_eq!(custody.stock().table_stock().len(), pool_pages);
            assert_eq!(custody.stock().lifecycle_stock().len(), lifecycle_slots);
        }
    }

    #[test]
    fn two_live_children_take_distinct_boot_lifecycle_pages() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        custody
            .install_boot_stock(
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            )
            .expect("production boot stock");
        let mut ledger = El1FrameGrantLedger::default();
        let parent = test_execution(41, 0, 301);
        let mut lifecycles = Vec::new();
        for child_mm in [302, 303] {
            let request = test_request(parent, child_mm, 1, 1);
            let mut exchange = ForkStockExchange::new(request).unwrap();
            let loan = custody
                .service_loan(&mut ledger, parent, &mut exchange, &test_hygiene())
                .expect("fork while prior child remains live");
            lifecycles.push(loan.lifecycle);
            let completion = PortalForkCompletion {
                request: loan.request,
                child: unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        carrier,
                        request.child_mm,
                        NonZeroU64::MIN,
                    )
                },
                parent_generation: ReservationGeneration::INITIAL,
                child_tables_used: 4096,
                parent_tables_used: 0,
            };
            let mut commit =
                ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                    .unwrap();
            custody
                .service_settlement(
                    &mut ledger,
                    parent,
                    &mut commit,
                    |_| true,
                    |_| true,
                    &test_hygiene(),
                )
                .expect("committed child stays live");
        }
        assert_ne!(lifecycles[0], lifecycles[1]);
        assert_eq!(custody.stock().live_children(), 2);
    }

    /// HVF adapter witness: with the production boot stock and a two-ASID
    /// allocator, fork far beyond both while the previous child is still
    /// installed in quarantine. No loan reuses an installed child's pages,
    /// every reclaim returns its ledger grants, and ASIDs recycle.
    #[test]
    fn interleaved_fork_retire_beyond_stock_balances_the_grant_ledger() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody =
            ForkStockHostCustody::with_asids(carrier, AsidAllocator::with_limit_for_tests(2));
        custody
            .install_boot_stock(
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            )
            .expect("production boot stock");
        let mut ledger = El1FrameGrantLedger::default();
        let parent = test_execution(41, 0, 301);
        let pool = custody.stock().table_stock().len() as u64;
        let records = custody.stock().lifecycle_stock().len() as u64;
        let cycles = pool.max(records) + 3;
        let mut installed: Option<ReservationMm> = None;
        for cycle in 0..cycles {
            let child_mm = 302 + cycle;
            let held = custody.stock().quarantined_tables();
            let request = test_request(parent, child_mm, 1, 1);
            let mut exchange = ForkStockExchange::new(request).unwrap();
            let loan = custody
                .service_loan(&mut ledger, parent, &mut exchange, &test_hygiene())
                .unwrap_or_else(|refusal| panic!("cycle {cycle}: {refusal:?}"));
            let issued = &custody.stock().pending(parent.cpu).unwrap().child_tables;
            assert!(issued.iter().all(|page| !held.contains(page)));
            let completion = PortalForkCompletion {
                request: loan.request,
                child: unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        carrier,
                        request.child_mm,
                        NonZeroU64::MIN,
                    )
                },
                parent_generation: ReservationGeneration::INITIAL,
                child_tables_used: 4096,
                parent_tables_used: 0,
            };
            let mut commit =
                ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                    .unwrap();
            custody
                .service_settlement(
                    &mut ledger,
                    parent,
                    &mut commit,
                    |_| true,
                    |_| true,
                    &test_hygiene(),
                )
                .expect("commit");
            let child = child_execution(42 + cycle, &loan);
            let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
            custody
                .service_child_retire(child, &mut retire)
                .expect("child quarantine");
            let previous = installed.replace(ReservationMm::new(child_mm).unwrap());
            let still = installed;
            let returned = custody
                .reclaim_retired(
                    &mut ledger,
                    ReservationMm::new(parent.binding.mm.raw()).unwrap(),
                    |mm| SlotAbsence::scan(mm, still.map(|still| still.raw())),
                    |_| true,
                    &test_hygiene(),
                )
                .expect("reclaim");
            assert_eq!(returned, usize::from(previous.is_some()), "cycle {cycle}");
        }
        assert_eq!(custody.returned_children(), cycles - 1);
        // Only the last child's one committed page is still granted.
        let stats = ledger.snapshot();
        assert_eq!(stats.bytes_granted - stats.bytes_returned, 4096);
        assert_eq!(custody.stock().counters().capacity_refusals, 0);
    }

    #[test]
    fn quarantined_child_tables_are_not_reissued_while_mm_is_live() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        custody
            .install_boot_stock(
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
                carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64,
            )
            .expect("production boot stock");
        let mut ledger = El1FrameGrantLedger::default();
        let parent = test_execution(41, 0, 301);
        let pool_pages = custody.stock().table_stock().len() as u64;
        let request = test_request(parent, 302, pool_pages - 1, 1);
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let loan = custody
            .service_loan(&mut ledger, parent, &mut exchange, &test_hygiene())
            .expect("first child takes available table stock");
        let completion = PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    carrier,
                    request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: (pool_pages - 1) * 4096,
            parent_tables_used: 0,
        };
        let mut commit =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                .unwrap();
        custody
            .service_settlement(
                &mut ledger,
                parent,
                &mut commit,
                |_| true,
                |_| true,
                &test_hygiene(),
            )
            .expect("commit first child");
        let child = child_execution(42, &loan);
        let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
        custody
            .service_child_retire(child, &mut retire)
            .expect("quarantine child tables");
        assert_eq!(
            custody
                .reclaim_retired(
                    &mut ledger,
                    ReservationMm::new(parent.binding.mm.raw()).unwrap(),
                    |mm| SlotAbsence::scan(mm, [mm.raw()]),
                    |_| true,
                    &test_hygiene()
                )
                .unwrap(),
            0
        );
        let next = test_request(parent, 303, pool_pages - 1, 1);
        let mut refused = ForkStockExchange::new(next).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, parent, &mut refused, &test_hygiene()),
            Err(ForkStockRefusal::Capacity)
        );
        assert_eq!(
            custody
                .reclaim_retired(
                    &mut ledger,
                    ReservationMm::new(parent.binding.mm.raw()).unwrap(),
                    |mm| SlotAbsence::scan(mm, []),
                    |_| true,
                    &test_hygiene()
                )
                .unwrap(),
            1
        );
        let mut admitted = ForkStockExchange::new(next).unwrap();
        custody
            .service_loan(&mut ledger, parent, &mut admitted, &test_hygiene())
            .expect("stock is reusable only after quarantine drains");
    }

    #[repr(C, align(16384))]
    struct LifecycleBacking([u8; 0x4000]);

    /// Back the ARM default lifecycle record with a carrier stage-2 record,
    /// as the production boot stock extent is.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn publish_lifecycle_record(
        custody: &CarrierVmCustody,
        generation: crate::trap::CarrierVmGeneration,
    ) -> Box<LifecycleBacking> {
        let mut backing = Box::new(LifecycleBacking([0u8; 0x4000]));
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: carrick_el1_abi::ForkLifecycleLoan::ARM_DEFAULT.page.raw(),
            len: 0x4000,
            host_addr: backing.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 900,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();
        backing
    }

    #[repr(align(64))]
    struct AlignedPage([u8; 4096]);

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_round_trip_and_settlement() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);

        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();

        let carrier = NonZeroU64::new(7).unwrap();
        let mut stock_pages: Vec<Box<AlignedPage>> =
            (0..8).map(|_| Box::new(AlignedPage([0u8; 4096]))).collect();
        for (i, p) in stock_pages.iter_mut().enumerate() {
            let ipa = 0x2001_0000u64 + (i as u64) * 4096;
            let spec = crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa,
                len: 4096,
                host_addr: p.0.as_mut_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: 2 + i as u64,
                    generation: 1,
                }),
            };
            custody.publish_stage2_record_using(spec, || 0).unwrap();
        }
        {
            let mut fork = custody.fork_stock.lock();
            fork.seed_for_tests((0..8).map(|i| page(0x2001_0000u64 + i * 4096)).collect());
            fork.set_carrier_for_tests(carrier);
        }

        let exec = test_execution(41, 0, 301);

        let req = test_request(exec, 302, 4, 1);
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }

        // Dispatch Loan via service_metadata_operation
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatcher call succeeds");
        assert_eq!(result, [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]);

        // Verify exchange was updated in place and can be taken
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        let loan = exchange.take(req).unwrap().unwrap();
        assert_eq!(loan.request.child_mm, req.child_mm);
        assert_eq!(loan.request.child_tables.len, 4 * 4096);
        assert_eq!(loan.request.parent_tables.len, 4096);

        // Verify ledger accounted for the grant
        let child_mm = El1FrameGrantMm::new(302).unwrap();
        let parent_mm = El1FrameGrantMm::new(301).unwrap();
        {
            let ledger = custody.el1_frame_grants.lock();
            let child_stats = ledger.snapshot_mm(child_mm).unwrap();
            let parent_stats = ledger.snapshot_mm(parent_mm).unwrap();
            assert_eq!(child_stats.bytes_granted, 4 * 4096);
            assert_eq!(parent_stats.bytes_granted, 4096);
        }

        // Prepare settlement commit: 1 child page used, 1 parent page used (3 child returned)
        let completion = PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    req.operation.carrier,
                    req.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0x2D_0800_4000), 0).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockSettlement).write(settlement);
        }

        // Dispatch Settlement via service_metadata_operation
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatcher settlement succeeds");
        assert_eq!(result, [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]);

        // Verify settlement was accepted and consumed once
        let settlement = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockSettlement) };
        assert_eq!(settlement.take(loan), Some(Ok(())));
        assert!(settlement.take(loan).is_none());

        // Verify unused pages returned to ledger and grant_tables
        {
            let ledger = custody.el1_frame_grants.lock();
            let child_stats = ledger.snapshot_mm(child_mm).unwrap();
            assert_eq!(child_stats.bytes_returned, 3 * 4096);
        }
        assert_eq!(custody.fork_stock.lock().stock().table_stock().len(), 6);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_refusal_on_stale_custody_and_malformed() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);

        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();

        let carrier = NonZeroU64::new(7).unwrap();
        {
            let mut fork = custody.fork_stock.lock();
            fork.seed_for_tests((0..8).map(|i| page(0x40000 + i * 4096)).collect());
            fork.set_carrier_for_tests(carrier);
        }

        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 4, 1);
        let initial_ledger = custody.el1_frame_grants.lock().snapshot();

        // Case 1: Missing active execution -> typed refusal (Stale), ledger unchanged
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            None,
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 2, 0, 0]
        );
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
        assert_eq!(custody.fork_stock.lock().stock().table_stock().len(), 8);

        // Case 2: Mismatched foreign execution -> typed refusal (Stale), ledger unchanged
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(999);
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            foreign_exec.cpu,
            Some(foreign_exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 2, 0, 0]
        );
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
        assert_eq!(custody.fork_stock.lock().stock().table_stock().len(), 8);

        // Case 3: An authenticated request with no lifecycle stock reports
        // the first typed capacity refusal through the trap result.
        {
            let mut fork = custody.fork_stock.lock();
            let tables = fork.stock().table_stock().to_vec();
            *fork = ForkStockHostCustody::new(carrier);
            fork.seed_with_for_tests(tables, Vec::new());
        }
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched capacity refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 3, 0, 0]
        );
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Capacity)));

        // Case 4: Misaligned GPA -> METADATA_GRANT_ERR_ALIGNMENT, ledger unchanged
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa + 1,
            0,
            0,
        )
        .expect("alignment refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_ALIGNMENT, 0, 0, 0]
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);

        // Case 5: Unmapped GPA -> METADATA_GRANT_ERR_INVALID, ledger unchanged
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            0x9999_0000,
            0,
            0,
        )
        .expect("unmapped refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_INVALID, 0, 0, 0]
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
    }

    /// Commit and retire one child of `parent` whose single table page is
    /// the published stage-2 page at `ipa`; returns the child MM.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn quarantine_one_child(
        custody: &CarrierVmCustody,
        generation: crate::trap::CarrierVmGeneration,
        pages: &mut Vec<Box<AlignedPage>>,
        parent: GrantExecution,
    ) -> ReservationMm {
        let mut tables = Vec::new();
        for i in 0..4u64 {
            let mut aligned = Box::new(AlignedPage([0u8; 4096]));
            let ipa = 0x2001_0000u64 + i * 4096;
            let spec = crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa,
                len: 4096,
                host_addr: aligned.0.as_mut_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: 2 + i,
                    generation: 1,
                }),
            };
            custody.publish_stage2_record_using(spec, || 0).unwrap();
            pages.push(aligned);
            tables.push(page(ipa));
        }
        let carrier = NonZeroU64::new(7).unwrap();
        let mut fork = custody.fork_stock.lock();
        fork.seed_for_tests(tables);
        fork.set_carrier_for_tests(carrier);
        let mut ledger = custody.el1_frame_grants.lock();
        let request = test_request(parent, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let loan = fork
            .service_loan(&mut ledger, parent, &mut exchange, &test_hygiene())
            .expect("loan");
        let completion = PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    carrier,
                    request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let mut commit =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                .unwrap();
        fork.service_settlement(
            &mut ledger,
            parent,
            &mut commit,
            |_| true,
            |_| true,
            &test_hygiene(),
        )
        .expect("commit");
        let child = child_execution(42, &loan);
        let mut retire = NativeChildRetire::new(child.binding, child.context).unwrap();
        fork.service_child_retire(child, &mut retire)
            .expect("quarantine");
        request.child_mm
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_child_retire_reply_word_agrees_with_x0() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);
        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();
        // Not a committed child: refused with x0 DENIED and a Stale reply.
        let stranger = test_execution(42, 0, 777);
        let record = NativeChildRetire::new(stranger.binding, stranger.context).unwrap();
        unsafe { (record_page.0.as_mut_ptr() as *mut NativeChildRetire).write(record) };
        let reply = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            stranger.cpu,
            Some(stranger),
            carrick_el1_abi::GRANT_OP_CHILD_RETIRE,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched refusal");
        assert_eq!(reply, [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]);
        let written = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut NativeChildRetire) };
        assert_eq!(
            written.take(stranger.binding, stranger.context),
            Some(Err(carrick_el1_abi::ChildRetireRefusal::Stale))
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn quarantine_drain_without_occupancy_authority_is_a_typed_error() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);
        let parent = test_execution(41, 0, 301);
        // Nothing quarantined: no occupancy proof is needed.
        assert_eq!(
            crate::metadata_grant::drain_fork_quarantine(&custody, parent, None),
            Ok(())
        );
        let mut pages = Vec::new();
        let child = quarantine_one_child(&custody, generation, &mut pages, parent);
        assert_eq!(
            crate::metadata_grant::drain_fork_quarantine(&custody, parent, None),
            Err(ForkStockServiceError::OccupancyUnavailable)
        );
        assert!(custody.fork_stock.lock().stock().is_quarantined(child));
        assert_eq!(custody.fork_stock.lock().returned_children(), 0);

        // With a zone that installs nothing, the same drain reclaims.
        let layout = std::alloc::Layout::new::<carrick_el1_abi::ZoneTables>();
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        let zone = unsafe { Box::from_raw(pointer.cast::<carrick_el1_abi::ZoneTables>()) };
        assert_eq!(
            crate::metadata_grant::drain_fork_quarantine(&custody, parent, Some(&zone)),
            Ok(())
        );
        assert!(!custody.fork_stock.lock().stock().is_quarantined(child));
        assert_eq!(custody.fork_stock.lock().returned_children(), 1);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_root_exit_success_and_stale_refusal() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);

        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();

        let initial_ledger = custody.el1_frame_grants.lock().snapshot();
        let exec = test_execution(41, 0, 301);
        let status = LinuxWaitStatus::from_wait_encoding(25 << 8);
        let root_exit = NativeRootExit::new(exec.binding, status).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut NativeRootExit).write(root_exit);
        }

        // Case 1: Matching active execution -> SUCCESS with status, ledger unchanged
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_ROOT_EXIT,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched root exit");
        assert_eq!(
            result,
            [
                carrick_el1_abi::METADATA_GRANT_SUCCESS,
                (25 << 8) as u64,
                0,
                0
            ]
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);

        // Case 2: Stale active execution -> ERR_DENIED, ledger unchanged
        let mut foreign_exec = exec;
        foreign_exec.binding.generation = EntryGeneration::from_raw(999);
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            foreign_exec.cpu,
            Some(foreign_exec),
            carrick_el1_abi::GRANT_OP_ROOT_EXIT,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched root exit refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_refuses_foreign_or_out_of_range_guest_cpu_index() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);

        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();

        let mut tables = Vec::new();
        let mut pages: Vec<Box<AlignedPage>> =
            (0..8).map(|_| Box::new(AlignedPage([0u8; 4096]))).collect();
        for (i, aligned_page) in pages.iter_mut().enumerate() {
            let ipa = 0x2001_0000u64 + (i as u64) * 4096;
            let spec = crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa,
                len: 4096,
                host_addr: aligned_page.0.as_mut_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: 2 + i as u64,
                    generation: 1,
                }),
            };
            custody.publish_stage2_record_using(spec, || 0).unwrap();
            tables.push(page(ipa));
        }

        custody.fork_stock.lock().seed_for_tests(tables);
        let exec_0 = test_execution(41, 0, 300);
        let exec_a = test_execution(41, 1, 301);
        let exec_b = test_execution(41, 2, 302);
        custody
            .fork_stock
            .lock()
            .set_carrier_for_tests(NonZeroU64::new(7).unwrap());

        let initial_ledger = custody.el1_frame_grants.lock().snapshot();

        // Case 1: Trapped on vCPU A (1), guest attempts to name vCPU B (2).
        // Must be refused, never charged to B or CPU 0.
        let req_b = test_request(exec_b, 303, 4, 1);
        let exchange = ForkStockExchange::new(req_b).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            exec_b.cpu.raw() as u64, // Guest attempts to name vCPU B
            0,
        )
        .expect("dispatcher call");

        // The refused loan record reports its typed Stale refusal (wire 2).
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 2, 0, 0]
        );
        // Neither B nor 0 is charged
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_b.cpu)
                .is_none()
        );
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_0.cpu)
                .is_none()
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);

        // Case 2: Trapped on vCPU A (1), guest passes arg2 = 9999 (out-of-range).
        // Must be refused, never fall back to CPU 0.
        let req_0 = test_request(exec_0, 304, 4, 1);
        let exchange = ForkStockExchange::new(req_0).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            9999, // Out of range!
            0,
        )
        .expect("dispatcher call");

        // The refused loan record reports its typed Stale refusal (wire 2).
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 2, 0, 0]
        );
        // CPU 0 must NOT have been charged via silent fallback
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_0.cpu)
                .is_none()
        );
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);

        // Case 3: Trapped on vCPU A (1) with valid request for A.
        // It is charged to A!
        let req_a = test_request(exec_a, 305, 4, 1);
        let exchange = ForkStockExchange::new(req_a).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatcher call");

        assert_eq!(result, [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]);
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_a.cpu)
                .is_some()
        );
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_b.cpu)
                .is_none()
        );
        assert!(
            custody
                .fork_stock
                .lock()
                .stock()
                .pending(exec_0.cpu)
                .is_none()
        );

        // Case 4: Root exit trapped on vCPU A (1) naming vCPU B in arg2 -> refused
        let status = LinuxWaitStatus::from_wait_encoding(25 << 8);
        let root_exit = NativeRootExit::new(exec_b.binding, status).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut NativeRootExit).write(root_exit);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec_a.cpu,
            Some(exec_a), // Trapped on A
            carrick_el1_abi::GRANT_OP_ROOT_EXIT,
            record_ipa,
            exec_b.cpu.raw() as u64, // Guest attempts to name B
            0,
        )
        .expect("dispatcher call");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_commit_with_unresolvable_page_refuses_and_preserves_ledger() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let _lifecycle = publish_lifecycle_record(&custody, generation);

        let mut record_page = Box::new(AlignedPage([0u8; 4096]));
        let record_ipa = 0x2000_0000u64;
        let spec = crate::trap::CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: record_ipa,
            len: 4096,
            host_addr: record_page.0.as_mut_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: 3,
            logical_owner: Some(crate::trap::CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        custody.publish_stage2_record_using(spec, || 0).unwrap();

        // Map 3 child pages and 4 parent pages into stage-2
        let mut child_pages: Vec<Box<AlignedPage>> =
            (0..3).map(|_| Box::new(AlignedPage([0u8; 4096]))).collect();
        let mut parent_pages: Vec<Box<AlignedPage>> =
            (0..4).map(|_| Box::new(AlignedPage([0u8; 4096]))).collect();
        for (i, page) in child_pages.iter_mut().enumerate() {
            let ipa = 0x2001_0000u64 + (i as u64) * 4096;
            let spec = crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa,
                len: 4096,
                host_addr: page.0.as_mut_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: 2 + i as u64,
                    generation: 1,
                }),
            };
            custody.publish_stage2_record_using(spec, || 0).unwrap();
        }
        for (i, page) in parent_pages.iter_mut().enumerate() {
            let ipa = 0x2002_0000u64 + (i as u64) * 4096;
            let spec = crate::trap::CarrierStage2RecordSpec {
                vm_generation: generation,
                ipa,
                len: 4096,
                host_addr: page.0.as_mut_ptr() as usize,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                logical_owner: Some(crate::trap::CarrierLogicalOwner {
                    id: 10 + i as u64,
                    generation: 1,
                }),
            };
            custody.publish_stage2_record_using(spec, || 0).unwrap();
        }

        // Add 4 contiguous child pages (0x2001_0000..0x2001_3000) where the 4th page is unmapped/unresolvable,
        // plus mapped parent pages.
        {
            // i=3 of the child run is unmapped.
            let tables = (0..4)
                .map(|i| page(0x2001_0000u64 + i * 4096))
                .chain((0..4).map(|i| page(0x2002_0000u64 + i * 4096)))
                .collect();
            custody.fork_stock.lock().seed_for_tests(tables);
        }

        let exec = test_execution(41, 0, 301);
        custody
            .fork_stock
            .lock()
            .set_carrier_for_tests(NonZeroU64::new(7).unwrap());
        let req = test_request(exec, 302, 4, 1);

        // Perform Loan
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("loan dispatched");
        assert_eq!(result, [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]);

        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        let loan = exchange.take(req).unwrap().unwrap();

        // Snapshot ledger immediately after loan
        let ledger_after_loan = custody.el1_frame_grants.lock().snapshot();

        // Now prepare a Commit settlement: 1 child page used, 1 parent page used (3 child returned)
        let completion = PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    req.operation.carrier,
                    req.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0x2D_0800_4000), 0).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockSettlement).write(settlement);
        }

        // Dispatch Commit via service_metadata_operation
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
            Some(exec),
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("commit dispatched");

        // Must be refused with METADATA_GRANT_ERR_DENIED
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );

        // Settlement record must have typed refusal Invalid
        let mut settlement = unsafe { *(record_page.0.as_mut_ptr() as *mut ForkStockSettlement) };
        assert_eq!(settlement.take(loan), Some(Err(ForkStockRefusal::Invalid)));

        // Ledger must be completely unchanged from post-loan state!
        assert_eq!(
            custody.el1_frame_grants.lock().snapshot(),
            ledger_after_loan
        );
    }

    #[test]
    fn double_release_unpublished_is_reported_as_error() {
        let asid_allocator = AsidAllocator::with_limit_for_tests(2);
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::with_asids(carrier, asid_allocator.clone());
        let mut ledger = El1FrameGrantLedger::default();

        custody.seed_for_tests(
            (0..16)
                .map(|i| RootGpa::page_aligned(FrameGpa::new(0x2_0000 + i * 4096)).unwrap())
                .collect(),
        );
        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange, &test_hygiene())
            .expect("loan granted");
        let child_asid = loan.asid.expect("child ASID granted");

        // Release the ASID out of band to simulate a prior release:
        let pending_asid_gen = custody.stock().pending(exec.cpu).unwrap().tag;
        asid_allocator
            .release_unpublished(pending_asid_gen)
            .expect("first release succeeds");

        // Now abort settlement attempts to release the same ASID generation again
        let mut abort = ForkStockSettlement::abort(loan);
        let result = custody.service_settlement(
            &mut ledger,
            exec,
            &mut abort,
            |_| true,
            |_| true,
            &test_hygiene(),
        );

        // Double release must be reported as a typed error, not ignored
        assert_eq!(
            result,
            Err(ForkStockServiceError::Asid(AsidError::NotLive(child_asid))),
            "double release must be reported as a typed error"
        );
    }
}

#[cfg(test)]
mod design_doc_tests {
    /// The design doc's AArch64 live-children limit is this stock's size.
    #[test]
    fn design_doc_names_the_hvf_lifecycle_record_count() {
        let doc = include_str!("../../../docs/design/arm-fork-stock-crossing.md");
        let text = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        let claim = format!(
            "AArch64 has {} records (one {} KiB metadata extent, {} KiB per record",
            super::HVF_FORK_LIFECYCLE_SLOTS,
            carrick_el1_abi::EL1_DYNAMIC_METADATA_EXTENT_SIZE / 1024,
            carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE / 1024,
        );
        assert!(text.contains(&claim), "doc must say: {claim}");
    }
}
