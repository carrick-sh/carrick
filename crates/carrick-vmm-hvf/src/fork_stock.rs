//! Physical page-table stock loans and root-exit notifications for AArch64 EL1.
//!
//! On AArch64, this crossing is driven synchronously through `HVC #6` using operation
//! codes [`carrick_el1_abi::GRANT_OP_FORK_STOCK`] and [`carrick_el1_abi::GRANT_OP_ROOT_EXIT`].
//! The stopped vCPU retains its exclusive execution context and stack-allocated wire
//! record ([`ForkStockExchange`], [`ForkStockSettlement`], or [`NativeRootExit`]).
//!
//! Frame authority is rooted in `CarrierVmCustody`:
//! - `grant_tables: Vec<RootGpa>` supplies bounded stage-2 table frames;
//! - `El1FrameGrantLedger` accounts for all physical grants and returns;
//! - [`PendingForkLoan`] records outstanding loans and validates exactly-once completion.

use carrick_el1_abi::{
    ForkLifecycleLoan, ForkStockExchange, ForkStockLoan, ForkStockRefusal, ForkStockSettlement,
    NativeRootExit,
};
use carrick_guest_arch::{AddressContext, CpuId, RootGpa};
use carrick_sched_core::process::LinuxWaitStatus;
use core::num::NonZeroU64;

use crate::trap::{CarrierVmCustody, El1FrameGrantLedger, El1FrameGrantMm};

/// Admitted vCPU execution context for physical grant authentication.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GrantExecution {
    pub cpu: CpuId,
    pub binding: carrick_el1_abi::ExecutionBinding,
    pub context: AddressContext<RootGpa>,
}

impl GrantExecution {
    pub fn new(
        cpu: CpuId,
        binding: carrick_el1_abi::ExecutionBinding,
        context: AddressContext<RootGpa>,
    ) -> Self {
        Self {
            cpu,
            binding,
            context,
        }
    }

    pub fn matches(self, current: Self) -> bool {
        self.cpu == current.cpu
            && self.binding == current.binding
            && self.context == current.context
    }
}

/// Outstanding physical table loan held by a stopped vCPU.
#[derive(Clone, Debug)]
pub struct PendingForkLoan {
    pub loan: ForkStockLoan,
    pub execution: GrantExecution,
    pub child_tables: Vec<RootGpa>,
    pub parent_tables: Vec<RootGpa>,
}

/// Errors returned by the fork stock host service.
#[derive(Debug, PartialEq, Eq)]
pub enum ForkStockServiceError {
    NoPendingLoan,
    StaleExecution,
    LoanMismatch,
    ExposedDirtyTable,
    InvalidRecord,
    MemoryAccessFailed,
}

/// Deterministic table stock allocator: takes contiguous 4 KiB page runs for child
/// and parent from available stock.
pub fn take_fork_table_stock(
    stock: &mut Vec<RootGpa>,
    child_bytes: u64,
    parent_bytes: u64,
) -> Option<(Vec<RootGpa>, Vec<RootGpa>)> {
    if child_bytes == 0
        || parent_bytes == 0
        || !child_bytes.is_multiple_of(4096)
        || !parent_bytes.is_multiple_of(4096)
    {
        return None;
    }
    let child = usize::try_from(child_bytes / 4096).ok()?;
    let parent = usize::try_from(parent_bytes / 4096).ok()?;
    if stock.len() < child.checked_add(parent)? {
        return None;
    }
    let mut available = stock.clone();
    available.sort_unstable_by_key(|page| page.address().raw());
    if available.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    fn take_run(pages: &mut Vec<RootGpa>, count: usize) -> Option<Vec<RootGpa>> {
        let start = pages.windows(count).position(|run| {
            run.windows(2).all(|pair| {
                pair[0].address().raw().checked_add(4096) == Some(pair[1].address().raw())
            })
        })?;
        Some(pages.drain(start..start + count).collect())
    }
    let (child_tables, parent_tables) = if child >= parent {
        let child_tables = take_run(&mut available, child)?;
        (child_tables, take_run(&mut available, parent)?)
    } else {
        let parent_tables = take_run(&mut available, parent)?;
        (take_run(&mut available, child)?, parent_tables)
    };
    *stock = available;
    Some((child_tables, parent_tables))
}

/// Host custody of physical table stock and pending loans for an AArch64 carrier.
#[derive(Debug)]
pub struct ForkStockHostCustody {
    pub grant_tables: Vec<RootGpa>,
    pub pending_loans: Vec<Option<PendingForkLoan>>,
    pub active_executions: Vec<Option<GrantExecution>>,
    pub fork_next_loan: u64,
    pub fork_lifecycle_available: bool,
    pub kernel_region_gpa: u64,
    pub lifecycle: ForkLifecycleLoan,
    pub carrier: NonZeroU64,
}

#[allow(dead_code)]
impl ForkStockHostCustody {
    pub fn new(carrier: NonZeroU64) -> Self {
        Self {
            grant_tables: Vec::new(),
            pending_loans: vec![None; 32],
            active_executions: vec![None; 32],
            fork_next_loan: 1,
            fork_lifecycle_available: true,
            kernel_region_gpa: carrick_mem::memory::LINUX_KERNEL_REGION_BASE,
            lifecycle: ForkLifecycleLoan::ARM_DEFAULT,
            carrier,
        }
    }

    pub fn set_active_execution(&mut self, execution: GrantExecution) {
        let cpu = execution.cpu.raw() as usize;
        if cpu >= self.active_executions.len() {
            self.active_executions.resize(cpu + 1, None);
        }
        self.active_executions[cpu] = Some(execution);
    }

    pub fn clear_active_execution(&mut self, cpu: CpuId) {
        let cpu = cpu.raw() as usize;
        if cpu < self.active_executions.len() {
            self.active_executions[cpu] = None;
        }
    }

    pub fn active_execution_for_cpu(&self, cpu: CpuId) -> Option<GrantExecution> {
        let cpu = cpu.raw() as usize;
        self.active_executions.get(cpu).copied().flatten()
    }

    /// Service a stopped-vCPU loan request.
    pub(crate) fn service_loan(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        execution: GrantExecution,
        exchange: &mut ForkStockExchange,
    ) -> Result<ForkStockLoan, ForkStockRefusal> {
        let Some(request) = exchange.request() else {
            exchange.refuse(ForkStockRefusal::Invalid);
            return Err(ForkStockRefusal::Invalid);
        };
        let cpu_index = execution.cpu.raw() as usize;
        if request.binding != execution.binding
            || request.context != execution.context
            || request.operation.carrier != self.carrier
        {
            exchange.refuse(ForkStockRefusal::Stale);
            return Err(ForkStockRefusal::Stale);
        }
        if cpu_index >= self.pending_loans.len() {
            self.pending_loans.resize(cpu_index + 1, None);
        }
        if self.pending_loans[cpu_index].is_some() || !self.fork_lifecycle_available {
            exchange.refuse(ForkStockRefusal::Capacity);
            return Err(ForkStockRefusal::Capacity);
        }
        let Some((child_tables, parent_tables)) = take_fork_table_stock(
            &mut self.grant_tables,
            request.child_bytes,
            request.parent_bytes,
        ) else {
            exchange.refuse(ForkStockRefusal::Capacity);
            return Err(ForkStockRefusal::Capacity);
        };
        let Some(id) = NonZeroU64::new(self.fork_next_loan) else {
            self.grant_tables.extend(child_tables);
            self.grant_tables.extend(parent_tables);
            exchange.refuse(ForkStockRefusal::Capacity);
            return Err(ForkStockRefusal::Capacity);
        };
        let Some(next_loan) = self.fork_next_loan.checked_add(1) else {
            self.grant_tables.extend(child_tables);
            self.grant_tables.extend(parent_tables);
            exchange.refuse(ForkStockRefusal::Capacity);
            return Err(ForkStockRefusal::Capacity);
        };
        self.fork_next_loan = next_loan;
        let child_base = child_tables[0].address().raw();
        let parent_base = parent_tables[0].address().raw();
        let Some(loan) = request.admit_loan(
            child_base,
            parent_base,
            self.kernel_region_gpa,
            id,
            self.lifecycle,
        ) else {
            self.grant_tables.extend(child_tables);
            self.grant_tables.extend(parent_tables);
            exchange.refuse(ForkStockRefusal::Invalid);
            return Err(ForkStockRefusal::Invalid);
        };

        let child_mm = match El1FrameGrantMm::new(request.child_mm.raw()) {
            Some(mm) => mm,
            None => {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                exchange.refuse(ForkStockRefusal::Invalid);
                return Err(ForkStockRefusal::Invalid);
            }
        };
        let parent_mm = match El1FrameGrantMm::new(request.operation.mm.raw()) {
            Some(mm) => mm,
            None => {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                exchange.refuse(ForkStockRefusal::Invalid);
                return Err(ForkStockRefusal::Invalid);
            }
        };

        let mut granted_child = Vec::new();
        for page in &child_tables {
            if ledger
                .mark_grant(page.address().raw(), 4096, child_mm)
                .is_err()
            {
                for granted in granted_child {
                    ledger.mark_return(granted, 4096, child_mm, false);
                }
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                exchange.refuse(ForkStockRefusal::Capacity);
                return Err(ForkStockRefusal::Capacity);
            }
            granted_child.push(page.address().raw());
        }
        let mut granted_parent = Vec::new();
        for page in &parent_tables {
            if ledger
                .mark_grant(page.address().raw(), 4096, parent_mm)
                .is_err()
            {
                for granted in granted_child {
                    ledger.mark_return(granted, 4096, child_mm, false);
                }
                for granted in granted_parent {
                    ledger.mark_return(granted, 4096, parent_mm, false);
                }
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                exchange.refuse(ForkStockRefusal::Capacity);
                return Err(ForkStockRefusal::Capacity);
            }
            granted_parent.push(page.address().raw());
        }

        self.fork_lifecycle_available = false;
        self.pending_loans[cpu_index] = Some(PendingForkLoan {
            loan,
            execution,
            child_tables,
            parent_tables,
        });

        if !exchange.grant(
            child_base,
            parent_base,
            self.kernel_region_gpa,
            id,
            self.lifecycle,
        ) {
            if let Some(pending) = self.pending_loans[cpu_index].take() {
                for page in &pending.child_tables {
                    ledger.mark_return(page.address().raw(), 4096, child_mm, false);
                }
                for page in &pending.parent_tables {
                    ledger.mark_return(page.address().raw(), 4096, parent_mm, false);
                }
                self.grant_tables.extend(pending.child_tables);
                self.grant_tables.extend(pending.parent_tables);
            }
            self.fork_lifecycle_available = true;
            exchange.refuse(ForkStockRefusal::Invalid);
            return Err(ForkStockRefusal::Invalid);
        }
        Ok(loan)
    }

    /// Service a stopped-vCPU settlement (Commit or Abort).
    pub(crate) fn service_settlement(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        execution: GrantExecution,
        settlement: &mut ForkStockSettlement,
        is_resolvable: impl Fn(&[RootGpa]) -> bool,
        is_clean: impl Fn(&[RootGpa]) -> bool,
    ) -> Result<(), ForkStockServiceError> {
        let cpu_index = execution.cpu.raw() as usize;
        let pending = self
            .pending_loans
            .get(cpu_index)
            .and_then(|p| p.as_ref())
            .ok_or(ForkStockServiceError::NoPendingLoan)?;
        if !pending.execution.matches(execution) {
            return Err(ForkStockServiceError::StaleExecution);
        }
        let loan = pending.loan;
        if settlement.abort_matches(loan) {
            // Abort: loaned pages must be completely clean/untouched and resolvable
            if !is_resolvable(&pending.child_tables) || !is_resolvable(&pending.parent_tables) {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            if !is_clean(&pending.child_tables) || !is_clean(&pending.parent_tables) {
                return Err(ForkStockServiceError::ExposedDirtyTable);
            }
            let pending = self.pending_loans[cpu_index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;
            let child_mm = El1FrameGrantMm::new(loan.request.child_mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            let parent_mm = El1FrameGrantMm::new(loan.request.operation.mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            for page in &pending.child_tables {
                ledger.mark_return(page.address().raw(), 4096, child_mm, false);
            }
            for page in &pending.parent_tables {
                ledger.mark_return(page.address().raw(), 4096, parent_mm, false);
            }
            self.grant_tables.extend(pending.child_tables);
            self.grant_tables.extend(pending.parent_tables);
            self.fork_lifecycle_available = true;
            if !settlement.accept(loan) {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            Ok(())
        } else {
            // Commit
            let (completion, _custody, _count) = settlement
                .request(loan)
                .ok_or(ForkStockServiceError::LoanMismatch)?;
            let child_used = usize::try_from(completion.child_tables_used / 4096)
                .map_err(|_| ForkStockServiceError::InvalidRecord)?;
            let parent_used = usize::try_from(completion.parent_tables_used / 4096)
                .map_err(|_| ForkStockServiceError::InvalidRecord)?;
            if child_used > pending.child_tables.len() || parent_used > pending.parent_tables.len()
            {
                return Err(ForkStockServiceError::InvalidRecord);
            }

            // Unresolvable pages in the loaned page list must refuse
            if !is_resolvable(&pending.child_tables) || !is_resolvable(&pending.parent_tables) {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }

            // Unused pages returned to the pool must be clean
            let unused_child = &pending.child_tables[child_used..];
            let unused_parent = &pending.parent_tables[parent_used..];
            if !is_clean(unused_child) || !is_clean(unused_parent) {
                return Err(ForkStockServiceError::ExposedDirtyTable);
            }

            let child_mm = El1FrameGrantMm::new(loan.request.child_mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            let parent_mm = El1FrameGrantMm::new(loan.request.operation.mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;

            let mut pending = self.pending_loans[cpu_index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;

            let unused_child: Vec<_> = pending.child_tables.drain(child_used..).collect();
            let unused_parent: Vec<_> = pending.parent_tables.drain(parent_used..).collect();

            for page in &unused_child {
                ledger.mark_return(page.address().raw(), 4096, child_mm, false);
            }
            self.grant_tables.extend(unused_child);

            for page in &unused_parent {
                ledger.mark_return(page.address().raw(), 4096, parent_mm, false);
            }
            self.grant_tables.extend(unused_parent);

            if !settlement.accept(loan) {
                return Err(ForkStockServiceError::InvalidRecord);
            }
            Ok(())
        }
    }

    /// Service a container root exit notification.
    ///
    /// Validates the executing task binding against the record and returns the Linux wait status.
    /// If the binding does not match, returns `Err(StaleExecution)` without modifying any ledger.
    pub(crate) fn service_root_exit(
        &self,
        execution: GrantExecution,
        root_exit: &NativeRootExit,
    ) -> Result<LinuxWaitStatus, ForkStockServiceError> {
        root_exit
            .status_for(execution.binding)
            .ok_or(ForkStockServiceError::StaleExecution)
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

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
        PortalForkCompletion, PortalOperation, ReservationGeneration, ReservationMm,
    };
    use carrick_guest_arch::{ContextGeneration, FrameGpa, KernelVa, MmGeneration};
    use core::num::NonZeroU64;

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
        custody.grant_tables = (0..8).map(|i| page(0x20000 + i * 4096)).collect();
        let initial_stock_len = custody.grant_tables.len();

        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 4, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();

        // Service Loan
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange)
            .expect("loan should succeed");
        assert_eq!(custody.grant_tables.len(), initial_stock_len - 5);
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
            .service_settlement(&mut ledger, exec, &mut settlement, |_| true, |_| true)
            .expect("settlement commit should succeed");

        // Unused 3 child pages returned to stock: initial (8) - 2 used = 6 remaining
        assert_eq!(custody.grant_tables.len(), 6);
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
                |_| true
            ),
            Err(ForkStockServiceError::NoPendingLoan)
        );
    }

    #[test]
    fn refusal_on_stale_or_foreign_custody() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let mut ledger = El1FrameGrantLedger::default();
        custody.grant_tables = (0..8).map(|i| page(0x20000 + i * 4096)).collect();

        let exec = test_execution(41, 0, 301);

        // Case A: Foreign task binding
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(999);
        let req = test_request(foreign_exec, 302, 2, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let result = custody.service_loan(&mut ledger, exec, &mut exchange);
        assert_eq!(result, Err(ForkStockRefusal::Stale));
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));

        // Case B: Foreign context
        let mut foreign_context_exec = exec;
        foreign_context_exec.context.root = page(0x9000);
        let req = test_request(foreign_context_exec, 302, 2, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange),
            Err(ForkStockRefusal::Stale)
        );

        // Case C: Foreign carrier
        let mut foreign_carrier_req = test_request(exec, 302, 2, 1);
        foreign_carrier_req.operation.carrier = NonZeroU64::new(99).unwrap();
        let mut exchange = ForkStockExchange::new(foreign_carrier_req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange),
            Err(ForkStockRefusal::Stale)
        );

        // Case D: Capacity refusal when stock insufficient
        let huge_req = test_request(exec, 302, 100, 100);
        let mut exchange = ForkStockExchange::new(huge_req).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, exec, &mut exchange),
            Err(ForkStockRefusal::Capacity)
        );

        // Verify stock and ledger were completely untouched across all refusals
        assert_eq!(custody.grant_tables.len(), 8);
        assert_eq!(ledger.snapshot().bytes_granted, 0);
    }

    #[test]
    fn rollback_returns_pages_exactly_once() {
        let carrier = NonZeroU64::new(7).unwrap();
        let mut custody = ForkStockHostCustody::new(carrier);
        let mut ledger = El1FrameGrantLedger::default();
        custody.grant_tables = (0..6).map(|i| page(0x20000 + i * 4096)).collect();
        assert_eq!(custody.grant_tables.len(), 6);

        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 3, 1); // 4 pages total
        let mut exchange = ForkStockExchange::new(req).unwrap();

        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange)
            .expect("loan succeeds");
        assert_eq!(custody.grant_tables.len(), 2);
        assert_eq!(ledger.snapshot().bytes_granted, 4 * 4096);
        assert_eq!(ledger.snapshot().bytes_returned, 0);

        // Abort the loan
        let mut abort_settlement = ForkStockSettlement::abort(loan);
        custody
            .service_settlement(&mut ledger, exec, &mut abort_settlement, |_| true, |_| true)
            .expect("abort succeeds");

        // All 4 pages restored to stock exactly once
        assert_eq!(custody.grant_tables.len(), 6);
        assert_eq!(ledger.snapshot().bytes_returned, 4 * 4096);
        assert_eq!(ledger.snapshot().returns_completed, 4); // 3 child + 1 parent

        // A second abort attempt must fail with NoPendingLoan and NOT return pages again
        assert_eq!(
            custody.service_settlement(
                &mut ledger,
                exec,
                &mut abort_settlement,
                |_| true,
                |_| true
            ),
            Err(ForkStockServiceError::NoPendingLoan)
        );
        assert_eq!(custody.grant_tables.len(), 6);
        assert_eq!(ledger.snapshot().bytes_returned, 4 * 4096);

        // Dirty page verification: if pages were modified, abort fails closed
        let mut second_exchange = ForkStockExchange::new(req).unwrap();
        let second_loan = custody
            .service_loan(&mut ledger, exec, &mut second_exchange)
            .unwrap();
        let mut dirty_abort = ForkStockSettlement::abort(second_loan);
        let result =
            custody.service_settlement(&mut ledger, exec, &mut dirty_abort, |_| true, |_| false);
        assert_eq!(result, Err(ForkStockServiceError::ExposedDirtyTable));
    }

    #[test]
    fn root_exit_refuses_stale_custody_and_leaves_ledger_unchanged() {
        let carrier = NonZeroU64::new(7).unwrap();
        let custody = ForkStockHostCustody::new(carrier);
        let ledger = El1FrameGrantLedger::default();
        let initial_stats = ledger.snapshot();

        let exec = test_execution(41, 0, 301);
        let valid_status = LinuxWaitStatus::from_wait_encoding(42 << 8);
        let root_exit = NativeRootExit::new(exec.binding, valid_status).unwrap();

        // Foreign execution binding (wrong task ID)
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(99);
        let result = custody.service_root_exit(foreign_exec, &root_exit);
        assert_eq!(result, Err(ForkStockServiceError::StaleExecution));

        // Foreign generation
        let mut foreign_gen_exec = exec;
        foreign_gen_exec.binding.generation = EntryGeneration::from_raw(99);
        assert_eq!(
            custody.service_root_exit(foreign_gen_exec, &root_exit),
            Err(ForkStockServiceError::StaleExecution)
        );

        // Foreign MM
        let mut foreign_mm_exec = exec;
        foreign_mm_exec.binding.mm = EntryMmKey::from_raw(99);
        assert_eq!(
            custody.service_root_exit(foreign_mm_exec, &root_exit),
            Err(ForkStockServiceError::StaleExecution)
        );

        // Assert that the ledger was left completely unchanged!
        assert_eq!(ledger.snapshot(), initial_stats);

        // Matching binding succeeds and still leaves ledger unchanged
        let exit_status = custody.service_root_exit(exec, &root_exit).unwrap();
        assert_eq!(exit_status, valid_status);
        assert_eq!(ledger.snapshot(), initial_stats);
    }

    #[repr(align(64))]
    struct AlignedPage([u8; 4096]);

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_round_trip_and_settlement() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();

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
            fork.grant_tables = (0..8).map(|i| page(0x2001_0000u64 + i * 4096)).collect();
            fork.carrier = carrier;
        }

        let exec = test_execution(41, 0, 301);
        custody.fork_stock.lock().set_active_execution(exec);

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
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 6);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_refusal_on_stale_custody_and_malformed() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();

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
            fork.grant_tables = (0..8).map(|i| page(0x40000 + i * 4096)).collect();
            fork.carrier = carrier;
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
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 8);

        // Case 2: Mismatched foreign execution -> typed refusal (Stale), ledger unchanged
        let mut foreign_exec = exec;
        foreign_exec.binding.task = EntryTaskKey::from_raw(999);
        custody.fork_stock.lock().set_active_execution(foreign_exec);
        let exchange = ForkStockExchange::new(req).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut ForkStockExchange).write(exchange);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            foreign_exec.cpu,
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatched refusal");
        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
        let exchange = unsafe { &mut *(record_page.0.as_mut_ptr() as *mut ForkStockExchange) };
        assert_eq!(exchange.take(req), Some(Err(ForkStockRefusal::Stale)));
        assert_eq!(custody.el1_frame_grants.lock().snapshot(), initial_ledger);
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 8);

        // Case 3: Misaligned GPA -> METADATA_GRANT_ERR_ALIGNMENT, ledger unchanged
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
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

        // Case 4: Unmapped GPA -> METADATA_GRANT_ERR_INVALID, ledger unchanged
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
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

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_root_exit_success_and_stale_refusal() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();

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
        custody.fork_stock.lock().set_active_execution(exec);
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec.cpu,
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
        custody.fork_stock.lock().set_active_execution(foreign_exec);
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            foreign_exec.cpu,
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
            custody.fork_stock.lock().grant_tables.push(page(ipa));
        }

        let exec_0 = test_execution(41, 0, 300);
        let exec_a = test_execution(41, 1, 301);
        let exec_b = test_execution(41, 2, 302);
        custody.fork_stock.lock().set_active_execution(exec_0);
        custody.fork_stock.lock().set_active_execution(exec_a);
        custody.fork_stock.lock().set_active_execution(exec_b);
        custody.fork_stock.lock().carrier = NonZeroU64::new(7).unwrap();

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
            exec_a.cpu, // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            exec_b.cpu.raw() as u64, // Guest attempts to name vCPU B
            0,
        )
        .expect("dispatcher call");

        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
        // Neither B nor 0 is charged
        assert!(custody.fork_stock.lock().pending_loans[exec_b.cpu.raw() as usize].is_none());
        assert!(custody.fork_stock.lock().pending_loans[exec_0.cpu.raw() as usize].is_none());
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
            exec_a.cpu, // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            9999, // Out of range!
            0,
        )
        .expect("dispatcher call");

        assert_eq!(
            result,
            [carrick_el1_abi::METADATA_GRANT_ERR_DENIED, 0, 0, 0]
        );
        // CPU 0 must NOT have been charged via silent fallback
        assert!(custody.fork_stock.lock().pending_loans[exec_0.cpu.raw() as usize].is_none());
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
            exec_a.cpu, // Trapped on vCPU A!
            carrick_el1_abi::GRANT_OP_FORK_STOCK,
            record_ipa,
            0,
            0,
        )
        .expect("dispatcher call");

        assert_eq!(result, [carrick_el1_abi::METADATA_GRANT_SUCCESS, 0, 0, 0]);
        assert!(custody.fork_stock.lock().pending_loans[exec_a.cpu.raw() as usize].is_some());
        assert!(custody.fork_stock.lock().pending_loans[exec_b.cpu.raw() as usize].is_none());
        assert!(custody.fork_stock.lock().pending_loans[exec_0.cpu.raw() as usize].is_none());

        // Case 4: Root exit trapped on vCPU A (1) naming vCPU B in arg2 -> refused
        let status = LinuxWaitStatus::from_wait_encoding(25 << 8);
        let root_exit = NativeRootExit::new(exec_b.binding, status).unwrap();
        unsafe {
            (record_page.0.as_mut_ptr() as *mut NativeRootExit).write(root_exit);
        }
        let result = crate::metadata_grant::service_metadata_operation(
            &custody,
            Some(generation),
            exec_a.cpu, // Trapped on A
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
            let mut fs = custody.fork_stock.lock();
            for i in 0..4 {
                fs.grant_tables.push(page(0x2001_0000u64 + i * 4096)); // i=3 is unmapped!
            }
            for i in 0..4 {
                fs.grant_tables.push(page(0x2002_0000u64 + i * 4096));
            }
        }

        let exec = test_execution(41, 0, 301);
        custody.fork_stock.lock().set_active_execution(exec);
        custody.fork_stock.lock().carrier = NonZeroU64::new(7).unwrap();
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
}
