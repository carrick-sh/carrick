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

use std::collections::{BTreeMap, BTreeSet};

use carrick_el1_abi::{
    ForkLifecycleLoan, ForkStockExchange, ForkStockLoan, ForkStockRefusal, ForkStockSettlement,
    NativeChildRetire, NativeRootExit,
};
use carrick_guest_arch::{AddressContext, CpuId, FrameGpa, KernelVa, RootGpa};
use carrick_hal::asid::{AsidAllocator, AsidError, AsidGeneration};
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
    pub lifecycle: ForkLifecycleLoan,
    pub asid_gen: AsidGeneration,
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
    Asid(AsidError),
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
#[derive(::core::fmt::Debug)]
struct NativeRootCustody {
    context: AddressContext<RootGpa>,
    frames: Option<carrick_hal::NativeRootFrameSnapshot>,
}

#[derive(Debug)]
pub struct ForkStockHostCustody {
    pub grant_tables: Vec<RootGpa>,
    pub pending_loans: Vec<Option<PendingForkLoan>>,
    pub fork_next_loan: u64,
    pub lifecycle_stock: Vec<ForkLifecycleLoan>,
    pub committed_lifecycle: BTreeMap<u64, ForkLifecycleLoan>,
    pub committed_tables: BTreeMap<u64, Vec<RootGpa>>,
    /// Address authority of committed guest-only MMs. Record rehoming does
    /// not change this generation or manufacture a host MM binding.
    native_roots: BTreeMap<NonZeroU64, NativeRootCustody>,
    pub retired_mms: BTreeSet<u64>,
    pub kernel_region_gpa: u64,
    pub carrier: NonZeroU64,
    pub asids: AsidAllocator,
    pub committed_asids: BTreeMap<u64, AsidGeneration>,
    run_failure: carrick_el1_abi::NativeRunFailureConsumer,
    /// Retired child stocks reclaimed after slot absence and table clearing.
    pub returned_children: u64,
}

#[allow(dead_code)]
impl ForkStockHostCustody {
    pub fn new(carrier: NonZeroU64) -> Self {
        Self::with_asids(carrier, AsidAllocator::new())
    }

    pub fn asids(&self) -> &AsidAllocator {
        &self.asids
    }

    pub fn with_asids(carrier: NonZeroU64, asids: AsidAllocator) -> Self {
        Self {
            grant_tables: Vec::new(),
            pending_loans: vec![None; 32],
            fork_next_loan: 1,
            lifecycle_stock: if cfg!(test) {
                vec![ForkLifecycleLoan::ARM_DEFAULT]
            } else {
                Vec::new()
            },
            committed_lifecycle: BTreeMap::new(),
            committed_tables: BTreeMap::new(),
            native_roots: BTreeMap::new(),
            retired_mms: BTreeSet::new(),
            kernel_region_gpa: carrick_mem::memory::LINUX_KERNEL_REGION_BASE,
            carrier,
            asids,
            committed_asids: BTreeMap::new(),
            run_failure: carrick_el1_abi::NativeRunFailureConsumer::default(),
            returned_children: 0,
        }
    }

    pub fn root(&self, mm: NonZeroU64) -> Option<AddressContext<RootGpa>> {
        self.native_roots.get(&mm).map(|root| root.context)
    }

    /// Captured row identities are a root-owned projection, not an inventory.
    /// A physical service must recheck every selected row in the canonical source.
    pub fn root_frames(
        &self,
        context: AddressContext<RootGpa>,
    ) -> Option<&carrick_hal::NativeRootFrameSnapshot> {
        let root = self.native_roots.get(&context.mm.raw())?;
        (root.context == context)
            .then_some(root.frames.as_ref())
            .flatten()
    }

    pub(crate) fn register_native_root(
        &mut self,
        context: AddressContext<RootGpa>,
        mut frames: carrick_hal::NativeRootFrameSnapshot,
    ) -> Result<(), ForkStockRefusal> {
        if frames.owner != context.into() {
            return Err(ForkStockRefusal::Stale);
        }
        match self.native_roots.get(&context.mm.raw()) {
            Some(current) if current.context != context => Err(ForkStockRefusal::Stale),
            Some(_) => Ok(()),
            None => {
                frames
                    .mappings
                    .sort_unstable_by_key(|row| (row.gpa.0, row.mapping));
                self.native_roots.insert(
                    context.mm.raw(),
                    NativeRootCustody {
                        context,
                        frames: Some(frames),
                    },
                );
                Ok(())
            }
        }
    }

    pub(crate) fn publish_child_frame_snapshot(
        &mut self,
        context: AddressContext<RootGpa>,
        mut frames: carrick_hal::NativeRootFrameSnapshot,
    ) -> Result<(), ForkStockServiceError> {
        let root = self
            .native_roots
            .get_mut(&context.mm.raw())
            .filter(|root| root.context == context && root.frames.is_none())
            .ok_or(ForkStockServiceError::StaleExecution)?;
        if frames.owner != context.into() {
            return Err(ForkStockServiceError::StaleExecution);
        }
        frames
            .mappings
            .sort_unstable_by_key(|row| (row.gpa.0, row.mapping));
        root.frames = Some(frames);
        Ok(())
    }

    /// Publish a verified native COW replacement without changing retained
    /// source identities. Shared MM retirement owns both physical rows.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn publish_native_cow_frame(
        &mut self,
        context: AddressContext<RootGpa>,
        source: carrick_hal::PhysicalMappingRow,
        replacement: carrick_hal::PhysicalMappingRow,
        revision: NonZeroU64,
    ) -> Result<(), ForkStockServiceError> {
        let frames = self
            .native_roots
            .get_mut(&context.mm.raw())
            .filter(|root| root.context == context)
            .and_then(|root| root.frames.as_mut())
            .ok_or(ForkStockServiceError::StaleExecution)?;
        if super::trap::native_frame_custody::selected_row(
            frames,
            FrameGpa::new(source.gpa.0),
            source.length.raw(),
        )? != source
        {
            return Err(ForkStockServiceError::StaleExecution);
        }
        let index = frames
            .mappings
            .partition_point(|row| row.gpa.0 < replacement.gpa.0);
        if let Some(current) = frames.mappings.get(index)
            && current.gpa.0 == replacement.gpa.0
        {
            return if *current == replacement {
                Ok(())
            } else {
                Err(ForkStockServiceError::StaleExecution)
            };
        }
        frames.mappings.insert(index, replacement);
        frames.revision = revision;
        Ok(())
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
        if !valid(lifecycle_base)
            || !valid(table_base)
            || lifecycle_base == table_base
            || !self.grant_tables.is_empty()
            || !self.committed_tables.is_empty()
            || !self.committed_lifecycle.is_empty()
            || self.pending_loans.iter().any(Option::is_some)
        {
            return Err(ForkStockServiceError::InvalidRecord);
        }
        let lifecycles = ((lifecycle_base + 0x4000)..(lifecycle_base + extent))
            .step_by(0x4000)
            .map(|page| {
                ForkLifecycleLoan::new_for_base(
                    aperture,
                    KernelVa::new(page),
                    KernelVa::new(page + 0x1000),
                )
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        let tables = (table_base..table_base + extent)
            .step_by(4096)
            .map(|ipa| RootGpa::page_aligned(FrameGpa::new(ipa)))
            .collect::<Option<Vec<_>>>()
            .ok_or(ForkStockServiceError::InvalidRecord)?;
        self.lifecycle_stock = lifecycles;
        self.grant_tables = tables;
        Ok(())
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
        if self.pending_loans[cpu_index].is_some() || self.lifecycle_stock.is_empty() {
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
        let asid_gen = match self.asids.allocate() {
            Ok(asid_gen) => asid_gen,
            Err(_) => {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                exchange.refuse(ForkStockRefusal::Capacity);
                return Err(ForkStockRefusal::Capacity);
            }
        };
        let Some(lifecycle) = self.lifecycle_stock.pop() else {
            self.grant_tables.extend(child_tables);
            self.grant_tables.extend(parent_tables);
            self.asids
                .release_unpublished(asid_gen)
                .map_err(|_| ForkStockRefusal::Capacity)?;
            exchange.refuse(ForkStockRefusal::Capacity);
            return Err(ForkStockRefusal::Capacity);
        };
        let Some(loan) = request.admit_loan(
            child_base,
            parent_base,
            self.kernel_region_gpa,
            id,
            lifecycle,
            Some(asid_gen.asid()),
        ) else {
            self.grant_tables.extend(child_tables);
            self.grant_tables.extend(parent_tables);
            self.lifecycle_stock.push(lifecycle);
            self.asids
                .release_unpublished(asid_gen)
                .map_err(|_| ForkStockRefusal::Invalid)?;
            exchange.refuse(ForkStockRefusal::Invalid);
            return Err(ForkStockRefusal::Invalid);
        };

        let child_mm = match El1FrameGrantMm::new(request.child_mm.raw()) {
            Some(mm) => mm,
            None => {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                self.lifecycle_stock.push(lifecycle);
                self.asids
                    .release_unpublished(asid_gen)
                    .map_err(|_| ForkStockRefusal::Invalid)?;
                exchange.refuse(ForkStockRefusal::Invalid);
                return Err(ForkStockRefusal::Invalid);
            }
        };
        let parent_mm = match El1FrameGrantMm::new(request.operation.mm.raw()) {
            Some(mm) => mm,
            None => {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                self.lifecycle_stock.push(lifecycle);
                self.asids
                    .release_unpublished(asid_gen)
                    .map_err(|_| ForkStockRefusal::Invalid)?;
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
                self.lifecycle_stock.push(lifecycle);
                self.asids
                    .release_unpublished(asid_gen)
                    .map_err(|_| ForkStockRefusal::Capacity)?;
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
                self.lifecycle_stock.push(lifecycle);
                self.asids
                    .release_unpublished(asid_gen)
                    .map_err(|_| ForkStockRefusal::Capacity)?;
                exchange.refuse(ForkStockRefusal::Capacity);
                return Err(ForkStockRefusal::Capacity);
            }
            granted_parent.push(page.address().raw());
        }

        self.pending_loans[cpu_index] = Some(PendingForkLoan {
            loan,
            execution,
            child_tables,
            parent_tables,
            lifecycle,
            asid_gen,
        });

        if !exchange.grant(
            child_base,
            parent_base,
            self.kernel_region_gpa,
            id,
            lifecycle,
            Some(asid_gen.asid()),
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
                self.lifecycle_stock.push(pending.lifecycle);
                self.asids
                    .release_unpublished(pending.asid_gen)
                    .map_err(|_| ForkStockRefusal::Invalid)?;
            }
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
            self.lifecycle_stock.push(pending.lifecycle);
            self.asids
                .release_unpublished(pending.asid_gen)
                .map_err(ForkStockServiceError::Asid)?;
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

            let native_mm = NonZeroU64::new(loan.request.child_mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            let native_context = AddressContext {
                mm: carrick_guest_arch::MmGeneration::new(native_mm),
                root: RootGpa::page_aligned(FrameGpa::new(loan.request.child_tables.base))
                    .ok_or(ForkStockServiceError::InvalidRecord)?,
                generation: carrick_guest_arch::ContextGeneration::new(
                    completion.child.incarnation(),
                ),
            };
            if self.native_roots.contains_key(&native_mm) {
                return Err(ForkStockServiceError::InvalidRecord);
            }

            let child_mm = El1FrameGrantMm::new(loan.request.child_mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;
            let parent_mm = El1FrameGrantMm::new(loan.request.operation.mm.raw())
                .ok_or(ForkStockServiceError::InvalidRecord)?;

            let mut pending = self.pending_loans[cpu_index]
                .take()
                .ok_or(ForkStockServiceError::NoPendingLoan)?;
            self.committed_asids
                .insert(pending.loan.request.child_mm.raw(), pending.asid_gen);
            self.committed_lifecycle
                .insert(pending.loan.request.child_mm.raw(), pending.lifecycle);
            self.native_roots.insert(
                native_mm,
                NativeRootCustody {
                    context: native_context,
                    frames: None,
                },
            );

            let unused_child: Vec<_> = pending.child_tables.drain(child_used..).collect();
            let unused_parent: Vec<_> = pending.parent_tables.drain(parent_used..).collect();

            self.committed_tables
                .entry(loan.request.child_mm.raw())
                .or_default()
                .extend(pending.child_tables);
            self.committed_tables
                .entry(loan.request.operation.mm.raw())
                .or_default()
                .extend(pending.parent_tables);

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

    /// Authenticate a terminal native failure against this stopped CPU's lane.
    pub(crate) fn service_run_failure(
        &mut self,
        binding: Option<carrick_el1_abi::ExecutionBinding>,
        record: &carrick_el1_abi::NativeRunFailure,
    ) -> Result<(carrick_el1_abi::NativeRunFailureReason, u64), ForkStockServiceError> {
        let binding = binding.ok_or(ForkStockServiceError::StaleExecution)?;
        let result = self
            .run_failure
            .consume(record, binding)
            .ok_or(ForkStockServiceError::StaleExecution)?;
        Ok(result)
    }

    /// Service a container root exit notification.
    ///
    /// Validates the executing task binding against the record, retires the child's ASID
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
        if let Some(asid_gen) = self.committed_asids.remove(&binding.mm.raw()) {
            let retired = self
                .asids
                .retire(asid_gen)
                .map_err(ForkStockServiceError::Asid)?;
            self.asids
                .acknowledge_tlb_flush(retired)
                .map_err(ForkStockServiceError::Asid)?;
        }
        Ok(status)
    }

    pub(crate) fn service_child_retire(
        &mut self,
        execution: GrantExecution,
        retire: &NativeChildRetire,
    ) -> Result<(), ForkStockServiceError> {
        if !retire.matches(execution.binding, execution.context)
            || !self
                .committed_asids
                .contains_key(&execution.binding.mm.raw())
            || !self
                .committed_lifecycle
                .contains_key(&execution.binding.mm.raw())
        {
            return Err(ForkStockServiceError::StaleExecution);
        }
        self.retired_mms.insert(execution.binding.mm.raw());
        Ok(())
    }

    /// Reclaim only MMs whose final guest execution has moved off their root.
    /// The caller authenticates absence from every live zone slot and clears
    /// physical table bytes before returned pages reenter the stock.
    pub(crate) fn reclaim_retired(
        &mut self,
        ledger: &mut El1FrameGrantLedger,
        active_mm: u64,
        safe_to_reclaim: impl Fn(u64) -> bool,
        clear_tables: impl Fn(&[RootGpa]) -> bool,
    ) -> Result<usize, ForkStockServiceError> {
        let candidates: Vec<_> = self
            .retired_mms
            .iter()
            .copied()
            .filter(|mm| *mm != active_mm && safe_to_reclaim(*mm))
            .collect();
        let mut reclaimed = 0;
        for mm in candidates {
            let pages = self
                .committed_tables
                .get(&mm)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if !clear_tables(pages) {
                return Err(ForkStockServiceError::MemoryAccessFailed);
            }
            if let Some(asid_gen) = self.committed_asids.remove(&mm) {
                let retired = self
                    .asids
                    .retire(asid_gen)
                    .map_err(ForkStockServiceError::Asid)?;
                self.asids
                    .acknowledge_tlb_flush(retired)
                    .map_err(ForkStockServiceError::Asid)?;
            }
            if let Some(pages) = self.committed_tables.remove(&mm) {
                if let Some(key) = NonZeroU64::new(mm) {
                    self.native_roots.remove(&key);
                }
                let owner = El1FrameGrantMm::new(mm).ok_or(ForkStockServiceError::InvalidRecord)?;
                for page in &pages {
                    ledger.mark_return(page.address().raw(), 4096, owner, false);
                }
                self.grant_tables.extend(pages);
            }
            if let Some(lifecycle) = self.committed_lifecycle.remove(&mm) {
                self.lifecycle_stock.push(lifecycle);
            }
            self.retired_mms.remove(&mm);
            reclaimed += 1;
            self.returned_children += 1;
        }
        Ok(reclaimed)
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
    fn native_run_failure_authenticates_arm_lane_and_counts_only_terminal_crossing() {
        let mut custody = ForkStockHostCustody::new(NonZeroU64::new(7).unwrap());
        let execution = test_execution(41, 0, 301);
        let reason = carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody;
        let record = carrick_el1_abi::NativeRunFailure::new(execution.binding, reason);
        assert_eq!(
            custody.service_run_failure(None, &record),
            Err(ForkStockServiceError::StaleExecution)
        );
        assert_eq!(custody.run_failure.crossings(), 0);
        assert_eq!(
            custody.service_run_failure(Some(execution.binding), &record),
            Ok((reason, 1))
        );
        assert_eq!(
            custody.service_run_failure(Some(execution.binding), &record),
            Err(ForkStockServiceError::StaleExecution)
        );
        assert_eq!(custody.run_failure.crossings(), 1);
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
                    NonZeroU64::new(7).unwrap(),
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

        let child_root = custody.root(NonZeroU64::new(302).unwrap()).unwrap();
        assert_eq!(child_root.mm.raw().get(), 302);
        assert_eq!(child_root.root, page(loan.request.child_tables.base));
        assert_eq!(child_root.generation.raw(), completion.child.incarnation());
        assert_ne!(
            child_root.generation.raw().get(),
            exec.binding.generation.raw()
        );
        assert!(custody.root(NonZeroU64::new(301).unwrap()).is_none());

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
        let mut second_exchange = ForkStockExchange::new(test_request(exec, 303, 3, 1)).unwrap();
        let second_loan = custody
            .service_loan(&mut ledger, exec, &mut second_exchange)
            .unwrap();
        let mut dirty_abort = ForkStockSettlement::abort(second_loan);
        let result =
            custody.service_settlement(&mut ledger, exec, &mut dirty_abort, |_| true, |_| false);
        assert_eq!(result, Err(ForkStockServiceError::ExposedDirtyTable));
        custody
            .service_settlement(&mut ledger, exec, &mut dirty_abort, |_| true, |_| true)
            .expect("guest cleared the loan after refusal");
        let mut third_exchange = ForkStockExchange::new(test_request(exec, 304, 3, 1)).unwrap();
        custody
            .service_loan(&mut ledger, exec, &mut third_exchange)
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
        custody.grant_tables = (0..16)
            .map(|i| RootGpa::page_aligned(FrameGpa::new(0x2_0000 + i * 4096)).unwrap())
            .collect();
        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange)
            .expect("loan granted");

        let child_asid = loan.asid.expect("child ASID granted");
        assert_ne!(
            child_asid, host_asid,
            "child ASID must differ from host MM ASID"
        );

        // 3. Abort releases the ASID back to reusable pool
        let mut abort = ForkStockSettlement::abort(loan);
        custody
            .service_settlement(&mut ledger, exec, &mut abort, |_| true, |_| true)
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
            .service_loan(&mut ledger, exec, &mut exchange2)
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
            .service_settlement(&mut ledger, exec, &mut commit, |_| true, |_| true)
            .expect("commit settlement");

        // Child exit marks the MM retired while its TTBR0 may still be live.
        let child_exec = test_execution(42, 0, 303);
        let retire = NativeChildRetire::new(child_exec.binding, child_exec.context).unwrap();
        custody
            .service_child_retire(child_exec, &retire)
            .expect("child quarantine");

        assert!(custody.committed_asids.contains_key(&303));
        assert_eq!(
            custody
                .reclaim_retired(&mut ledger, exec.binding.mm.raw(), |_| true, |_| true)
                .expect("reclaim after parent resumes"),
            1
        );
        // A second pass cannot reclaim the same child twice.
        assert_eq!(
            custody
                .reclaim_retired(&mut ledger, exec.binding.mm.raw(), |_| true, |_| true)
                .expect("exactly once"),
            0
        );
        assert!(custody.committed_asids.get(&303).is_none());

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
        let pool_pages = custody.grant_tables.len();
        let lifecycle_slots = custody.lifecycle_stock.len();
        let parent = test_execution(41, 0, 301);

        for cycle in 0..=pool_pages as u64 {
            let child_mm = 302 + cycle;
            let request = test_request(parent, child_mm, 1, 1);
            let mut exchange = ForkStockExchange::new(request).unwrap();
            let loan = custody
                .service_loan(&mut ledger, parent, &mut exchange)
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
                .service_settlement(&mut ledger, parent, &mut commit, |_| true, |_| true)
                .expect("settle child and return unused parent page");
            let child = test_execution(42 + cycle, 0, child_mm);
            let retire = NativeChildRetire::new(child.binding, child.context).unwrap();
            custody
                .service_child_retire(child, &retire)
                .expect("child quarantine");
            assert_eq!(
                custody
                    .reclaim_retired(&mut ledger, parent.binding.mm.raw(), |_| true, |_| true)
                    .expect("parent has resumed"),
                1
            );
            assert_eq!(custody.grant_tables.len(), pool_pages);
            assert_eq!(custody.lifecycle_stock.len(), lifecycle_slots);
            assert!(custody.root(NonZeroU64::new(child_mm).unwrap()).is_none());
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
                .service_loan(&mut ledger, parent, &mut exchange)
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
                .service_settlement(&mut ledger, parent, &mut commit, |_| true, |_| true)
                .expect("committed child stays live");
        }
        assert_ne!(lifecycles[0], lifecycles[1]);
        assert_eq!(custody.committed_lifecycle.len(), 2);
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
        let pool_pages = custody.grant_tables.len() as u64;
        let request = test_request(parent, 302, pool_pages - 1, 1);
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let loan = custody
            .service_loan(&mut ledger, parent, &mut exchange)
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
            .service_settlement(&mut ledger, parent, &mut commit, |_| true, |_| true)
            .expect("commit first child");
        let child = test_execution(42, 0, 302);
        let retire = NativeChildRetire::new(child.binding, child.context).unwrap();
        custody
            .service_child_retire(child, &retire)
            .expect("quarantine child tables");
        assert_eq!(
            custody
                .reclaim_retired(&mut ledger, parent.binding.mm.raw(), |_| false, |_| true)
                .unwrap(),
            0
        );
        let next = test_request(parent, 303, pool_pages - 1, 1);
        let mut refused = ForkStockExchange::new(next).unwrap();
        assert_eq!(
            custody.service_loan(&mut ledger, parent, &mut refused),
            Err(ForkStockRefusal::Capacity)
        );
        assert_eq!(
            custody
                .reclaim_retired(&mut ledger, parent.binding.mm.raw(), |_| true, |_| true)
                .unwrap(),
            1
        );
        let mut admitted = ForkStockExchange::new(next).unwrap();
        custody
            .service_loan(&mut ledger, parent, &mut admitted)
            .expect("stock is reusable only after quarantine drains");
    }

    #[repr(align(64))]
    struct AlignedPage([u8; 4096]);

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_round_trip_and_settlement() {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
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
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 6);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_commit_publishes_native_child_frame_custody() {
        use carrick_hal::PhysicalFrameInventory;
        use std::sync::Arc;

        struct Admission {
            source: Arc<dyn PhysicalFrameInventory>,
            snapshot: carrick_hal::NativeRootFrameSnapshot,
            context: AddressContext<RootGpa>,
        }
        impl carrick_hal::NativeFrameInventoryAdmission for Admission {
            fn inventory(&self) -> Arc<dyn PhysicalFrameInventory> {
                Arc::clone(&self.source)
            }
            fn admit_root(
                &self,
                context: AddressContext<RootGpa>,
            ) -> Result<
                carrick_hal::NativeRootFrameSnapshot,
                Box<dyn std::error::Error + Send + Sync>,
            > {
                if context != self.context {
                    return Err(Box::new(std::io::Error::other("foreign fixture root")));
                }
                Ok(self.snapshot.clone())
            }
        }
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let vm_generation = custody.begin_create().unwrap();
        custody.commit_create(vm_generation).unwrap();
        let mut execution = test_execution(41, 0, 301);
        execution.context.generation = ContextGeneration::new(NonZeroU64::new(7).unwrap());
        let inventory = Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new());
        let source = inventory
            .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()));
        let parent = source.bind(execution.context.into());
        let mut reservation = parent.reserve(1, 1, 2).unwrap();
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        // All generation domains deliberately differ in this witness.
        let mapping_generation =
            carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::MIN);
        let length = carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(16384).unwrap());
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: mapping_generation,
                gpa: carrick_guest_mem::Gpa(0x50000),
                length,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: mapping_generation,
            })
            .unwrap();
        let receipt = parent.apply_with_receipt(reservation.commit(())).unwrap();
        custody
            .bind_native_frame_inventory(Arc::new(Admission {
                source: Arc::clone(&source),
                context: execution.context,
                snapshot: carrick_hal::NativeRootFrameSnapshot {
                    owner: execution.context.into(),
                    revision: NonZeroU64::new(receipt.revision()).unwrap(),
                    mappings: vec![parent.live_mapping_row(mapping).unwrap()],
                },
            }))
            .unwrap();

        let mut records = Box::new(AlignedPage([0; 4096]));
        let record_ipa = 0x2000_0000;
        let mut residency = Box::<carrick_el1_abi::FrameGrantResidencyTable>::new_uninit();
        // SAFETY: Box provides the ABI table's alignment and complete writable
        // storage; initialization avoids a large stack temporary.
        unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(residency.as_mut_ptr());
        }
        let residency = unsafe { residency.assume_init() };
        custody
            .publish_stage2_record_using(
                crate::trap::CarrierStage2RecordSpec {
                    vm_generation,
                    ipa: carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_BASE,
                    len: core::mem::size_of::<carrick_el1_abi::FrameGrantResidencyTable>(),
                    host_addr: (&*residency as *const carrick_el1_abi::FrameGrantResidencyTable)
                        as usize,
                    mapped: true,
                    backend_map_installed: true,
                    release_ipa: false,
                    perms: 3,
                    logical_owner: Some(crate::trap::CarrierLogicalOwner {
                        id: 98,
                        generation: 83,
                    }),
                },
                || 0,
            )
            .unwrap();
        let mut tables: Vec<_> = (0..8).map(|_| Box::new(AlignedPage([0; 4096]))).collect();
        let mut parent_tables: Vec<_> = (0..4).map(|_| Box::new(AlignedPage([0; 4096]))).collect();
        let mut data: Vec<_> = (0..4).map(|_| Box::new(AlignedPage([0; 4096]))).collect();
        let publish = |ipa, host_addr, generation| {
            custody
                .publish_stage2_record_using(
                    crate::trap::CarrierStage2RecordSpec {
                        vm_generation,
                        ipa,
                        len: 4096,
                        host_addr,
                        mapped: true,
                        backend_map_installed: true,
                        release_ipa: false,
                        perms: 3,
                        logical_owner: Some(crate::trap::CarrierLogicalOwner {
                            id: ipa,
                            generation,
                        }),
                    },
                    || 0,
                )
                .unwrap();
        };
        publish(record_ipa, records.0.as_mut_ptr() as usize, 5);
        for (index, page) in tables.iter_mut().enumerate() {
            publish(
                0x2001_0000 + index as u64 * 4096,
                page.0.as_mut_ptr() as usize,
                13,
            );
        }
        for (index, page) in parent_tables.iter_mut().enumerate() {
            publish(
                0x1000 + index as u64 * 4096,
                page.0.as_mut_ptr() as usize,
                17,
            );
        }
        for (index, page) in data.iter_mut().enumerate() {
            publish(
                0x50000 + index as u64 * 4096,
                page.0.as_mut_ptr() as usize,
                73,
            );
        }
        {
            let mut stock = custody.fork_stock.lock();
            stock.carrier = NonZeroU64::new(7).unwrap();
            stock.grant_tables = (0..8)
                .map(|index| page(0x2001_0000 + index * 4096))
                .collect();
        }
        let request = test_request(execution, 302, 4, 1);
        // SAFETY: aligned retained fixture record; the dispatcher owns it while stopped.
        unsafe {
            records
                .0
                .as_mut_ptr()
                .cast::<ForkStockExchange>()
                .write(ForkStockExchange::new(request).unwrap());
        }
        let dispatch = || {
            crate::metadata_grant::service_metadata_operation(
                &custody,
                Some(vm_generation),
                execution.cpu,
                Some(execution),
                carrick_el1_abi::GRANT_OP_FORK_STOCK,
                record_ipa,
                0,
                0,
            )
            .unwrap()
        };
        assert_eq!(dispatch()[0], carrick_el1_abi::METADATA_GRANT_SUCCESS);
        let loan = unsafe { &mut *records.0.as_mut_ptr().cast::<ForkStockExchange>() }
            .take(request)
            .unwrap()
            .unwrap();
        // Four levels, one inherited private data page, no table stores at commit.
        let leaf: u64 = 0x50000
            | 3
            | (1 << 10)
            | (3 << 6)
            | (1 << 11)
            | (1 << 54)
            | (1 << 55)
            | (1 << 56)
            | (1 << 57);
        for index in 0..3 {
            let parent_next = 0x1000 + (index as u64 + 1) * 4096;
            parent_tables[index].0[..8].copy_from_slice(&(parent_next | 3).to_ne_bytes());
            let child_next = loan.request.child_tables.base + (index as u64 + 1) * 4096;
            tables[index].0[..8].copy_from_slice(&(child_next | 3).to_ne_bytes());
        }
        // The settlement custody pointer is a kernel VA, resolved through
        // the stopped parent's live root rather than treated as an IPA.
        let kernel_block: u64 = 0x2000_0000 | 1 | (1 << 10) | (1 << 54);
        parent_tables[2].0[2048..2056].copy_from_slice(&kernel_block.to_ne_bytes());
        parent_tables[3].0[32..40].copy_from_slice(&leaf.to_ne_bytes());
        tables[3].0[32..40].copy_from_slice(&leaf.to_ne_bytes());
        let words = carrick_el1_abi::PortalForkCustody::Frame {
            va: 0x4000,
            ipa: 0x50000,
            len: 4096,
            shared: false,
        }
        .words();
        for (index, word) in words.iter().enumerate() {
            records.0[512 + index * 8..520 + index * 8].copy_from_slice(&word.to_ne_bytes());
        }
        let child_handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                request.operation.carrier,
                request.child_mm,
                NonZeroU64::new(19).unwrap(),
            )
        };
        let completion = PortalForkCompletion {
            request: loan.request,
            child: child_handle,
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4 * 4096,
            parent_tables_used: 4096,
        };
        let settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(record_ipa + 512), 1).unwrap();
        unsafe {
            records
                .0
                .as_mut_ptr()
                .cast::<ForkStockSettlement>()
                .write(settlement);
        }
        // A custody selection must name the actual output of both roots.
        records.0[528..536].copy_from_slice(&0x51000u64.to_ne_bytes());
        assert_eq!(dispatch()[0], carrick_el1_abi::METADATA_GRANT_ERR_DENIED);
        assert_eq!(parent.frame_mapping_count(frame).unwrap(), Some(1));
        records.0[528..536].copy_from_slice(&0x50000u64.to_ne_bytes());
        // Alias staging must roll back if table settlement subsequently
        // refuses a dirty page advertised as unused.
        let parent_stock_index = ((loan.request.parent_tables.base - 0x2001_0000) / 4096) as usize;
        tables[parent_stock_index].0[0] = 1;
        let refused_completion = PortalForkCompletion {
            parent_tables_used: 0,
            ..completion
        };
        let refused =
            ForkStockSettlement::new(loan, refused_completion, KernelVa::new(record_ipa + 512), 1)
                .unwrap();
        unsafe {
            records
                .0
                .as_mut_ptr()
                .cast::<ForkStockSettlement>()
                .write(refused);
        }
        assert_eq!(dispatch()[0], carrick_el1_abi::METADATA_GRANT_ERR_DENIED);
        assert_eq!(parent.frame_mapping_count(frame).unwrap(), Some(1));
        tables[parent_stock_index].0[0] = 0;
        let settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(record_ipa + 512), 1).unwrap();
        unsafe {
            records
                .0
                .as_mut_ptr()
                .cast::<ForkStockSettlement>()
                .write(settlement);
        }
        assert_eq!(dispatch()[0], carrick_el1_abi::METADATA_GRANT_SUCCESS);
        assert_eq!(
            parent.frame_mapping_count(frame).unwrap(),
            Some(2),
            "fork commit must publish the native child's reference before it can enter"
        );
        let child = custody
            .fork_stock
            .lock()
            .root(NonZeroU64::new(302).unwrap())
            .unwrap();
        let child_rows = custody
            .fork_stock
            .lock()
            .root_frames(child)
            .unwrap()
            .clone();
        assert_eq!(child_rows.owner, child.into());
        assert_eq!(child_rows.mappings.len(), 1);
        let child_row = child_rows.mappings[0];
        assert_eq!(child_row.frame, frame);
        assert_ne!(child_row.mapping, mapping);
        assert_eq!(child_row.generation.raw(), 1);
        let child_page = residency
            .lookup(child.mm.raw().get(), 0x4000)
            .expect("fork commit must publish the child's inherited residency before entry");
        assert_eq!(child_page.expected_ipa, 0x50000);
        assert_eq!(child_page.identity.frame_id, child_row.frame.raw());
        assert_eq!(child_page.identity.mapping_id, child_row.mapping.raw());
        assert_eq!(child_page.identity.owner_generation, 73);
        assert_eq!(
            child_page.identity.inventory_revision,
            child_rows.revision.get()
        );
        assert!(residency.is_guest_committed(child.mm.raw().get(), 0x4000));
        assert!(residency.is_guest_committed(execution.context.mm.raw().get(), 0x4000));
        assert_eq!(
            source
                .bind(child.into())
                .live_mapping_row(child_row.mapping),
            Some(child_row)
        );
        // This child has no host KernelContext or MmAccessState. Its COW
        // source must be admitted through the same canonical guest custody.
        let mut child_execution = execution;
        child_execution.context = child;
        child_execution.binding.mm = carrick_el1_abi::EntryMmKey::from_raw(302);
        assert_eq!(
            crate::trap::native_cow::selected_source(
                &custody,
                child_execution,
                carrick_guest_arch::UserVa::new(0x4000)
            )
            .expect("guest-only child COW source must be admitted"),
            child_row
        );
        let mut stale_execution = child_execution;
        stale_execution.context.generation = ContextGeneration::new(NonZeroU64::new(20).unwrap());
        assert!(
            crate::trap::native_cow::selected_source(
                &custody,
                stale_execution,
                carrick_guest_arch::UserVa::new(0x4000)
            )
            .is_err()
        );
        let mut wrong_execution = child_execution;
        wrong_execution.binding.mm = execution.binding.mm;
        assert!(
            crate::trap::native_cow::selected_source(
                &custody,
                wrong_execution,
                carrick_guest_arch::UserVa::new(0x4000)
            )
            .is_err()
        );
        // Exercise the production owner supply crossing with no host MM row.
        // Atomic ABI records have a valid all-zero empty state and are heap
        // allocated with their type alignment, never through byte vectors.
        fn empty_record<T>() -> Box<T> {
            let layout = std::alloc::Layout::new::<T>();
            unsafe {
                let pointer = std::alloc::alloc_zeroed(layout).cast::<T>();
                assert!(!pointer.is_null());
                Box::from_raw(pointer)
            }
        }
        let pool = empty_record::<carrick_el1_abi::CowGrantPool>();
        let portal = empty_record::<carrick_el1_abi::MmPortalSlots>();
        let zone = empty_record::<carrick_el1_abi::ZoneTables>();
        for (ipa, host_addr, len) in [
            (
                carrick_el1_abi::EL1_COW_GRANT_POOL_BASE,
                &*pool as *const _ as usize,
                core::mem::size_of::<carrick_el1_abi::CowGrantPool>(),
            ),
            (
                carrick_el1_abi::EL1_MM_PORTAL_BASE,
                &*portal as *const _ as usize,
                core::mem::size_of::<carrick_el1_abi::MmPortalSlots>(),
            ),
            (
                carrick_el1_abi::EL1_ZONE_BASE,
                &*zone as *const _ as usize,
                core::mem::size_of::<carrick_el1_abi::ZoneTables>(),
            ),
        ] {
            custody
                .publish_stage2_record_using(
                    crate::trap::CarrierStage2RecordSpec {
                        vm_generation,
                        ipa,
                        host_addr,
                        len,
                        mapped: true,
                        backend_map_installed: true,
                        release_ipa: false,
                        perms: 3,
                        logical_owner: Some(crate::trap::CarrierLogicalOwner {
                            id: ipa,
                            generation: 91,
                        }),
                    },
                    || 0,
                )
                .unwrap();
        }
        *custody.native_space_completion.lock() = Some(Arc::new(
            carrick_kernel::el1_zone::NativeSpaceCompletionWake,
        ));
        let space = zone
            .spaces
            .publish_closed(302, child.root.address().raw(), 0)
            .unwrap();
        zone.spaces.open(space);
        assert!(portal.bind_carrier(custody.transfer_carrier));
        let window = carrick_el1_abi::PortalGrantWindow::decode([
            custody.transfer_carrier.get(),
            302,
            2,
            3,
            4,
            0x4000,
            0x5000,
            3,
            0x4000,
            0,
            0,
            0,
            0,
        ])
        .unwrap();
        assert!(
            portal
                .grant(0)
                .unwrap()
                .publish_cow_fault_selection(3, window)
        );
        let owner_crossing = |active| {
            crate::metadata_grant::service_metadata_operation(
                &custody,
                Some(vm_generation),
                child_execution.cpu,
                Some(active),
                carrick_el1_abi::GRANT_OP_OWNER_SUPPLY,
                0x4000,
                u64::from(child_execution.cpu.raw()),
                0,
            )
        };
        assert_eq!(
            owner_crossing(child_execution).unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert_eq!(custody.host_cow_ledger.snapshot().guest_cow_provisioned, 1);
        let scope =
            carrick_el1_abi::CowGrantScope::checked(child_execution.binding, child).unwrap();
        let mut foreign_scope = scope;
        foreign_scope.execution.generation = EntryGeneration::from_raw(99);
        assert!(pool.claim(foreign_scope).is_none());
        let grant = pool
            .claim(scope)
            .expect("native replacement is ready for the exact child");
        assert!(owner_crossing(stale_execution).is_err());
        assert!(custody.native_cow_pending[0].lock().is_some());
        // The guest resolver owns copy and stores. This fixture performs its
        // exact final projection and receipt against real retained leaf words.
        assert!(residency.retire_small_span(302, 0x4000, 4096));
        let replacement_leaf = (leaf & !0x0000_ffff_ffff_f000 & !(3 << 6) & !(1 << 55))
            | grant.physical_ipa
            | (1 << 6);
        tables[3].0[32..40].copy_from_slice(&replacement_leaf.to_ne_bytes());
        let replacement_residency = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: 302,
            semantic_base: 0x4000,
            physical_ipa: grant.physical_ipa,
            len: 4096,
            frame_id: grant.backing.frame_id.get(),
            mapping_id: grant.backing.mapping_id.get(),
            owner_generation: grant.backing.owner_generation.get(),
            inventory_revision: grant.backing.inventory_revision.get(),
        };
        assert!(residency.publish(replacement_residency).is_some());
        assert!(residency.record_commit(residency.lookup(302, 0x4000).unwrap()));
        let completion = carrick_el1_abi::CowGrantCompletion {
            purpose: carrick_el1_abi::CowGrantPurpose::UserWrite,
            grant,
            span_va: 0x4000,
            span_len: 4096,
            old_ipa: 0x50000,
            new_ipa: grant.physical_ipa,
        };
        assert!(pool.complete(&completion));
        assert_eq!(
            owner_crossing(child_execution).unwrap()[0],
            carrick_el1_abi::METADATA_GRANT_SUCCESS
        );
        assert!(custody.native_cow_pending[0].lock().is_none());
        assert!(!pool.any_completed());
        assert_eq!(custody.host_cow_ledger.snapshot().guest_cow_settled, 1);
        assert_eq!(
            custody
                .fork_stock
                .lock()
                .root_frames(child)
                .unwrap()
                .mappings
                .len(),
            2
        );
        let wrong_owner = carrick_hal::GuestFrameOwner {
            root_generation: ContextGeneration::new(NonZeroU64::new(20).unwrap()),
            ..child.into()
        };
        assert!(
            source
                .bind(wrong_owner)
                .live_mapping_row(child_row.mapping)
                .is_none()
        );
        assert!(
            source
                .bind(execution.context.into())
                .live_mapping_row(child_row.mapping)
                .is_none()
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_fork_stock_refusal_on_stale_custody_and_malformed() {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
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
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 8);

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
        assert_eq!(custody.fork_stock.lock().grant_tables.len(), 8);

        // Case 3: An authenticated request with no lifecycle stock reports
        // the first typed capacity refusal through the trap result.
        custody.fork_stock.lock().lifecycle_stock.clear();
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

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn dispatcher_root_exit_success_and_stale_refusal() {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
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
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
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
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
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
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
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
            exec_a.cpu,
            Some(exec_a), // Trapped on vCPU A!
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
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
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

        custody.grant_tables = (0..16)
            .map(|i| RootGpa::page_aligned(FrameGpa::new(0x2_0000 + i * 4096)).unwrap())
            .collect();
        let exec = test_execution(41, 0, 301);
        let req = test_request(exec, 302, 1, 1);
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let loan = custody
            .service_loan(&mut ledger, exec, &mut exchange)
            .expect("loan granted");
        let child_asid = loan.asid.expect("child ASID granted");

        // Release the ASID out of band to simulate a prior release:
        let pending_asid_gen = custody.pending_loans[exec.cpu.raw() as usize]
            .as_ref()
            .unwrap()
            .asid_gen;
        asid_allocator
            .release_unpublished(pending_asid_gen)
            .expect("first release succeeds");

        // Now abort settlement attempts to release the same ASID generation again
        let mut abort = ForkStockSettlement::abort(loan);
        let result = custody.service_settlement(&mut ledger, exec, &mut abort, |_| true, |_| true);

        // Double release must be reported as a typed error, not ignored
        assert_eq!(
            result,
            Err(ForkStockServiceError::Asid(AsidError::NotLive(child_asid))),
            "double release must be reported as a typed error"
        );
    }
}
