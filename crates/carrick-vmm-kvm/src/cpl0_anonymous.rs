//! Physical custody service for CPL0-selected anonymous windows. No host VMA
//! selection or live descriptor store occurs at this boundary.
use super::*;
use carrick_el1_abi::{MmPortalSlots, PortalGrantWindow};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp as WireOp, DescriptorTxn as WireTxn, TableGrants,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

const _: () = {
    let physical = [
        carrick_el1_abi::X86_FORK_STOCK_PORT,
        carrick_el1_abi::X86_NATIVE_ROOT_EXIT_PORT,
        carrick_el1_abi::X86_NATIVE_PEER_READY_PORT,
    ];
    let existing = [
        FAULT_DOORBELL_PORT,
        FORWARD_PORT,
        CONTROL_PORT,
        ENTRY_KICK_PORT,
        RETURN_KICK_PORT,
        WORK_PORT,
        FATAL_PORT,
        YIELD_PORT,
        OWNER_GRANT_PORT,
        carrick_el1_abi::X86_INITIAL_BOOT_PORT,
        carrick_x86::FP_STUB_DOORBELL_PORT,
        carrick_x86::cpl0_scheduler::PROGRESS_ENTRY_PORT,
        carrick_x86::cpl0_scheduler::PROGRESS_RETURN_PORT,
        carrick_x86::cpl0_scheduler::PROGRESS_DONE_PORT,
    ];
    let mut i = 0;
    while i < physical.len() {
        let mut j = 0;
        while j < existing.len() {
            assert!(physical[i] != existing[j]);
            j += 1;
        }
        j = 0;
        while j < i {
            assert!(physical[i] != physical[j]);
            j += 1;
        }
        i += 1;
    }
};

#[derive(Clone, Copy)]
struct GrantExecution {
    cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    context: AddressContext<RootGpa>,
}
impl GrantExecution {
    fn matches(self, current: Self) -> bool {
        self.cpu == current.cpu
            && self.binding == current.binding
            && self.context == current.context
    }
}

fn take_fork_table_stock(
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

fn reserve_table_stock(stock: &mut Vec<RootGpa>) -> Vec<RootGpa> {
    let count = stock
        .len()
        .min(carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS);
    stock.drain(..count).collect()
}

pub(super) struct PendingForkLoan {
    loan: carrick_el1_abi::X86ForkStockLoan,
    execution: GrantExecution,
    child_tables: Vec<RootGpa>,
    parent_tables: Vec<RootGpa>,
}

pub(super) struct PendingPrepare {
    peer: crate::cpl0_private_witness::PeerActivity,
    window: PortalGrantWindow,
    txn: WireTxn,
    inventory: InitialInventory,
    handle: BackingHandle,
    execution: GrantExecution,
    tables: Vec<RootGpa>,
}

pub(super) struct PendingCow {
    window: PortalGrantWindow,
    inventory: InitialInventory,
    handle: BackingHandle,
    execution: GrantExecution,
    source: FrameGpa,
    source_identity: BackingIdentity,
    grant: carrick_el1_abi::CowGrant,
}

pub(super) enum PendingGrant {
    Prepare(PendingPrepare),
    Cow(PendingCow),
}
impl PendingGrant {
    fn execution(&self) -> GrantExecution {
        match self {
            Self::Prepare(pending) => pending.execution,
            Self::Cow(pending) => pending.execution,
        }
    }
}

fn exact_cow_receipt(
    grant: carrick_el1_abi::CowGrant,
    page: u64,
    source: FrameGpa,
    receipt: &carrick_el1_abi::CowGrantCompletion,
) -> bool {
    receipt.is_well_formed()
        && receipt.purpose == carrick_el1_abi::CowGrantPurpose::UserWrite
        && receipt.grant == grant
        && receipt.span_va == page
        && receipt.span_len == 4096
        && receipt.old_ipa == source.raw()
        && receipt.new_ipa == grant.physical_ipa + (source.raw() & 0x3fff)
        && source.raw() & !0x3fff != grant.physical_ipa
}

fn retained_cow_zone(ram: &GuestRam) -> Result<&X86Cpl0Zone, TrapError> {
    let ptr = ram
        .host_ptr(
            META_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
            size_of::<X86Cpl0Zone>(),
        )
        .ok_or_else(|| fail("owner COW zone"))?;
    // SAFETY: boot initialized aligned production zone retained by this RAM.
    Ok(unsafe { &*ptr.cast::<X86Cpl0Zone>() })
}
struct CowPause<'a> {
    spaces: &'a carrick_sched_core::AddressSpaces,
    index: carrick_sched_core::SpaceIndex,
    excluded: carrick_el1_abi::ExcludedEditor<'a>,
}
impl<'a> CowPause<'a> {
    fn new(spaces: &'a carrick_sched_core::AddressSpaces, mm: u64) -> Result<Self, TrapError> {
        let index = spaces.find(mm).ok_or_else(|| fail("owner COW space"))?;
        spaces.raise(index);
        // First raise blocks new editors. Refuse an existing editor rather
        // than holding physical capacity while a peer must make progress.
        if spaces.active_editor(index).is_some() {
            spaces.lower(index);
            return Err(fail("owner COW editor remains active at physical crossing"));
        }
        let excluded = spaces.raise_and_wait_for_editor(index, || std::process::abort());
        Ok(Self {
            spaces,
            index,
            excluded,
        })
    }
}
impl Drop for CowPause<'_> {
    fn drop(&mut self) {
        self.spaces.lower(self.index);
        self.spaces.lower(self.index);
    }
}

impl Cpl0HostCustody {
    fn physical_execution(&self, lease: &StoppedCpuLease<'_>) -> Result<GrantExecution, TrapError> {
        let task = self.task(lease.cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("physical loan MM"))?;
        let context = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("physical loan root"))?;
        let native = self.binding(lease.cpu);
        let live_root = RootGpa::page_aligned(FrameGpa::new(lease.vcpu.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("physical loan root alignment"))?;
        let generation = ContextGeneration::new(
            NonZeroU64::new(native.mm_owner_generation.load(Ordering::Acquire))
                .ok_or_else(|| fail("physical loan incarnation"))?,
        );
        admit_forward_execution(
            lease.cpu,
            carrick_guest_arch::CpuId::new(native.cpu_slot),
            binding,
            context,
            live_root,
            generation,
        )?;
        Ok(GrantExecution {
            cpu: lease.cpu,
            binding,
            context,
        })
    }

    fn stack_record_physical<T>(
        &self,
        lease: &StoppedCpuLease<'_>,
        context: AddressContext<RootGpa>,
        address: u64,
    ) -> Result<FrameGpa, TrapError> {
        let top = self
            .binding(lease.cpu)
            .kernel_stack
            .checked_add(16)
            .ok_or_else(|| fail("physical stack top"))?;
        let base = top
            .checked_sub(0x10000)
            .ok_or_else(|| fail("physical stack base"))?;
        let end = address
            .checked_add(size_of::<T>() as u64)
            .ok_or_else(|| fail("physical record overflow"))?;
        if address < base || end > top || !address.is_multiple_of(align_of::<T>() as u64) {
            return Err(fail(format!(
                "physical record outside stopped CPU stack: cpu={} address={address:#x} end={end:#x} base={base:#x} top={top:#x} size={} alignment={} rsp={:#x}",
                lease.cpu.raw(),
                size_of::<T>(),
                align_of::<T>(),
                lease.vcpu.get_gpr(X86Reg::Rsp)?
            )));
        }
        let mut page = address & !4095;
        while page < end {
            let leaf = translate_leaf(
                &self._vm.words(),
                context.root,
                UserVa::new(page),
                Access::Write,
                false,
            )
            .map_err(|reason| fail(format!("physical stack record translation: {reason:?}")))?;
            if leaf.output.raw()
                != page
                    .checked_sub(DIRECT_VA)
                    .ok_or_else(|| fail("physical record direct address"))?
            {
                return Err(fail("physical stack record alias mismatch"));
            }
            page += 4096;
        }
        Ok(FrameGpa::new(address - DIRECT_VA))
    }

    /// T must be a fully initialized, padding-free POD physical ABI record.
    unsafe fn read_stack_record<T>(
        &self,
        lease: &StoppedCpuLease<'_>,
        context: AddressContext<RootGpa>,
        address: u64,
    ) -> Result<(FrameGpa, T), TrapError> {
        let physical = self.stack_record_physical::<T>(lease, context, address)?;
        let bytes = self
            ._vm
            .read(physical, size_of::<T>())
            .map_err(|error| fail(error.to_string()))?;
        let mut record = std::mem::MaybeUninit::<T>::uninit();
        // SAFETY: caller supplies an all-bit-pattern-valid POD record; aligned
        // local storage and exact retained byte count establish its storage.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        Ok((physical, unsafe { record.assume_init() }))
    }

    pub(super) fn service_root_exit(
        &self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<GuestExitStatus, TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the root exit record consists of eight fully initialized u64s.
        let (_, record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::X86NativeRootExit>(
                lease,
                execution.context,
                lease.vcpu.get_gpr(X86Reg::Rax)?,
            )
        }?;
        let status = record
            .status_for(execution.binding)
            .ok_or_else(|| fail("native root exit execution/status"))?;
        Ok(GuestExitStatus::from_linux_code(status.raw() >> 8))
    }

    pub(super) fn service_fork_stock(
        &mut self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<(), TrapError> {
        use carrick_el1_abi::{X86ForkLifecycleLoan, X86ForkStockExchange, X86ForkStockRefusal};
        use carrick_guest_arch::KernelVa;
        let execution = self.physical_execution(lease)?;
        let address = lease.vcpu.get_gpr(X86Reg::Rax)?;
        let (_, tag) = unsafe { self.read_stack_record::<u64>(lease, execution.context, address) }?;
        match carrick_el1_abi::X86ForkStockKind::decode(tag) {
            Some(carrick_el1_abi::X86ForkStockKind::Loan) => {}
            Some(
                carrick_el1_abi::X86ForkStockKind::Commit
                | carrick_el1_abi::X86ForkStockKind::Abort,
            ) => {
                return self.settle_fork_stock(lease, execution, address);
            }
            None => return Err(fail("physical fork stock unknown record tag")),
        }
        let physical =
            self.stack_record_physical::<X86ForkStockExchange>(lease, execution.context, address)?;
        let bytes = self
            ._vm
            .read(physical, size_of::<X86ForkStockExchange>())
            .map_err(|error| fail(error.to_string()))?;
        let mut record = std::mem::MaybeUninit::<X86ForkStockExchange>::uninit();
        // SAFETY: this ABI record consists solely of u64 words, so every bit
        // pattern is valid. Local typed storage supplies the record alignment.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        let mut record = unsafe { record.assume_init() };
        let request = record
            .request()
            .ok_or_else(|| fail("physical fork stock malformed request"))?;
        let index = lease.cpu.raw() as usize;
        if request.binding != execution.binding
            || request.context != execution.context
            || request.operation.carrier != self._vm.identity().nonzero()
        {
            record.refuse(X86ForkStockRefusal::Stale);
        } else if self.fork_pending[index].is_some() || !self.fork_lifecycle_available {
            record.refuse(X86ForkStockRefusal::Capacity);
        } else if let Some((child_tables, parent_tables)) = take_fork_table_stock(
            &mut self.grant_tables,
            request.child_bytes,
            request.parent_bytes,
        ) {
            let lifecycle = X86ForkLifecycleLoan::new(
                KernelVa::new(METADATA_VA + 0x4000),
                KernelVa::new(METADATA_VA + 0x5000),
            )
            .ok_or_else(|| fail("physical fork lifecycle layout"))?;
            let id = NonZeroU64::new(self.fork_next_loan)
                .ok_or_else(|| fail("physical fork loan identity exhausted"))?;
            self.fork_next_loan = self
                .fork_next_loan
                .checked_add(1)
                .ok_or_else(|| fail("physical fork loan identity exhausted"))?;
            let child_base = child_tables[0].address().raw();
            let parent_base = parent_tables[0].address().raw();
            let loan = request
                .admit_loan(child_base, parent_base, KERNEL_REGION_GPA, id, lifecycle)
                .ok_or_else(|| fail("physical fork loan geometry"))?;
            // The one-use metadata gap is cold physical stock. The guest
            // initializes its typed lifecycle/census before claiming a task.
            // SAFETY: these reserved disjoint ranges remain unexposed under
            // the host's exclusive physical loan token.
            let fresh = unsafe {
                std::slice::from_raw_parts(
                    self.metadata_base.as_ptr().add(0x4000),
                    size_of::<ThreadLifecyclePage>(),
                )
                .iter()
                .all(|byte| *byte == 0)
                    && std::slice::from_raw_parts(
                        self.metadata_base.as_ptr().add(0x5000),
                        size_of::<ThreadControlSlot>() * 9,
                    )
                    .iter()
                    .all(|byte| *byte == 0)
            };
            if !fresh {
                self.grant_tables.extend(child_tables);
                self.grant_tables.extend(parent_tables);
                return Err(fail("physical fork lifecycle stock is not fresh"));
            }
            self.fork_lifecycle_available = false;
            self.fork_pending[index] = Some(PendingForkLoan {
                loan,
                execution,
                child_tables,
                parent_tables,
            });
            if !record.grant(child_base, parent_base, KERNEL_REGION_GPA, id, lifecycle) {
                return Err(fail("physical fork stock reply changed"));
            }
        } else {
            record.refuse(X86ForkStockRefusal::Capacity);
        }
        // SAFETY: expose only initialized u64 fields/padding in the copied ABI
        // record. The stopped CPU exclusively owns these validated stack bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<X86ForkStockExchange>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|error| fail(error.to_string()))
    }

    fn settle_fork_stock(
        &mut self,
        lease: &StoppedCpuLease<'_>,
        execution: GrantExecution,
        address: u64,
    ) -> Result<(), TrapError> {
        use carrick_el1_abi::{PortalForkCustody, X86ForkStockSettlement};
        let index = lease.cpu.raw() as usize;
        let pending = self.fork_pending[index]
            .as_ref()
            .ok_or_else(|| fail("physical fork settlement without loan"))?;
        if !pending.execution.matches(execution) {
            return Err(fail("physical fork settlement stale execution"));
        }
        let loan = pending.loan;
        let (physical, mut record) = unsafe {
            self.read_stack_record::<X86ForkStockSettlement>(lease, execution.context, address)
        }?;
        if record.abort_matches(loan) {
            // A restored descriptor tree needs its own exact guest receipt;
            // this early-abort form licenses only untouched cold table stock.
            for page in pending.child_tables.iter().chain(&pending.parent_tables) {
                if self
                    ._vm
                    .read(page.address(), 4096)
                    .map_err(|e| fail(e.to_string()))?
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(fail("physical fork abort retains exposed table loan"));
                }
            }
            let pending = self.fork_pending[index]
                .take()
                .ok_or_else(|| fail("physical fork abort loan changed"))?;
            self.grant_tables.extend(pending.child_tables);
            self.grant_tables.extend(pending.parent_tables);
            // Initialized lifecycle stock remains exclusive and is retained;
            // reuse requires a separate retired lifecycle receipt.
        } else {
            let (completion, custody, count) = record
                .request(loan)
                .ok_or_else(|| fail("physical fork settlement receipt"))?;
            let child = AddressContext {
                mm: carrick_guest_arch::MmGeneration::new(
                    NonZeroU64::new(loan.request.child_mm.raw())
                        .ok_or_else(|| fail("physical child MM"))?,
                ),
                root: RootGpa::page_aligned(FrameGpa::new(loan.request.child_tables.base))
                    .ok_or_else(|| fail("physical child root"))?,
                generation: carrick_guest_arch::ContextGeneration::new(
                    completion.child.incarnation(),
                ),
            };
            let len = count
                .checked_mul(32)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| fail("physical fork custody length"))?;
            let mut wire = Vec::new();
            wire.try_reserve_exact(len)
                .map_err(|_| fail("physical fork custody allocation"))?;
            let mut offset = 0usize;
            while offset < len {
                let va = custody
                    .raw()
                    .checked_add(offset as u64)
                    .ok_or_else(|| fail("physical fork custody overflow"))?;
                let n = ((4096 - (va & 4095)) as usize).min(len - offset);
                let leaf = translate_leaf(
                    &self._vm.words(),
                    execution.context.root,
                    UserVa::new(va),
                    Access::Read,
                    false,
                )
                .map_err(|e| fail(format!("physical fork custody translation: {e:?}")))?;
                if va < DIRECT_VA || leaf.output.raw() != va - DIRECT_VA {
                    return Err(fail(
                        "physical fork custody is not exclusive supervisor storage",
                    ));
                }
                wire.extend(
                    self._vm
                        .read(leaf.output, n)
                        .map_err(|e| fail(e.to_string()))?,
                );
                offset += n;
            }
            let mut edges = Vec::new();
            let mut spans = std::collections::BTreeSet::new();
            for words in wire.chunks_exact(32) {
                let words = std::array::from_fn(|i| {
                    u64::from_ne_bytes(std::array::from_fn(|byte| words[i * 8 + byte]))
                });
                let selected = PortalForkCustody::decode(words)
                    .ok_or_else(|| fail("physical fork custody encoding"))?;
                let selected_edges = self
                    ._vm
                    .select_inherited_frames(execution.context, selected, &self.frame_inventory)
                    .map_err(|e| fail(e.to_string()))?;
                for edge in selected_edges {
                    if !spans.insert(edge.span().va) {
                        return Err(fail("physical fork duplicate inherited page"));
                    }
                    edges.push(edge);
                }
            }
            let parent_mm = MmId::from_raw_u64(execution.context.mm.raw().get())
                .ok_or_else(|| fail("physical parent inventory MM"))?;
            let child_mm = MmId::from_raw_u64(child.mm.raw().get())
                .ok_or_else(|| fail("physical child inventory MM"))?;
            let mut rows = std::collections::BTreeMap::new();
            for edge in &edges {
                let identity = edge.identity();
                let mapping = MappingId::from_kernel_allocation(identity.mapping_id);
                let row = self
                    .frame_inventory
                    .live_mapping_row(parent_mm, mapping)
                    .ok_or_else(|| fail("physical fork source mapping absent"))?;
                if row.frame != FrameId::from_kernel_allocation(identity.frame_id)
                    || row.generation
                        != MappingGeneration::from_backend_counter(identity.owner_generation)
                    || edge.physical().raw() < row.gpa.0
                    || edge.physical().raw().checked_add(4096).is_none_or(|end| {
                        row.gpa
                            .0
                            .checked_add(row.length.raw())
                            .is_none_or(|limit| end > limit)
                    })
                {
                    return Err(fail("physical fork source mapping identity"));
                }
                rows.insert(identity.mapping_id, row);
            }
            let capacity = FrameEventCapacity::for_event_count(
                rows.len()
                    .checked_mul(2)
                    .ok_or_else(|| fail("physical fork inventory capacity"))?,
            )
            .map_err(|e| fail(e.to_string()))?;
            let mut reservation = self
                .frame_inventory
                .reserve(&self.object_ids, 0, rows.len(), capacity)
                .map_err(|e| fail(e.to_string()))?;
            let transaction = reservation.transaction();
            let generation = MappingGeneration::from_backend_counter(NonZeroU64::MIN);
            let mut mappings = std::collections::BTreeMap::new();
            for (source, row) in &rows {
                let mapping = reservation
                    .claim_mapping()
                    .map_err(|e| fail(e.to_string()))?;
                reservation
                    .push(FrameInventoryEvent::PrepareMapping {
                        transaction,
                        frame: row.frame,
                        mapping,
                        generation,
                        gpa: row.gpa,
                        length: row.length,
                        permissions: row.permissions,
                    })
                    .map_err(|e| fail(e.to_string()))?;
                reservation
                    .push(FrameInventoryEvent::PublishMapping {
                        transaction,
                        mapping,
                        generation,
                    })
                    .map_err(|e| fail(e.to_string()))?;
                mappings.insert(*source, mapping);
            }
            let (_, receipt) = self
                .frame_inventory
                .apply_with_receipt(child_mm, reservation.commit(()))
                .map_err(|e| fail(e.to_string()))?;
            self._vm
                .install_root(child.mm.raw(), child)
                .map_err(|e| fail(e.to_string()))?;
            let mut resident_windows = std::collections::BTreeSet::new();
            for edge in &edges {
                let source = edge.identity();
                let mapping = mappings
                    .get(&source.mapping_id)
                    .ok_or_else(|| fail("physical fork mapping selection"))?;
                let identity = BackingIdentity {
                    frame_id: source.frame_id,
                    mapping_id: NonZeroU64::new(mapping.raw())
                        .ok_or_else(|| fail("physical fork mapping identity"))?,
                    owner_generation: NonZeroU64::MIN,
                    inventory_revision: NonZeroU64::new(receipt.revision())
                        .ok_or_else(|| fail("physical fork inventory revision"))?,
                };
                self._vm
                    .attach_inherited_frame(child, edge, identity, &receipt, &self.frame_inventory)
                    .map_err(|e| fail(e.to_string()))?;
                let parent = self
                    .cow_residency()?
                    .lookup(execution.context.mm.raw().get(), edge.span().va);
                let mut resident = parent.map(|page| page.identity).unwrap_or(
                    carrick_el1_abi::FrameGrantResidencyIdentity {
                        mm_key: execution.context.mm.raw().get(),
                        semantic_base: edge.span().va,
                        physical_ipa: edge.physical().raw(),
                        len: 4096,
                        frame_id: source.frame_id.get(),
                        mapping_id: source.mapping_id.get(),
                        owner_generation: source.owner_generation.get(),
                        inventory_revision: source.inventory_revision.get(),
                    },
                );
                if parent.is_none() {
                    self.cow_residency()?
                        .publish(resident)
                        .ok_or_else(|| fail("physical fork source residency capacity"))?;
                    let page = self
                        .cow_residency()?
                        .lookup(resident.mm_key, edge.span().va)
                        .ok_or_else(|| fail("physical fork source residency publication"))?;
                    if edge.is_resident() && !self.cow_residency()?.record_commit(page) {
                        return Err(fail("physical fork source commit proof"));
                    }
                }
                resident.mm_key = child.mm.raw().get();
                resident.mapping_id = identity.mapping_id.get();
                resident.owner_generation = identity.owner_generation.get();
                resident.inventory_revision = identity.inventory_revision.get();
                if resident_windows.insert(resident.semantic_base) {
                    self.cow_residency()?
                        .publish(resident)
                        .ok_or_else(|| fail("physical fork child residency capacity"))?;
                }
                let page = self
                    .cow_residency()?
                    .lookup(resident.mm_key, edge.span().va)
                    .ok_or_else(|| fail("physical fork child residency publication"))?;
                if page.expected_ipa != edge.physical().raw()
                    || (edge.is_resident() && !self.cow_residency()?.record_commit(page))
                {
                    return Err(fail("physical fork child commit proof"));
                }
            }
            let mut pending = self.fork_pending[index]
                .take()
                .ok_or_else(|| fail("physical fork settlement loan changed"))?;
            self.grant_tables.extend(
                pending
                    .child_tables
                    .drain(completion.child_tables_used as usize / 4096..),
            );
            self.grant_tables.extend(
                pending
                    .parent_tables
                    .drain(completion.parent_tables_used as usize / 4096..),
            );
        }
        if !record.accept(loan) {
            return Err(fail("physical fork settlement reply changed"));
        }
        // SAFETY: settlement is a fully initialized array of sixteen u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<X86ForkStockSettlement>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))
    }

    fn cow_pool(&self) -> Result<&carrick_el1_abi::CowGrantPool, TrapError> {
        // SAFETY: retained aligned atomic-only kernel record initialized at boot.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_COW_GRANT_POOL_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    fn cow_residency(&self) -> Result<&carrick_el1_abi::FrameGrantResidencyTable, TrapError> {
        // SAFETY: same retained kernel region as the original COW pool.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    fn supply_cow_grant(
        &mut self,
        index: usize,
        execution: GrantExecution,
        window: PortalGrantWindow,
    ) -> Result<(), TrapError> {
        let mm = execution.context.mm.raw();
        if !window.valid()
            || self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.operation.mm.raw() != mm.get()
            || window.range.len() != 4096
            || window.range.start() != window.fault_page
            || window.host_backing.is_some()
        {
            return Err(fail("owner COW selection identity"));
        }
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let pause = CowPause::new(&zone.spaces, mm.get())?;
        let run = carrick_mmu_core::x86::descriptor_txn::classify_guest_cow_write(
            &self._vm.words(),
            execution.context.root,
            UserVa::new(window.fault_page),
            false,
        )
        .map_err(|reason| fail(format!("owner COW source: {reason:?}")))?;
        let leaf = translate_leaf(
            &self._vm.words(),
            execution.context.root,
            UserVa::new(window.fault_page),
            Access::Read,
            true,
        )
        .map_err(|reason| fail(format!("owner COW leaf: {reason:?}")))?;
        if leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::PRIVATE == 0
            || run.va != window.fault_page
            || run.len != 4096
        {
            return Err(fail("owner COW source is not exact private page"));
        }
        let source_identity = self
            ._vm
            .frame_identity(mm, run.old_ipa)
            .map_err(|error| fail(error.to_string()))?;
        let resident = self
            .cow_residency()?
            .lookup(mm.get(), run.va)
            .ok_or_else(|| fail("owner COW source residency"))?;
        let identity = resident.identity;
        if resident.expected_ipa != run.old_ipa.raw()
            || identity.frame_id != source_identity.frame_id.get()
            || identity.mapping_id != source_identity.mapping_id.get()
            || identity.owner_generation != source_identity.owner_generation.get()
            || identity.inventory_revision != source_identity.inventory_revision.get()
            || !self.cow_residency()?.is_guest_committed(mm.get(), run.va)
        {
            return Err(fail("owner COW source custody mismatch"));
        }
        let size = carrick_el1_abi::COW_GRANT_SIZE;
        let physical = self
            .anonymous_next_gpa
            .raw()
            .checked_add(size - 1)
            .map(|next| next & !(size - 1))
            .ok_or_else(|| fail("owner COW GPA exhausted"))?;
        if physical == run.old_ipa.raw() & !(size - 1) {
            return Err(fail("owner COW source/replacement physical alias"));
        }
        let gpa = FrameGpa::new(physical);
        self.anonymous_next_gpa = FrameGpa::new(
            physical
                .checked_add(size)
                .ok_or_else(|| fail("owner COW GPA exhausted"))?,
        );
        let (mut inventory, _) = InitialInventory::stage(
            Arc::clone(&self.frame_inventory),
            &self.object_ids,
            [gpa],
            0,
            size,
            NonZeroU64::MIN,
            MmId::from_raw_u64(mm.get()).ok_or_else(|| fail("owner COW MM"))?,
        )?;
        let backing = inventory
            .frames
            .first()
            .ok_or_else(|| fail("owner COW identity"))?
            .1;
        let extent =
            BackingExtent::private(gpa, size as usize).map_err(|error| fail(error.to_string()))?;
        let handles = self
            ._vm
            .prepare(
                &[PreparedBacking {
                    extent: Arc::new(extent),
                    identity: backing,
                }],
                &mut inventory,
            )
            .map_err(|error| fail(error.to_string()))?;
        let handle = handles[0];
        let Some(grant) = self.cow_pool()?.publish(mm.get(), physical, backing) else {
            // SAFETY: no grant exposed this fresh physical extent to the guest.
            unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                .map_err(|error| fail(error.to_string()))?;
            return Err(fail("owner COW pool full"));
        };
        // The original pool record now permits a guest copy/repoint. On any
        // subsequent failure retain the extent through carrier teardown.
        inventory.expected = 1;
        inventory.guest_exposed = true;
        self.anonymous_pending[index] = Some(PendingGrant::Cow(PendingCow {
            window,
            inventory,
            handle,
            execution,
            source: run.old_ipa,
            source_identity,
            grant,
        }));
        if !self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner COW slot"))?
            .take_cow_fault_selection(window)
        {
            return Err(fail("owner COW demand changed during physical publication"));
        }
        drop(pause);
        Ok(())
    }

    fn settle_cow_grant(
        &mut self,
        index: usize,
        execution: GrantExecution,
    ) -> Result<(), TrapError> {
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let pause = CowPause::new(&zone.spaces, execution.context.mm.raw().get())?;
        let pending = match self.anonymous_pending[index].as_ref() {
            Some(PendingGrant::Cow(pending)) if pending.execution.matches(execution) => pending,
            _ => return Err(fail("owner COW pending identity")),
        };
        if self
            ._vm
            .frame_identity(execution.context.mm.raw(), pending.source)
            .map_err(|error| fail(error.to_string()))?
            != pending.source_identity
        {
            return Err(fail("owner COW source identity changed"));
        }
        let receipt = self
            .cow_pool()?
            .completions(&pause.excluded)
            .find(|receipt| receipt.grant == pending.grant)
            .filter(|receipt| {
                exact_cow_receipt(
                    pending.grant,
                    pending.window.fault_page,
                    pending.source,
                    receipt,
                )
            })
            .ok_or_else(|| fail("owner COW exact completed receipt absent"))?;
        let resident = self
            .cow_residency()?
            .lookup(receipt.grant.mm_key, receipt.span_va)
            .ok_or_else(|| fail("owner COW replacement residency absent"))?;
        if resident.expected_ipa != receipt.new_ipa
            || resident.identity.frame_id != receipt.grant.backing.frame_id.get()
            || resident.identity.mapping_id != receipt.grant.backing.mapping_id.get()
            || resident.identity.owner_generation != receipt.grant.backing.owner_generation.get()
            || resident.identity.inventory_revision
                != receipt.grant.backing.inventory_revision.get()
            || !self
                .cow_residency()?
                .is_guest_committed(receipt.grant.mm_key, receipt.span_va)
        {
            return Err(fail("owner COW replacement residency identity"));
        }
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: execution.context.mm.raw(),
                generation: NonZeroU64::new(receipt.grant.epoch)
                    .ok_or_else(|| fail("owner COW grant epoch"))?,
            },
            root: execution.context.root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(receipt.span_va, receipt.span_len),
                old: pending.source,
                new: FrameGpa::new(receipt.new_ipa),
                backing: pending.grant.backing,
            },
            tables: &[],
        };
        let publication = GuestMmuPublication::from_x86_cow_completion(&txn, &receipt)
            .ok_or_else(|| fail("owner COW publication identity"))?;
        let Some(PendingGrant::Cow(mut pending)) = self.anonymous_pending[index].take() else {
            return Err(fail("owner COW pending disappeared"));
        };
        self._vm
            .publish(&txn, publication, &mut pending.inventory)
            .map_err(|error| fail(error.to_string()))?;
        pending.inventory.finish()?;
        if !self.cow_pool()?.finish(&pause.excluded, &pending.grant) {
            return Err(fail("owner COW completion changed after settlement"));
        }
        self.anonymous_private_pages = self
            .anonymous_private_pages
            .checked_add(1)
            .ok_or_else(|| fail("owner COW witness overflow"))?;
        let _retained = pending.handle;
        Ok(())
    }

    fn grant_portal(&self) -> Result<&MmPortalSlots, TrapError> {
        // SAFETY: the boot owner zero-initializes this atomic-only record in
        // the retained supervisor kernel region before either vCPU runs.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    pub(super) fn bind_grant_portal(&self) -> Result<(), TrapError> {
        let carrier = self._vm.identity().nonzero();
        if !self.grant_portal()?.bind_carrier(carrier) {
            return Err(fail("carrier portal already bound"));
        }
        Ok(())
    }

    pub(super) fn service_anonymous_grant(
        &mut self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<(), TrapError> {
        let cpu = lease.cpu;
        let index = cpu.raw() as usize;
        let lane = &*lease.vcpu;
        if lane.get_gpr(X86Reg::Rax)? != u64::from(cpu.raw()) {
            return Err(fail("owner grant CPU identity"));
        }
        let task = self.task(cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("owner grant MM"))?;
        let context = self._vm.root(mm).ok_or_else(|| fail("owner grant root"))?;
        if !binding.issued()
            || binding.thread_generation.raw() == 0
            || context.mm.raw() != mm
            || lane.get_gpr(X86Reg::Cr3)? != context.root.address().raw()
        {
            return Err(fail("owner grant inactive execution/root"));
        }
        let native = self.binding(cpu);
        if native.cpu_slot != cpu.raw()
            || native.mm_owner_generation.load(Ordering::Acquire) != context.generation.raw().get()
        {
            return Err(fail("owner grant address incarnation"));
        }
        let execution = GrantExecution {
            cpu,
            binding,
            context,
        };
        if let Some(pending) = &self.anonymous_pending[index]
            && !pending.execution().matches(execution)
        {
            return Err(fail("owner grant stale execution/root"));
        }
        if matches!(self.anonymous_pending[index], Some(PendingGrant::Cow(_))) {
            return self.settle_cow_grant(index, execution);
        }
        if let Some(PendingGrant::Prepare(mut pending)) = self.anonymous_pending[index].take() {
            let receipt = self
                .grant_portal()?
                .grant(index)
                .ok_or_else(|| fail("owner grant slot"))?
                .take_receipt(pending.window, &pending.txn)
                .ok_or_else(|| fail("owner grant receipt absent"))?;
            let publication = GuestMmuPublication::from_x86_owner_grant(&pending.txn, &receipt)
                .ok_or_else(|| fail(format!("owner grant refused: {:?}", receipt.outcome)))?;
            X86Mmu::project_grant(pending.txn.root.raw(), &pending.txn, |native| {
                self._vm
                    .publish(native, publication, &mut pending.inventory)
            })
            .map_err(|error| fail(format!("owner grant projection: {error:?}")))?
            .map_err(|error| fail(error.to_string()))?;
            pending.inventory.finish()?;
            self.private_anonymous_witness.record_settled(
                crate::cpl0_private_witness::SettledPrivateGrant {
                    memory: &self._vm,
                    inventory: &self.frame_inventory,
                    binding: pending.execution.binding,
                    context: pending.execution.context,
                    window: pending.window,
                    txn: &pending.txn,
                    publication,
                    peer: pending
                        .peer
                        .combine(crate::cpl0_private_witness::PeerActivity::observe(
                            &self.actual_run[1 - index],
                        )),
                },
            )?;
            self.anonymous_private_pages = self
                .anonymous_private_pages
                .checked_add(pending.window.range.len() / 4096)
                .ok_or_else(|| fail("owner grant witness overflow"))?;
            let used = publication.tables_linked as usize;
            if used > pending.txn.tables.len() {
                return Err(fail("owner grant table receipt"));
            }
            self.grant_tables.extend(pending.tables.drain(used..));
            // Retained stage-2 custody now belongs to the live guest graph.
            let _retained = pending.handle;
            return Ok(());
        }
        let far = lease.vcpu.get_gpr(X86Reg::Cr2)?;
        if let Some((_, window)) = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner COW slot"))?
            .pending_cow_fault_selection(mm.get(), far)
        {
            return self.supply_cow_grant(index, execution, window);
        }
        let (_, window) = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner grant slot"))?
            .pending_fault_selection(mm.get(), far)
            .ok_or_else(|| fail("owner fault selection absent"))?;
        if self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.host_backing.is_some()
            || window.range.len() > carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
        {
            return Err(fail("owner grant selection identity"));
        }
        let root = context.root;
        let gpa = self.anonymous_next_gpa;
        let len = window.range.len();
        self.anonymous_next_gpa = FrameGpa::new(
            gpa.raw()
                .checked_add(len)
                .ok_or_else(|| fail("owner grant GPA exhausted"))?,
        );
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(&self.frame_inventory),
            &self.object_ids,
            [gpa],
            0,
            len,
            // A newly allocated physical mapping starts at generation one;
            // the guest operation sequence belongs to the descriptor txn.
            NonZeroU64::MIN,
            MmId::from_raw_u64(mm.get()).ok_or_else(|| fail("owner inventory MM"))?,
        )?;
        let identity = inventory
            .frames
            .first()
            .ok_or_else(|| fail("owner grant backing identity"))?
            .1;
        let extent =
            BackingExtent::private(gpa, len as usize).map_err(|error| fail(error.to_string()))?;
        let handles = self
            ._vm
            .prepare(
                &[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }],
                &mut inventory,
            )
            .map_err(|error| fail(error.to_string()))?;
        let handle = handles[0];
        let grant = grants[0];
        let owned_tables = reserve_table_stock(&mut self.grant_tables);
        let tables: Vec<_> = owned_tables
            .iter()
            .map(|table| SubstrateGpa(table.address().raw()))
            .collect();
        let txn = WireTxn {
            id: DescriptorTxnId {
                mm_key: mm,
                generation: window.operation.sequence,
            },
            root: SubstrateGpa(root.address().raw()),
            op: WireOp::Prepare {
                publication: GuestLeafPublication {
                    va: window.range.start(),
                    ipa: grant.gpa,
                    len,
                    writable: window
                        .protection
                        .permits(carrick_el1_abi::ReservationProtection::WRITE),
                    executable: window
                        .protection
                        .permits(carrick_el1_abi::ReservationProtection::EXECUTE),
                },
                resident: PageSpan::new(window.fault_page, 4096),
                backing: identity,
            },
            tables: TableGrants::new(&tables).ok_or_else(|| fail("owner table grant encoding"))?,
        };
        let admission = X86Mmu::project_grant(root.address().raw(), &txn, |native| {
            self._vm.admit_guest_edit(native)
        });
        if !matches!(admission, Ok(Ok(())))
            || !self
                .grant_portal()?
                .grant(index)
                .ok_or_else(|| fail("owner grant slot"))?
                .submit(window, &txn)
        {
            // SAFETY: the vCPU is stopped, and no descriptor submission was
            // admitted. The fresh extent has never been guest-visible.
            unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                .map_err(|error| fail(error.to_string()))?;
            self.grant_tables.extend(owned_tables);
            return Err(fail("owner grant admission refused"));
        }
        inventory.expected = 1;
        // Once submitted, guest descriptor publication may have happened even
        // if the carrier never receives a verifiable completion. Keep physical
        // custody through carrier teardown rather than rolling inventory back.
        inventory.guest_exposed = true;
        self.anonymous_pending[index] = Some(PendingGrant::Prepare(PendingPrepare {
            peer: crate::cpl0_private_witness::PeerActivity::observe(&self.actual_run[1 - index]),
            window,
            txn,
            inventory,
            handle,
            execution,
            tables: owned_tables,
        }));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod custody_tests {
    use super::*;
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    };
    fn execution() -> GrantExecution {
        GrantExecution {
            cpu: carrick_guest_arch::CpuId::new(1),
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(42),
                generation: EntryGeneration::from_raw(12),
                mm: EntryMmKey::from_raw(302),
                thread_generation: EntryThreadGeneration::from_raw(102),
            },
            context: AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).unwrap(),
                mm: MmGeneration::new(NonZeroU64::new(302).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::new(17).unwrap()),
            },
        }
    }
    #[test]
    fn production_physical_ports_do_not_alias_native_or_fixture_doorbells() {
        let physical = [
            carrick_el1_abi::X86_FORK_STOCK_PORT,
            carrick_el1_abi::X86_NATIVE_ROOT_EXIT_PORT,
            carrick_el1_abi::X86_NATIVE_PEER_READY_PORT,
        ];
        let existing = [
            FAULT_DOORBELL_PORT,
            FORWARD_PORT,
            CONTROL_PORT,
            ENTRY_KICK_PORT,
            RETURN_KICK_PORT,
            WORK_PORT,
            FATAL_PORT,
            YIELD_PORT,
            OWNER_GRANT_PORT,
            carrick_el1_abi::X86_INITIAL_BOOT_PORT,
            carrick_x86::FP_STUB_DOORBELL_PORT,
            carrick_x86::cpl0_scheduler::PROGRESS_ENTRY_PORT,
            carrick_x86::cpl0_scheduler::PROGRESS_RETURN_PORT,
            carrick_x86::cpl0_scheduler::PROGRESS_DONE_PORT,
        ];
        for (index, port) in physical.iter().enumerate() {
            assert!(
                !existing.contains(port),
                "physical port {port:#x} aliases an existing doorbell"
            );
            assert!(!physical[..index].contains(port));
        }
    }

    #[test]
    fn owner_grant_receipt_refuses_recycled_execution_or_root() {
        let admitted = execution();
        assert!(admitted.matches(admitted));
        let mut foreign = admitted;
        foreign.binding.task = EntryTaskKey::from_raw(43);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.generation = EntryGeneration::from_raw(13);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.mm = EntryMmKey::from_raw(303);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.thread_generation = EntryThreadGeneration::from_raw(103);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.cpu = carrick_guest_arch::CpuId::new(0);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.root = RootGpa::page_aligned(FrameGpa::new(0x8000)).unwrap();
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.generation = ContextGeneration::new(NonZeroU64::new(18).unwrap());
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.mm = MmGeneration::new(NonZeroU64::new(303).unwrap());
        assert!(!admitted.matches(foreign));
    }
    #[test]
    fn owner_grants_reserve_disjoint_table_stock_before_receipt() {
        let mut stock: Vec<_> = (1..=32)
            .map(|n| RootGpa::page_aligned(FrameGpa::new(n * 4096)).unwrap())
            .collect();
        let first = reserve_table_stock(&mut stock);
        let second = reserve_table_stock(&mut stock);
        assert!(!first.is_empty());
        assert!(first.iter().all(|frame| !second.contains(frame)));
    }
    #[test]
    fn fork_physical_stock_requires_exact_disjoint_contiguous_capacity() {
        let page = |address| RootGpa::page_aligned(FrameGpa::new(address)).unwrap();
        let mut holes = vec![page(0x1000), page(0x3000), page(0x5000)];
        let before = holes.clone();
        assert!(take_fork_table_stock(&mut holes, 8192, 4096).is_none());
        assert_eq!(holes, before);
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
        for arena in [&child, &parent] {
            assert!(
                arena
                    .windows(2)
                    .all(|pair| pair[1].address().raw() == pair[0].address().raw() + 4096)
            );
        }
        assert!(
            child
                .iter()
                .all(|frame| !parent.contains(frame) && !stock.contains(frame))
        );
        let mut alias = vec![page(0x1000), page(0x1000), page(0x2000)];
        assert!(take_fork_table_stock(&mut alias, 4096, 4096).is_none());
    }

    #[test]
    fn cow_physical_exclusion_refuses_live_editor_and_reopens_after_settlement() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let index = spaces.publish_closed(302, 0x7000, 0x7000).unwrap();
        spaces.open(index);
        let editor = spaces.try_begin_edit(index, 302, NonZeroU64::MIN).unwrap();
        assert!(CowPause::new(&spaces, 302).is_err());
        drop(editor);
        let pause = CowPause::new(&spaces, 302).unwrap();
        assert_eq!(pause.excluded.key(), 302);
        assert!(spaces.try_begin_edit(index, 302, NonZeroU64::MIN).is_none());
        drop(pause);
        assert!(spaces.try_begin_edit(index, 302, NonZeroU64::MIN).is_some());
    }

    #[test]
    fn cow_loan_refuses_source_alias_and_foreign_completion() {
        use carrick_el1_abi::{CowGrant, CowGrantCompletion, CowGrantPurpose};
        let grant = CowGrant {
            slot: 4,
            epoch: 8,
            mm_key: 302,
            physical_ipa: 0x10000,
            backing: BackingIdentity {
                frame_id: NonZeroU64::new(1).unwrap(),
                mapping_id: NonZeroU64::new(2).unwrap(),
                owner_generation: NonZeroU64::new(3).unwrap(),
                inventory_revision: NonZeroU64::new(4).unwrap(),
            },
        };
        let source = FrameGpa::new(0x21000);
        let receipt = CowGrantCompletion {
            purpose: CowGrantPurpose::UserWrite,
            grant,
            span_va: 0x401000,
            span_len: 4096,
            old_ipa: source.raw(),
            new_ipa: 0x11000,
        };
        assert!(exact_cow_receipt(grant, 0x401000, source, &receipt));
        let mut wrong = receipt;
        wrong.old_ipa = 0x31000;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let mut wrong = receipt;
        wrong.grant.mm_key += 1;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let mut wrong = receipt;
        wrong.grant.epoch += 8;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let mut wrong = receipt;
        wrong.new_ipa += 4096;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let mut wrong = receipt;
        wrong.span_va += 4096;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let mut wrong = receipt;
        wrong.purpose = CowGrantPurpose::RetiredBacking;
        assert!(!exact_cow_receipt(grant, 0x401000, source, &wrong));
        let alias = CowGrant {
            physical_ipa: 0x20000,
            ..grant
        };
        let alias_receipt = CowGrantCompletion {
            grant: alias,
            new_ipa: source.raw(),
            ..receipt
        };
        assert!(!exact_cow_receipt(alias, 0x401000, source, &alias_receipt));
    }
}
