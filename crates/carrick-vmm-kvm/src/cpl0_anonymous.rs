//! Physical custody service for CPL0-selected anonymous windows. No host VMA
//! selection or live descriptor store occurs at this boundary.
use super::*;
use carrick_el1_abi::{MmPortalSlots, PortalGrantWindow};
use carrick_hal::fork_stock::{
    ForkStockServiceError, GrantExecution, LifecycleWindow, NoTableLedger, SlotAbsence,
    lifecycle_slots,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp as WireOp, DescriptorTxn as WireTxn, TableGrants,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

/// Every I/O port this CPL0 carrier decodes from one VM; each must be
/// distinct. `carrick_x86::FP_STUB_DOORBELL_PORT` (0xc6) is deliberately
/// absent: only the legacy no-FP-getter x86 engine in a bhyve VM decodes
/// it (`run_fp_stub`), never a KVM CPL0 VM, so its number is shared with
/// [`carrick_el1_abi::X86_INITIAL_BOOT_PORT`] without aliasing.
pub(super) const CPL0_CARRIER_PORTS: [u16; 17] = [
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
    carrick_x86::cpl0_scheduler::PROGRESS_ENTRY_PORT,
    carrick_x86::cpl0_scheduler::PROGRESS_RETURN_PORT,
    carrick_x86::cpl0_scheduler::PROGRESS_DONE_PORT,
    carrick_el1_abi::FORK_STOCK_PORT,
    carrick_el1_abi::NATIVE_ROOT_EXIT_PORT,
    carrick_el1_abi::NATIVE_PEER_READY_PORT,
    carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
];

const _: () = {
    let ports = CPL0_CARRIER_PORTS;
    let mut i = 0;
    while i < ports.len() {
        let mut j = 0;
        while j < i {
            assert!(
                ports[i] != ports[j],
                "CPL0 carrier ports must be pairwise distinct"
            );
            j += 1;
        }
        i += 1;
    }
};

/// Immutable physical storage licensed by the supervisor image's ELF loads.
/// This qualifies transport bytes without importing process or MM policy.
pub(super) struct KernelPodStorage {
    start: carrick_guest_arch::KernelVa,
    len: u64,
    physical: FrameGpa,
}
impl KernelPodStorage {
    /// The global allocator admits exactly this ABI-declared aperture;
    /// physical bootstrap owns its private window at the matching offset.
    pub(super) fn for_bootstrap() -> Self {
        Self {
            start: carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE),
            len: EL1_BOOTSTRAP_METADATA_SIZE,
            physical: FrameGpa::new(ALLOCATOR_GPA),
        }
    }

    pub(super) fn from_load(segment: &carrick_mem::elf::LoadSegment) -> Option<Self> {
        let end = segment.virtual_address.checked_add(segment.memory_size)?;
        if !segment.perms.read
            || !segment.perms.write
            || segment.perms.execute
            || segment.memory_size == 0
            || segment.virtual_address < IMAGE_VA
            || end > IMAGE_VA + 0x10_0000
        {
            return None;
        }
        Some(Self {
            start: carrick_guest_arch::KernelVa::new(segment.virtual_address),
            len: segment.memory_size,
            physical: FrameGpa::new(IMAGE_GPA.checked_add(segment.virtual_address - IMAGE_VA)?),
        })
    }
}

pub(super) fn retained_kernel_pod_storage(
    segments: &[carrick_mem::elf::LoadSegment],
) -> Vec<KernelPodStorage> {
    let mut storage: Vec<_> = segments
        .iter()
        .filter_map(KernelPodStorage::from_load)
        .collect();
    storage.push(KernelPodStorage::for_bootstrap());
    storage
}

fn kernel_pod_physical(
    storage: &[KernelPodStorage],
    address: carrick_guest_arch::KernelVa,
    len: usize,
    alignment: usize,
) -> Option<FrameGpa> {
    if len == 0 || alignment == 0 || !address.raw().is_multiple_of(alignment as u64) {
        return None;
    }
    let end = address.raw().checked_add(u64::try_from(len).ok()?)?;
    let source = storage.iter().find(|source| {
        address.raw() >= source.start.raw()
            && source
                .start
                .raw()
                .checked_add(source.len)
                .is_some_and(|limit| end <= limit)
    })?;
    Some(FrameGpa::new(
        source
            .physical
            .raw()
            .checked_add(address.raw() - source.start.raw())?,
    ))
}

pub(super) type PrepareTableSpan = carrick_el1_abi::X86PrepareTableSpan;

pub(super) fn prepare_table_working_bytes() -> Option<usize> {
    let lanes = core::num::NonZeroUsize::new(carrick_x86::cpl0_entry::CPL0_CPU_COUNT)?;
    usize::try_from(PrepareTableSpan::working_bytes(lanes)?.raw()).ok()
}

pub(super) fn prepare_table_suffix(
    extent_bytes: usize,
    occupied_end: usize,
) -> Option<PrepareTableSpan> {
    PrepareTableSpan::derive(
        carrick_guest_arch::GuestLen::new(u64::try_from(extent_bytes).ok()?),
        FrameGpa::new(INITIAL_EXTENT_GPA.checked_add(u64::try_from(occupied_end).ok()?)?),
        core::num::NonZeroUsize::new(carrick_x86::cpl0_entry::CPL0_CPU_COUNT)?,
    )
}

/// Exclusive physical credits for owner-selected Prepare operations. This
/// capability exposes no mutable vector that the fork stock service can take.
pub(super) struct PrepareTableStock {
    span: PrepareTableSpan,
    pages: Vec<RootGpa>,
}
struct PrepareTableLoan {
    span: PrepareTableSpan,
    pages: Vec<RootGpa>,
}
impl PrepareTableStock {
    pub(super) fn seed(span: PrepareTableSpan, bytes: &[u8]) -> Option<Self> {
        if usize::try_from(span.len().raw()).ok()? != prepare_table_working_bytes()?
            || bytes.len() != usize::try_from(span.len().raw()).ok()?
            || bytes.iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let pages = (0..span.page_count())
            .map(|index| {
                RootGpa::page_aligned(FrameGpa::new(span.start().raw() + index as u64 * 4096))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { span, pages })
    }
    fn candidates(&self) -> &[RootGpa] {
        &self.pages
    }
    fn loan(&mut self, required: usize) -> Option<PrepareTableLoan> {
        Some(PrepareTableLoan {
            span: self.span,
            pages: reserve_table_stock(&mut self.pages, required)?,
        })
    }
    fn return_unused(&mut self, loan: PrepareTableLoan, used: usize) -> Result<(), TrapError> {
        if loan.span != self.span || used > loan.pages.len() {
            return Err(fail("Prepare table loan custody mismatch"));
        }
        self.pages.extend(loan.pages.into_iter().skip(used));
        Ok(())
    }
}
impl PrepareTableLoan {
    fn len(&self) -> usize {
        self.pages.len()
    }
}

fn reserve_table_stock(stock: &mut Vec<RootGpa>, required: usize) -> Option<Vec<RootGpa>> {
    if required > carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS
        || required > stock.len()
    {
        return None;
    }
    Some(stock.drain(..required).collect())
}

pub(super) struct PendingPrepare {
    peer: crate::cpl0_private_witness::PeerActivity,
    window: PortalGrantWindow,
    txn: WireTxn,
    inventory: InitialInventory,
    handle: BackingHandle,
    execution: GrantExecution,
    tables: PrepareTableLoan,
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

struct HostCowWake<'a> {
    routes: &'a PublishedApicIds,
    vm: Arc<VmFd>,
    error: std::cell::RefCell<Option<TrapError>>,
}
impl<'a> HostCowWake<'a> {
    fn new(ram: &'a GuestRam, vm: Arc<VmFd>) -> Result<Self, TrapError> {
        let pointer = ram
            .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
            .ok_or_else(|| fail("owner COW retained APIC routes"))?;
        // SAFETY: bootstrap initialized this retained aligned atomic record.
        let routes = unsafe { &*pointer.cast::<PublishedApicIds>() };
        Ok(Self {
            routes,
            vm,
            error: std::cell::RefCell::new(None),
        })
    }
    fn deliver(
        &self,
        _: &X86Cpl0Zone,
        _: Waker,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        let (_, effects) = owned.deliver_handbacks(&mut |_| {
            self.error.borrow_mut().get_or_insert_with(|| {
                fail("native COW release produced unsupported host-home completion custody")
            });
        });
        if effects.misplaced || effects.queued_own {
            self.error
                .borrow_mut()
                .get_or_insert_with(|| fail("host COW release produced guest-own wake effects"));
        }
        for slot in effects.sgi_slots() {
            let result = self
                .routes
                .destination(carrick_guest_arch::CpuId::new(u32::from(slot.raw())))
                .ok_or_else(|| fail("owner COW wake APIC route absent"))
                .and_then(|apic| {
                    self.vm
                        .signal_msi(kvm_msi {
                            address_lo: 0xfee0_0000 | (u32::from(apic.0) << 12),
                            data: u32::from(carrick_x86::interrupts::RESCHED_VECTOR),
                            ..Default::default()
                        })
                        .map_err(|error| fail(format!("owner COW wake MSI: {error}")))
                })
                .and_then(|sent| {
                    if sent > 0 {
                        Ok(())
                    } else {
                        Err(fail("owner COW wake MSI blocked"))
                    }
                });
            if let Err(error) = result {
                self.error.borrow_mut().get_or_insert(error);
            }
        }
    }
    fn finish(&self) -> Result<(), TrapError> {
        self.error.borrow_mut().take().map_or(Ok(()), Err)
    }
}
struct CowPause<'a> {
    exclusion: carrick_sched_core::spaces::notification::SpaceExclusion<
        'a,
        carrick_sched_core::ParkedContextWords,
    >,
}
impl<'a> CowPause<'a> {
    fn new(
        access: SpaceAccess<'a, carrick_sched_core::ParkedContextWords>,
        mm: u64,
    ) -> Result<Self, TrapError> {
        let spaces = access.table();
        let index = spaces.find(mm).ok_or_else(|| fail("owner COW space"))?;
        let exclusion = access
            .try_exclude_editor(index, mm)
            .map_err(|reason| fail(format!("owner COW editor exclusion refused: {reason:?}")))?;
        Ok(Self { exclusion })
    }
    fn proof(&self) -> &carrick_el1_abi::ExcludedEditor<'_> {
        self.exclusion.proof()
    }
}

/// Release a reclaimed child's carrier-wide state: its frame-inventory rows
/// and COW residency (shared composition), then its CR3/alias registrations
/// and the memslots admitted only for it.
fn release_retired_child(
    memory: &mut CarrierMemory,
    inventory: &dyn carrick_hal::PhysicalFrameInventory,
    absence: &SlotAbsence,
) -> Result<crate::carrier_memory::RetiredChild, TrapError> {
    // SAFETY: the retained aligned residency table initialized at boot.
    let residency = unsafe {
        memory.retained_record::<carrick_el1_abi::FrameGrantResidencyTable>(FrameGpa::new(
            KERNEL_REGION_GPA + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
        ))
    }
    .map_err(|e| fail(e.to_string()))?;
    if !carrick_hal::fork_stock::release_child_mm(inventory, residency, absence.mm()) {
        return Err(fail("retired child inventory or residency release"));
    }
    memory
        .retire_child(absence, inventory)
        .map_err(|e| fail(e.to_string()))
}

fn tables_resolve(memory: &CarrierMemory, pages: &[RootGpa]) -> bool {
    pages
        .iter()
        .all(|page| memory.read(page.address(), 4096).is_ok())
}

fn tables_are_zero(memory: &CarrierMemory, pages: &[RootGpa]) -> bool {
    pages.iter().all(|page| {
        memory
            .read(page.address(), 4096)
            .is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
    })
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

    fn read_kernel_pod_bytes(
        &self,
        context: AddressContext<RootGpa>,
        address: carrick_guest_arch::KernelVa,
        len: usize,
        alignment: usize,
    ) -> Result<Vec<u8>, TrapError> {
        let physical = kernel_pod_physical(&self.kernel_pod_storage, address, len, alignment)
            .ok_or_else(|| fail(format!(
                "physical kernel POD outside retained storage: va={:#x} len={len:#x} alignment={alignment} mm={} root={:#x} spans={:?}",
                address.raw(), context.mm.raw(), context.root.address().raw(),
                self.kernel_pod_storage.iter().map(|span| format!("{:#x}..{:#x}->{:#x}", span.start.raw(), span.start.raw() + span.len, span.physical.raw())).collect::<Vec<_>>()
            )))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| fail("physical kernel POD allocation"))?;
        while bytes.len() < len {
            let offset = bytes.len();
            let va = address
                .raw()
                .checked_add(offset as u64)
                .ok_or_else(|| fail("physical kernel POD address"))?;
            let count = ((4096 - (va & 4095)) as usize).min(len - offset);
            let leaf = translate_leaf(
                &self._vm.words(),
                context.root,
                UserVa::new(va),
                Access::Write,
                false,
            )
            .map_err(|e| fail(format!("physical kernel POD translation: {e:?}")))?;
            let expected = FrameGpa::new(
                physical
                    .raw()
                    .checked_add(offset as u64)
                    .ok_or_else(|| fail("physical kernel POD output"))?,
            );
            if leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::USER != 0
                || leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::WRITE == 0
                || !leaf.ancestors_writable
                || leaf.executable
                || leaf.output != expected
            {
                return Err(fail(
                    "physical kernel POD supervisor permission/physical identity",
                ));
            }
            bytes.extend(
                self._vm
                    .read(expected, count)
                    .map_err(|e| fail(e.to_string()))?,
            );
        }
        Ok(bytes)
    }

    pub(super) fn service_root_exit(
        &self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<GuestExitStatus, TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the root exit record consists of eight fully initialized u64s.
        let (_, record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeRootExit>(
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

    /// Seed the bounded fork stock after the initial MM is published. One
    /// unused initial table grant becomes the carrier's maintenance root:
    /// only the initial root's shared supervisor branches, published as the
    /// zone's idle root so a CPU can leave every process root before its
    /// slot reports no installed MM. The rest become fork table stock.
    pub(super) fn install_fork_stock(
        &mut self,
        initial_root: RootGpa,
        mut unused: Vec<RootGpa>,
    ) -> Result<(), TrapError> {
        use carrick_mmu_core::owner_mmu::OwnerForkMmu;
        if unused.is_empty() {
            return Err(fail("no initial table grant for the maintenance root"));
        }
        let maintenance = unused.remove(0);
        // The guest reads both roots through its direct window to verify
        // the shared supervisor entries before every maintenance install.
        if maintenance
            .address()
            .raw()
            .checked_add(4096)
            .is_none_or(|end| end > carrick_el1_abi::X86_CPL0_DIRECT_WINDOW_BYTES)
        {
            return Err(fail("maintenance root outside the CPL0 direct window"));
        }
        let source = self
            ._vm
            .read(initial_root.address(), 4096)
            .map_err(|e| fail(e.to_string()))?;
        let mut root = vec![0u8; 4096];
        for index in (256..512).filter(|index| X86Mmu::is_shared_root_entry(*index)) {
            root[index * 8..index * 8 + 8].copy_from_slice(&source[index * 8..index * 8 + 8]);
        }
        if self
            ._vm
            .read(maintenance.address(), 4096)
            .map_err(|e| fail(e.to_string()))?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(fail("maintenance root grant is not zero storage"));
        }
        self._vm
            .write(maintenance.address(), &root)
            .map_err(|e| fail(e.to_string()))?;
        retained_cow_zone(&self.ram)?
            .spaces
            .set_idle_ttbr(maintenance.address().raw());
        let lifecycles = lifecycle_slots(
            METADATA_VA,
            METADATA_VA + FORK_LIFECYCLE_OFFSET,
            FORK_LIFECYCLE_SLOTS,
        )
        .ok_or_else(|| fail("fork lifecycle stock layout"))?;
        self.fork_stock
            .install(unused, lifecycles)
            .map_err(|e| fail(format!("fork stock install: {e:?}")))
    }

    /// The retained metadata window holding the fork lifecycle stock.
    fn lifecycle_window(&self) -> LifecycleWindow {
        // SAFETY: `metadata_base` retains META_LEN host bytes backing
        // METADATA_VA for the VM lifetime.
        unsafe { LifecycleWindow::new(self.metadata_base, METADATA_VA, META_LEN) }
    }

    /// Return quarantined child stock whose MM no zone slot has installed.
    /// The servicing CPU's own MM is never a candidate. Inside the shared
    /// reclaim, before any of the child's stock can be reissued, the child's
    /// carrier state is released (frame inventory, COW residency, CR3 and
    /// aliases, private memslots); a refused release keeps it quarantined.
    fn drain_fork_quarantine(&mut self, execution: GrantExecution) -> Result<(), TrapError> {
        let active = ReservationMm::new(execution.binding.mm.raw())
            .ok_or_else(|| fail("fork quarantine active MM"))?;
        let zone = retained_cow_zone(&self.ram)?;
        let installed: Vec<u64> = (0..carrick_x86::cpl0_entry::CPL0_CPU_COUNT)
            .filter_map(|slot| u8::try_from(slot).ok())
            .map(|slot| zone.installed_space(SlotId::new(slot)))
            .collect();
        let window = self.lifecycle_window();
        let inventory = Arc::clone(&self.frame_inventory);
        let memory = std::cell::RefCell::new(&mut self._vm);
        let zero = [0u8; 4096];
        self.fork_stock
            .reclaim(
                &mut NoTableLedger,
                active,
                |mm| SlotAbsence::scan(mm, installed.iter().copied()),
                |tables| {
                    let mut memory = memory.borrow_mut();
                    tables
                        .iter()
                        .all(|page| memory.write(page.address(), &zero).is_ok())
                },
                |lifecycle| window.clear(lifecycle),
                |absence| {
                    release_retired_child(&mut memory.borrow_mut(), &*inventory, absence).is_ok()
                },
            )
            .map(|_| ())
            .map_err(|e| fail(format!("fork quarantine reclaim: {e:?}")))
    }

    /// A fork child left the shared owner graph: quarantine its stock. The
    /// record must name this stopped CPU's live binding and child root. A
    /// refusal is a typed reply in the record (the guest fails only that
    /// process's stock return); only an unreadable record stops the carrier.
    pub(super) fn service_child_retire(
        &mut self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<(), TrapError> {
        let execution = self.physical_execution(lease)?;
        // SAFETY: the retire record consists of eight fully initialized u64s.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<carrick_el1_abi::NativeChildRetire>(
                lease,
                execution.context,
                lease.vcpu.get_gpr(X86Reg::Rax)?,
            )
        }?;
        // Refusal is recorded in the reply word and counted by the stock.
        let _ = self.fork_stock.retire_child(execution, &mut record);
        // SAFETY: the record is a fully initialized array of eight u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<carrick_el1_abi::NativeChildRetire>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))
    }

    /// Counters of the shared fork stock (loans, counted refusals, returns).
    pub(super) fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.fork_stock.counters()
    }

    pub(super) fn service_fork_stock(
        &mut self,
        lease: &StoppedCpuLease<'_>,
    ) -> Result<(), TrapError> {
        use carrick_el1_abi::{ForkStockExchange, ForkStockRefusal};
        let execution = self.physical_execution(lease)?;
        self.drain_fork_quarantine(execution)?;
        let address = lease.vcpu.get_gpr(X86Reg::Rax)?;
        let (_, tag) = unsafe { self.read_stack_record::<u64>(lease, execution.context, address) }?;
        match carrick_el1_abi::ForkStockKind::decode(tag) {
            Some(carrick_el1_abi::ForkStockKind::Loan) => {}
            Some(
                carrick_el1_abi::ForkStockKind::Commit | carrick_el1_abi::ForkStockKind::Abort,
            ) => {
                return self.settle_fork_stock(lease, execution, address);
            }
            None => return Err(fail("physical fork stock unknown record tag")),
        }
        let physical =
            self.stack_record_physical::<ForkStockExchange>(lease, execution.context, address)?;
        let bytes = self
            ._vm
            .read(physical, size_of::<ForkStockExchange>())
            .map_err(|error| fail(error.to_string()))?;
        let mut record = std::mem::MaybeUninit::<ForkStockExchange>::uninit();
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
        if record.request().is_none() {
            return Err(fail("physical fork stock malformed request"));
        }
        // Lifecycle stock is cold zero storage until the guest initializes
        // its typed census; a dirty record is a custody fault, not capacity.
        let window = self.lifecycle_window();
        let fresh = std::cell::Cell::new(true);
        let result =
            self.fork_stock
                .loan(&mut NoTableLedger, execution, &mut record, |lifecycle| {
                    fresh.set(window.is_zero(lifecycle));
                    fresh.get()
                });
        if result == Err(ForkStockRefusal::Inventory) && !fresh.get() {
            return Err(fail("physical fork lifecycle stock is not fresh"));
        }
        // SAFETY: expose only initialized u64 fields/padding in the copied ABI
        // record. The stopped CPU exclusively owns these validated stack bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ForkStockExchange>(),
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
        use carrick_el1_abi::{ForkStockSettlement, PortalForkCustody};
        let loan = self
            .fork_stock
            .settlement_loan(execution)
            .map_err(|e| fail(format!("physical fork settlement: {e:?}")))?;
        let (physical, mut record) = unsafe {
            self.read_stack_record::<ForkStockSettlement>(lease, execution.context, address)
        }?;
        // An early abort licenses only untouched cold table stock, which the
        // shared settlement proves zero; a restored descriptor tree would
        // need its own exact guest receipt. A commit first attaches the
        // child's inherited frames and residency.
        if !record.abort_matches(loan) {
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
            let wire = self.read_kernel_pod_bytes(execution.context, custody, len, 8)?;
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
                    .select_inherited_frames(execution.context, selected, &*self.frame_inventory)
                    .map_err(|e| fail(e.to_string()))?;
                for edge in selected_edges {
                    if !spans.insert(edge.span().va) {
                        return Err(fail("physical fork duplicate inherited page"));
                    }
                    edges.push(edge);
                }
            }
            let parent_inventory = self.frame_inventory.bind(execution.context.mm);
            let child_inventory = self.frame_inventory.bind(child.mm);
            let mut rows = std::collections::BTreeMap::new();
            for edge in &edges {
                let identity = edge.identity();
                let mapping = MappingId::from_kernel_allocation(identity.mapping_id);
                let row = parent_inventory
                    .live_mapping_row(mapping)
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
            let mut reservation = child_inventory
                .reserve(0, rows.len(), capacity.get())
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
            let receipt = child_inventory
                .apply_with_receipt(reservation.commit(()))
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
                    .attach_inherited_frame(child, edge, identity, &receipt, &*self.frame_inventory)
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
        }
        let window = self.lifecycle_window();
        let memory = &self._vm;
        self.fork_stock
            .settle(
                &mut NoTableLedger,
                execution,
                &mut record,
                |pages| tables_resolve(memory, pages),
                |pages| tables_are_zero(memory, pages),
                |lifecycle| window.clear(lifecycle),
            )
            .map_err(|e: ForkStockServiceError| fail(format!("physical fork settlement: {e:?}")))?;
        // SAFETY: settlement is a fully initialized array of sixteen u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ForkStockSettlement>(),
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
        let wake = HostCowWake::new(&self.ram, Arc::clone(&self._vm.vm().vm))?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        let pause = CowPause::new(
            SpaceAccess::notified(SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &delivery,
                ),
            }),
            mm.get(),
        )?;
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
            [gpa],
            0,
            size,
            NonZeroU64::MIN,
            MmGeneration::new(mm),
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
        wake.finish()
    }

    fn settle_cow_grant(
        &mut self,
        index: usize,
        execution: GrantExecution,
    ) -> Result<(), TrapError> {
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&self.ram, Arc::clone(&self._vm.vm().vm))?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        let pause = CowPause::new(
            SpaceAccess::notified(SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &delivery,
                ),
            }),
            execution.context.mm.raw().get(),
        )?;
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
            .completions(pause.proof())
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
        if !self.cow_pool()?.finish(pause.proof(), &pending.grant) {
            return Err(fail("owner COW completion changed after settlement"));
        }
        let _retained = pending.handle;
        drop(pause);
        wake.finish()
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
                .ok_or_else(|| {
                    let linked = match receipt.outcome {
                        carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(applied) => Some(applied.tables_linked),
                        _ => None,
                    };
                    fail(format!("owner grant refused: {:?}; cpu={} mm={} root={:#x} window_va={:#x} window_len={:#x} offered_tables={} receipt_tables_linked={linked:?}", receipt.outcome, execution.cpu.raw(), execution.context.mm.raw(), execution.context.root.address().raw(), pending.window.range.start(), pending.window.range.len(), pending.txn.tables.len()))
                })?;
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
                    inventory: &*self.frame_inventory,
                    binding: pending.execution.binding,
                    cpu: pending.execution.cpu,
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
            let used = publication.tables_linked as usize;
            if pending.txn.tables.len() != pending.tables.len() || used > pending.tables.len() {
                return Err(fail("owner grant table receipt"));
            }
            self.prepare_table_stock
                .as_mut()
                .ok_or_else(|| fail("Prepare table stock absent at settlement"))?
                .return_unused(pending.tables, used)?;
            // Retained stage-2 custody now belongs to the live guest graph.
            let _retained = pending.handle;
            return Ok(());
        }
        // Hardware faults and kernel-owned user copies share this crossing.
        // Its selected address is explicit; CR2 may name an unrelated fault.
        let far = lease.vcpu.get_gpr(X86Reg::Rdi)?;
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
        if self.prepare_table_stock.is_none() {
            return Err(fail("Prepare table stock absent"));
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
            [gpa],
            0,
            len,
            // A newly allocated physical mapping starts at generation one;
            // the guest operation sequence belongs to the descriptor txn.
            NonZeroU64::MIN,
            MmGeneration::new(mm),
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
        let tables: Vec<_> = self
            .prepare_table_stock
            .as_ref()
            .ok_or_else(|| fail("Prepare table stock absent"))?
            .candidates()
            .iter()
            .take(carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS)
            .map(|table| SubstrateGpa(table.address().raw()))
            .collect();
        let mut txn = WireTxn {
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
        let demand = (|| -> Result<usize, TrapError> {
            let zone = retained_cow_zone(&self.ram)?;
            let wake = HostCowWake::new(&self.ram, Arc::clone(&self._vm.vm().vm))?;
            let delivery = |zone: &X86Cpl0Zone,
                            waker: Waker,
                            owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >| wake.deliver(zone, waker, owned);
            let pause = CowPause::new(
                SpaceAccess::notified(SpaceReleaseVenue {
                    zone,
                    waker: Waker::Host,
                    deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                        &delivery,
                    ),
                }),
                mm.get(),
            )?;
            let planned = X86Mmu::project_grant(root.address().raw(), &txn, |native| {
                self._vm.admit_guest_edit(native).map_err(|error| fail(error.to_string()))?;
                carrick_mmu_core::x86::descriptor_txn::plan_descriptor_txn(&self._vm.words(), native, root)
                    .map(|plan| plan.tables_linked)
                    .map_err(|error| fail(format!("owner grant physical table plan refused: {error:?}; cpu={} mm={} root={:#x} window_va={:#x} window_len={:#x} available_tables={}", execution.cpu.raw(), mm, root.address().raw(), window.range.start(), len, tables.len())))
            }).map_err(|error| fail(format!("owner grant table plan projection: {error:?}")));
            drop(pause);
            wake.finish()?;
            planned?
        })();
        let required = match demand {
            Ok(required) => required,
            Err(error) => {
                // Neither the read-only planner nor the release venue made
                // this fresh backing guest-visible.
                unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                    .map_err(|error| fail(error.to_string()))?;
                return Err(error);
            }
        };
        let owned_tables = match self
            .prepare_table_stock
            .as_mut()
            .and_then(|stock| stock.loan(required))
        {
            Some(owned) => owned,
            None => {
                unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                    .map_err(|error| fail(error.to_string()))?;
                return Err(fail(format!(
                    "owner grant physical table credit exhausted: cpu={} mm={} required={required} available={}",
                    execution.cpu.raw(),
                    mm,
                    self.prepare_table_stock
                        .as_ref()
                        .map_or(0, |stock| stock.candidates().len())
                )));
            }
        };
        txn.tables = TableGrants::new(&tables[..required])
            .ok_or_else(|| fail("owner exact table credit encoding"))?;
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
            self.prepare_table_stock
                .as_mut()
                .ok_or_else(|| fail("Prepare stock absent on rollback"))?
                .return_unused(owned_tables, 0)?;
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
    fn kernel_pod_transport_authenticates_declared_bootstrap_allocator_aperture() {
        use carrick_guest_arch::KernelVa;
        let storage = retained_kernel_pod_storage(&[]);
        let start = X86_CPL0_BOOTSTRAP_METADATA_BASE;
        assert_eq!(
            kernel_pod_physical(&storage, KernelVa::new(start + 0xff8), 64, 8),
            Some(FrameGpa::new(ALLOCATOR_GPA + 0xff8))
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(start - 8), 64, 8).is_none());
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(start + EL1_BOOTSTRAP_METADATA_SIZE - 32),
                64,
                8
            )
            .is_none()
        );
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_HEAP_OFFSET),
                64,
                8
            )
            .is_none()
        );
    }

    #[test]
    fn kernel_pod_transport_uses_exact_writable_elf_storage_not_virtual_alias_shape() {
        use carrick_guest_arch::KernelVa;
        use carrick_mem::elf::{LoadSegment, SegmentPerms};
        let segment = LoadSegment {
            file_offset: 0,
            virtual_address: IMAGE_VA + 0x70000,
            file_size: 0,
            memory_size: 0x3000,
            alignment: 4096,
            perms: SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
        };
        let writable = KernelPodStorage::from_load(&segment).unwrap();
        let storage = [writable];
        let address = KernelVa::new(segment.virtual_address + 0xff8);
        assert_eq!(
            kernel_pod_physical(&storage, address, 64, 8),
            Some(FrameGpa::new(IMAGE_GPA + 0x70ff8))
        );
        assert!(
            kernel_pod_physical(&storage, KernelVa::new(segment.virtual_address - 8), 64, 8)
                .is_none()
        );
        assert!(
            kernel_pod_physical(
                &storage,
                KernelVa::new(segment.virtual_address + 0x2fe0),
                64,
                8
            )
            .is_none()
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(address.raw() + 1), 64, 8).is_none());
        assert!(
            kernel_pod_physical(&storage, KernelVa::new(DIRECT_VA + 0x900000), 64, 8).is_none()
        );
        assert!(kernel_pod_physical(&storage, KernelVa::new(u64::MAX - 7), 64, 8).is_none());
        assert!(
            KernelPodStorage::from_load(&LoadSegment {
                perms: SegmentPerms {
                    read: true,
                    write: true,
                    execute: true
                },
                ..segment
            })
            .is_none()
        );
        assert!(
            KernelPodStorage::from_load(&LoadSegment {
                perms: SegmentPerms {
                    read: true,
                    write: false,
                    execute: false
                },
                ..segment
            })
            .is_none()
        );
    }

    #[test]
    fn production_physical_ports_do_not_alias_native_or_fixture_doorbells() {
        for (index, port) in CPL0_CARRIER_PORTS.iter().enumerate() {
            assert!(
                !CPL0_CARRIER_PORTS[..index].contains(port),
                "CPL0 carrier port {port:#x} is decoded twice"
            );
        }
        // The bhyve-only FP-stub doorbell shares its number with the
        // initial-boot port, which this carrier decodes exactly once.
        assert_eq!(
            carrick_x86::FP_STUB_DOORBELL_PORT,
            carrick_el1_abi::X86_INITIAL_BOOT_PORT
        );
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
    fn prepare_working_stock_is_independent_owned_zero_suffix() {
        let working = prepare_table_working_bytes().unwrap();
        assert_eq!(working, 2 * 6 * 4096);
        let span = prepare_table_suffix(0x20000, 0x10000).unwrap();
        assert_eq!(
            span.start().raw(),
            INITIAL_EXTENT_GPA + 0x20000 - working as u64
        );
        assert_eq!(span.end().raw(), INITIAL_EXTENT_GPA + 0x20000);
        assert_eq!(span.page_count(), 12);
        assert!(prepare_table_suffix(0x20000, 0x20000 - working + 4096).is_none());
        assert!(prepare_table_suffix(0x20001, 0x10000).is_none());
        assert!(prepare_table_suffix(working - 4096, 0).is_none());
        let mut bytes = vec![0; working];
        let mut stock = PrepareTableStock::seed(span, &bytes).unwrap();
        let first = stock.loan(6).unwrap();
        let second = stock.loan(6).unwrap();
        assert!(stock.loan(1).is_none());
        assert!(first.pages.iter().all(|page| !second.pages.contains(page)));
        stock.return_unused(first, 0).unwrap();
        stock.return_unused(second, 2).unwrap();
        assert_eq!(stock.candidates().len(), 10);
        bytes[4096] = 1;
        assert!(PrepareTableStock::seed(span, &bytes).is_none());
        assert!(PrepareTableStock::seed(span, &bytes[..working - 1]).is_none());
    }
    #[test]
    fn owner_grants_reserve_disjoint_table_stock_before_receipt() {
        let mut stock: Vec<_> = (1..=8)
            .map(|n| RootGpa::page_aligned(FrameGpa::new(n * 4096)).unwrap())
            .collect();
        let first = reserve_table_stock(&mut stock, 3).unwrap();
        let second = reserve_table_stock(&mut stock, 3).unwrap();
        assert!(
            !second.is_empty(),
            "the second MM must own pending table credits"
        );
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert_eq!(stock.len(), 2);
        assert!(first.iter().all(|frame| !second.contains(frame)));
    }
    #[test]
    fn owner_table_loans_use_shared_exact_root_plan_before_either_receipt() {
        use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;
        use carrick_mmu_core::x86::descriptor_txn::{DescriptorRefusal, plan_descriptor_txn};
        struct ReadOnlyWords(std::collections::BTreeMap<u64, u64>);
        impl LiveDescriptorWords for ReadOnlyWords {
            fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
                self.0
                    .get(&pa)
                    .copied()
                    .ok_or(DescriptorRefusal::MissingTable)
            }
            fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
                panic!("physical table query must not write")
            }
            fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
                panic!("physical table query must not write")
            }
            fn publish_barrier(&self) {
                panic!("physical table query must not publish")
            }
            fn invalidate_range(&self, _: u64, _: u64) {
                panic!("physical table query must not invalidate")
            }
        }
        let page = |pa| RootGpa::page_aligned(FrameGpa::new(pa)).unwrap();
        let mut words = ReadOnlyWords((0x1000..0xa000).step_by(8).map(|pa| (pa, 0)).collect());
        // Both live roots already have a private PDPT, so each selected
        // 64-KiB window requires only a PD and a PT.
        words.0.insert(0x1000, 0x2000 | 7);
        words.0.insert(0x3000, 0x4000 | 7);
        let range = carrick_el1_abi::ReservationRange::new(0x4000_0000, 0x4001_0000).unwrap();
        let backing = carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
            frame_id: NonZeroU64::MIN,
            mapping_id: NonZeroU64::MIN,
            owner_generation: NonZeroU64::MIN,
            inventory_revision: NonZeroU64::MIN,
        };
        let mut stock = (0x5000..0xa000).step_by(4096).map(page).collect::<Vec<_>>();
        let mut loans = Vec::new();
        for (mm, root) in [(302, page(0x1000)), (304, page(0x3000))] {
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: NonZeroU64::new(mm).unwrap(),
                    generation: NonZeroU64::MIN,
                },
                root,
                op: DescriptorOp::Prepare {
                    span: PageSpan::new(range.start(), range.len()),
                    output: FrameGpa::new(0x100000),
                    permissions: Permissions {
                        writable: true,
                        executable: false,
                        user: true,
                    },
                    resident: PageSpan::new(range.start(), 4096),
                    backing,
                },
                tables: &stock,
            };
            let plan = plan_descriptor_txn(&words, &txn, root).unwrap();
            assert_eq!(plan.tables_linked, 2);
            assert!(plan.words_read <= stock.len() * 512 + 16 * 4 + 8);
            assert!(matches!(
                plan_descriptor_txn(&words, &txn, page(0x9000)),
                Err(DescriptorRefusal::StaleRoot)
            ));
            let loan = reserve_table_stock(&mut stock, plan.tables_linked).unwrap();
            assert_eq!(loan.len(), plan.tables_linked);
            loans.push(loan);
        }
        assert_eq!(stock.len(), 1);
        assert!(loans[0].iter().all(|page| !loans[1].contains(page)));
        let invalid = [page(0xa000)];
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(302).unwrap(),
                generation: NonZeroU64::MIN,
            },
            root: page(0x1000),
            op: DescriptorOp::Unmap(PageSpan::new(range.start(), 4096)),
            tables: &invalid,
        };
        assert!(matches!(
            plan_descriptor_txn(&words, &txn, txn.root),
            Err(DescriptorRefusal::MissingTable)
        ));
        words.0.insert(0x9000, 1);
        let dirty = [page(0x9000)];
        let dirty_txn = DescriptorTxn {
            tables: &dirty,
            ..txn
        };
        assert!(matches!(
            plan_descriptor_txn(&words, &dirty_txn, dirty_txn.root),
            Err(DescriptorRefusal::BadTableGrant)
        ));
    }
    #[test]
    fn owner_table_credits_refuse_without_partial_loans() {
        let page = |n: u64| RootGpa::page_aligned(FrameGpa::new(n * 4096)).unwrap();
        let mut stock = (1..=2).map(page).collect::<Vec<_>>();
        let before = stock.clone();
        assert!(reserve_table_stock(&mut stock, 3).is_none());
        assert_eq!(stock, before);
        let mut stock = (1..=16).map(page).collect::<Vec<_>>();
        let before = stock.clone();
        assert!(
            reserve_table_stock(
                &mut stock,
                carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS + 1
            )
            .is_none()
        );
        assert_eq!(stock, before);
        assert!(reserve_table_stock(&mut stock, 0).unwrap().is_empty());
        assert_eq!(stock, before);
    }
    #[test]
    fn fork_physical_stock_requires_exact_disjoint_contiguous_capacity() {
        use carrick_hal::fork_stock::take_fork_table_stock;
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
    fn cow_physical_pause_releases_admitted_gate_through_owned_venue() {
        let layout = std::alloc::Layout::new::<X86Cpl0Zone>();
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        let zone = unsafe { Box::from_raw(pointer.cast::<X86Cpl0Zone>()) };
        let index = zone.spaces.publish_closed(302, 0x7000, 0x7000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(302).unwrap()).unwrap();
        entry
            .admit_notifications(
                NonZeroU64::MIN,
                &carrick_sched_core::BoundedSpin(0),
                &|owned| {
                    let _ = owned.deliver_handbacks(&mut |_| panic!("no enrolled waiters"));
                },
            )
            .unwrap();
        let calls = std::cell::Cell::new(0);
        let delivery = |_: &X86Cpl0Zone,
                        _: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            let _ = owned.deliver_handbacks(&mut |_| panic!("no enrolled waiters"));
            calls.set(calls.get() + 1);
        };
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        });
        access.open(index);
        let before = calls.get();
        let pause = CowPause::new(access, 302).unwrap();
        assert_eq!(zone.spaces.gate(index), 1);
        drop(pause);
        assert_eq!(zone.spaces.gate(index), 0);
        assert_eq!(calls.get(), before + 1);
        let editor = access.try_begin_edit(index, 302, NonZeroU64::MIN).unwrap();
        assert!(CowPause::new(access, 302).is_err());
        assert_eq!(zone.spaces.gate(index), 0);
        drop(editor);
    }
    #[test]
    fn cow_physical_exclusion_refuses_live_editor_and_reopens_after_settlement() {
        let pointer = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<X86Cpl0Zone>()) };
        assert!(!pointer.is_null());
        let zone = unsafe { Box::from_raw(pointer.cast::<X86Cpl0Zone>()) };
        let spaces = &zone.spaces;
        let delivery = |_: &X86Cpl0Zone,
                        _: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            let _ = owned.deliver_handbacks(&mut |_| panic!("no waiters"));
        };
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        });
        let index = spaces.publish_closed(302, 0x7000, 0x7000).unwrap();
        spaces.open(index);
        let editor = spaces.try_begin_edit(index, 302, NonZeroU64::MIN).unwrap();
        assert!(CowPause::new(access, 302).is_err());
        drop(editor);
        let pause = CowPause::new(access, 302).unwrap();
        assert_eq!(pause.proof().key(), 302);
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
