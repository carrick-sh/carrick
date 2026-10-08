// Guest-owned process MM custody for the stopped KVM lifecycle fixture. The
// descriptor transaction is the shared generic fork owner; this module only
// supplies the x86 physical window and the fixture's two admitted roots.
use super::{FORK_RESIDENCY_ADDRESS, InitialWords, SHARED_COW_POOL};
use carrick_core::mm::fork::{
    ForkChildRoot, ForkError, ForkParentRoot, Mapping, MappingInheritancePolicy, Policy,
};
use carrick_el1_abi::{
    El1MmHandle, FrameGrantResidencyIdentity, FrameGrantResidencyTable, GuestMmuPublication,
    PortalForkRequest, PortalForkTableArena, PortalOperation, ReservationGeneration, ReservationMm,
    ReservationNodeFlags, ReservationProtection, ReservationRange,
};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
use carrick_mmu_core::x86::descriptor_txn::{Access, translate_leaf};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

const PARENT_MM: u64 = 77;
const CHILD_MM: u64 = 78;
const CHILD_ROOT: u64 = 0x31_0000;
const CHILD_TABLE_BYTES: u64 = 0x4_0000;
const PARENT_TABLE_BASE: u64 = CHILD_ROOT + CHILD_TABLE_BYTES;
const PARENT_TABLE_BYTES: u64 = 0x1_0000;
const STACK_BASE: u64 = 0x7ffe_c000;
const STACK_TOP: u64 = 0x7fff_0000;

static CHILD_ORIGIN: AtomicU64 = AtomicU64::new(0);
static CHILD_ADMITTED: AtomicU64 = AtomicU64::new(0);
static PARENT_PENDING: AtomicU64 = AtomicU64::new(0);
static WAIT_OUTPUTS: carrick_el1::lock::SpinLock<Option<PreparedWaitOutputs>> =
    carrick_el1::lock::SpinLock::new(None);
static CHILD_EXIT: super::super::lifecycle::ChildExitRecord =
    super::super::lifecycle::ChildExitRecord::new(carrick_core_abi::EntryMmKey::from_raw(PARENT_MM));
static FORK_PUBLICATION: carrick_el1::lock::SpinLock<Option<GuestMmuPublication>> =
    carrick_el1::lock::SpinLock::new(None);

struct LinuxPolicy;
impl MappingInheritancePolicy for LinuxPolicy {
    fn inheritance_policy(&self, mapping: &Mapping) -> Policy {
        if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
            Policy::Omit
        } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
            Policy::Wipe
        } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
            Policy::Private
        } else {
            Policy::Keep
        }
    }
    fn is_shared(&self, mapping: &Mapping) -> bool {
        !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
    }
}

struct Parent;
struct Child;
impl ForkParentRoot<Child> for Parent {
    fn incarnation(&self) -> u64 { 1 }
    fn generation(&self) -> ReservationGeneration {
        ReservationGeneration::INITIAL
    }
    fn operation_sequence(&self) -> u64 { 1 }
    fn fork_ready(&mut self) -> bool { PARENT_PENDING.load(Ordering::Acquire) == 0 }
    fn fork_write_authorized(&mut self, sequence: Option<NonZeroU64>) -> bool {
        sequence.is_some_and(|value| PARENT_PENDING.load(Ordering::Acquire) == value.get())
    }
    fn reserve_fork_certificate(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        PARENT_PENDING.compare_exchange(0, request.operation.sequence.get(), Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ForkError::Busy)
    }
    fn clone_into(&mut self, _: &mut Child) -> Result<(), ForkError> {
        // The fixture's complete VMA census is the two static load regions
        // supplied to ForkScratch. No other reservation can be inherited.
        Ok(())
    }
    fn publish_fork_parent(&mut self, _: PortalForkRequest) -> Result<ReservationGeneration, ForkError> {
        Ok(self.generation())
    }
    fn finish_fork_publication(&mut self, operation: PortalOperation) -> Result<(), ForkError> {
        PARENT_PENDING.compare_exchange(operation.sequence.get(), 0, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ForkError::Stale)
    }
    fn commit_fork_generation(&mut self) -> Result<ReservationGeneration, ForkError> {
        ReservationGeneration::new(2).ok_or(ForkError::Stale)
    }
}
impl ForkChildRoot for Child {
    fn incarnation(&self) -> u64 { 1 }
    fn is_admitted(&self) -> bool { CHILD_ADMITTED.load(Ordering::Acquire) != 0 }
    fn fork_write_authorized(&mut self, sequence: Option<NonZeroU64>) -> bool {
        sequence.is_some_and(|value| CHILD_ORIGIN.load(Ordering::Acquire) == value.get())
    }
    fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool {
        CHILD_ORIGIN.load(Ordering::Acquire) == request.operation.sequence.get()
    }
    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        CHILD_ORIGIN.compare_exchange(0, request.operation.sequence.get(), Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ForkError::Busy)
    }
    fn clear_fork_origin(&mut self) { CHILD_ORIGIN.store(0, Ordering::Release); }
    fn publish_fork_child(&mut self, _: PortalForkRequest) -> Result<(), ForkError> {
        CHILD_ADMITTED.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ForkError::Busy)
    }
    fn finish_fork_publication(&mut self, _: PortalOperation) -> Result<(), ForkError> { Ok(()) }
    fn retire(self) -> Result<(), ForkError> {
        CHILD_ADMITTED.store(0, Ordering::Release);
        CHILD_ORIGIN.store(0, Ordering::Release);
        Ok(())
    }
}

fn mapping(start: u64, end: u64, protection: ReservationProtection) -> Option<Mapping> {
    Some(Mapping {
        range: ReservationRange::new(start, end)?,
        protection,
        anonymous: true,
        flags: ReservationNodeFlags::ANONYMOUS_PRIVATE,
        generation: ReservationGeneration::new(1)?,
        host_backing: None,
    })
}

pub(crate) fn process_mode() -> bool {
    FORK_RESIDENCY_ADDRESS.load(Ordering::Acquire) != 0
}

pub(crate) fn residency() -> Option<&'static FrameGrantResidencyTable> {
    let address = FORK_RESIDENCY_ADDRESS.load(Ordering::Acquire);
    if address == 0 { return None; }
    // SAFETY: initial MM admission initialized this aligned table in retained
    // guest heap storage, then published the address with Release ordering.
    Some(unsafe { &*(address as *const FrameGrantResidencyTable) })
}

pub(super) fn admit_initial(
    binding: &super::super::adapter::CpuBinding,
    stack_pointer: u64,
    root: u64,
) -> bool {
    use carrick_sched_core::ZoneTables;
    if binding.scheduler_witness.load(Ordering::Acquire) != super::super::lifecycle::LIFECYCLE_LANE
        || process_mode() || root != 0x30_0000
    { return false; }
    let Some(slot)=super::super::adapter::checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot)) else { return false; };
    let layout = core::alloc::Layout::new::<FrameGrantResidencyTable>();
    // SAFETY: the guest allocator returns storage with the table's alignment
    // and size; ownership stays with this one stopped-carrier fixture.
    let pointer = unsafe { crate::rust_alloc::alloc::alloc(layout) };
    if pointer.is_null() { return false; }
    // SAFETY: pointer is non-null and has precisely the table's layout.
    let table = unsafe {
        let table = pointer.cast::<FrameGrantResidencyTable>();
        FrameGrantResidencyTable::init_in_place(table);
        &*table
    };
    let Some(root) = RootGpa::page_aligned(FrameGpa::new(root)) else { return false; };
    let stack_va = stack_pointer & !4095;
    let Ok(leaf) = translate_leaf(&InitialWords::fixture(), root, UserVa::new(stack_va), Access::Read, true) else { return false; };
    let identity = FrameGrantResidencyIdentity {
        mm_key: PARENT_MM,
        semantic_base: stack_va,
        physical_ipa: leaf.output.raw() & !4095,
        len: 4096,
        mapping_id: leaf.output.raw() & !4095,
        frame_id: leaf.output.raw() & !4095,
        owner_generation: 1,
        inventory_revision: 1,
    };
    if table.publish(identity).is_none() { return false; }
    let Some(page) = table.lookup(PARENT_MM, stack_va) else { return false; };
    if !table.record_commit(page) { return false; }
    // SAFETY: boot_lifecycle retains the aligned zone, task and lane at these
    // supervisor addresses until both KVM vCPUs stop.
    let (zone, task, lane) = unsafe {
        (
            &*(super::super::lifecycle::LIFECYCLE_ZONE as *const ZoneTables),
            &*(binding.task_address as *const carrick_el1_abi::CurrentTask),
            &mut *(super::super::lifecycle::LIFECYCLE_LANE as *mut super::super::lifecycle::LifecycleLane),
        )
    };
    let Some(index) = zone.spaces.publish_closed(PARENT_MM, root.address().raw(), 0) else { return false; };
    zone.spaces.open(index);
    zone.release_space(slot);
    if zone.install_space(slot, PARENT_MM).is_none() { return false; }
    lane.parent.mm = PARENT_MM;
    task.mm.key.store(PARENT_MM, Ordering::Release);
    FORK_RESIDENCY_ADDRESS.store(pointer as u64, Ordering::Release);
    true
}

pub(crate) fn fork_mm(parent_root: RootGpa) -> Option<(RootGpa, GuestMmuPublication)> {
    // The fixture grants an unused physical extent, but its KVM RAM backing
    // is not an allocation contract until CPL0 zeroes every unlinked table.
    for pa in (CHILD_ROOT..PARENT_TABLE_BASE + PARENT_TABLE_BYTES).step_by(4096) {
        super::InitialFrames::zeroed(pa);
    }
    let one = NonZeroU64::MIN;
    let request = PortalForkRequest {
        operation: PortalOperation {
            carrier: one,
            mm: ReservationMm::new(PARENT_MM)?,
            incarnation: one,
            sequence: one,
        },
        parent_generation: ReservationGeneration::new(1)?,
        child_mm: ReservationMm::new(CHILD_MM)?,
        child_tables: PortalForkTableArena::new(CHILD_ROOT, CHILD_TABLE_BYTES)?,
        parent_tables: PortalForkTableArena::new(PARENT_TABLE_BASE, PARENT_TABLE_BYTES)?,
        kernel_control_ipa: 0xa0_0000,
    };
    let mappings = [
        mapping(0x400000, 0x401000, ReservationProtection::READ)?,
        mapping(STACK_BASE, STACK_TOP, ReservationProtection::READ_WRITE)?,
    ];
    let plan = carrick_el1::isa::x86::fork_mm::prepare_owner_fork(
        &InitialWords::fixture(), request, parent_root, &mappings, &LinuxPolicy,
    ).ok()?;
    let parent_stores = plan.scratch.edits.len();
    // SAFETY: the fixture reserved the child root under the same retained
    // carrier before the guest publishes it; no host descriptor author runs.
    let handle = unsafe { El1MmHandle::from_admitted_owner(one, request.child_mm, one) };
    let mut child = plan.publish(&InitialWords::fixture(), Parent, Child, handle).ok()?;
    let completion = child.commit(Parent, Child).ok()?;
    let publication = GuestMmuPublication::from_x86_fork(
        parent_root.address().raw(), completion, parent_stores,
    ).unwrap_or_else(|| super::lifecycle_invariant_error(super::super::lifecycle::LifecycleInvariant::ForkPublication));
    *FORK_PUBLICATION.lock() = Some(publication);
    Some((child_root(), publication))
}

pub(crate) fn publish_child_stack(residency: &FrameGrantResidencyTable, parent_root: RootGpa) -> bool {
    let Ok(leaf) = translate_leaf(&InitialWords::fixture(), parent_root, UserVa::new(STACK_TOP - 4096), Access::Read, true) else { return false; };
    let old = leaf.output.raw() & !4095;
    let identity = FrameGrantResidencyIdentity {
        mm_key: CHILD_MM, semantic_base: STACK_TOP - 4096,
        physical_ipa: old, len: 4096, mapping_id: old,
        frame_id: old, owner_generation: 1, inventory_revision: 1,
    };
    if residency.publish(identity).is_none() { return false; }
    let Some(page) = residency.lookup(CHILD_MM, STACK_TOP - 4096) else { return false; };
    if !residency.record_commit(page) { return false; }
    let child_backing = carrick_mmu_core::x86::descriptor_txn::BackingIdentity {
        frame_id: NonZeroU64::new(0x41_4000).unwrap_or(NonZeroU64::MIN),
        mapping_id: NonZeroU64::new(0x41_4000).unwrap_or(NonZeroU64::MIN),
        owner_generation: NonZeroU64::MIN,
        inventory_revision: NonZeroU64::MIN,
    };
    if SHARED_COW_POOL.publish(CHILD_MM, 0x41_4000, child_backing).is_none() { return false; }
    let parent_backing = carrick_mmu_core::x86::descriptor_txn::BackingIdentity {
        frame_id: NonZeroU64::new(0x41_8000).unwrap_or(NonZeroU64::MIN),
        mapping_id: NonZeroU64::new(0x41_8000).unwrap_or(NonZeroU64::MIN),
        owner_generation: NonZeroU64::MIN,
        inventory_revision: NonZeroU64::MIN,
    };
    SHARED_COW_POOL.publish(PARENT_MM, 0x41_8000, parent_backing).is_some()
}

pub(crate) fn child_root() -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(CHILD_ROOT)).unwrap_or_else(||
        super::lifecycle_invariant_error(super::super::lifecycle::LifecycleInvariant::ForkPublication))
}
pub(crate) fn child_mm() -> u64 { CHILD_MM }
pub(crate) fn parent_mm() -> u64 { PARENT_MM }
pub(crate) fn child_pid(parent_pid: u64) -> u64 { parent_pid + 1 }
pub(crate) fn child_exit() -> &'static super::super::lifecycle::ChildExitRecord { &CHILD_EXIT }

/// One retained parent write authority for this bounded fixture. The parent
/// cannot edit or retire its private stack while parked behind this child.
struct PreparedParentOutput {
    destination: carrick_guest_arch::KernelVa,
}
pub(crate) struct PreparedWaitOutputs {
    status: Option<PreparedParentOutput>,
    rusage: Option<PreparedParentOutput>,
}
impl PreparedWaitOutputs {
    pub(crate) fn complete(self, child: super::super::lifecycle::ReapedChild) {
        if child.parent_mm().raw()!=PARENT_MM {
            super::lifecycle_invariant_error(super::super::lifecycle::LifecycleInvariant::ExitReap);
        }
        // SAFETY: both exact-parent destinations were translated and retained
        // before wait enrollment. Reap custody excludes every competing writer;
        // this fixture has no other thread able to change the parked parent MM.
        unsafe {
            if let Some(output)=self.status {
                core::ptr::write_unaligned(output.destination.raw() as *mut u32,u32::from(child.status())<<8);
            }
            if let Some(output)=self.rusage {
                core::ptr::write_bytes(output.destination.raw() as *mut u8,0,carrick_syscall_abi::LINUX_RUSAGE_BYTES);
            }
        }
    }
}
pub(crate) fn publish_wait_outputs(outputs: PreparedWaitOutputs) {
    let mut pending=WAIT_OUTPUTS.lock();
    if pending.is_some() { super::lifecycle_invariant_error(super::super::lifecycle::LifecycleInvariant::WaitPublication); }
    *pending=Some(outputs);
}
pub(crate) fn complete_published_wait_outputs(child: super::super::lifecycle::ReapedChild) {
    let outputs=WAIT_OUTPUTS.lock().take().unwrap_or_else(||
        super::lifecycle_invariant_error(super::super::lifecycle::LifecycleInvariant::ExitReap));
    outputs.complete(child);
}
pub(crate) fn prepare_wait_outputs(
    lane: &mut super::super::lifecycle::NativeLane<'_>,
    status: UserVa,
    rusage: UserVa,
) -> Option<PreparedWaitOutputs> {
    let status=if status.raw()==0 { None } else { Some(prepare_parent_output(lane,status,4)?) };
    let rusage=if rusage.raw()==0 { None } else {
        Some(prepare_parent_output(lane,rusage,carrick_syscall_abi::LINUX_RUSAGE_BYTES)?)
    };
    Some(PreparedWaitOutputs { status,rusage })
}
fn prepare_parent_output(
    lane: &mut super::super::lifecycle::NativeLane<'_>,
    address: UserVa,
    size: usize,
) -> Option<PreparedParentOutput> {
    use carrick_core::mm::transfer::resolver::NoopPreparedResolver;
    use carrick_el1::fault::{GrantMailboxes, X86CowResolver, dispatch_x86_fault_with_prepared};
    use carrick_el1_abi::Action;
    use carrick_guest_arch::{Access as FaultAccess, FaultInfo};
    if address.raw()<STACK_TOP-4096 || address.raw().checked_add(size as u64).is_none_or(|end|end>STACK_TOP)
        || lane.task.mm.key.load(Ordering::Acquire)!=PARENT_MM { return None; }
    let root=carrick_el1::isa::x86::hardware_live_root().ok()?;
    let words = InitialWords::fixture();
    if translate_leaf(&words,root,address,Access::Write,true).is_err() {
        let mut cow=X86CowResolver { words: &words, pool:&SHARED_COW_POOL,residency:residency()?,completion:None };
        let result=dispatch_x86_fault_with_prepared(
            carrick_guest_arch::CpuId::new(0),FaultInfo {address,access:FaultAccess::Write,present:true},lane.counters,lane.task,
            carrick_el1::substrate::sched::object_wait::space_access(lane.zone,lane.lane.slot),
            GrantMailboxes::own(&super::SHARED_FAULT_MAILBOX),
            None::<carrick_el1::fault::PreparedFaultPath<'_,NoopPreparedResolver>>,&mut cow,
        );
        if result!=Action::Served { return None; }
    }
    let leaf=translate_leaf(&words,root,address,Access::Write,true).ok()?;
    let destination=carrick_el1_abi::X86_CPL0_DIRECT_VA.checked_add(leaf.output.raw())?;
    Some(PreparedParentOutput { destination:carrick_guest_arch::KernelVa::new(destination) })
}
