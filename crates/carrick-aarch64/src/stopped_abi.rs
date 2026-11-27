//! Host readers of a stopped AArch64 CPU's EL1 ABI records: its current
//! task, the zone tables and the wire records on its EL1 stack. Every
//! AArch64 carrier (HVF, soft) authenticates a stopped lane's crossing
//! through these, never through a carrier-private copy.

/// Raw view of the retained kernel ABI mapping. It carries no shared byte
/// slice: a wire reply mutates its stopped CPU's stack while other CPUs may
/// use disjoint atomic ABI records in the same mapping.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct RetainedAbiRegion<'a> {
    base: core::ptr::NonNull<u8>,
    _retained: core::marker::PhantomData<&'a core::cell::UnsafeCell<u8>>,
}
impl<'a> RetainedAbiRegion<'a> {
    /// # Safety
    /// The caller retains an initialized EL1 mapping of `len` bytes through
    /// `'a`. Only the synchronously stopped CPU may access its wire stack;
    /// shared fixed records use their ABI atomics and ownership protocol.
    pub unsafe fn new(base: *mut u8, len: usize) -> Option<Self> {
        let base = core::ptr::NonNull::new(base)?;
        if len != carrick_el1_abi::EL1_REGION_SIZE as usize {
            return None;
        }
        Some(Self {
            base,
            _retained: core::marker::PhantomData,
        })
    }
    pub fn record_ptr<T>(self, offset: usize) -> Option<*mut T> {
        if offset.checked_add(core::mem::size_of::<T>())?
            > carrick_el1_abi::EL1_REGION_SIZE as usize
        {
            return None;
        }
        // SAFETY: checked offset remains inside the retained mapping.
        let pointer = unsafe { self.base.as_ptr().add(offset) };
        pointer
            .addr()
            .is_multiple_of(core::mem::align_of::<T>())
            .then_some(pointer.cast())
    }
}

/// Read only a complete aligned terminal record on the stopped CPU's ABI stack.
pub fn root_stack_record<'a>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<&'a carrick_core_abi::NativeRootExit> {
    let pointer = abi_stack_ptr::<carrick_core_abi::NativeRootExit>(region, cpu, address)?;
    // SAFETY: complete aligned immutable record on a retained stopped stack.
    Some(unsafe { &*pointer })
}

/// Read a complete aligned immutable record on the stopped CPU's ABI stack.
pub fn abi_stack_record<'a, T>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<&'a T> {
    let pointer = abi_stack_ptr::<T>(region, cpu, address)?;
    // SAFETY: complete aligned immutable record retained on the stopped CPU stack.
    Some(unsafe { &*pointer })
}

/// Resolve only this CPU's complete aligned kernel-stack record. The address
/// type cannot be passed to the physical table-frame resolver.
pub fn abi_stack_ptr<T>(
    region: RetainedAbiRegion<'_>,
    cpu: carrick_guest_arch::CpuId,
    address: carrick_guest_arch::KernelVa,
) -> Option<*mut T> {
    if cpu.raw() >= carrick_el1_abi::EL1_STACK_SLOTS as u32 {
        return None;
    }
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let start = carrick_el1_abi::stack_slot_usable_base(slot.raw() as usize);
    let top = carrick_el1_abi::stack_slot_top(slot.raw() as usize);
    let end = address
        .raw()
        .checked_add(core::mem::size_of::<T>() as u64)?;
    if address.raw() < start
        || end > top
        || !address
            .raw()
            .is_multiple_of(core::mem::align_of::<T>() as u64)
    {
        return None;
    }
    region.record_ptr::<T>(
        usize::try_from(
            address
                .raw()
                .checked_sub(carrick_el1_abi::EL1_REGION_BASE)?,
        )
        .ok()?,
    )
}

/// Authenticate the execution a stopped CPU's lane runs under `ttbr0`.
pub fn stopped_execution(
    region: RetainedAbiRegion<'_>,
    cpu: carrick_guest_arch::CpuId,
    ttbr0: u64,
) -> Option<carrick_hal::fork_stock::GrantExecution> {
    let (task, zone) = stopped_records(region, cpu)?;
    root_execution(cpu, task, zone, ttbr0)
}

/// The stopped CPU's current-task record and the carrier's zone tables.
pub fn stopped_records<'a>(
    region: RetainedAbiRegion<'a>,
    cpu: carrick_guest_arch::CpuId,
) -> Option<(
    &'a carrick_el1_abi::CurrentTask,
    &'a carrick_el1_abi::ZoneTables,
)> {
    let slot = carrick_guest_arch::SlotId::from_index(cpu.raw() as usize)?;
    let task_offset = carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
        + usize::from(slot.raw()) * core::mem::size_of::<carrick_el1_abi::CurrentTask>();
    let task = region.record_ptr::<carrick_el1_abi::CurrentTask>(task_offset)?;
    let zone = region
        .record_ptr::<carrick_el1_abi::ZoneTables>(carrick_el1_abi::EL1_ZONE_OFFSET as usize)?;
    // SAFETY: initialized disjoint fixed ABI records; mutation uses their atomics.
    Some(unsafe { (&*task, &*zone) })
}

/// The lane's issued execution, if `ttbr0` is its installed MM's live root.
pub fn root_execution(
    cpu: carrick_guest_arch::CpuId,
    task: &carrick_el1_abi::CurrentTask,
    zone: &carrick_el1_abi::ZoneTables,
    ttbr0: u64,
) -> Option<carrick_hal::fork_stock::GrantExecution> {
    carrick_hal::fork_stock::GrantExecution::from_stopped_lane(
        cpu,
        carrick_core::entry::binding(&task.execution, &task.mm),
        task.root_generation(),
        zone,
        carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(
            ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK,
        ))?,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use core::sync::atomic::Ordering;

    /// A stopped root's terminal record authenticates only on its own CPU's
    /// stack, under its installed MM's live root, for an issued execution,
    /// and names exactly the status the ring wrote.
    #[test]
    fn root_exit_authenticates_only_the_stopped_lane_that_wrote_it() {
        let mut storage = carrick_test_support::TestEl1Region::zeroed();
        let ptr = storage.as_mut_ptr();
        // SAFETY: aligned retained zeroed ABI storage; all zone fields accept zero.
        let zone = unsafe {
            &*ptr
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        let cpu = carrick_guest_arch::CpuId::new(3);
        let slot = carrick_guest_arch::SlotId::new(3);
        let ttbr = (4 << 48) | 0x90000;
        let space = zone.spaces.publish_closed(5, ttbr, ttbr).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 5, &carrick_sched_core::OwedPasses::new());
        zone.publish_slot(slot, 5, Some(3), 1, &carrick_sched_core::OwedPasses::new());
        zone.enter_guest(slot);
        zone.install_space(slot, 5).unwrap();
        let task_offset = carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
            + 3 * core::mem::size_of::<carrick_el1_abi::CurrentTask>();
        // SAFETY: the zeroed current-task record of slot 3 in the region.
        let task = unsafe { &*ptr.add(task_offset).cast::<carrick_el1_abi::CurrentTask>() };
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            1,
        );
        task.mm.key.store(5, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        // SAFETY: the test owns the whole region for its lifetime.
        let region = unsafe {
            RetainedAbiRegion::new(ptr, carrick_el1_abi::EL1_REGION_SIZE as usize).unwrap()
        };
        assert!(
            stopped_execution(region, cpu, ttbr).is_none(),
            "no root incarnation is published yet"
        );
        task.publish_root_generation(carrick_guest_arch::ContextGeneration::new(
            core::num::NonZeroU64::new(77).unwrap(),
        ));
        let execution = stopped_execution(region, cpu, ttbr).unwrap();
        assert_eq!(execution.binding.generation.raw(), 11);
        assert_eq!(execution.context.generation.raw().get(), 77);
        assert_eq!(execution.context.root.address().raw(), 0x90000);

        let address = carrick_guest_arch::KernelVa::new(carrick_el1_abi::stack_slot_usable_base(3));
        let offset = (address.raw() - carrick_el1_abi::EL1_REGION_BASE) as usize;
        // SAFETY: an aligned record on slot 3's stack, which this test owns.
        unsafe {
            ptr.add(offset)
                .cast::<carrick_core_abi::NativeRootExit>()
                .write(
                    carrick_core_abi::NativeRootExit::new(
                        execution.binding,
                        carrick_sched_core::process::TerminationStatus::exited(7),
                    )
                    .unwrap(),
                );
        }
        let record = root_stack_record(region, cpu, address).unwrap();
        assert_eq!(
            record.status_for(execution.binding),
            Some(carrick_sched_core::process::TerminationStatus::exited(7))
        );
        assert!(
            root_stack_record(region, carrick_guest_arch::CpuId::new(2), address).is_none(),
            "another CPU's stack never names this record"
        );
        assert!(
            root_stack_record(
                region,
                cpu,
                carrick_guest_arch::KernelVa::new(address.raw() + 4)
            )
            .is_none(),
            "a misaligned record is refused"
        );
        assert!(stopped_execution(region, cpu, ttbr + 4096).is_none());
        assert!(stopped_execution(region, carrick_guest_arch::CpuId::new(2), ttbr).is_none());
        task.execution.generation.store(
            carrick_el1_abi::SnapshotGeneration::UNISSUED,
            Ordering::Release,
        );
        assert!(stopped_execution(region, cpu, ttbr).is_none());
    }
}
