//! Soft carrier physical memory: the [`CarrierMemoryIo`] slot table the
//! shared [`carrick_x86_cpl0_host::carrier_memory::CarrierMemory`] registers
//! into, and the [`SoftMmuMemory`] view a [`carrick_softcpu_x86::SoftMachine`]
//! translates through.
//!
//! The KVM carrier registers each retained allocation (bootstrap windows,
//! IPC backings, the kernel file region, the initial extent) as its own
//! memslot. [`SoftVm`] records the same registrations; [`SoftCarrierMemory`]
//! places each as one linear segment, so the soft CPU reads and writes the
//! very allocations `CarrierMemory` owns. Nothing is copied: the view
//! retains its own `Arc` of each backing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use carrick_hal::{OsError, TrapError};
use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, LinearPlacement, MmioHoles, OwnerGeneration, RootGpa,
    SoftMmuMemory,
};
use carrick_softmmu::{HostWriteError, MAX_PLACEMENT_SEGMENTS, PAGE_SIZE_4K, PlacementSegment};
use carrick_x86_cpl0_host::carrier_memory::{BackingExtent, CarrierMemoryIo, CarrierMemoryRegion};
use carrick_x86_cpl0_host::cpl0_boot::retained_slots::RetainedCarrierSlots;
use carrick_x86_cpl0_host::cpl0_boot::{ProductionCpuFactory, fail};

use crate::carrier::SoftCpuIo;

/// One owner generation authenticates every registered slot and root.
const BOOT_GENERATION: OwnerGeneration = OwnerGeneration::FIRST;

/// The soft carrier's slot namespace: the memory registrations a
/// `CarrierMemory<SoftVm>` makes, keyed by slot. Clones share the table.
#[derive(Clone, Default)]
pub struct SoftVm {
    slots: Arc<Mutex<SlotTable>>,
}

#[derive(Default)]
struct SlotTable {
    regions: BTreeMap<u32, CarrierMemoryRegion>,
    retained: Option<Arc<RetainedSlots>>,
    host_written: BTreeSet<FrameGpa>,
}

type RetainedSlots = BTreeMap<u32, RetainedSlot>;

struct RetainedSlot {
    region: CarrierMemoryRegion,
    backing: Arc<BackingExtent>,
}

impl RetainedSlot {
    fn same_registration(&self, other: Option<&Self>) -> bool {
        other.is_some_and(|other| {
            self.region == other.region && Arc::ptr_eq(&self.backing, &other.backing)
        })
    }
}

impl SoftVm {
    pub fn new() -> Self {
        Self::default()
    }

    fn slots(&self) -> MutexGuard<'_, SlotTable> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn publish_backings(
        memory: RetainedCarrierSlots<'_, Self>,
    ) -> Result<(), TrapError> {
        let mut slots = memory.vm().slots();
        if slots.retained.is_some() {
            return Ok(());
        }

        let backings: BTreeMap<_, _> = memory
            .backings()
            .map(|backing| (backing.base.raw(), backing))
            .collect();
        if slots.regions.len() != backings.len() {
            return Err(fail("soft slot and retained backing counts differ"));
        }
        let retained = slots
            .regions
            .iter()
            .map(|(&slot, region)| {
                let backing = backings
                    .get(&region.guest_phys_addr)
                    .filter(|backing| backing.matches_slot_region(region))
                    .ok_or_else(|| {
                        fail(format!(
                            "soft slot {:#x}+{:#x} names no retained backing",
                            region.guest_phys_addr, region.memory_size
                        ))
                    })?;
                Ok((
                    slot,
                    RetainedSlot {
                        region: *region,
                        backing: Arc::clone(backing),
                    },
                ))
            })
            .collect::<Result<_, TrapError>>()?;
        slots.retained = Some(Arc::new(retained));
        Ok(())
    }

    fn retained_slots(&self) -> Result<Arc<RetainedSlots>, TrapError> {
        self.slots()
            .retained
            .clone()
            .ok_or_else(|| fail("soft slots changed without retained backing publication"))
    }
}

/// Publish installed backings from production custody after servicing a
/// physical doorbell. A vCPU never enters the guest with unpublished slots.
pub fn publish_worker_backings(
    factory: &ProductionCpuFactory<SoftCpuIo, SoftVm>,
) -> Result<(), TrapError> {
    factory.with_retained_slots(SoftVm::publish_backings)
}

impl CarrierMemoryIo for SoftVm {
    fn carrier_slot_limit(&self) -> Result<u32, OsError> {
        u32::try_from(MAX_PLACEMENT_SEGMENTS).map_err(|_| OsError::new("soft slot limit"))
    }

    unsafe fn set_user_memory_region(&self, region: CarrierMemoryRegion) -> Result<(), OsError> {
        let mut slots = self.slots();
        if region.memory_size == 0 {
            slots.regions.remove(&region.slot);
        } else {
            slots.regions.insert(region.slot, region);
        }
        slots.retained = None;
        Ok(())
    }

    fn signal_msi(&self, _address_lo: u32, _data: u32) -> Result<(), OsError> {
        // M1 is single-vCPU (#2397): no peer exists to receive an MSI, and
        // the ApicCluster route is a later slice. Refuse rather than drop.
        Err(OsError::new(
            "soft carrier has no MSI route (single-vCPU M1)",
        ))
    }

    fn host_wrote_ram(&self, start: FrameGpa, len: usize) {
        let Some(last) = len
            .checked_sub(1)
            .and_then(|offset| start.raw().checked_add(offset as u64))
        else {
            return;
        };
        let mask = !(PAGE_SIZE_4K - 1);
        let pages = ((start.raw() & mask)..=(last & mask)).step_by(PAGE_SIZE_4K as usize);
        self.slots().host_written.extend(pages.map(FrameGpa::new));
    }
}

/// The soft CPU's view of the registered slots. Each view retains its
/// snapshot until the next stopped refresh, including when the slot table
/// changes or custody drops its own references.
pub struct SoftCarrierMemory {
    placement: LinearPlacement,
    extents: ExtentTable,
    retained: Arc<RetainedSlots>,
    vm: SoftVm,
}

impl SoftCarrierMemory {
    pub(crate) fn new(vm: &SoftVm, root: u64) -> Result<Self, TrapError> {
        let retained = vm.retained_slots()?;
        let placement = Self::placement_for(&retained)?;
        let mut extents =
            ExtentTable::new().map_err(|_| fail("soft extent table generation exhausted"))?;
        for slot in retained.values() {
            Self::install_extent(&mut extents, &slot.region)?;
        }
        let mut memory = Self {
            placement,
            extents,
            retained,
            vm: vm.clone(),
        };
        memory.admit_root(root)?;
        Ok(memory)
    }

    fn placement_for(slots: &RetainedSlots) -> Result<LinearPlacement, TrapError> {
        let segments = slots
            .values()
            .map(|slot| {
                let region = &slot.region;
                Ok(PlacementSegment::new(
                    region.guest_phys_addr,
                    region.memory_size,
                    usize::try_from(region.userspace_addr)
                        .map_err(|_| fail("soft slot host address width"))?,
                ))
            })
            .collect::<Result<Vec<_>, TrapError>>()?;
        // SAFETY: publication matches every registration to the exact
        // retained allocation (host base, GPA and length). The caller
        // stores that snapshot with the placement.
        unsafe { LinearPlacement::with_segments(&segments, MmioHoles::x86_default()) }
            .map_err(|error| fail(format!("soft placement: {error:?}")))
    }

    fn install_extent(
        extents: &mut ExtentTable,
        region: &CarrierMemoryRegion,
    ) -> Result<(), TrapError> {
        let record = ExtentRecord::new(
            FrameGpa::new(region.guest_phys_addr),
            region.memory_size,
            BOOT_GENERATION,
        );
        if extents.install(record) {
            Ok(())
        } else {
            Err(fail(format!(
                "soft extent {:#x}+{:#x} refused",
                region.guest_phys_addr, region.memory_size
            )))
        }
    }

    /// Refresh the published slot snapshot while the vCPU is stopped. Keep
    /// the same invalidation domain and frame code generations across reuse.
    pub(crate) fn refresh(&mut self) -> Result<bool, TrapError> {
        let retained = self.vm.retained_slots()?;
        if Arc::ptr_eq(&self.retained, &retained) {
            return Ok(false);
        }

        let retired = self
            .retained
            .iter()
            .filter(|(index, old)| !old.same_registration(retained.get(index)))
            .map(|(_, old)| FrameGpa::new(old.region.guest_phys_addr))
            .collect::<Vec<_>>();
        if retired.is_empty() && self.retained.len() == retained.len() {
            self.retained = retained;
            return Ok(false);
        }

        let placement = Self::placement_for(&retained)?;
        // The old snapshot keeps its backings alive during retirement. The
        // only runnable vCPU parks at the end of each step, so completion is
        // immediate and its next admission serves the invalidation debt.
        for base in retired {
            let retirement = self
                .extents
                .remove(base, None)
                .map_err(|error| fail(format!("soft slot retirement {base:?}: {error:?}")))?
                .ok_or_else(|| fail(format!("soft slot retirement missing extent {base:?}")))?;
            let completion = retirement
                .pending
                .try_complete()
                .map_err(|_| fail("soft slot retirement found a running vCPU"))?;
            self.extents.reclaim(&completion);
        }
        for (index, slot) in retained.iter() {
            if !slot.same_registration(self.retained.get(index)) {
                Self::install_extent(&mut self.extents, &slot.region)?;
            }
        }

        self.placement = placement;
        self.retained = retained;
        Ok(true)
    }

    /// Consume the writes in the only runnable (slot 0) view. A peer cannot
    /// run with an independent code inventory until the multi-vCPU work.
    pub(crate) fn invalidate_host_writes(&mut self) -> Result<(), TrapError> {
        let mut slots = self.vm.slots();
        for &page in &slots.host_written {
            match self
                .extents
                .invalidate_host_written_page(page, BOOT_GENERATION)
            {
                // Custody recorded the write while the slot existed. A
                // subsequent retirement already deactivated its code pages.
                Ok(()) | Err(HostWriteError::Owner) => {}
                Err(error) => return Err(fail(format!("soft host write {page:?}: {error:?}"))),
            }
        }
        slots.host_written.clear();
        Ok(())
    }

    /// Authenticate `root` (a page-table root inside a registered slot) for
    /// walks; an already-admitted root is accepted unchanged.
    pub fn admit_root(&mut self, root: u64) -> Result<(), TrapError> {
        let root = RootGpa::page_aligned(FrameGpa::new(root))
            .ok_or_else(|| fail("soft root alignment"))?;
        if self
            .extents
            .lookup_span(root.address().raw(), PAGE_SIZE_4K)
            .is_some_and(|extent| extent.generation == BOOT_GENERATION)
            && (self.extents.expected_generation(root) == Some(BOOT_GENERATION)
                || self.extents.set_root_generation(root, BOOT_GENERATION))
        {
            Ok(())
        } else {
            Err(fail(format!(
                "soft root {:#x} refused",
                root.address().raw()
            )))
        }
    }
}

// SAFETY: each placement points to allocations held by its retained
// snapshot. Refresh completes removals in the CPU's own invalidation domain
// before replacing the placement or releasing the previous snapshot.
unsafe impl SoftMmuMemory for SoftCarrierMemory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
}

#[cfg(test)]
mod tests {
    //! Production `SoftCarrierMemory::refresh` retirement witnesses (#2546
    //! review P0): skipping the extent removal or its reclaim in `refresh`
    //! must fail a test, not leave the suite green.
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// A page-aligned 4 KiB host page standing in for a registered backing.
    #[repr(C, align(4096))]
    struct HostPages<const N: usize>([[u8; 4096]; N]);

    const ROOT_GPA: u64 = 0x10_0000;
    const CHILD_GPA: u64 = 0x20_0000;

    fn slot<const N: usize>(
        index: u32,
        gpa: u64,
        host: &mut Box<HostPages<N>>,
        backing: &Arc<BackingExtent>,
    ) -> RetainedSlot {
        RetainedSlot {
            region: CarrierMemoryRegion {
                slot: index,
                flags: 0,
                guest_phys_addr: gpa,
                memory_size: (N * 4096) as u64,
                userspace_addr: host.0.as_mut_ptr() as u64,
            },
            backing: Arc::clone(backing),
        }
    }

    fn publish(vm: &SoftVm, slots: impl IntoIterator<Item = (u32, RetainedSlot)>) {
        vm.slots().retained = Some(Arc::new(slots.into_iter().collect()));
    }

    #[test]
    fn refresh_retires_a_slot_and_installs_a_replacement_at_the_same_gpa() {
        let vm = SoftVm::new();
        let mut root_host = Box::new(HostPages::<2>([[0; 4096]; 2]));
        let mut child_host = Box::new(HostPages::<1>([[0; 4096]; 1]));
        let mut replacement_host = Box::new(HostPages::<1>([[0; 4096]; 1]));
        let root_backing = Arc::new(
            BackingExtent::private(FrameGpa::new(ROOT_GPA), 2 * 4096).expect("root backing"),
        );
        let child_backing = Arc::new(
            BackingExtent::private(FrameGpa::new(CHILD_GPA), 4096).expect("child backing"),
        );
        let replacement_backing = Arc::new(
            BackingExtent::private(FrameGpa::new(CHILD_GPA), 4096).expect("replacement backing"),
        );
        publish(
            &vm,
            [
                (0, slot(0, ROOT_GPA, &mut root_host, &root_backing)),
                (1, slot(1, CHILD_GPA, &mut child_host, &child_backing)),
            ],
        );
        let mut memory = SoftCarrierMemory::new(&vm, ROOT_GPA).expect("soft memory");
        assert!(memory.extents().lookup_span(CHILD_GPA, 4096).is_some());
        let probe = [0x5a_u8; 8];
        memory
            .write_host_bytes(FrameGpa::new(CHILD_GPA), BOOT_GENERATION, &probe)
            .expect("the live slot accepts an authenticated write");
        assert_eq!(child_host.0[0][..8], probe);

        // Retire the child slot: the root slot stays registered unchanged.
        publish(&vm, [(0, slot(0, ROOT_GPA, &mut root_host, &root_backing))]);
        assert!(memory.refresh().expect("refresh retires the slot"));
        assert!(
            memory.extents().lookup_span(CHILD_GPA, 4096).is_none(),
            "the retired slot's extent must be removed"
        );
        assert_eq!(
            memory.extents().pending_identities(),
            0,
            "the retirement must be reclaimed in the CPU's own domain"
        );
        assert!(
            memory
                .write_host_bytes(FrameGpa::new(CHILD_GPA), BOOT_GENERATION, &probe)
                .is_err(),
            "an access to the retired GPA must fault"
        );
        assert!(
            memory.extents().lookup_span(ROOT_GPA, 4096).is_some(),
            "an unrelated slot survives the retirement"
        );

        // A replacement registered at the same GPA installs and reads back.
        publish(
            &vm,
            [
                (0, slot(0, ROOT_GPA, &mut root_host, &root_backing)),
                (
                    1,
                    slot(1, CHILD_GPA, &mut replacement_host, &replacement_backing),
                ),
            ],
        );
        assert!(memory.refresh().expect("refresh installs the replacement"));
        assert!(memory.extents().lookup_span(CHILD_GPA, 4096).is_some());
        let fresh = [0xc3_u8; 8];
        memory
            .write_host_bytes(FrameGpa::new(CHILD_GPA), BOOT_GENERATION, &fresh)
            .expect("the replacement accepts an authenticated write");
        assert_eq!(
            replacement_host.0[0][..8],
            fresh,
            "the replacement backing is read and written through the new placement"
        );
        assert_eq!(
            child_host.0[0][..8],
            probe,
            "the retired backing is untouched"
        );
    }
}
