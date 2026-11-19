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
use carrick_softmmu::{MAX_PLACEMENT_SEGMENTS, PAGE_SIZE_4K, PlacementSegment};
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

    /// Refresh additions while the vCPU is stopped. The existing extent
    /// table keeps the CPU's seat, admitted roots and frame code generations.
    pub(crate) fn refresh(&mut self) -> Result<bool, TrapError> {
        let retained = self.vm.retained_slots()?;
        if Arc::ptr_eq(&self.retained, &retained) {
            return Ok(false);
        }

        for (&index, old) in self.retained.iter() {
            if retained.get(&index).is_none_or(|slot| {
                slot.region != old.region || !Arc::ptr_eq(&slot.backing, &old.backing)
            }) {
                return Err(fail(format!(
                    "soft slot {index} changed or retired without a retirement protocol"
                )));
            }
        }

        if self.retained.len() == retained.len() {
            self.retained = retained;
            return Ok(false);
        }

        let placement = Self::placement_for(&retained)?;
        for (index, slot) in retained.iter() {
            if !self.retained.contains_key(index) {
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
            self.extents
                .invalidate_host_written_page(page, BOOT_GENERATION)
                .map_err(|error| fail(format!("soft host write {page:?}: {error:?}")))?;
        }
        slots.host_written.clear();
        Ok(())
    }

    /// Authenticate `root` (a page-table root inside a registered slot) for
    /// walks; an already-admitted root is accepted unchanged.
    pub fn admit_root(&mut self, root: u64) -> Result<(), TrapError> {
        let root = RootGpa::page_aligned(FrameGpa::new(root))
            .ok_or_else(|| fail("soft root alignment"))?;
        if self.extents.expected_generation(root) == Some(BOOT_GENERATION)
            || (self
                .extents
                .lookup_span(root.address().raw(), PAGE_SIZE_4K)
                .is_some_and(|extent| extent.generation == BOOT_GENERATION)
                && self.extents.set_root_generation(root, BOOT_GENERATION))
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
// snapshot. Refresh preserves the actual backing of every existing slot and
// updates the same inventory domain as the CPU's invalidation seat.
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
