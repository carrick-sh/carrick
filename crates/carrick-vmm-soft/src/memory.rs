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
//! retains its own `Arc` of each backing ([`SoftBackings`]).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use carrick_hal::{OsError, TrapError};
use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, LinearPlacement, MmioHoles, OwnerGeneration, RootGpa,
    SoftMmuMemory,
};
use carrick_softmmu::{MAX_PLACEMENT_SEGMENTS, PlacementSegment};
use carrick_x86_cpl0_host::carrier_memory::{BackingExtent, CarrierMemoryIo, CarrierMemoryRegion};
use carrick_x86_cpl0_host::cpl0_boot::fail;
use carrick_x86_cpl0_host::guest_ram::GuestRam;

/// One owner generation authenticates every registered slot and root.
const BOOT_GENERATION: OwnerGeneration = OwnerGeneration::FIRST;

/// The soft carrier's slot namespace: the memory registrations a
/// `CarrierMemory<SoftVm>` makes, keyed by slot. Clones share the table.
#[derive(Clone, Default)]
pub struct SoftVm {
    slots: Arc<Mutex<BTreeMap<u32, CarrierMemoryRegion>>>,
}

impl SoftVm {
    pub fn new() -> Self {
        Self::default()
    }

    fn regions(&self) -> Vec<CarrierMemoryRegion> {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}

impl CarrierMemoryIo for SoftVm {
    fn carrier_slot_limit(&self) -> Result<u32, OsError> {
        u32::try_from(MAX_PLACEMENT_SEGMENTS).map_err(|_| OsError::new("soft slot limit"))
    }

    unsafe fn set_user_memory_region(&self, region: CarrierMemoryRegion) -> Result<(), OsError> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if region.memory_size == 0 {
            slots.remove(&region.slot);
        } else {
            slots.insert(region.slot, region);
        }
        Ok(())
    }

    fn signal_msi(&self, _address_lo: u32, _data: u32) -> Result<(), OsError> {
        // M1 is single-vCPU (#2397): no peer exists to receive an MSI, and
        // the ApicCluster route is a later slice. Refuse rather than drop.
        Err(OsError::new(
            "soft carrier has no MSI route (single-vCPU M1)",
        ))
    }
}

/// The slot backings a [`SoftCarrierMemory`] translates through. The view
/// holds these `Arc`s itself, so no custody edit, swap or drop can free a
/// host allocation while a soft CPU still places it.
#[derive(Clone)]
pub struct SoftBackings {
    /// The bootstrap windows' owner.
    ram: Arc<GuestRam>,
    /// Every other registered extent (IPC, kernel region, initial extent).
    extents: Vec<Arc<BackingExtent>>,
}

impl SoftBackings {
    pub fn new(ram: Arc<GuestRam>, extents: Vec<Arc<BackingExtent>>) -> Self {
        Self { ram, extents }
    }

    /// Whether `region` is memory these backings retain: a bootstrap window
    /// at the same host address, or an extent at the same GPA and length.
    fn retains(&self, region: &CarrierMemoryRegion) -> bool {
        let len = usize::try_from(region.memory_size).ok();
        self.ram.slot_windows().iter().any(|&(gpa, host, size)| {
            gpa == region.guest_phys_addr
                && host as u64 == region.userspace_addr
                && Some(size) == len
        }) || self
            .extents
            .iter()
            .any(|extent| extent.base.raw() == region.guest_phys_addr && Some(extent.len) == len)
    }
}

/// The soft CPU's view of the registered slots: one linear placement
/// segment and one authenticated extent per slot, over backings the view
/// itself retains.
pub struct SoftCarrierMemory {
    placement: LinearPlacement,
    extents: ExtentTable,
    /// Keeps every placed host allocation alive for the life of the view
    /// (and so of any soft CPU seated on it).
    _backings: SoftBackings,
}

impl SoftCarrierMemory {
    /// Place every slot `vm` holds and authenticate `root` as the first
    /// page-table root. Refuses a registration `backings` does not retain.
    ///
    /// # Safety
    ///
    /// Every registration in `vm` must have been made by the
    /// `CarrierMemory<SoftVm>` whose backings `backings` names, under
    /// `set_user_memory_region`'s contract: its host address is the start of
    /// the retained allocation registered at that GPA.
    pub(crate) unsafe fn new(
        vm: &SoftVm,
        root: u64,
        backings: SoftBackings,
    ) -> Result<Self, TrapError> {
        let regions = vm.regions();
        let segments: Vec<PlacementSegment> = regions
            .iter()
            .map(|region| {
                if !backings.retains(region) {
                    return Err(fail(format!(
                        "soft slot {:#x}+{:#x} names no retained backing",
                        region.guest_phys_addr, region.memory_size
                    )));
                }
                Ok(PlacementSegment::new(
                    region.guest_phys_addr,
                    region.memory_size,
                    usize::try_from(region.userspace_addr)
                        .map_err(|_| fail("soft slot host address width"))?,
                ))
            })
            .collect::<Result<_, TrapError>>()?;
        // SAFETY: each segment is a registration of a backing `backings`
        // retains (checked above; the host address is the caller's
        // contract): a page-aligned, initialized, writable allocation of
        // `memory_size` bytes at a stable address. The view owns
        // `backings`, so the allocations outlive the placement.
        let placement =
            unsafe { LinearPlacement::with_segments(&segments, MmioHoles::x86_default()) }
                .map_err(|error| fail(format!("soft placement: {error:?}")))?;
        let mut extents =
            ExtentTable::new().map_err(|_| fail("soft extent table generation exhausted"))?;
        for region in &regions {
            let record = ExtentRecord::new(
                FrameGpa::new(region.guest_phys_addr),
                region.memory_size,
                BOOT_GENERATION,
            );
            if !extents.install(record) {
                return Err(fail(format!(
                    "soft extent {:#x}+{:#x} refused",
                    region.guest_phys_addr, region.memory_size
                )));
            }
        }
        let mut memory = Self {
            placement,
            extents,
            _backings: backings,
        };
        memory.admit_root(root)?;
        Ok(memory)
    }

    /// Authenticate `root` (a page-table root inside a registered slot) for
    /// walks; an already-admitted root is accepted unchanged.
    pub fn admit_root(&mut self, root: u64) -> Result<(), TrapError> {
        let root = RootGpa::page_aligned(FrameGpa::new(root))
            .ok_or_else(|| fail("soft root alignment"))?;
        if self.extents.expected_generation(root).is_some()
            || self.extents.set_root_generation(root, BOOT_GENERATION)
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

// SAFETY: `placement` describes only allocations `_backings` retains for
// the life of this value (see `SoftCarrierMemory::new`), and `extents` is
// this memory's single inventory domain; both outlive every translation a
// CPU seated here can cache.
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
