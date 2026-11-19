//! Read-only backing publication for carriers that place host allocations
//! in a software MMU after a stopped doorbell service.

use std::sync::Arc;

use carrick_hal::TrapError;

use crate::carrier_cpu::CarrierCpuIo;
use crate::carrier_memory::{BackingExtent, CarrierMemory, CarrierMemoryIo, CarrierMemoryRegion};

use super::{ProductionCpuFactory, fail};

/// The VM's installed allocations, borrowed with its custody still held.
pub struct RetainedCarrierSlots<'a, M: CarrierMemoryIo>(&'a CarrierMemory<M>);

impl<'a, M: CarrierMemoryIo> RetainedCarrierSlots<'a, M> {
    pub fn new(memory: &'a CarrierMemory<M>) -> Result<Self, TrapError> {
        memory
            .ensure_available()
            .map_err(|error| fail(error.to_string()))?;
        Ok(Self(memory))
    }

    pub fn vm(&self) -> &M {
        self.0.vm()
    }

    pub fn backings(&self) -> impl Iterator<Item = &Arc<BackingExtent>> {
        self.0.retained_backings()
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionCpuFactory<M, Mem> {
    /// Borrow installed backing authority after a stopped carrier service.
    /// Slot changes cannot race publication while the custody lock is held.
    pub fn with_retained_slots<R>(
        &self,
        publish: impl FnOnce(RetainedCarrierSlots<'_, Mem>) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        publish(RetainedCarrierSlots::new(&custody._vm)?)
    }
}

impl BackingExtent {
    /// Prove that a region names this exact allocation. A matching GPA
    /// and size alone cannot distinguish a replacement allocation.
    pub fn matches_slot_region(&self, region: &CarrierMemoryRegion) -> bool {
        self.base.raw() == region.guest_phys_addr
            && usize::try_from(region.memory_size) == Ok(self.len)
            && self
                .host_base()
                .is_ok_and(|host| usize::try_from(region.userspace_addr) == Ok(host.raw()))
    }
}
