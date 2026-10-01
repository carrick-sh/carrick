//! Bind host reservation views to the exact persistent carrier's mappings.

use std::sync::Arc;

use carrick_el1::memory::reservations::{
    Refusal, Reservations, ResolvedReservationNodes, SharedReservations,
};
use carrick_el1_abi::ReservationMm;
use carrick_kernel::dispatch::mem::el1_reservations::{
    HostReservationProvider, PreparedHostReservations,
};
use carrick_vmm_hvf::metadata_grant::{CarrierMetadataAccess, HostMetadataExtentPin};
use parking_lot::Mutex;

pub(super) struct CarrierReservations {
    access: Arc<CarrierMetadataAccess>,
    prepared: Mutex<Option<Arc<Prepared>>>,
}

impl CarrierReservations {
    pub(super) fn new(access: CarrierMetadataAccess) -> Self {
        Self {
            access: Arc::new(access),
            prepared: Mutex::new(None),
        }
    }
}

struct Prepared {
    access: Arc<CarrierMetadataAccess>,
    nodes: ResolvedReservationNodes<HostMetadataExtentPin>,
    generation: u32,
}

// SAFETY: the view is immutable after construction. Its exact carrier and
// extent pins retain every address. SharedReservations serializes node access
// through the exact MM root lock; no mutable reference is exposed by this view.
unsafe impl Send for Prepared {}
unsafe impl Sync for Prepared {}

fn table(access: &CarrierMetadataAccess) -> Result<&SharedReservations, Refusal> {
    let region = access.region().map_err(|_| Refusal::Stale)?;
    // SAFETY: access owns the complete aligned carrier region; the reservation
    // ABI asserts this table fits its assigned region. It starts zero-filled.
    Ok(unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
            .cast::<SharedReservations>()
    })
}

impl HostReservationProvider for CarrierReservations {
    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
        let table = table(&self.access)?;
        let generation = table.storage_generation();
        let mut cached = self.prepared.lock();
        if let Some(view) = cached.as_ref().filter(|view| view.generation == generation) {
            return Ok(Box::new(PreparedView(Arc::clone(view))));
        }
        let mut nodes = ResolvedReservationNodes::default();
        let region = self.access.region().map_err(|_| Refusal::Stale)?;
        // SAFETY: the prepared view retains the same region owner and all
        // resolved extent pins; refresh runs before taking any MM permit.
        unsafe {
            nodes.refresh(table, &*self.access, region)?;
        }
        let view = Arc::new(Prepared {
            access: Arc::clone(&self.access),
            nodes,
            generation,
        });
        *cached = Some(Arc::clone(&view));
        Ok(Box::new(PreparedView(view)))
    }
}

struct PreparedView(Arc<Prepared>);

impl PreparedHostReservations for PreparedView {
    fn lock(&self, mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
        let region = self.0.access.region().map_err(|_| Refusal::Stale)?;
        // SAFETY: this is the same owned carrier region as the reservation
        // table. ZoneTables are shared atomics and fit the ABI region bounds.
        let zone = unsafe {
            &*region
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        let index = zone.spaces.find(mm.raw()).ok_or(Refusal::Stale)?.index();
        table(&self.0.access)?.lock_resolved(
            index,
            mm,
            &self.0.nodes,
            &carrick_kernel::el1_zone::HostLockWait,
        )
    }
}
