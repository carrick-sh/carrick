//! Bind host reservation views to the exact persistent carrier's mappings.

use std::sync::Arc;

use carrick_el1::memory::reservations::{
    Refusal, Reservations, ResolvedReservationNodes, SharedReservations,
};
use carrick_el1_abi::ReservationMm;
use carrick_guest_mem::HostVa;
use carrick_host::host_mapping::{HostMappingKind, OwnedHostMapping};
use carrick_kernel::dispatch::mem::el1_reservations::{
    HostReservationProvider, PreparedHostReservations,
};
use carrick_vmm_hvf::metadata_grant::{
    CarrierMetadataAccess, HostMetadataExtentPin, RetainedMetadataBacking,
};
use parking_lot::Mutex;

pub(super) struct CarrierReservations {
    access: Arc<CarrierMetadataAccess>,
    prepared: Mutex<Option<Arc<Prepared>>>,
    capacity: Mutex<()>,
}

impl CarrierReservations {
    pub(super) fn new(access: CarrierMetadataAccess) -> Self {
        Self {
            access: Arc::new(access),
            prepared: Mutex::new(None),
            capacity: Mutex::new(()),
        }
    }
}

#[derive(Debug)]
struct ReservationBankBacking(OwnedHostMapping);
// SAFETY: only shared ABI nodes inhabit this stable MAP_SHARED allocation.
// Access is serialized by reservation root locks and atomic pool operations;
// the carrier retains the owner until VM destruction.
unsafe impl Send for ReservationBankBacking {}
unsafe impl Sync for ReservationBankBacking {}
unsafe impl RetainedMetadataBacking for ReservationBankBacking {
    fn host_base(&self) -> HostVa {
        HostVa(self.0.as_ptr() as usize)
    }
    fn mapped_len(&self) -> usize {
        self.0.len()
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
    fn provision_metadata(&self, mm: ReservationMm) -> Result<(), Refusal> {
        // Carrier capacity publication is serialized outside all MM locks.
        let _capacity = self.capacity.lock();
        let view = self.prepare()?;
        let mut root = view.lock(mm)?;
        match root.secure_host_nodes(carrick_el1::memory::reservations::HOST_RESERVE) {
            Ok(()) => return Ok(()),
            Err(Refusal::MetadataRequired) => {}
            Err(refusal) => return Err(refusal),
        }
        let table = table(&self.access)?;
        let generation = table.storage_generation();
        drop(root);
        drop(view);
        let bytes = SharedReservations::metadata_bank_layout().size();
        let bytes = bytes.next_multiple_of(16 * 1024);
        let backing = OwnedHostMapping::map_shared_anon(bytes, HostMappingKind::SharedAnon)
            .map_err(|_| Refusal::MetadataRequired)?;
        let mapping = self
            .access
            .map_retained(Arc::new(ReservationBankBacking(backing)))
            .map_err(|_| Refusal::MetadataRequired)?;
        let result = mapping
            .pin()
            .map_err(|_| Refusal::Stale)
            .and_then(|pin| table.provision_metadata(&pin, generation));
        if result.is_err() {
            let _ = mapping.try_retire();
        }
        result
    }

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
            &carrick_kernel::dispatch::mem::el1_reservations::RootHostWait::new(),
        )
    }
}
