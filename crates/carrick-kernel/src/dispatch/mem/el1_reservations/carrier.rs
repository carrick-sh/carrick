//! The one host reservation provider every carrier installs: it binds the
//! shared reservation views to the exact carrier's EL1 region and its
//! dynamic metadata aperture. A backend supplies only the metadata access
//! ([`CarrierReservationAccess`]); the views, the bank provisioning and the
//! publication backing are shared.

use std::num::NonZeroU64;
use std::sync::Arc;

use carrick_el1::memory::reservations::{
    HostBankInstall, Refusal, Reservations, ResolvedReservationNodes, RootReleaseVenue, RootWait,
    SharedReservations,
};
use carrick_el1_abi::{MetadataExtentResolver, ReservationMm};
use carrick_guest_mem::HostVa;
use carrick_hal::retained_metadata::{
    RetainedMetadataBacking, RetainedMetadataExtent, RetainedMetadataMapper,
};
use carrick_host::host_mapping::{HostMappingKind, OwnedHostMapping};
use parking_lot::Mutex;

use super::{HostReservationProvider, PreparedHostReservations};
use crate::kernel::mm_occupancy::{AddressSpaceBacking, AddressSpaceRegion};

/// One carrier generation's metadata access: its EL1 region and dynamic
/// aperture ([`RetainedMetadataMapper`]), the authenticated pin of an extent
/// EL1 names ([`MetadataExtentResolver`]), its transfer identity, and its
/// guest COW settlement.
pub trait CarrierReservationAccess:
    RetainedMetadataMapper + MetadataExtentResolver + 'static
{
    /// The carrier's transfer identity, as its portal is bound to it.
    fn carrier_identity(&self) -> NonZeroU64;

    /// The carrier's guest COW grant settlement, if it settles any.
    fn guest_cow_settlement(&self) -> Option<Arc<dyn carrick_el1_abi::CowGrantSettlement>>;

    /// Who serves this carrier's delegated private file pages
    /// ([`HostReservationProvider::private_file_venue`]): `OwnerGrant` only
    /// if its owner frame grant serves them.
    fn private_file_venue(&self) -> carrick_guest_mem::PrivateFileVenue;
}

/// The reservation provider of one carrier generation.
pub struct CarrierReservations<A: CarrierReservationAccess> {
    access: Arc<A>,
    prepared: Mutex<Option<Arc<Prepared<A>>>>,
    capacity: Mutex<()>,
}

impl<A: CarrierReservationAccess> CarrierReservations<A> {
    pub fn new(access: A) -> Self {
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
        HostVa::new(self.0.as_ptr() as usize)
    }
    fn mapped_len(&self) -> usize {
        self.0.len()
    }
}

struct Prepared<A: CarrierReservationAccess> {
    access: Arc<A>,
    nodes: ResolvedReservationNodes<<A as MetadataExtentResolver>::Pin>,
    generation: u32,
}

// SAFETY: the view is immutable after construction. Its exact carrier and
// extent pins retain every address. SharedReservations serializes node access
// through the exact MM root lock; no mutable reference is exposed by this view.
unsafe impl<A: CarrierReservationAccess> Send for Prepared<A> {}
unsafe impl<A: CarrierReservationAccess> Sync for Prepared<A> {}

fn table<A: CarrierReservationAccess>(access: &A) -> Result<&SharedReservations, Refusal> {
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

/// The host venue that wakes this carrier's waiters: a reservation root's
/// release, and every Metadata waiter when a host bank window closes
/// (#3085).
fn host_release_venue<A: CarrierReservationAccess>(
    access: &A,
) -> Result<
    carrick_sched_core::spaces::notification::SpaceReleaseVenue<
        '_,
        carrick_el1_abi::Aarch64ParkedContext,
    >,
    Refusal,
> {
    let region = access.region().map_err(|_| Refusal::Stale)?;
    // SAFETY: this is the same owned carrier region as the reservation
    // table. ZoneTables are shared atomics and fit the ABI region bounds.
    let zone = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<carrick_el1_abi::ZoneTables>()
    };
    fn deliver(
        zone: &carrick_el1_abi::ZoneTables,
        _: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_el1_abi::Aarch64ParkedContext,
        >,
    ) {
        carrick_sched_core::LockWait::complete_object_wake(
            &crate::el1_zone::HostLockWait,
            zone,
            effects,
        );
    }
    Ok(
        carrick_sched_core::spaces::notification::SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(deliver),
        },
    )
}

impl<A: CarrierReservationAccess> HostReservationProvider for CarrierReservations<A> {
    fn private_file_venue(&self) -> carrick_guest_mem::PrivateFileVenue {
        self.access.private_file_venue()
    }

    fn address_space_backing(&self) -> Option<Arc<dyn AddressSpaceBacking>> {
        self.access.region().ok()?;
        Some(Arc::new(CarrierPublicationBacking(Arc::clone(
            &self.access,
        ))))
    }
    fn provision_metadata(
        &self,
        mm: ReservationMm,
        wait: &dyn RootWait,
    ) -> Result<HostBankInstall, Refusal> {
        // Carrier capacity publication is serialized outside all MM locks.
        let _capacity = self.capacity.lock();
        let view = self.prepare()?;
        let mut root = view.lock(mm, wait)?;
        match root.secure_host_nodes(carrick_el1::memory::reservations::HOST_RESERVE) {
            // A peer's bank already serves this root: decide again.
            Ok(()) => return Ok(HostBankInstall::Redundant),
            Err(Refusal::MetadataRequired) => {}
            Err(refusal) => return Err(refusal),
        }
        let table = table(&*self.access)?;
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
        let result = mapping.pin().map_err(|_| Refusal::Stale).and_then(|pin| {
            table.provision_metadata(&pin, generation, &host_release_venue(&*self.access)?)
        });
        // Only a published grant became a bank; a redundant one, or one
        // refused by a held window, is retired here.
        if !matches!(result, Ok(HostBankInstall::Published)) {
            let _ = mapping.try_retire();
        }
        result
    }

    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
        let table = table(&*self.access)?;
        let generation = table.storage_generation();
        let mut cached = self.prepared.lock();
        if let Some(view) = cached.as_ref().filter(|view| view.generation == generation) {
            return Ok(Box::new(PreparedView(Arc::clone(view))));
        }
        let mut nodes = ResolvedReservationNodes::default();
        let region = self.access.region().map_err(|_| Refusal::Stale)?;
        // SAFETY: the prepared view retains the same region owner (whose
        // bootstrap metadata arena lies inside it) and all resolved extent
        // pins; refresh runs before taking any MM permit.
        unsafe {
            let bootstrap = region.add(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize);
            nodes.refresh(table, &*self.access, bootstrap)?;
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

struct PreparedView<A: CarrierReservationAccess>(Arc<Prepared<A>>);

impl<A: CarrierReservationAccess> PreparedHostReservations for PreparedView<A> {
    fn lock(&self, mm: ReservationMm, wait: &dyn RootWait) -> Result<Reservations<'_>, Refusal> {
        let release = host_release_venue(&*self.0.access)?;
        let index = release
            .zone
            .spaces
            .find(mm.raw())
            .ok_or(Refusal::Stale)?
            .index();
        RootReleaseVenue::new(table(&*self.0.access)?, release)?.lock_resolved(
            index,
            mm,
            &self.0.nodes,
            wait,
        )
    }
}

/// This physical view retains the exact carrier used for both publication and
/// cleanup. It contains no process registry or lifecycle policy.
struct CarrierPublicationBacking<A: CarrierReservationAccess>(Arc<A>);
// SAFETY: metadata access retains the exact immutable carrier mapping inventory.
unsafe impl<A: CarrierReservationAccess> AddressSpaceBacking for CarrierPublicationBacking<A> {
    fn region(&self) -> Option<AddressSpaceRegion<'_>> {
        let region = self.0.region().ok()?;
        // SAFETY: the retained access owns the complete aligned ABI region.
        let zone = unsafe {
            &*region
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<carrick_el1_abi::ZoneTables>()
        };
        Some(AddressSpaceRegion {
            carrier: self.0.carrier_identity(),
            zone,
            reservations: table(&*self.0).ok()?,
        })
    }
    fn settlement(&self) -> Option<Arc<dyn carrick_el1_abi::CowGrantSettlement>> {
        self.0.guest_cow_settlement()
    }
}
