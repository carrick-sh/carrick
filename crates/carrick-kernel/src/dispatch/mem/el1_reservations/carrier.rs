//! The one host reservation provider every carrier installs: it binds the
//! shared reservation views to the exact carrier's EL1 region and its
//! dynamic metadata aperture. A backend supplies only the metadata access
//! ([`CarrierReservationAccess`]); the views, the bank provisioning and the
//! publication backing are shared.

use std::num::NonZeroU64;
use std::sync::Arc;

use carrick_el1::memory::reservations::{
    HostBankGrant, HostBankInstall, Refusal, Reservations, ResolvedReservationNodes,
    RootReleaseVenue, RootWait, SharedReservations,
};
use carrick_el1_abi::{MetadataExtentResolver, MetadataResolutionError, ReservationMm};
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
    /// Unpublished grants whose retirement the backend refused although
    /// nothing pinned them: a broken invariant. Their authority is kept
    /// here, never dropped, so each occupied aperture slot stays this
    /// carrier's, accounted until the carrier goes (#3085).
    quarantined: Mutex<Vec<<A as RetainedMetadataMapper>::Extent>>,
}

impl<A: CarrierReservationAccess> CarrierReservations<A> {
    pub fn new(access: A) -> Self {
        Self {
            access: Arc::new(access),
            prepared: Mutex::new(None),
            capacity: Mutex::new(()),
            quarantined: Mutex::new(Vec::new()),
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

/// A host bank grant: one retained mapping in this carrier's aperture.
struct RetainedBankGrant<E>(E);
impl<E: RetainedMetadataExtent> HostBankGrant for RetainedBankGrant<E> {
    type Pin = E::Pin;
    fn pin(&self) -> Result<E::Pin, Refusal> {
        self.0.pin().map_err(|_| Refusal::Stale)
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
        let table = table(&*self.access)?;
        let view = PreparedView(self.prepared()?);
        // What this root decides against: the view's capacity. A lock
        // refused because a bank landed after the view was read, and a root
        // the pool cannot serve, are the same `MetadataRequired` against it,
        // and only the table's own decision below answers either (#3085).
        let observed = view.0.nodes.capacity();
        match view.lock(mm, wait).and_then(|mut root| {
            root.secure_host_nodes(carrick_el1::memory::reservations::HOST_RESERVE)
        }) {
            // A peer's bank already serves this root: decide again.
            Ok(()) => return Ok(HostBankInstall::Redundant),
            Err(Refusal::MetadataRequired) => {}
            Err(refusal) => return Err(refusal),
        }
        drop(view);
        let release = host_release_venue(&*self.access)?;
        // No host memory or no aperture slot is not an answer by itself: the
        // table decides it, after reading whether a peer published, or holds
        // the window, meanwhile. A stale carrier generation or an invalid
        // extent is a broken invariant, never that miss (never ENOMEM).
        let decision = table.install_host_bank(
            observed,
            || {
                let bytes = SharedReservations::metadata_bank_layout().size();
                let bytes = bytes.next_multiple_of(16 * 1024);
                let Ok(backing) =
                    OwnedHostMapping::map_shared_anon(bytes, HostMappingKind::SharedAnon)
                else {
                    return Ok(None);
                };
                match self
                    .access
                    .map_retained(Arc::new(ReservationBankBacking(backing)))
                {
                    Ok(mapping) => Ok(Some(RetainedBankGrant(mapping))),
                    Err(MetadataResolutionError::Busy) => Ok(None),
                    Err(MetadataResolutionError::StaleOwner) => Err(Refusal::Stale),
                    Err(MetadataResolutionError::InvalidExtent) => Err(Refusal::Invalid),
                }
            },
            &release,
        );
        // Only a published grant became a bank; a redundant one, or one
        // refused by a held window, is retired here.
        let Some(RetainedBankGrant(mapping)) = decision.unpublished else {
            return decision.answer;
        };
        match mapping.try_retire() {
            Ok(()) => decision.answer,
            // Nothing pins an unpublished grant, so a refused retirement is
            // a broken invariant (or this carrier generation is gone): fatal,
            // and the grant is quarantined, never dropped with its slot.
            Err(stranded) => {
                let refusal = match self.access.region() {
                    Ok(_) => Refusal::Invalid,
                    Err(_) => Refusal::Stale,
                };
                self.quarantined.lock().push(stranded);
                Err(refusal)
            }
        }
    }

    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
        self.prepared()
            .map(|view| Box::new(PreparedView(view)) as _)
    }
}

impl<A: CarrierReservationAccess> CarrierReservations<A> {
    /// The resolved view of the table's published banks now, cached per
    /// storage generation.
    fn prepared(&self) -> Result<Arc<Prepared<A>>, Refusal> {
        let table = table(&*self.access)?;
        let generation = table.storage_generation();
        let mut cached = self.prepared.lock();
        if let Some(view) = cached.as_ref().filter(|view| view.generation == generation) {
            return Ok(Arc::clone(view));
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
        Ok(view)
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
