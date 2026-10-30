//! Carrier-owned metadata access, installed before MM publication. The provider
//! owns the VM/region lifetime; a prepared view owns all dynamic extent pins.
//! Preparation resolves newly published banks outside MM admission/metadata
//! guards. Locking a prepared view performs no backing allocation or resolution.

use super::*;
use crate::dispatch::mm_authority::DispatchMmAuthority;
use carrick_el1::memory::reservations::{NoRootWait, RootHolder, RootWait};

/// A refused root probe, retaining the exact release producer and the holder
/// from that same failed acquisition. It owns no lock or execution capacity.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
    ::thiserror::Error,
)]
#[error("reservation root held by {holder:?}")]
pub struct ReservationBusy {
    pub wait: carrick_el1_abi::PortalOwnerWait,
    pub holder: RootHolder,
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum RootAccessRefusal {
    Busy(ReservationBusy),
    Refused(Refusal),
}
impl From<Refusal> for RootAccessRefusal {
    fn from(value: Refusal) -> Self {
        Self::Refused(value)
    }
}
impl RootAccessRefusal {
    pub fn refusal(self) -> Refusal {
        match self {
            Self::Busy(_) => Refusal::Busy,
            Self::Refused(value) => value,
        }
    }
}
struct RootProbe {
    observed: carrick_el1_abi::PortalOwnerWait,
    holder: std::cell::Cell<Option<RootHolder>>,
}
impl RootWait for RootProbe {
    fn wait(&self, _: u32, holder: RootHolder) -> bool {
        // lock_using passes RootHolder::of_word(held) from its failed CAS.
        self.holder.set(Some(holder));
        false
    }
}
impl RootProbe {
    fn refusal(&self, refusal: Refusal) -> RootAccessRefusal {
        match (refusal, self.holder.get()) {
            (Refusal::Busy, Some(holder)) => RootAccessRefusal::Busy(ReservationBusy {
                wait: self.observed,
                holder,
            }),
            (refusal, _) => RootAccessRefusal::Refused(refusal),
        }
    }
}

pub trait HostReservationProvider: Send + Sync {
    /// Exact retained carrier venue for publication and final cleanup. Providers
    /// used only for isolated root fixtures need not expose a carrier region.
    fn address_space_backing(
        &self,
    ) -> Option<Arc<dyn crate::kernel::mm_occupancy::AddressSpaceBacking>> {
        None
    }

    /// Called before taking an MM permit. Return MetadataRequired if the
    /// existing metadata service must provision storage before resubmission.
    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal>;

    /// Service a capacity refusal after releasing MM metadata/root guards.
    /// Providers without an elastic carrier authority decline the request.
    /// `Limit` requires a Linux resource-limit authority. Missing carrier
    /// storage remains `MetadataRequired` at this service boundary; after
    /// this attempt fails, the personality may answer Linux ENOMEM without
    /// transferring the admitted root back to a host placement authority.
    fn provision_metadata(&self, _mm: ReservationMm, _wait: &dyn RootWait) -> Result<(), Refusal> {
        Err(Refusal::MetadataRequired)
    }
}

pub trait PreparedHostReservations {
    /// The returned guard borrows this view, retaining the region and exact
    /// extent pins until the operation finishes. Resolve the exact MM's slot
    /// and use SharedReservations::lock_resolved, never a guest pointer cast.
    /// Acquisition is one-shot. `Busy` requires exact-MM editor exclusion
    /// before policy is observed; a pre-exclusion fault classifier selects
    /// that mutation route instead of waiting while holding `MemState`.
    fn lock(&self, mm: ReservationMm, wait: &dyn RootWait) -> Result<Reservations<'_>, Refusal>;
}

/// Prepared pins plus their installed carrier provenance. A caller cannot
/// transplant a view from a different VM whose numeric MM key happens to match.
pub struct PreparedReservationSession {
    provider: Arc<dyn HostReservationProvider>,
    view: Box<dyn PreparedHostReservations>,
}

#[derive(::core::default::Default)]
pub(in crate::dispatch) struct ReservationProviderSlot {
    published: bool,
    provider: Option<Arc<dyn HostReservationProvider>>,
    /// Serializes every host venue of THIS MM's root, so the root lock's
    /// only other holder a host venue can meet is an EL1 critical section.
    /// The provider refuses that contention without polling.
    host_serial: Arc<parking_lot::Mutex<()>>,
    /// Root node reads by every host-venue step on this MM's root: the
    /// work-budget instrument of the delegated readers' cost contracts.
    #[cfg(test)]
    node_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ReservationProviderSlot {
    pub(in crate::dispatch) fn inherited(&self) -> Self {
        Self {
            published: false,
            provider: self.provider.clone(),
            // A successor MM has its own root, hence its own host queue.
            host_serial: Arc::default(),
            #[cfg(test)]
            node_reads: Arc::default(),
        }
    }
}

/// The exact root that owns a delegated MM's anonymous memory: the installed
/// carrier provider, this MM's key and its host queue. Minted only from the
/// MM's own authority, so it cannot name a sibling's or a successor's root.
#[derive(::core::clone::Clone)]
pub(in crate::dispatch) struct DelegatedRoot {
    provider: Arc<dyn HostReservationProvider>,
    host_serial: Arc<parking_lot::Mutex<()>>,
    mm: ReservationMm,
    #[cfg(test)]
    node_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl DelegatedRoot {
    fn observe_probe(&self) -> Result<RootProbe, Refusal> {
        use carrick_sched_core::spaces::notification::SpaceWaitCause;
        use std::num::NonZeroU64;
        let backing = self
            .provider
            .address_space_backing()
            .ok_or(Refusal::Stale)?;
        let region = backing.region().ok_or(Refusal::Stale)?;
        let source = region
            .zone
            .space_entry(NonZeroU64::new(self.mm.raw()).ok_or(Refusal::Stale)?)
            .ok_or(Refusal::Stale)?
            .live_notifications()
            .map_err(|_| Refusal::Stale)?;
        // SAFETY: finish_import admitted this exact root's notification source;
        // the retained provider authenticates its carrier and MM identity.
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                region.carrier,
                self.mm,
                source.identity().incarnation,
            )
        };
        // SAFETY: sampled from this live source before the root predicate.
        let observed = unsafe {
            carrick_el1_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_el1_abi::PortalWaitCause::Reservations,
                source.observe(SpaceWaitCause::Reservations).revision(),
            )
        };
        Ok(RootProbe {
            observed,
            holder: std::cell::Cell::new(None),
        })
    }
    /// Observe before checking MM-owned proposal custody. Its adoption drops
    /// the root guard and publishes this same Reservations release source.
    pub(in crate::dispatch) fn observe_release(
        &self,
    ) -> Result<carrick_el1_abi::PortalOwnerWait, Refusal> {
        self.observe_probe().map(|probe| probe.observed)
    }
    pub(in crate::dispatch) fn handle(&self) -> Result<carrick_el1_abi::El1MmHandle, Refusal> {
        self.observe_probe().map(|probe| probe.observed.handle())
    }
    pub(in crate::dispatch) fn provision_metadata(&self) -> Result<(), RootAccessRefusal> {
        let _host = self.host_serial.lock();
        let probe = self.observe_probe()?;
        self.provider
            .provision_metadata(self.mm, &probe)
            .map_err(|error| probe.refusal(error))
    }
    /// One step on the exact admitted root. Observe the release source before
    /// probing; the guard lives only inside step and cannot cross suspension.
    pub(in crate::dispatch) fn with_root<R>(
        &self,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<R, Refusal>,
    ) -> Result<R, RootAccessRefusal> {
        let _host = self.host_serial.lock();
        let probe = self.observe_probe()?;
        let view = self.provider.prepare()?;
        let mut model = view
            .lock(self.mm, &probe)
            .map_err(|error| probe.refusal(error))?;
        if model.mm() != self.mm
            || !model.is_admitted()
            || model.incarnation().raw() != probe.observed.handle().incarnation().get()
        {
            return Err(Refusal::Stale.into());
        }
        let result = step(&mut model).map_err(RootAccessRefusal::Refused);
        #[cfg(test)]
        self.node_reads
            .fetch_add(model.work, std::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Root node reads by this MM's host-venue steps so far.
    #[cfg(test)]
    pub(in crate::dispatch) fn node_reads(&self) -> usize {
        self.node_reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// This root's MM key.
    pub(in crate::dispatch) fn mm(&self) -> ReservationMm {
        self.mm
    }

    /// The admission step: the exact published root before it is sealed.
    pub(in crate::dispatch) fn with_root_for_import<R>(
        &self,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let _host = self.host_serial.lock();
        let view = self.provider.prepare()?;
        let mut model = view.lock(self.mm, &NoRootWait)?;
        if model.mm() != self.mm || model.is_admitted() {
            return Err(Refusal::Stale);
        }
        step(&mut model)
    }
}

impl DispatchMmAuthority {
    pub(in crate::dispatch) fn reservation_provider_for_publication(
        &self,
    ) -> Option<Arc<dyn HostReservationProvider>> {
        self.reservation_provider.lock().provider.clone()
    }
    /// Runtime installs its carrier/VM-generation-bound provider before the
    /// first address-space publication. Installation is one-shot; a fork/exec
    /// successor inherits the same carrier provider, not a parent root handle.
    pub fn install_reservation_provider(
        &self,
        provider: Arc<dyn HostReservationProvider>,
    ) -> Result<(), Refusal> {
        let mut slot = self.reservation_provider.lock();
        if slot.published {
            return Err(Refusal::Stale);
        }
        if slot.provider.is_some() {
            return Err(Refusal::Collision);
        }
        slot.provider = Some(provider);
        Ok(())
    }

    pub(in crate::dispatch) fn seal_reservation_provider(&self) {
        self.reservation_provider.lock().published = true;
    }

    /// Whether this MM's address space was published (its provider sealed):
    /// an MM that never published never ran guest code under EL1.
    pub(in crate::dispatch) fn reservation_provider_published(&self) -> bool {
        self.reservation_provider.lock().published
    }

    pub(in crate::dispatch) fn has_reservation_provider(&self) -> bool {
        self.reservation_provider.lock().provider.is_some()
    }

    /// The handle of this exact MM's root, for its admission.
    pub(in crate::dispatch) fn delegated_root(&self) -> Result<DelegatedRoot, Refusal> {
        let slot = self.reservation_provider.lock();
        Ok(DelegatedRoot {
            provider: slot.provider.clone().ok_or(Refusal::ForeignMapping)?,
            host_serial: Arc::clone(&slot.host_serial),
            mm: ReservationMm::new(self.mm_id.raw()).ok_or(Refusal::Invalid)?,
            #[cfg(test)]
            node_reads: Arc::clone(&slot.node_reads),
        })
    }

    pub fn prepare_el1_reservations(&self) -> Result<PreparedReservationSession, Refusal> {
        let provider = self
            .reservation_provider
            .lock()
            .provider
            .clone()
            .ok_or(Refusal::ForeignMapping)?;
        // No slot lock is held across host allocation or pin resolution.
        let view = provider.prepare()?;
        Ok(PreparedReservationSession { provider, view })
    }

    /// A read-only projection for the proc consumer under the caller's exact
    /// MM exclusion. Missing/stale metadata is a refusal, never permission to
    /// fall back to a MemState anonymous snapshot from another generation.
    pub fn observe_el1_proc_maps(
        &self,
        permit: &crate::dispatch::mm_mutation::HostAliasPermit<'_>,
        prepared: &PreparedReservationSession,
        host: &NonAnonymousVmas,
    ) -> Result<ReservationProcMaps, Refusal> {
        if !permit.authorizes(&self.mutation_coordinator, self.mm_id) {
            return Err(Refusal::Stale);
        }
        let (installed, host_serial) = {
            let slot = self.reservation_provider.lock();
            (
                slot.provider.clone().ok_or(Refusal::ForeignMapping)?,
                Arc::clone(&slot.host_serial),
            )
        };
        if !Arc::ptr_eq(&installed, &prepared.provider) {
            return Err(Refusal::Stale);
        }
        let _host = host_serial.lock();
        let mm = ReservationMm::new(self.mm_id.raw()).ok_or(Refusal::Invalid)?;
        let mut model = prepared.view.lock(mm, &NoRootWait)?;
        if model.mm() != mm {
            return Err(Refusal::Stale);
        }
        ReservationProcMaps::capture(&mut model, host)
    }
}

impl SyscallDispatcher {
    /// Carrier setup boundary; call before publishing this dispatcher's first
    /// MM. Fork/rebind/exec staging preserve the installed carrier provider.
    pub fn install_reservation_provider(
        &self,
        provider: Arc<dyn HostReservationProvider>,
    ) -> Result<(), Refusal> {
        self.mm_authority().install_reservation_provider(provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn metadata_provisioning_joins_the_same_host_queue_as_root_observation() {
        struct Provisioner {
            inner: Arc<dyn HostReservationProvider>,
            serial: Arc<parking_lot::Mutex<()>>,
            entered: std::sync::mpsc::SyncSender<()>,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl HostReservationProvider for Provisioner {
            fn address_space_backing(
                &self,
            ) -> Option<Arc<dyn crate::kernel::mm_occupancy::AddressSpaceBacking>> {
                self.inner.address_space_backing()
            }
            fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
                self.inner.prepare()
            }
            fn provision_metadata(
                &self,
                mm: ReservationMm,
                wait: &dyn RootWait,
            ) -> Result<(), Refusal> {
                assert!(
                    self.serial.is_locked(),
                    "metadata provisioning bypassed host serialization"
                );
                let view = self.prepare()?;
                let held = view.lock(mm, wait)?;
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                drop(held);
                Ok(())
            }
        }
        let dispatcher = SyscallDispatcher::new();
        let _fixture = crate::dispatch::mem::delegated_tests::Root::admit(&dispatcher);
        let mut root = dispatcher.mem().lock().delegated_root().cloned().unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        root.provider = Arc::new(Provisioner {
            inner: Arc::clone(&root.provider),
            serial: Arc::clone(&root.host_serial),
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        std::thread::scope(|scope| {
            let provisioner = root.clone();
            let provision = scope.spawn(move || provisioner.provision_metadata());
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let observer = root.clone();
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let observe = scope.spawn(move || {
                started_tx.send(()).unwrap();
                observer.with_root(|model| Ok(model.mm()))
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            release_tx.send(()).unwrap();
            assert_eq!(provision.join().unwrap(), Ok(()));
            assert_eq!(observe.join().unwrap(), Ok(root.mm()));
        });
    }
}
