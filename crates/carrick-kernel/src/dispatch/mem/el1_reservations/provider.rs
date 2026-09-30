//! Carrier-owned metadata access, installed before MM publication. The provider
//! owns the VM/region lifetime; a prepared view owns all dynamic extent pins.
//! Preparation resolves newly published banks outside MM admission/metadata
//! guards. Locking a prepared view performs no backing allocation or resolution.

use super::*;
use crate::dispatch::mm_authority::DispatchMmAuthority;

pub trait HostReservationProvider: Send + Sync {
    /// Called before taking an MM permit. Return MetadataRequired if the
    /// existing metadata service must provision storage before resubmission.
    fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal>;
}

pub trait PreparedHostReservations {
    /// The returned guard borrows this view, retaining the region and exact
    /// extent pins until the operation finishes. Resolve the exact MM's slot
    /// and use SharedReservations::lock_resolved, never a guest pointer cast.
    fn lock(&self, mm: ReservationMm) -> Result<Reservations<'_>, Refusal>;
}

/// Prepared pins plus their installed carrier provenance. A caller cannot
/// transplant a view from a different VM whose numeric MM key happens to match.
pub struct PreparedReservationSession {
    provider: Arc<dyn HostReservationProvider>,
    view: Box<dyn PreparedHostReservations>,
}

#[derive(Default)]
pub(in crate::dispatch) struct ReservationProviderSlot {
    published: bool,
    provider: Option<Arc<dyn HostReservationProvider>>,
    /// Serializes every host venue of THIS MM's root. The root lock is a
    /// bounded try-lock sized for EL1 critical sections; two host threads of
    /// one MM must queue here instead of refusing each other with `Busy`.
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
#[derive(Clone)]
pub(in crate::dispatch) struct DelegatedRoot {
    provider: Arc<dyn HostReservationProvider>,
    host_serial: Arc<parking_lot::Mutex<()>>,
    mm: ReservationMm,
    #[cfg(test)]
    node_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl DelegatedRoot {
    /// One host-venue step on the exact admitted root. The root guard lives
    /// only for `step`: no host backend service ever runs under it.
    pub(in crate::dispatch) fn with_root<R>(
        &self,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let _host = self.host_serial.lock();
        let view = self.provider.prepare()?;
        let mut model = view.lock(self.mm)?;
        if model.mm() != self.mm || !model.is_admitted() {
            return Err(Refusal::Stale);
        }
        let result = step(&mut model);
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
        let mut model = view.lock(self.mm)?;
        if model.mm() != self.mm || model.is_admitted() {
            return Err(Refusal::Stale);
        }
        step(&mut model)
    }

    /// The fork admission step: `parent`'s exact admitted root and this
    /// child's exact published, unsealed root, both views prepared before
    /// either root guard is taken. Host queues are taken parent first.
    pub(in crate::dispatch) fn seed_from<R>(
        &self,
        parent: &DelegatedRoot,
        step: impl FnOnce(&mut Reservations<'_>, &mut Reservations<'_>) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        if parent.mm == self.mm || Arc::ptr_eq(&parent.host_serial, &self.host_serial) {
            return Err(Refusal::Invalid);
        }
        let _parent_host = parent.host_serial.lock();
        let _host = self.host_serial.lock();
        let parent_view = parent.provider.prepare()?;
        let view = self.provider.prepare()?;
        let mut parent_model = parent_view.lock(parent.mm)?;
        if parent_model.mm() != parent.mm || !parent_model.is_admitted() {
            return Err(Refusal::Stale);
        }
        let mut model = view.lock(self.mm)?;
        if model.mm() != self.mm || model.is_admitted() {
            return Err(Refusal::Stale);
        }
        step(&mut parent_model, &mut model)
    }
}

impl DispatchMmAuthority {
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
        let mut model = prepared.view.lock(mm)?;
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
