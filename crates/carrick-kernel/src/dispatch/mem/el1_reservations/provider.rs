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
}

impl ReservationProviderSlot {
    pub(in crate::dispatch) fn inherited(&self) -> Self {
        Self {
            published: false,
            provider: self.provider.clone(),
        }
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
        let installed = self
            .reservation_provider
            .lock()
            .provider
            .clone()
            .ok_or(Refusal::ForeignMapping)?;
        if !Arc::ptr_eq(&installed, &prepared.provider) {
            return Err(Refusal::Stale);
        }
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
