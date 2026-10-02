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

    /// Service a capacity refusal after releasing MM metadata/root guards.
    /// Providers without an elastic carrier authority decline the request.
    /// `Limit` requires a Linux resource-limit authority. Missing carrier
    /// storage remains `MetadataRequired` at this service boundary; after
    /// this attempt fails, the personality may answer Linux ENOMEM without
    /// transferring the admitted root back to a host placement authority.
    fn provision_metadata(&self, _mm: ReservationMm) -> Result<(), Refusal> {
        Err(Refusal::MetadataRequired)
    }
}

/// How a host thread waits for a held reservation root: spin briefly, then
/// yield, then park in short naps, for as long as the holder makes progress.
/// The holder is guest EL1 on some vCPU slot (host venues of one MM queue on
/// their host serial first): its critical section never blocks, and the run
/// loop resumes it to completion while the slot's run sequence is odd
/// ([`carrick_el1_abi::slot_run_sequence`]). There is no attempt or time
/// limit, which load would turn into a verdict. The only failure is a proven
/// contradiction: the root still names a slot whose run sequence is even and
/// unchanged across a whole failed attempt, i.e. a vCPU that executed nothing
/// while it held the root. That is fatal (the root can never be released),
/// never a silent park of a thread holding the MM's `MemState`.
#[derive(Default)]
pub struct RootHostWait {
    /// The EL1 slot and its (even) run sequence at the previous attempt.
    idle_holder: std::cell::Cell<Option<(u32, u64)>>,
}

impl RootHostWait {
    pub fn new() -> Self {
        Self::default()
    }
}

impl carrick_el1::memory::reservations::RootWait for RootHostWait {
    fn wait(&self, attempt: u32, holder: carrick_el1::memory::reservations::RootHolder) -> bool {
        use carrick_el1::memory::reservations::RootHolder;
        let idle = match holder {
            RootHolder::El1Slot(slot) => {
                let sequence = carrick_el1_abi::slot_run_sequence(slot as usize);
                sequence.is_multiple_of(2).then_some((slot, sequence))
            }
            RootHolder::Host => None,
        };
        if let Some((slot, sequence)) = idle
            && self.idle_holder.get() == Some((slot, sequence))
        {
            carrick_fatal::carrick_fatal!(
                "dispatch::el1_reservations",
                "reservation root held by EL1 slot {slot} while that slot's vCPU ran nothing (run sequence {sequence}): it left an EL1 critical section holding the root"
            );
        }
        self.idle_holder.set(idle);
        if attempt < 128 {
            std::hint::spin_loop();
        } else if attempt < 1024 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
        true
    }
}

pub trait PreparedHostReservations {
    /// The returned guard borrows this view, retaining the region and exact
    /// extent pins until the operation finishes. Resolve the exact MM's slot
    /// and use SharedReservations::lock_resolved, never a guest pointer cast.
    /// The host waits out a held root with [`RootHostWait`]: its holder is
    /// EL1 on some vCPU, whose critical section always completes, so `Busy`
    /// is never this lock's answer to a held root.
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
    /// Serializes every host venue of THIS MM's root, so the root lock's
    /// only other holder a host venue can meet is an EL1 critical section,
    /// which it waits out (see [`PreparedHostReservations::lock`]).
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
    pub(in crate::dispatch) fn provision_metadata(&self) -> Result<(), Refusal> {
        self.provider.provision_metadata(self.mm)
    }
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
