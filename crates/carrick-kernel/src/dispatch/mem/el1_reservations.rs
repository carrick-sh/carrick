//! Host venue of the shared EL1 anonymous reservation authority, and the ONE
//! production admission of an MM's delegated anonymous root.
//!
//! [`SyscallDispatcher::admit_el1_reservations`] seals the MM's published
//! root as the single owner of its anonymous-private memory
//! ([`anonymous::AnonymousAuthority::Delegated`]). The runtime calls it under
//! the MM's [`HostAliasPermit`]:
//! - at the initial MM bind and at exec ([`El1AdmissionOrigin::Bind`]): the
//!   MM's own host-setup rows are imported: plain private anonymous rows
//!   inside the heap/arena layout as EL1-editable nodes that then leave
//!   `MemState`, everything else as opaque placement obstacles the host
//!   keeps;
//! - at fork commit ([`El1AdmissionOrigin::ForkCommit`]), holding both MM
//!   permits: the child's root is seeded from the parent's committed root
//!   (`clone_into`), so a fork child stays delegated. Its host-setup twin
//!   (`MemState::fork_materialized`) only bridges fork preparation, where
//!   the child's root is not yet published.
//!
//! `CARRICK_EL1_RESERVATIONS=0` makes every admission answer
//! [`El1Admission::HostSetup`] through the same entry point: the host keeps
//! the anonymous facts, exactly as before admission existed.
//!
//! Once admitted, brk, mmap, munmap, mprotect, mremap placement, the
//! anonymous-private rows and their mlock/madvise attributes have one owner,
//! the root. Fault planning and mincore ask the root which anonymous pages
//! exist and at which protection (`fault::FirstTouchOwner`); the host keeps
//! only the residency its own venue committed, retired where the root hands
//! a hole out again and handed over when a root row is demoted.

use super::anonymous::{
    AnonymousAuthority, HostCharges, broken_root, carried_flags, opaque_flags, root_owned_row,
};
use super::*;
use crate::dispatch::mm_mutation::HostAliasPermit;
use carrick_el1::memory::reservations::{Refusal, Reservations};
use carrick_el1_abi::{
    ReservationGeneration, ReservationMm, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use std::sync::OnceLock;

/// Where an admitted root's contents come from.
pub enum El1AdmissionOrigin<'a, 'p> {
    /// Initial MM bind, or the new MM of an exec: this MM's own host-setup
    /// rows are the root's contents.
    Bind,
    /// Fork commit of a copied MM: the child (the admitting dispatcher) is
    /// seeded from `parent`'s committed root. `parent_permit` must be the
    /// parent MM's permit, held with the child's for the whole admission.
    ForkCommit {
        parent: &'a SyscallDispatcher,
        parent_permit: &'a HostAliasPermit<'p>,
    },
}

/// The owner of an MM's anonymous memory after an admission request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum El1Admission {
    /// The root owns the anonymous-private facts (now, or already).
    Delegated,
    /// The host keeps them: `CARRICK_EL1_RESERVATIONS=0`, or this carrier
    /// installed no reservation provider (no zone).
    HostSetup,
}

/// The fork a host-setup twin was materialized from: its parent's root and
/// that root's committed generation. A fork-commit admission seeds the child
/// root only from exactly this parent generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::dispatch) struct ForkSeed {
    pub(in crate::dispatch) parent: ReservationMm,
    pub(in crate::dispatch) generation: ReservationGeneration,
}

/// `CARRICK_EL1_RESERVATIONS=0` keeps every MM in host setup.
pub fn el1_reservations_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_EL1_RESERVATIONS").map_or(true, |value| value.trim() != "0")
    })
}

/// A root row to import: range, protection and insertion-time attributes.
type ImportRow = (
    ReservationRange,
    ReservationProtection,
    ReservationNodeFlags,
);

/// Every host row as a root node, and the rows the root will own (which then
/// leave `MemState`).
struct AdmissionRows {
    rows: Vec<ImportRow>,
    owned: Vec<(u64, u64)>,
}

fn admission_rows(mem: &MemState) -> Result<AdmissionRows, Refusal> {
    let mut owned = Vec::new();
    let rows = mem
        .semantic_vmas
        .iter()
        .map(|vma| {
            let range = ReservationRange::new(vma.start, vma.end).ok_or(Refusal::Invalid)?;
            let bits =
                u64::from(vma.read) | (u64::from(vma.write) << 1) | (u64::from(vma.execute) << 2);
            let prot = ReservationProtection::from_bits(bits).ok_or(Refusal::Invalid)?;
            let flags = if root_owned_row(vma, mem) {
                owned.push((vma.start, vma.end));
                ReservationNodeFlags::ANONYMOUS_PRIVATE.union(carried_flags(vma))
            } else {
                opaque_flags(vma, mem)
            };
            Ok((range, prot, flags))
        })
        .collect::<Result<_, Refusal>>()?;
    Ok(AdmissionRows { rows, owned })
}

/// An admission of an MM that is already delegated: idempotent for its own
/// root, stale for any other.
fn already_delegated(mem: &MemState, root: &DelegatedRoot) -> Result<El1Admission, Refusal> {
    match mem.delegated_root() {
        Some(own) if own.mm() == root.mm() => Ok(El1Admission::Delegated),
        _ => Err(Refusal::Stale),
    }
}

/// Seal `mem`'s own rows into its published root.
fn admit_bind(
    mem: &mut MemState,
    root: &DelegatedRoot,
    (address_limit, data_limit): (u64, u64),
) -> Result<El1Admission, Refusal> {
    match mem.anonymous_authority() {
        AnonymousAuthority::Delegated(_) => return already_delegated(mem, root),
        // A fork twin carries its parent's incarnations: only its fork
        // commit may seal it.
        AnonymousAuthority::HostSetup(arena) if arena.fork_seed.is_some() => {
            return Err(Refusal::Stale);
        }
        AnonymousAuthority::HostSetup(_) => {}
    }
    let brk = mem.program_break();
    let layout = mem.layout;
    let heap = layout
        .heap_base
        .checked_add(layout.heap_size)
        .and_then(|end| ReservationRange::new(layout.heap_base, end))
        .ok_or(Refusal::Invalid)?;
    let arena = layout
        .mmap_base
        .checked_add(layout.mmap_size)
        .and_then(|end| ReservationRange::new(layout.mmap_base, end))
        .ok_or(Refusal::Invalid)?;
    let AdmissionRows { rows, owned } = admission_rows(mem)?;
    // Taken before the root guard (the projection must not read the root).
    // Every owned row becomes a root node, so it is never charged here.
    let host = HostCharges::at_admission(mem);
    root.with_root_for_import(|model| {
        let result = (|| {
            let mut import = model.layout();
            import.heap = heap;
            import.arena = arena;
            import.brk = brk;
            import.address_limit = address_limit;
            import.data_limit = data_limit;
            import.external_address_bytes = 0;
            import.external_data_bytes = 0;
            model.configure_import(import)?;
            for (range, prot, flags) in rows {
                model.import_with(range, prot, flags)?;
            }
            // Sealed with the exact charges of everything it does not hold:
            // the guest venue decides against them from its first proposal.
            let (address, data) = host.beyond(model)?;
            model.set_external_charges(address, data);
            model.finish_import()
        })();
        if result.is_err() && !model.is_admitted() {
            // A failed import exposes no partial authority.
            model.abort_import()?;
        }
        result
    })?;
    mem.seal_delegated(root, &owned);
    Ok(El1Admission::Delegated)
}

/// Seed the fork child `mem`'s root from `parent`'s committed root.
fn admit_fork(
    parent: &MemState,
    mem: &mut MemState,
    root: &DelegatedRoot,
    (address_limit, data_limit): (u64, u64),
    unchanged: bool,
) -> Result<El1Admission, Refusal> {
    let seed = match mem.anonymous_authority() {
        AnonymousAuthority::Delegated(_) => return already_delegated(mem, root),
        AnonymousAuthority::HostSetup(arena) => arena.fork_seed.ok_or(Refusal::Stale)?,
    };
    let parent_root = parent.delegated_root().ok_or(Refusal::Stale)?;
    // The twin must still be exactly the fork's: neither MM edited since.
    if seed.parent != parent_root.mm() || !unchanged {
        return Err(Refusal::Stale);
    }
    // The parent's permit excludes its host venue; one still open is a
    // syscall that never settled.
    if parent.host_venue_open() {
        return Err(Refusal::Busy);
    }
    let host = HostCharges::at_admission(mem);
    let mut owned = Vec::new();
    root.seed_from(parent_root, |parent, child| {
        if parent.generation() != seed.generation {
            return Err(Refusal::Stale);
        }
        // Busy while a guest-venue proposal is pending on the parent: its
        // backend work must settle first, never be copied half-done.
        parent.clone_into(child)?;
        // The child root is admitted: nothing below may refuse.
        child.set_limits(address_limit, data_limit);
        let (address, data) = host
            .beyond(child)
            .unwrap_or_else(|refusal| broken_root("a fork admission charge", refusal));
        child.set_external_charges(address, data);
        child
            .observe_mappings(&mut |mapping| {
                if mapping.anonymous {
                    owned.push((mapping.range.start(), mapping.range.end()));
                }
            })
            .unwrap_or_else(|refusal| broken_root("a fork admission observation", refusal));
        Ok(())
    })?;
    mem.seal_delegated(root, &owned);
    Ok(El1Admission::Delegated)
}

impl MemView<'_> {
    /// See [`SyscallDispatcher::admit_el1_reservations`]; `enabled` is the
    /// `CARRICK_EL1_RESERVATIONS` hatch.
    pub(in crate::dispatch) fn admit_el1_reservations(
        &self,
        permit: &HostAliasPermit<'_>,
        origin: El1AdmissionOrigin<'_, '_>,
        enabled: bool,
    ) -> Result<El1Admission, Refusal> {
        let authority = self.mm_authority();
        if permit.mm() != authority.mm_id {
            return Err(Refusal::Stale);
        }
        if !enabled || !authority.has_reservation_provider() {
            return Ok(El1Admission::HostSetup);
        }
        let _exclusion = self.begin_host_alias_dispatch(permit);
        let root = authority.delegated_root()?;
        let limits = self
            .address_space_limits_apply(true)
            .unwrap_or((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY));
        match origin {
            El1AdmissionOrigin::Bind => admit_bind(&mut authority.lock(), &root, limits),
            El1AdmissionOrigin::ForkCommit {
                parent,
                parent_permit,
            } => {
                let parent_authority = parent.mm_authority();
                if parent_authority.mm_id == authority.mm_id
                    || !parent_permit.authorizes(
                        &parent_authority.mutation_coordinator,
                        parent_authority.mm_id,
                    )
                {
                    return Err(Refusal::Stale);
                }
                // The child's host-setup twin starts at the parent's VMA
                // revision; any host edit of either since moves it.
                let unchanged = authority.vma_revision() == parent_authority.vma_revision();
                // Parent before child, the fork's own order.
                let parent_mem = parent_authority.lock();
                let mut mem = authority.lock();
                admit_fork(&parent_mem, &mut mem, &root, limits, unchanged)
            }
        }
    }
}

impl MemView<'_> {
    /// Hand the root everything it now decides in the host protection
    /// registry: its holes in the heap and the mmap arena (a seeded heap
    /// `unmapped` mark, a loader's `munmap`) and the root-decided pages of
    /// its anonymous rows (see `GuestMemory::release_root_facts`). Guest
    /// EL1 places and edits there without the host, so a host fact left
    /// behind would refuse host reads and copyouts of EL1's mappings.
    pub(in crate::dispatch) fn release_root_territory<M: CurrentMmMemory + ?Sized>(
        &self,
        memory: &mut M,
    ) {
        let (root, layout, rows) = {
            let authority = self.mm_authority();
            let mem = authority.lock();
            let Some(root) = mem.delegated_root().cloned() else {
                return;
            };
            (root, mem.layout, mem.root_anonymous_rows())
        };
        let territory = [
            (layout.heap_base, layout.heap_size),
            (layout.mmap_base, layout.mmap_size),
        ];
        let mut holes = Vec::new();
        for (base, size) in territory {
            let Some(range) = base
                .checked_add(size)
                .and_then(|end| ReservationRange::new(base, end))
            else {
                continue;
            };
            holes.extend(
                root.with_root(|model| super::fault::root_holes(model, range))
                    .unwrap_or_else(|refusal| broken_root("a territory observation", refusal)),
            );
        }
        for (start, end) in holes {
            memory.return_to_root(start, (end - start) as usize);
        }
        for row in rows {
            memory.release_root_facts(row.start, (row.end - row.start) as usize);
        }
    }

    /// Whether this MM is a copied-MM fork twin of `parent`: a delegated
    /// parent's twin names its root; a host-setup parent's child carries no
    /// seed. A delegated MM is nobody's unsealed twin.
    pub(in crate::dispatch) fn is_fork_twin_of(&self, parent: crate::kernel::MmId) -> bool {
        match self.mm_authority().lock().anonymous_authority() {
            AnonymousAuthority::Delegated(_) => false,
            AnonymousAuthority::HostSetup(arena) => arena
                .fork_seed
                .is_none_or(|seed| seed.parent.raw() == parent.raw()),
        }
    }

    /// Publish a fork child's address space (and its reservation root) at
    /// its fork commit, with the anchors its host-setup twin carries and the
    /// forking thread's limits, which the child inherits. See
    /// [`crate::dispatch::mm_mutation::ForkCommit::publish_child_address_space`].
    pub(in crate::dispatch) fn publish_fork_child_address_space(
        &self,
        ttbr0: u64,
        ttbr1: u64,
    ) -> Option<crate::kernel::AddressSpacePublication> {
        let authority = self.mm_authority();
        authority.seal_reservation_provider();
        let (brk_current, mmap_next) = {
            let state = authority.lock();
            (state.program_break(), state.arena_high_water())
        };
        let (address, data) = self
            .address_space_limits_apply(true)
            .unwrap_or((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY));
        crate::kernel::publish_address_space_with_layout(
            authority.mm_id,
            authority.pt_quiesce(),
            ttbr0,
            ttbr1,
            brk_current,
            mmap_next,
            crate::kernel::mm_occupancy::ReservationRootPublication {
                limits: crate::kernel::ReservationLimits { address, data },
                provider: authority.reservation_provider_for_publication(),
            },
        )
    }
}

impl SyscallDispatcher {
    /// The ONE production admission of this MM's delegated anonymous root.
    ///
    /// Locking contract: the caller holds THIS MM's `permit` (and, for
    /// [`El1AdmissionOrigin::ForkCommit`], the parent MM's permit too, with
    /// the parent quiesced at its fork commit and the child not yet run).
    /// The root must be published (the MM's address space) and no root guard
    /// may be held. Inside, the MM's host-alias dispatch is begun, then the
    /// parent's `MemState` lock (fork), this MM's `MemState` lock, the
    /// parent's and this MM's host queues, and the root guards; no backend
    /// service runs under any of them.
    ///
    /// `Ok(HostSetup)`: `CARRICK_EL1_RESERVATIONS=0` or no carrier
    /// provider; nothing changed. `Ok(Delegated)`: the root owns the MM's
    /// anonymous memory (idempotent). `Err`: nothing changed; the MM stays
    /// in host setup (`Stale`: wrong permit, unpublished root, a fork twin
    /// admitted as a bind, or a fork parent that moved on; `Busy`: a root
    /// proposal is still pending; `MetadataRequired`: node storage must be
    /// provisioned first).
    pub(crate) fn admit_el1_reservations(
        &self,
        permit: &HostAliasPermit<'_>,
        origin: El1AdmissionOrigin<'_, '_>,
    ) -> Result<El1Admission, Refusal> {
        self.mem_view()
            .admit_el1_reservations(permit, origin, el1_reservations_enabled())
    }

    /// Publish this MM's address space at its first load (the initial
    /// runner, or the new MM of an exec) for guest EL1 to install, and admit
    /// its just-published reservation root as the owner of its anonymous
    /// memory ([`El1AdmissionOrigin::Bind`]) in the same step: an address
    /// space is never published without its admission being decided.
    /// `participation` is this MM's loading executor; the admission takes
    /// its exact-MM mutation authority before publication and retains it
    /// through admission.
    ///
    /// A fork child is published and admitted by its fork commit instead
    /// ([`crate::dispatch::mm_mutation::ForkCommit::publish_and_admit_child`]).
    /// `None`: nothing was published (no EL1 zone, or the table refused).
    /// Every admission outcome, including a refusal that leaves the MM in
    /// host setup, fires `hvpatch-el1-root-admission`.
    pub fn publish_bound_address_space<M: CurrentMmMemory + ?Sized>(
        &self,
        participation: &mut crate::dispatch::MmExecutorParticipation,
        memory: &mut M,
        ttbr0: u64,
        ttbr1: u64,
    ) -> Option<crate::kernel::AddressSpacePublication> {
        if !participation.authorizes(&self.mm_authority()) {
            carrick_fatal::carrick_fatal!(
                "dispatch::el1_reservations",
                "address space publication by another MM's executor: participation mm={:?}",
                participation.mm_id()
            );
        }
        self.with_address_space_admission(participation, |admission| {
            admission.publish(memory, ttbr0, ttbr1, false).map(|_| ())
        })
        .map(|(publication, ())| publication)
    }
}

/// Mutation admission precedes publication and remains held through root
/// import. The borrowed physical permit cannot outlive this exact owner.
pub struct BoundAddressSpaceAdmission<'a> {
    dispatcher: &'a SyscallDispatcher,
    mutation: crate::dispatch::mm_mutation::MmMutationGuard<'a>,
    owner: crate::dispatch::mm_authority::AddressSpacePublicationOwner,
    publication: crate::kernel::mm_occupancy::PreAdmissionGuard,
    prepared: core::cell::RefCell<Option<crate::kernel::AddressSpacePublication>>,
    #[cfg(test)]
    after_publication: core::cell::RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}
impl SyscallDispatcher {
    /// Run physical preparation and normal admission under one publication
    /// owner. The callback cannot let borrowed permits escape. The returned
    /// publication leaves only after the owner's lock is released.
    pub fn with_address_space_admission<R>(
        &self,
        participation: &mut crate::dispatch::MmExecutorParticipation,
        operation: impl FnOnce(&BoundAddressSpaceAdmission<'_>) -> Option<R>,
    ) -> Option<(crate::kernel::AddressSpacePublication, R)> {
        let admission = self.begin_address_space_admission(participation)?;
        let result = operation(&admission)?;
        let publication = admission.prepared.borrow_mut().take()?;
        drop(admission);
        Some((publication, result))
    }
    fn begin_address_space_admission<'a>(
        &'a self,
        participation: &'a mut crate::dispatch::MmExecutorParticipation,
    ) -> Option<BoundAddressSpaceAdmission<'a>> {
        self.begin_address_space_admission_with(
            participation,
            crate::kernel::mm_occupancy::PreAdmissionGuard::acquire,
        )
    }
    fn begin_address_space_admission_with<'a>(
        &'a self,
        participation: &'a mut crate::dispatch::MmExecutorParticipation,
        acquire: impl FnOnce(
            crate::kernel::MmId,
        ) -> Option<crate::kernel::mm_occupancy::PreAdmissionGuard>,
    ) -> Option<BoundAddressSpaceAdmission<'a>> {
        if !participation.authorizes(&self.mm_authority()) {
            return None;
        }
        let owner = participation.address_space_publication_owner();
        let mm = participation.mm_id();
        let mutation = match crate::dispatch::mm_mutation::from_executor(participation) {
            Ok(mutation) => mutation,
            Err(_) => {
                RootAdmission::NoAuthority.trace(
                    mm,
                    carrick_observability::probes::HvpatchEl1RootOrigin::Bind,
                );
                return None;
            }
        };
        let publication = acquire(mm)?;
        Some(BoundAddressSpaceAdmission {
            dispatcher: self,
            mutation,
            owner,
            publication,
            prepared: core::cell::RefCell::new(None),
            #[cfg(test)]
            after_publication: core::cell::RefCell::new(None),
        })
    }
}
impl BoundAddressSpaceAdmission<'_> {
    pub fn permit(&self) -> Option<carrick_hal::PreAdmissionPermit<'_>> {
        self.publication.permit()
    }
    /// A physical import requires successful normal delegated admission. On
    /// refusal, cleanup uses the same publication lock before physical rollback.
    pub fn publish_import<M: CurrentMmMemory + ?Sized>(
        &self,
        memory: &mut M,
        ttbr0: u64,
        ttbr1: u64,
    ) -> Option<carrick_hal::PreAdmissionReceipt<'_>> {
        self.publish(memory, ttbr0, ttbr1, true)?
    }
    fn publish<M: CurrentMmMemory + ?Sized>(
        &self,
        memory: &mut M,
        ttbr0: u64,
        ttbr1: u64,
        require_delegated: bool,
    ) -> Option<Option<carrick_hal::PreAdmissionReceipt<'_>>> {
        *self.prepared.borrow_mut() = Some(self.owner.publish(&self.publication, ttbr0, ttbr1)?);
        #[cfg(test)]
        if let Some(hook) = self.after_publication.borrow_mut().take() {
            hook();
        }
        let admission =
            RootAdmission::of(self.dispatcher.admit_el1_reservations(
                &self.mutation.host_alias_permit(),
                El1AdmissionOrigin::Bind,
            ));
        admission.trace(
            self.mutation.mm_id(),
            carrick_observability::probes::HvpatchEl1RootOrigin::Bind,
        );
        let receipt = if admission == RootAdmission::Decided(El1Admission::Delegated) {
            self.dispatcher.mem_view().release_root_territory(memory);
            // SAFETY: descriptor/backing setup preceded this call; exact root
            // import completed under mutation and publication authority.
            Some(unsafe { carrick_hal::PreAdmissionReceipt::after_admission(&self.publication) })
        } else {
            if require_delegated {
                if let Some(publication) = self.prepared.borrow_mut().take() {
                    self.publication.refuse(publication);
                }
                return None;
            }
            None
        };
        Some(receipt)
    }
}
impl Drop for BoundAddressSpaceAdmission<'_> {
    fn drop(&mut self) {
        if let Some(publication) = self.prepared.get_mut().take() {
            self.publication.refuse(publication);
        }
    }
}

/// What one published address space's root admission decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootAdmission {
    Decided(El1Admission),
    Refused(Refusal),
    /// No exact-MM mutation authority could be taken; nothing was asked.
    NoAuthority,
}

impl RootAdmission {
    pub(crate) fn of(result: Result<El1Admission, Refusal>) -> Self {
        result.map_or_else(Self::Refused, Self::Decided)
    }

    pub(crate) fn trace(
        self,
        mm: crate::kernel::MmId,
        origin: carrick_observability::probes::HvpatchEl1RootOrigin,
    ) {
        use carrick_observability::probes::HvpatchEl1RootAdmission as Outcome;
        let outcome = match self {
            Self::Decided(El1Admission::Delegated) => Outcome::Delegated,
            Self::Decided(El1Admission::HostSetup) => Outcome::HostSetup,
            Self::NoAuthority => Outcome::NoAuthority,
            Self::Refused(Refusal::Busy) => Outcome::RefusedBusy,
            Self::Refused(Refusal::Stale) => Outcome::RefusedStale,
            Self::Refused(Refusal::Invalid) => Outcome::RefusedInvalid,
            Self::Refused(Refusal::MetadataRequired) => Outcome::RefusedMetadataRequired,
            Self::Refused(_) => Outcome::RefusedOther,
        };
        crate::probes::hvpatch_el1_root_admission(mm.raw(), origin, outcome);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1::memory::reservations::{Decision, Layout, SharedReservations};
    use carrick_el1_abi::{ReservationBackingReceipt, ReservationCompletion};

    fn shared() -> Box<SharedReservations> {
        // This is the same zeroed-region initialization as EL1 bootstrap.
        let ptr =
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        unsafe { Box::from_raw(ptr.cast()) }
    }
    fn snapshot() -> MemState {
        let mut mem = MemState::new();
        mem.semantic_vmas
            .insert(SemanticVma {
                start: mem.layout.mmap_base,
                end: mem.layout.mmap_base + 8192,
                read: true,
                write: true,
                execute: false,
                provenance: VmaBackingProvenance::PrivateAnonymous,
                fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
                dump_policy: carrick_abi::VmaDumpPolicy::Include,
                droppable: false,
                path: String::new(),
                file_page_offset: None,
            })
            .unwrap();
        mem
    }
    /// The el1 model's own import API over a hand-built snapshot: a fixture
    /// of the root model, not a host admission (that is
    /// `SyscallDispatcher::admit_el1_reservations`).
    fn seal(model: &mut Reservations<'_>, mem: &MemState) -> Result<(), Refusal> {
        for vma in &mem.semantic_vmas {
            let range = ReservationRange::new(vma.start, vma.end).ok_or(Refusal::Invalid)?;
            let bits =
                u64::from(vma.read) | (u64::from(vma.write) << 1) | (u64::from(vma.execute) << 2);
            model.import(
                range,
                ReservationProtection::from_bits(bits).ok_or(Refusal::Invalid)?,
                vma.provenance.is_private_anonymous(),
            )?;
        }
        model.finish_import()
    }
    fn publish(table: &SharedReservations, mem: &MemState, index: usize) -> ReservationMm {
        let mm = ReservationMm::new(index as u64 + 41).unwrap();
        table
            .publish(
                index,
                mm,
                Layout {
                    heap: ReservationRange::new(
                        mem.layout.heap_base,
                        mem.layout.heap_base + mem.layout.heap_size,
                    )
                    .unwrap(),
                    arena: ReservationRange::new(
                        mem.layout.mmap_base,
                        mem.layout.mmap_base + mem.layout.mmap_size,
                    )
                    .unwrap(),
                    brk: mem.program_break(),
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        mm
    }

    #[test]
    fn reservation_proc_provider_rejects_wrong_mm_guard_and_wrong_permit() {
        struct View {
            table: Arc<SharedReservations>,
            index: usize,
            mm: ReservationMm,
        }
        impl PreparedHostReservations for View {
            fn lock(&self, _mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
                self.table.lock_waiting(
                    self.index,
                    self.mm,
                    &crate::dispatch::mem::el1_reservations::RootHostWait::new(),
                )
            }
        }
        let table: Arc<SharedReservations> = Arc::from(shared());
        let mem = snapshot();
        let a = publish(&table, &mem, 0);
        let b = publish(&table, &mem, 1);
        for (index, mm) in [(0, a), (1, b)] {
            seal(&mut table.lock(index, mm).unwrap(), &mem).unwrap();
        }
        let mm_id = |key: ReservationMm| {
            crate::kernel::MmId::from_registry_allocation(
                std::num::NonZeroU64::new(key.raw()).unwrap(),
            )
        };
        let authority = crate::dispatch::mm_authority::DispatchMmAuthority::new(mm_id(a));
        let peer = crate::dispatch::mm_authority::DispatchMmAuthority::new(mm_id(b));
        struct Provider {
            table: Arc<SharedReservations>,
            index: usize,
            mm: ReservationMm,
        }
        impl HostReservationProvider for Provider {
            fn prepare(&self) -> Result<Box<dyn PreparedHostReservations>, Refusal> {
                Ok(Box::new(View {
                    table: Arc::clone(&self.table),
                    index: self.index,
                    mm: self.mm,
                }))
            }
        }
        authority
            .install_reservation_provider(Arc::new(Provider {
                table: Arc::clone(&table),
                index: 0,
                mm: a,
            }))
            .unwrap();
        peer.install_reservation_provider(Arc::new(Provider {
            table: Arc::clone(&table),
            index: 0,
            mm: a,
        }))
        .unwrap();
        let defective = crate::dispatch::mm_authority::DispatchMmAuthority::new(mm_id(a));
        defective
            .install_reservation_provider(Arc::new(Provider {
                table,
                index: 1,
                mm: b,
            }))
            .unwrap();
        let own = authority.prepare_el1_reservations().unwrap();
        let wrong = peer.prepare_el1_reservations().unwrap();
        let mismatched_mm = defective.prepare_el1_reservations().unwrap();
        let host = NonAnonymousVmas::try_from((a, VmaMap::new())).unwrap();
        crate::dispatch::mm_mutation::test_support::with_permit(
            Arc::clone(&authority.mutation_coordinator),
            |permit| {
                assert_eq!(
                    authority
                        .observe_el1_proc_maps(permit, &own, &host)
                        .unwrap()
                        .mm(),
                    a
                );
                assert!(matches!(
                    authority.observe_el1_proc_maps(permit, &wrong, &host),
                    Err(Refusal::Stale)
                ));
            },
        );
        crate::dispatch::mm_mutation::test_support::with_permit(
            Arc::clone(&peer.mutation_coordinator),
            |permit| {
                assert!(matches!(
                    authority.observe_el1_proc_maps(permit, &own, &host),
                    Err(Refusal::Stale)
                ));
            },
        );
        crate::dispatch::mm_mutation::test_support::with_permit(
            Arc::clone(&defective.mutation_coordinator),
            |permit| {
                assert!(matches!(
                    defective.observe_el1_proc_maps(permit, &mismatched_mm, &host),
                    Err(Refusal::Stale)
                ));
            },
        );
    }

    #[test]
    fn reservation_proc_projection_rejects_a_second_anonymous_owner() {
        let mem = snapshot();
        assert!(matches!(
            NonAnonymousVmas::try_from((
                ReservationMm::new(41).unwrap(),
                mem.semantic_vmas.clone()
            )),
            Err(Refusal::ForeignMapping)
        ));
    }

    #[test]
    fn reservation_proc_projection_tracks_two_mm_generations_and_rollback() {
        let table = shared();
        let mem = snapshot();
        let va = mem.layout.mmap_base;
        let a = publish(&table, &mem, 0);
        let b = publish(&table, &mem, 1);
        let host = NonAnonymousVmas::try_from((a, VmaMap::new())).unwrap();
        for (index, mm) in [(0, a), (1, b)] {
            seal(&mut table.lock(index, mm).unwrap(), &mem).unwrap();
        }
        let initial = ReservationProcMaps::capture(&mut table.lock(0, a).unwrap(), &host).unwrap();
        let mut guest = table.lock(0, a).unwrap();
        let Decision::Work(request) = guest
            .mprotect(
                ReservationRange::new(va, va + 4096).unwrap(),
                ReservationProtection::NONE,
            )
            .unwrap()
        else {
            panic!("expected descriptor work")
        };
        let pending = ReservationProcMaps::capture(&mut guest, &host).unwrap();
        assert_eq!(pending.generation(), initial.generation());
        assert!(pending.maps()[0].write);
        guest.refuse(request).unwrap();
        let rolled_back = ReservationProcMaps::capture(&mut guest, &host).unwrap();
        assert_eq!(rolled_back.generation(), initial.generation());
        assert!(rolled_back.maps()[0].write);
        let Decision::Work(request) = guest
            .mprotect(
                ReservationRange::new(va, va + 4096).unwrap(),
                ReservationProtection::NONE,
            )
            .unwrap()
        else {
            panic!("expected descriptor work")
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        guest.complete(completion).unwrap();
        let changed = ReservationProcMaps::capture(&mut guest, &host).unwrap();
        assert_eq!(changed.mm(), a);
        assert_eq!(changed.generation(), guest.mapping(va).unwrap().generation);
        assert_ne!(changed.generation(), initial.generation());
        assert!(!changed.maps()[0].read);
        assert!(!changed.maps()[0].write);
        assert_eq!(changed.brk_current(), mem.layout.heap_base);
        drop(guest);
        let mut peer = table.lock(1, b).unwrap();
        assert!(matches!(
            ReservationProcMaps::capture(&mut peer, &host),
            Err(Refusal::Stale)
        ));
        let host = NonAnonymousVmas::try_from((b, VmaMap::new())).unwrap();
        let unchanged = ReservationProcMaps::capture(&mut peer, &host).unwrap();
        assert_eq!(unchanged.mm(), b);
        assert_eq!(unchanged.generation(), initial.generation());
        assert!(unchanged.maps()[0].write);
        assert_eq!(
            unchanged.generation(),
            peer.fault_plan(va, 4096, ReservationProtection::READ_WRITE)
                .unwrap()
                .generation
        );

        let mut conflicting = mem.semantic_vmas.clone().into_vec();
        conflicting[0].provenance = VmaBackingProvenance::SharedFile;
        let conflicting = NonAnonymousVmas::try_from((b, VmaMap::from_vec(conflicting))).unwrap();
        assert!(matches!(
            ReservationProcMaps::capture(&mut peer, &conflicting),
            Err(Refusal::ForeignMapping)
        ));
    }

    #[test]
    fn reservation_host_import_two_mm_observers_share_fault_generation() {
        let table = shared();
        let mem = snapshot();
        let a = publish(&table, &mem, 0);
        let b = publish(&table, &mem, 1);
        for (index, mm) in [(0, a), (1, b)] {
            seal(&mut table.lock(index, mm).unwrap(), &mem).unwrap();
        }
        let va = mem.layout.mmap_base;
        let original = table
            .lock(0, a)
            .unwrap()
            .fault_plan(va, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        let mut guest = table.lock(0, a).unwrap();
        let Decision::Work(request) = guest
            .mprotect(
                ReservationRange::new(va, va + 4096).unwrap(),
                ReservationProtection::NONE,
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(!guest.authenticate_fault(original));
        guest.refuse(request).unwrap();
        assert!(guest.authenticate_fault(original));
        let Decision::Work(request) = guest
            .mprotect(
                ReservationRange::new(va, va + 4096).unwrap(),
                ReservationProtection::NONE,
            )
            .unwrap()
        else {
            panic!()
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        guest.complete(completion).unwrap();
        drop(guest);
        let mut host = table.lock(0, a).unwrap();
        assert!(!host.authenticate_fault(original));
        assert_eq!(
            host.mapping(va).unwrap().protection,
            ReservationProtection::NONE
        );
        assert_eq!(
            host.fault_plan(va, 4096, ReservationProtection::READ_WRITE),
            Err(Refusal::Limit)
        );
        let mut peer = table.lock(1, b).unwrap();
        assert_eq!(
            peer.mapping(va).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert!(!peer.authenticate_fault(original));
    }

    #[test]
    fn reservation_host_failed_import_exposes_no_partial_authority() {
        let table = shared();
        let mut mem = snapshot();
        let mut invalid = mem.semantic_vmas.as_slice()[0].clone();
        invalid.start += 8193;
        invalid.end += 16384;
        mem.semantic_vmas.insert(invalid).unwrap();
        let mm = publish(&table, &mem, 0);
        let mut model = table.lock(0, mm).unwrap();
        assert_eq!(seal(&mut model, &mem), Err(Refusal::Invalid));
        assert!(model.mapping(mem.layout.mmap_base).is_none());
        model.abort_import().unwrap();
        assert!(model.mapping(mem.layout.mmap_base).is_none());
        let mem = snapshot();
        seal(&mut model, &mem).unwrap();
        assert!(model.mapping(mem.layout.mmap_base).is_some());
    }
    #[test]
    fn publication_to_root_admission_keeps_exact_mutation_authority() {
        let dispatcher = SyscallDispatcher::new();
        let mut executor = dispatcher.enter_mm_executor().unwrap();
        let mm = executor.mm_id();
        let spaces = Box::leak(Box::new(carrick_sched_core::AddressSpaces::new()));
        let occupancy = Box::leak(Box::new(carrick_sched_core::Occupancy::new()));
        let admission = dispatcher
            .begin_address_space_admission_with(&mut executor, |mm| {
                crate::kernel::mm_occupancy::PreAdmissionGuard::for_test(spaces, occupancy, mm)
            })
            .unwrap();
        *admission.after_publication.borrow_mut() = Some(Box::new(|| {
            let index = spaces.find(mm.raw()).unwrap();
            std::thread::scope(|scope| {
                let edit = scope.spawn(|| {
                    spaces
                        .try_begin_edit(index, mm.raw(), core::num::NonZeroU64::new(2).unwrap())
                        .is_some()
                });
                assert!(
                    !edit.join().unwrap(),
                    "edit entered after publication before root admission"
                );
            });
        }));
        let mut memory = crate::dispatch::LinearMemory::new(0x10000, vec![0; 4096]);
        assert!(
            admission
                .publish(&mut memory, 0x1000, 0x1000, false)
                .is_some()
        );
        let index = spaces.find(mm.raw()).unwrap();
        assert!(!spaces.is_open(mm.raw()));
        let publication = admission.prepared.borrow_mut().take().unwrap();
        drop(admission);
        assert!(
            spaces
                .try_begin_edit(index, mm.raw(), core::num::NonZeroU64::new(2).unwrap())
                .is_some()
        );
        drop(publication);
        // This VM-free owner has no installed zone root, so normal import
        // admission refuses delegation. Cleanup must reuse its held lock.
        let refused = dispatcher
            .begin_address_space_admission_with(&mut executor, |mm| {
                crate::kernel::mm_occupancy::PreAdmissionGuard::for_test(spaces, occupancy, mm)
            })
            .unwrap();
        assert!(
            refused
                .publish_import(&mut memory, 0x1000, 0x1000)
                .is_none()
        );
        assert!(spaces.find(mm.raw()).is_none());
        assert!(refused.prepared.borrow().is_none());
        assert!(refused.permit().is_some());
        drop(refused);
    }
}

#[path = "el1_reservations/projection.rs"]
mod projection;
pub use projection::{NonAnonymousVmas, ReservationProcMaps};

#[path = "el1_reservations/provider.rs"]
mod provider;
pub(in crate::dispatch) use provider::{DelegatedRoot, ReservationProviderSlot};
pub use provider::{
    HostReservationProvider, PreparedHostReservations, PreparedReservationSession, RootHostWait,
};

#[path = "el1_reservations/returns.rs"]
mod returns;
pub use returns::El1ReturnError;
pub(crate) use returns::settle_final_root;
