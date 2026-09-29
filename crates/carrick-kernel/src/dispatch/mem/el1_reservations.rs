//! Host venue of the shared EL1 anonymous reservation authority.
//!
//! T2 integration: before enabling `decide_anonymous_syscall` for an MM, call
//! `admit_el1_reservations` under its mutation permit. Thereafter grant service
//! uses `el1_reservation_fault_plan`, NOT `resident_frame_grant_plan`: backing
//! eligibility comes from the shared root, not FirstTouchArming. The plan owns
//! exact-MM alias exclusion and a borrowed owned-pin storage view across backing service.
//! Refresh `ResolvedReservationNodes` through the carrier metadata resolver before
//! acquiring the MM permit; pass that view to `el1_reservation_fault_plan`. Reauthenticate immediately
//! before publishing the grant receipt. A generation mismatch is refusal, never
//! permission to replay the Linux syscall or revive an old mapping.
//!
//! Production admission currently fails closed with `ForeignMapping`: the
//! legacy MemState authority still serves mmap/munmap/mprotect/brk/mremap,
//! madvise, fault planning, mincore, proc maps, fork and exec/exit. None of those
//! MMs may seal a shared root until those paths relinquish their anonymous
//! facts. The snapshot importer below is a host-only conformance fixture, not
//! a second production authority or an activation mechanism.

use super::*;
#[cfg(test)]
use carrick_el1::memory::reservations::Layout;
use carrick_el1::memory::reservations::{
    Refusal, ReservationFaultPlan, Reservations, ResolvedReservationNodes, shared_host,
};
#[cfg(test)]
use carrick_el1_abi::ReservationRange;
use carrick_el1_abi::{PinnedMetadataExtent, ReservationMm, ReservationProtection};

pub struct El1ReservationFaultPlan<'permit, P: PinnedMetadataExtent> {
    nodes: &'permit ResolvedReservationNodes<P>,
    plan: ReservationFaultPlan,
    index: usize,
    exclusion: HostAliasDispatchGuard<'permit>,
}

impl<P: PinnedMetadataExtent> El1ReservationFaultPlan<'_, P> {
    pub fn reservation(&self) -> ReservationFaultPlan {
        self.plan
    }
}

fn index_for(mm: ReservationMm) -> Result<usize, Refusal> {
    let zone = carrick_el1_abi::zone_tables().ok_or(Refusal::Stale)?;
    zone.spaces
        .find(mm.raw())
        .map(|index| index.index())
        .ok_or(Refusal::Stale)
}

fn admit_host_snapshot(
    _model: &mut Reservations<'_>,
    _mem: &MemState,
    _limits: (u64, u64),
) -> Result<(), Refusal> {
    // The presence of an accessible MemState means these facts still have a
    // host writer. Sealing a snapshot here would create two Linux answers.
    Err(Refusal::ForeignMapping)
}

#[cfg(test)]
fn import_snapshot(
    model: &mut Reservations<'_>,
    mem: &MemState,
    limits: (u64, u64),
) -> Result<(), Refusal> {
    if model.is_admitted() {
        return Err(Refusal::Stale);
    }
    let heap = mem
        .layout
        .heap_base
        .checked_add(mem.layout.heap_size)
        .and_then(|end| ReservationRange::new(mem.layout.heap_base, end))
        .ok_or(Refusal::Invalid)?;
    let arena = mem
        .layout
        .mmap_base
        .checked_add(mem.layout.mmap_size)
        .and_then(|end| ReservationRange::new(mem.layout.mmap_base, end))
        .ok_or(Refusal::Invalid)?;
    let mut modeled_address = 0u64;
    let mut modeled_data = 0u64;
    for vma in &mem.semantic_vmas {
        modeled_address = modeled_address
            .checked_add(vma.end - vma.start)
            .ok_or(Refusal::Invalid)?;
        if eligible(vma, mem) && vma.write {
            modeled_data = modeled_data
                .checked_add(vma.end - vma.start)
                .ok_or(Refusal::Invalid)?;
        }
    }
    model.configure_import(Layout {
        heap,
        arena,
        brk: mem.brk_current,
        address_limit: limits.0,
        data_limit: limits.1,
        external_address_bytes: committed_va_bytes(mem).saturating_sub(modeled_address),
        external_data_bytes: data_va_bytes(mem).saturating_sub(modeled_data),
    })?;
    for vma in &mem.semantic_vmas {
        let range = ReservationRange::new(vma.start, vma.end).ok_or(Refusal::Invalid)?;
        let bits =
            u64::from(vma.read) | (u64::from(vma.write) << 1) | (u64::from(vma.execute) << 2);
        model.import(
            range,
            ReservationProtection::from_bits(bits).ok_or(Refusal::Invalid)?,
            eligible(vma, mem),
        )?;
    }
    model.finish_import()
}

#[cfg(test)]
fn eligible(vma: &SemanticVma, mem: &MemState) -> bool {
    vma.provenance.is_private_anonymous()
        && vma.fork_policy == carrick_abi::VmaForkPolicy::DEFAULT
        && vma.dump_policy == carrick_abi::VmaDumpPolicy::Include
        && !vma.droppable
        && !mem
            .growdown_ranges
            .iter()
            .any(|(low, _, end)| vma.start < *end && *low < vma.end)
}

impl MemView<'_> {
    fn admit_el1_reservations(
        &self,
        permit: &super::super::mm_mutation::HostAliasPermit<'_>,
    ) -> Result<(), Refusal> {
        if permit.mm() != self.mm_authority().mm_id {
            return Err(Refusal::Stale);
        }
        if !self.mm_authority().has_reservation_provider() {
            return Err(Refusal::ForeignMapping);
        }
        let _exclusion = self.begin_host_alias_dispatch(permit);
        let mm = ReservationMm::new(permit.mm().raw()).ok_or(Refusal::Invalid)?;
        let table = shared_host().ok_or(Refusal::Stale)?;
        let mut model = table.lock(index_for(mm)?, mm)?;
        let limits = self
            .address_space_limits_apply(true)
            .unwrap_or((u64::MAX, u64::MAX));
        let authority = self.mem();
        let mem = authority.lock();
        let result = admit_host_snapshot(&mut model, &mem, limits);
        if result.is_err() && !model.is_admitted() {
            model.abort_import()?;
        }
        result
    }

    fn el1_reservation_fault_plan<'permit, P: PinnedMetadataExtent>(
        &self,
        permit: &'permit super::super::mm_mutation::HostAliasPermit<'_>,
        nodes: &'permit ResolvedReservationNodes<P>,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<El1ReservationFaultPlan<'permit, P>, Refusal> {
        if permit.mm() != self.mm_authority().mm_id {
            return Err(Refusal::Stale);
        }
        let exclusion = self.begin_host_alias_dispatch(permit);
        let mm = ReservationMm::new(permit.mm().raw()).ok_or(Refusal::Invalid)?;
        let index = index_for(mm)?;
        let plan = shared_host()
            .ok_or(Refusal::Stale)?
            .lock_resolved(index, mm, nodes)?
            .fault_plan(address, max_len, access)?;
        Ok(El1ReservationFaultPlan {
            nodes,
            plan,
            index,
            exclusion,
        })
    }

    fn authenticate_el1_reservation_fault<P: PinnedMetadataExtent>(
        &self,
        plan: &El1ReservationFaultPlan<'_, P>,
    ) -> bool {
        self.owns_host_alias_dispatch(&plan.exclusion)
            && shared_host()
                .and_then(|table| {
                    table
                        .lock_resolved(plan.index, plan.plan.mm, plan.nodes)
                        .ok()
                })
                .is_some_and(|mut model| model.authenticate_fault(plan.plan))
    }
}

impl SyscallDispatcher {
    pub fn admit_el1_reservations(
        &self,
        permit: &super::super::mm_mutation::HostAliasPermit<'_>,
    ) -> Result<(), Refusal> {
        self.mem_view().admit_el1_reservations(permit)
    }
    pub fn el1_reservation_fault_plan<'permit, P: PinnedMetadataExtent>(
        &self,
        permit: &'permit super::super::mm_mutation::HostAliasPermit<'_>,
        nodes: &'permit ResolvedReservationNodes<P>,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<El1ReservationFaultPlan<'permit, P>, Refusal> {
        self.mem_view()
            .el1_reservation_fault_plan(permit, nodes, address, max_len, access)
    }
    pub fn authenticate_el1_reservation_fault<P: PinnedMetadataExtent>(
        &self,
        plan: &El1ReservationFaultPlan<'_, P>,
    ) -> bool {
        self.mem_view().authenticate_el1_reservation_fault(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1::memory::reservations::{Decision, SharedReservations};
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
                    brk: mem.brk_current,
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
                self.table.lock(self.index, self.mm)
            }
        }
        let table: Arc<SharedReservations> = Arc::from(shared());
        let mem = snapshot();
        let a = publish(&table, &mem, 0);
        let b = publish(&table, &mem, 1);
        for (index, mm) in [(0, a), (1, b)] {
            import_snapshot(
                &mut table.lock(index, mm).unwrap(),
                &mem,
                (u64::MAX, u64::MAX),
            )
            .unwrap();
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
            import_snapshot(
                &mut table.lock(index, mm).unwrap(),
                &mem,
                (u64::MAX, u64::MAX),
            )
            .unwrap();
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
    fn reservation_legacy_host_authority_refuses_both_mm_admissions() {
        let table = shared();
        let mem = snapshot();
        for index in 0..2 {
            let mm = publish(&table, &mem, index);
            let mut model = table.lock(index, mm).unwrap();
            assert_eq!(
                admit_host_snapshot(&mut model, &mem, (u64::MAX, u64::MAX)),
                Err(Refusal::ForeignMapping)
            );
            assert!(!model.is_admitted());
            assert!(model.pending().is_none());
            assert!(model.mapping(mem.layout.mmap_base).is_none());
        }
        assert_eq!(mem.semantic_vmas.len(), 1);
    }

    #[test]
    fn reservation_host_import_two_mm_observers_share_fault_generation() {
        let table = shared();
        let mem = snapshot();
        let a = publish(&table, &mem, 0);
        let b = publish(&table, &mem, 1);
        for (index, mm) in [(0, a), (1, b)] {
            import_snapshot(
                &mut table.lock(index, mm).unwrap(),
                &mem,
                (u64::MAX, u64::MAX),
            )
            .unwrap();
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
        assert_eq!(
            import_snapshot(&mut model, &mem, (u64::MAX, u64::MAX)),
            Err(Refusal::Invalid)
        );
        assert!(model.mapping(mem.layout.mmap_base).is_none());
        model.abort_import().unwrap();
        assert!(model.mapping(mem.layout.mmap_base).is_none());
        let mem = snapshot();
        import_snapshot(&mut model, &mem, (u64::MAX, u64::MAX)).unwrap();
        assert!(model.mapping(mem.layout.mmap_base).is_some());
    }
}

#[path = "el1_reservations/projection.rs"]
mod projection;
pub use projection::{NonAnonymousVmas, ReservationProcMaps};

#[path = "el1_reservations/provider.rs"]
mod provider;
pub(in crate::dispatch) use provider::ReservationProviderSlot;
pub use provider::{HostReservationProvider, PreparedHostReservations, PreparedReservationSession};
