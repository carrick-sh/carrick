//! Host venue of the shared EL1 anonymous reservation authority.
//!
//! T2 integration: before enabling `decide_anonymous_syscall` for an MM, call
//! `admit_el1_reservations` under its mutation permit. Thereafter grant service
//! uses `el1_reservation_fault_plan`, NOT `resident_frame_grant_plan`: backing
//! eligibility comes from the shared root, not FirstTouchArming. The plan owns
//! exact-MM alias exclusion across backing service. Reauthenticate immediately
//! before publishing the grant receipt. A generation mismatch is refusal, never
//! permission to replay the Linux syscall or revive an old mapping.
//!
//! Admission is deliberately explicit while dispatch still forwards: sealing a
//! root and then allowing the old host mmap-family handlers to mutate MemState
//! would create two authorities. The activation change must route host memory
//! mutations through the same decision/completion API too.

use super::*;
use carrick_el1::memory::reservations::{
    Layout, Refusal, ReservationFaultPlan, Reservations, shared_host,
};
use carrick_el1_abi::{ReservationMm, ReservationProtection, ReservationRange};

pub struct El1ReservationFaultPlan<'permit> {
    plan: ReservationFaultPlan,
    index: usize,
    exclusion: HostAliasDispatchGuard<'permit>,
}

impl El1ReservationFaultPlan<'_> {
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
        let _exclusion = self.begin_host_alias_dispatch(permit);
        let mm = ReservationMm::new(permit.mm().raw()).ok_or(Refusal::Invalid)?;
        let table = shared_host().ok_or(Refusal::Stale)?;
        let mut model = table.lock(index_for(mm)?, mm)?;
        let limits = self
            .address_space_limits_apply(true)
            .unwrap_or((u64::MAX, u64::MAX));
        let authority = self.mem();
        let mem = authority.lock();
        let result = import_snapshot(&mut model, &mem, limits);
        if result.is_err() && !model.is_admitted() {
            model.abort_import()?;
        }
        result
    }

    fn el1_reservation_fault_plan<'permit>(
        &self,
        permit: &'permit super::super::mm_mutation::HostAliasPermit<'_>,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<El1ReservationFaultPlan<'permit>, Refusal> {
        if permit.mm() != self.mm_authority().mm_id {
            return Err(Refusal::Stale);
        }
        let exclusion = self.begin_host_alias_dispatch(permit);
        let mm = ReservationMm::new(permit.mm().raw()).ok_or(Refusal::Invalid)?;
        let index = index_for(mm)?;
        let plan = shared_host()
            .ok_or(Refusal::Stale)?
            .lock(index, mm)?
            .fault_plan(address, max_len, access)?;
        Ok(El1ReservationFaultPlan {
            plan,
            index,
            exclusion,
        })
    }

    fn authenticate_el1_reservation_fault(&self, plan: &El1ReservationFaultPlan<'_>) -> bool {
        self.owns_host_alias_dispatch(&plan.exclusion)
            && shared_host()
                .and_then(|table| table.lock(plan.index, plan.plan.mm).ok())
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
    pub fn el1_reservation_fault_plan<'permit>(
        &self,
        permit: &'permit super::super::mm_mutation::HostAliasPermit<'_>,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<El1ReservationFaultPlan<'permit>, Refusal> {
        self.mem_view()
            .el1_reservation_fault_plan(permit, address, max_len, access)
    }
    pub fn authenticate_el1_reservation_fault(&self, plan: &El1ReservationFaultPlan<'_>) -> bool {
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
