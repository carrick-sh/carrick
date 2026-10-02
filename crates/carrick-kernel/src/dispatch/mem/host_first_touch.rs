//! Deferred host-copyout publication. Planning does not consume arming;
//! residency is committed only after descriptor publication is authenticated.
use super::*;
use crate::dispatch::mm_mutation::{HostAliasPermit, MmMutationGuard};
use crate::dispatch::mm_quiesce::FrameCowExactMmGuard;
use crate::kernel::MmId;
use carrick_el1_abi::ReservationRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostFirstTouchIntent {
    pub mm: MmId,
    pub page: u64,
    pub prot: u64,
    pub arming_revision: u64,
}

/// Exact publication evidence consumed by the deferred first-touch commit.
/// The runtime adapter below binds a verified descriptor receipt to its intent.
///
/// # Safety
/// Values must come from authenticated successful descriptor publication in
/// the exact MM, with backing and invalidation complete. The receipt must own
/// completion authority until the caller commits host first-touch metadata.
pub unsafe trait HostFirstTouchDescriptorReceipt {
    fn mm(&self) -> MmId;
    fn resident(&self) -> ReservationRange;
    fn protection(&self) -> u64;
}

struct PublishedHostFirstTouch {
    resident: ReservationRange,
    intent: HostFirstTouchIntent,
    receipt: carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
}

// SAFETY: construction requires a verified Publish/Write transaction. The
// existing commit validates its exact MM/span and unchanged arming revision;
// Publish preserves the prepared leaf's permissions rather than changing them.
unsafe impl HostFirstTouchDescriptorReceipt for PublishedHostFirstTouch {
    fn mm(&self) -> MmId {
        MmId::from_registry_allocation(self.receipt.id().mm_key)
    }
    fn resident(&self) -> ReservationRange {
        self.resident
    }
    fn protection(&self) -> u64 {
        self.intent.prot
    }
}

impl SyscallDispatcher {
    pub fn commit_guest_host_first_touch(
        &self,
        authority: &mut FrameCowExactMmGuard,
        address: u64,
        publish: &mut dyn FnMut(
            std::num::NonZeroU64,
            u64,
        ) -> Result<
            carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
            String,
        >,
    ) -> Result<bool, String> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp;
        let Some(intent) = self.plan_host_first_touch(authority, address)? else {
            return Ok(false);
        };
        let receipt = publish(intent.mm.nonzero(), intent.page)?;
        if !matches!(
            receipt.txn().op,
            DescriptorOp::Publish {
                access: carrick_mmu_core::aarch64::LeafAccess::Write,
                ..
            }
        ) {
            return Err("host copyout requires a guest write-publication receipt".to_owned());
        }
        let span = receipt.resident();
        let resident = span
            .va
            .checked_add(span.len)
            .and_then(|end| ReservationRange::new(span.va, end))
            .ok_or_else(|| "host copyout publication has an invalid resident span".to_owned())?;
        let proof = PublishedHostFirstTouch {
            intent,
            receipt,
            resident,
        };
        let mutation = super::super::mm_mutation::from_frame_cow(authority);
        self.commit_host_first_touch_after_guest_publish(&mutation, intent, &proof)?;
        Ok(true)
    }

    fn first_touch_plan<'permit>(
        &self,
        permit: &'permit HostAliasPermit<'_>,
        address: u64,
    ) -> Result<Option<(HostFirstTouchIntent, ResidentFaultPlan<'permit>)>, String> {
        if self.mem_view().mm_authority().mm_id != permit.mm() {
            return Err("host first-touch authority names another MM".to_owned());
        }
        let Some(plan) = self.resident_fault_plan(permit, address) else {
            return Ok(None);
        };
        if plan.prot() & carrick_abi::LINUX_PROT_WRITE == 0 {
            return Err("armed host write page lacks Linux write permission".to_owned());
        }
        let intent = HostFirstTouchIntent {
            mm: permit.mm(),
            page: plan.page(),
            prot: plan.prot(),
            arming_revision: self.mem().lock().resident_fault_ranges.revision(),
        };
        Ok(Some((intent, plan)))
    }

    fn first_touch_guest_committed(&self, mutation: &MmMutationGuard<'_>, address: u64) -> bool {
        carrick_el1_abi::frame_grant_residency_host()
            .is_some_and(|table| table.is_guest_committed(mutation.mm_id().raw(), address))
    }

    pub fn plan_host_first_touch(
        &self,
        authority: &mut FrameCowExactMmGuard,
        address: u64,
    ) -> Result<Option<HostFirstTouchIntent>, String> {
        let mutation = super::super::mm_mutation::from_frame_cow(authority);
        if self.mem_view().mm_authority().mm_id != mutation.mm_id() {
            return Err("host first-touch authority names another MM".to_owned());
        }
        if self.first_touch_guest_committed(&mutation, address) {
            return Ok(None);
        }
        let permit = mutation.host_alias_permit();
        Ok(self
            .first_touch_plan(&permit, address)?
            .map(|(intent, _)| intent))
    }

    pub fn commit_host_first_touch_after_guest_publish(
        &self,
        mutation: &MmMutationGuard<'_>,
        intent: HostFirstTouchIntent,
        receipt: &impl HostFirstTouchDescriptorReceipt,
    ) -> Result<(), String> {
        if mutation.mm_id() != intent.mm
            || receipt.mm() != intent.mm
            || receipt.resident().start() != intent.page
            || intent.page.checked_add(4096) != Some(receipt.resident().end())
            || receipt.protection() != intent.prot
        {
            return Err("host first-touch receipt does not match the exact intent".to_owned());
        }
        let permit = mutation.host_alias_permit();
        let Some((current, plan)) = self.first_touch_plan(&permit, intent.page)? else {
            return Err("host first-touch intent is no longer armed".to_owned());
        };
        if current != intent {
            return Err("host first-touch arming changed before descriptor completion".to_owned());
        }
        self.commit_resident_fault(plan);
        Ok(())
    }

    /// Host venue: the same authenticated plan, host descriptor protection, then
    /// immediate metadata commit while alias exclusion remains continuously held.
    pub fn commit_host_first_touch(
        &self,
        authority: &mut FrameCowExactMmGuard,
        address: u64,
        protect: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    ) -> Result<bool, String> {
        let mutation = super::super::mm_mutation::from_frame_cow(authority);
        if self.mem_view().mm_authority().mm_id != mutation.mm_id() {
            return Err("host first-touch authority names another MM".to_owned());
        }
        if self.first_touch_guest_committed(&mutation, address) {
            return Ok(false);
        }
        let permit = mutation.host_alias_permit();
        let Some((intent, plan)) = self.first_touch_plan(&permit, address)? else {
            return Ok(false);
        };
        protect(intent.page, intent.prot)?;
        self.commit_resident_fault(plan);
        Ok(true)
    }
}

/// One planned EL1 frame grant, as both the EL1 mailbox and a host copyout
/// serve it: the request the backend prepares and the residency identity
/// published once the grant is live.
impl SyscallDispatcher {
    /// The backend request for `plan`, faulted at `fault_va` with `access`.
    pub fn el1_frame_grant_request(
        plan: &ResidentFrameGrantPlan<'_>,
        mm_key: u64,
        request_generation: u64,
        fault_va: u64,
        access: u64,
    ) -> carrick_hal::El1FrameGrantRequest {
        carrick_hal::El1FrameGrantRequest {
            mm_key,
            request_generation,
            fault_va,
            access,
            semantic_base: plan.start(),
            len: plan.len(),
            permissions: plan.prot(),
        }
    }

    /// Commit a published grant once stage-1, stage-2 and inventory are live
    /// (host lane) or EL1's receipt verifies (guest lane). Live grants publish
    /// residency; grants overtaken by retirement retain only return accounting.
    pub fn commit_published_frame_grant<'permit>(
        &self,
        plan: impl Into<PublishedFrameGrantPlan<'permit>>,
        residency: carrick_el1_abi::FrameGrantResidencyIdentity,
    ) {
        if self.mem_view().commit_published_frame_grant(plan.into())
            && let Some(table) = carrick_el1_abi::frame_grant_residency_host()
        {
            let _ = table.publish(residency);
        }
    }

    /// Serve the EL1 frame grant a host copyout into never-touched memory
    /// needs, exactly as an EL0 first touch of the run would be served:
    /// plan it from the root, publish its provenance, prepare and publish
    /// its backing through `venue`, then commit. A guest-lane publication is
    /// applied on the driving vCPU now and committed only after its verified
    /// receipt. `Ok(false)`: no root-owned writable grant applies here.
    ///
    /// `len` is the copyout's run of absent pages from `address`. The run is
    /// served as its aligned power-of-two pieces (the windows a root plan is
    /// drawn in), so the grants back exactly the run: never a page outside
    /// it, never a resident page, and at most two pieces per size class.
    ///
    /// `settle_pending` runs under the same mutation authority before the
    /// plan: an EL0 first touch's guest-lane grant that is published but
    /// not yet committed still reads as fresh root memory, so it must be
    /// settled (or withdrawn and rolled back) first, or the copyout would
    /// grant a second frame for the same page.
    pub fn grant_for_host_copyout(
        &self,
        authority: &mut FrameCowExactMmGuard,
        address: u64,
        len: u64,
        venue: &mut dyn carrick_hal::threaded::El1FrameGrantVenue,
        settle_pending: &mut dyn FnMut(
            &super::super::mm_mutation::MmMutationGuard<'_>,
            &mut dyn carrick_hal::threaded::El1FrameGrantVenue,
        ) -> Result<(), String>,
    ) -> Result<bool, String> {
        let mutation = super::super::mm_mutation::from_frame_cow(authority);
        if self.mem_view().mm_authority().mm_id != mutation.mm_id() {
            return Err("host copyout grant authority names another MM".to_owned());
        }
        settle_pending(&mutation, venue)?;
        let page_size = self.linux_page_size();
        let mm_key = mutation.mm_id().raw();
        let permit = mutation.host_alias_permit();
        let end = address
            .checked_add(len.max(1))
            .and_then(|end| end.checked_next_multiple_of(page_size))
            .ok_or_else(|| "host copyout grant run overflows".to_owned())?;
        let mut cursor = page_floor(address, page_size);
        let mut granted = false;
        while cursor < end {
            let piece = copyout_grant_piece(cursor, end - cursor, page_size);
            match self.grant_copyout_piece(&permit, mm_key, cursor, piece, venue)? {
                Some(next) => {
                    granted = true;
                    cursor = next.max(cursor + page_size);
                }
                None => break,
            }
        }
        Ok(granted)
    }

    /// One aligned piece of a copyout run: plan it from the root within
    /// `[cursor, cursor + piece)`, prepare and publish its backing, and
    /// commit. `Some(end)`: granted through `end`. `None`: no root-owned
    /// writable grant applies at `cursor` (or EL1 cleanly refused it).
    fn grant_copyout_piece(
        &self,
        permit: &super::super::mm_mutation::HostAliasPermit<'_>,
        mm_key: u64,
        cursor: u64,
        piece: u64,
        venue: &mut dyn carrick_hal::threaded::El1FrameGrantVenue,
    ) -> Result<Option<u64>, String> {
        use carrick_hal::threaded::{
            El1FrameGrantPublication, El1FrameGrantPublished, El1FrameGrantRollback,
        };
        let Some(plan) = self.resident_frame_grant_plan(permit, cursor, piece) else {
            return Ok(None);
        };
        if !plan.root_owned() || plan.prot() & carrick_abi::LINUX_PROT_WRITE == 0 {
            return Ok(None);
        }
        let plan_end = plan.start().saturating_add(plan.len());
        self.adopt_frame_grant_provenance(&plan);
        let request = Self::el1_frame_grant_request(&plan, mm_key, 0, cursor, 2);
        let Some(ready) = venue
            .prepare(request)
            .map_err(|error| format!("prepare host copyout grant: {error}"))?
        else {
            return Ok(None);
        };
        let rollback = El1FrameGrantRollback {
            mm_key,
            semantic_base: request.semantic_base,
            len: request.len,
            ready,
        };
        let published = venue
            .publish(El1FrameGrantPublication {
                mm_key,
                semantic_base: request.semantic_base,
                len: request.len,
                fault_va: plan.fault_page(),
                permissions: request.permissions,
                ready,
            })
            .map_err(|error| format!("publish host copyout grant: {error}"))?;
        match published {
            El1FrameGrantPublished::OnHost => {}
            El1FrameGrantPublished::Submit(txn) => {
                // EL1 refused or rolled back cleanly: nothing names the
                // prepared backing, so it is undone and no grant applies.
                if venue.apply_guest_publication(txn).is_err() {
                    venue
                        .roll_back(rollback)
                        .map_err(|undo| format!("roll back host copyout grant: {undo}"))?;
                    return Ok(None);
                }
                venue
                    .complete(rollback)
                    .map_err(|error| format!("complete host copyout grant: {error}"))?;
            }
            El1FrameGrantPublished::Unsupported | El1FrameGrantPublished::Refused(_) => {
                venue
                    .roll_back(rollback)
                    .map_err(|error| format!("roll back host copyout grant: {error}"))?;
                return Ok(None);
            }
        }
        self.commit_published_frame_grant(
            plan,
            carrick_el1_abi::FrameGrantResidencyIdentity {
                mm_key,
                semantic_base: request.semantic_base,
                physical_ipa: ready.physical_ipa,
                len: request.len,
                mapping_id: ready.mapping_id,
                frame_id: ready.frame_id,
                owner_generation: ready.owner_generation,
                inventory_revision: ready.inventory_revision,
            },
        );
        Ok(Some(plan_end))
    }

    /// Whether `page`'s first touch belongs to the delegated reservation
    /// root. A cheap filter before a copyout takes mutation authority; the
    /// grant re-asks under it.
    pub fn first_touch_is_root_owned(&self, page: u64) -> bool {
        let page = page_floor(page, self.linux_page_size());
        matches!(
            self.mem().lock().first_touch_owner(page),
            FirstTouchOwner::Root(..)
        )
    }

    /// Whether a host read of `page` sees fresh zero: a readable page of a
    /// root-owned live mapping that no one has touched, whose backing does
    /// not exist yet. The caller has established that the page's live leaf
    /// names no output at all.
    pub fn host_read_sees_fresh_zero(&self, page: u64) -> bool {
        let page = page_floor(page, self.linux_page_size());
        let mem_authority = self.mem();
        let mem = mem_authority.lock();
        match mem.first_touch_owner(page) {
            FirstTouchOwner::Root(mapping, incarnation) => mem
                .root_armed_prot(&mapping, incarnation, page)
                .is_some_and(|prot| prot.contains(LinuxProtFlags::READ)),
            FirstTouchOwner::Host | FirstTouchOwner::Unmapped => false,
        }
    }
}

/// The largest power-of-two piece at `cursor` that `cursor` is aligned to
/// and that fits in `remaining` (at least one page).
fn copyout_grant_piece(cursor: u64, remaining: u64, page_size: u64) -> u64 {
    let fits = 1_u64 << (u64::BITS - 1 - remaining.max(1).leading_zeros());
    let aligned = 1_u64
        .checked_shl(cursor.trailing_zeros())
        .unwrap_or(u64::MAX);
    fits.min(aligned).max(page_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_host_first_touch_commits_only_an_exact_write_publication() {
        use carrick_mmu_core::aarch64::descriptor_txn::*;
        use carrick_mmu_core::aarch64::{LeafAccess, SubstrateGpa};
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let mm = context.shared().mm().id();
        let page = crate::memory::LINUX_MMAP_BASE;
        dispatcher.seed_resident_fault_for_test(page, 3);
        let mut guard = crate::dispatch::mm_quiesce::acquire_host_write_mutation_quiesce(
            &dispatcher.pt_quiesce(),
            mm,
            dispatcher.mm_mutation_coordinator(),
            crate::thread::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
            crate::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
        )
        .unwrap();
        // Model authenticated descriptor outcomes here; runtime's executor
        // test separately proves the actual page-table mutation and receipt.
        let receipt = |mm_key, va, access| {
            let span = PageSpan::new(va, 4096);
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key,
                    generation: std::num::NonZeroU64::new(1).unwrap(),
                },
                root: SubstrateGpa(0x1000),
                op: DescriptorOp::Publish {
                    span,
                    expected_ipa: SubstrateGpa(0x2000),
                    access,
                },
                tables: TableGrants::NONE,
            };
            txn.verify_receipt(&DescriptorReceipt {
                id: txn.id,
                digest: txn.digest(),
                outcome: DescriptorOutcome::Applied(DescriptorApplied {
                    pages: 1,
                    resident: span,
                    tables_linked: 0,
                    reclaimed: ReclaimedTables::NONE,
                    live_stores: 1,
                    flush_required: true,
                }),
            })
            .unwrap()
        };
        assert!(
            dispatcher
                .commit_guest_host_first_touch(&mut guard, page, &mut |_, _| {
                    Err("publication refused".to_owned())
                })
                .is_err()
        );
        for invalid in [
            receipt(
                std::num::NonZeroU64::new(mm.raw() + 1).unwrap(),
                page,
                LeafAccess::Write,
            ),
            receipt(mm.nonzero(), page + 4096, LeafAccess::Write),
            receipt(mm.nonzero(), page, LeafAccess::Read),
        ] {
            assert!(
                dispatcher
                    .commit_guest_host_first_touch(&mut guard, page, &mut |_, _| Ok(invalid))
                    .is_err()
            );
            assert!(
                dispatcher
                    .plan_host_first_touch(&mut guard, page)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            dispatcher.commit_guest_host_first_touch(&mut guard, page + 8, &mut |key, address| {
                assert_eq!(key, mm.nonzero());
                assert_eq!(address, page);
                Ok(receipt(key, address, LeafAccess::Write))
            }),
            Ok(true)
        );
        assert_eq!(
            dispatcher.commit_guest_host_first_touch(&mut guard, page, &mut |_, _| {
                panic!("an already resident page must not republish")
            }),
            Ok(false)
        );
    }

    struct Receipt {
        mm: MmId,
        range: ReservationRange,
        prot: u64,
    }
    // SAFETY: the tests model descriptor publication without executing a VM.
    unsafe impl HostFirstTouchDescriptorReceipt for Receipt {
        fn mm(&self) -> MmId {
            self.mm
        }
        fn resident(&self) -> ReservationRange {
            self.range
        }
        fn protection(&self) -> u64 {
            self.prot
        }
    }
    fn intent(
        dispatcher: &SyscallDispatcher,
        mutation: &MmMutationGuard<'_>,
        page: u64,
    ) -> HostFirstTouchIntent {
        let permit = mutation.host_alias_permit();
        dispatcher
            .first_touch_plan(&permit, page)
            .unwrap()
            .unwrap()
            .0
    }
    #[test]
    fn host_first_touch_rejects_changed_arming_revision() {
        let dispatcher = SyscallDispatcher::new();
        let page = crate::memory::LINUX_MMAP_BASE;
        dispatcher.seed_resident_fault_for_test(page, 3);
        let mut executor = dispatcher.enter_mm_executor().unwrap();
        let mutation = super::super::super::mm_mutation::from_executor(&mut executor).unwrap();
        let old = intent(&dispatcher, &mutation, page);
        dispatcher.seed_resident_fault_for_test(page, 3);
        let receipt = Receipt {
            mm: old.mm,
            range: ReservationRange::new(page, page + 4096).unwrap(),
            prot: 3,
        };
        assert!(
            dispatcher
                .commit_host_first_touch_after_guest_publish(&mutation, old, &receipt)
                .is_err()
        );
        let current = intent(&dispatcher, &mutation, page);
        assert_ne!(current.arming_revision, old.arming_revision);
        dispatcher
            .commit_host_first_touch_after_guest_publish(&mutation, current, &receipt)
            .unwrap();
        assert!(
            dispatcher
                .first_touch_plan(&mutation.host_alias_permit(), page)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn host_first_touch_rejects_mismatched_resident_receipt() {
        let dispatcher = SyscallDispatcher::new();
        let page = crate::memory::LINUX_MMAP_BASE;
        dispatcher.seed_resident_fault_for_test(page, 3);
        let mut executor = dispatcher.enter_mm_executor().unwrap();
        let mutation = super::super::super::mm_mutation::from_executor(&mut executor).unwrap();
        let planned = intent(&dispatcher, &mutation, page);
        for (start, end, prot) in [
            (page + 4096, page + 8192, 3),
            (page, page + 8192, 3),
            (page, page + 4096, 1),
        ] {
            let receipt = Receipt {
                mm: planned.mm,
                range: ReservationRange::new(start, end).unwrap(),
                prot,
            };
            assert!(
                dispatcher
                    .commit_host_first_touch_after_guest_publish(&mutation, planned, &receipt)
                    .is_err()
            );
            assert_eq!(intent(&dispatcher, &mutation, page), planned);
        }
    }
}
