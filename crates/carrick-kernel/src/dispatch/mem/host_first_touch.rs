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
