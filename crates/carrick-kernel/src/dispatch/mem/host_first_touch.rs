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

/// T2 implements this on VerifiedDescriptorReceipt at integration. That type
/// is not present on this branch; the trait avoids inventing a second receipt.
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

impl SyscallDispatcher {
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
