//! Physical custody exchange for a production-owner Fork. The request contains
//! exact owner identity and physical capacity; it cannot carry host VMA policy.
use carrick_el1_abi::{
    PortalForkCompletion, PortalForkCustody, PortalForkRequest, PortalForkSlot, TrapFrame,
};
use carrick_hal::TrapError;

/// Retention authenticates the owner's selected backing; it does not select
/// translations, protection, private/shared policy, or omitted guest mappings.
pub trait ForkCustody {
    type Retention;
    fn retain(
        &self,
        request: PortalForkRequest,
        selected: PortalForkCustody,
    ) -> Result<Option<Self::Retention>, TrapError>;
}

/// Physical preparation of a child root. Capacity and retained owners are
/// supplied before EL1 publication; guest mapping policy is accepted only in
/// the exact completion and its owner-selected custody stream.
pub trait PhysicalForkBuilder<B>: ForkCustody<Retention = Box<dyn Send>> + Send {
    fn child_tables(&self) -> carrick_el1_abi::PortalForkTableArena;
    fn kernel_control_ipa(&self) -> u64;
    fn carrier(&self) -> core::num::NonZeroU64;
    fn consume_owner_fork_completion(
        &mut self,
        request: &carrick_hal::ProcessForkRequest,
        completion: PortalForkCompletion,
        selected: &[PortalForkCustody],
    ) -> Result<B, TrapError>;
    fn child_resolver(
        &self,
    ) -> std::sync::Arc<dyn carrick_mmu_core::aarch64::HostArenaResolver + Send + Sync>;
    fn settle(self: Box<Self>, committed: bool) -> Result<(), TrapError>;
}

/// Exact owner completion and the physical lifetimes it selected. A refused
/// operation cannot produce this receipt or transfer another operation's pins.
pub struct OwnerForkReceipt<P> {
    completion: PortalForkCompletion,
    retained: Vec<P>,
    host_backing: Vec<(core::num::NonZeroU64, core::num::NonZeroU64)>,
    selected: Vec<PortalForkCustody>,
}
impl<P> OwnerForkReceipt<P> {
    pub fn completion(&self) -> PortalForkCompletion {
        self.completion
    }
    pub fn inherited_host_backing(&self) -> &[(core::num::NonZeroU64, core::num::NonZeroU64)] {
        &self.host_backing
    }
    pub fn selected(&self) -> &[PortalForkCustody] {
        &self.selected
    }
    pub fn into_parts(self) -> (PortalForkCompletion, Vec<P>) {
        (self.completion, self.retained)
    }
}

/// Prepared owner child. The live parent undo remains in EL1 until this exact
/// pending operation is committed or aborted after task/inventory preparation.
#[must_use = "owner Fork must be settled with commit or abort"]
pub struct PendingOwnerFork<'a, P> {
    slot: &'a PortalForkSlot,
    ticket: carrick_el1_abi::PortalForkTicket<'a>,
    receipt: Option<OwnerForkReceipt<P>>,
}
impl<P> PendingOwnerFork<'_, P> {
    fn receipt(&self) -> &OwnerForkReceipt<P> {
        match self.receipt.as_ref() {
            Some(receipt) => receipt,
            None => carrick_fatal::carrick_fatal!(
                "aarch64::fork_cow",
                "settled owner Fork has no pending receipt"
            ),
        }
    }
    pub fn completion(&self) -> PortalForkCompletion {
        self.receipt().completion()
    }
    pub fn selected(&self) -> &[PortalForkCustody] {
        self.receipt().selected()
    }
    pub fn retained(&self) -> &[P] {
        &self.receipt().retained
    }
    pub fn inherited_host_backing(&self) -> &[(core::num::NonZeroU64, core::num::NonZeroU64)] {
        self.receipt().inherited_host_backing()
    }
    pub fn finish(
        mut self,
        commit: bool,
        run: impl FnOnce(TrapFrame, &mut dyn FnMut() -> bool) -> Result<TrapFrame, TrapError>,
    ) -> Result<OwnerForkReceipt<P>, TrapError> {
        if !self
            .slot
            .finish(self.completion().request.operation, commit)
        {
            return Err(TrapError::Hypervisor(
                "owner Fork final decision is stale".into(),
            ));
        }
        run(
            TrapFrame {
                esr: carrick_el1_abi::MM_PORTAL_FORK_FINISH_ESR,
                ..TrapFrame::default()
            },
            &mut || false,
        )?;
        let settled = self.ticket.take_completion().ok_or_else(|| {
            TrapError::Hypervisor("owner Fork returned without exact final settlement".into())
        })?;
        match settled {
            Ok(completion)
                if completion.request == self.completion().request
                    && completion.child == self.completion().child
                    && if commit {
                        completion == self.completion()
                    } else {
                        completion.parent_generation.raw()
                            == self
                                .completion()
                                .parent_generation
                                .raw()
                                .checked_add(1)
                                .unwrap_or(0)
                            && completion.child_tables_used == 0
                            && (completion.parent_tables_used == 0
                                || completion.parent_tables_used
                                    == self.completion().parent_tables_used)
                    } =>
            {
                let Some(mut receipt) = self.receipt.take() else {
                    carrick_fatal::carrick_fatal!(
                        "aarch64::fork_cow",
                        "owner Fork settlement lost exact physical receipt"
                    );
                };
                receipt.completion = completion;
                Ok(receipt)
            }
            Ok(_) => Err(TrapError::Hypervisor(
                "owner Fork completion does not match final decision".into(),
            )),
            Err(errno) => Err(TrapError::Hypervisor(format!(
                "owner Fork finish refused: errno {errno}"
            ))),
        }
    }
}

impl<P> Drop for PendingOwnerFork<'_, P> {
    fn drop(&mut self) {
        if self.receipt.is_some() {
            carrick_fatal::carrick_fatal!(
                "aarch64::fork_cow",
                "owner Fork dropped before exact commit or abort settlement"
            );
        }
    }
}

/// Prepare an unpublished child using only owner-selected physical custody.
/// The service returns after saving its rollback capsule in owner storage.
pub fn prepare<'a, C: ForkCustody + ?Sized>(
    request: PortalForkRequest,
    slot: &'a PortalForkSlot,
    custody: &C,
    run: impl FnOnce(TrapFrame, &mut dyn FnMut() -> bool) -> Result<TrapFrame, TrapError>,
) -> Result<Result<PendingOwnerFork<'a, C::Retention>, u32>, TrapError> {
    let mut ticket = slot.submit(request).ok_or_else(|| {
        TrapError::Hypervisor("owner Fork slot is occupied or request is invalid".into())
    })?;
    let mut retained = Vec::new();
    let mut host_backing = Vec::new();
    let mut selections = Vec::new();
    let mut failure = None;
    let mut expected_index = 0u64;
    let mut effect = || {
        let Some((selected_request, index, selected)) = slot.request_custody() else {
            return false;
        };
        let next_index = expected_index.checked_add(1);
        let exact = selected_request == request && index == expected_index && next_index.is_some();
        let pin = if exact && failure.is_none() {
            custody.retain(request, selected)
        } else {
            Ok(None)
        };
        let accepted = match pin {
            Ok(Some(pin)) => {
                retained.push(pin);
                selections.push(selected);
                if let PortalForkCustody::HostBacking { handle, generation } = selected {
                    host_backing.push((handle, generation));
                }
                true
            }
            Ok(None) => false,
            Err(error) => {
                failure = Some(error);
                false
            }
        };
        if slot.ack_custody(request.operation, index, accepted) {
            if let Some(next) = next_index {
                expected_index = next;
            }
            return true;
        }
        failure = Some(TrapError::Hypervisor(
            "owner Fork custody acknowledgment is stale".into(),
        ));
        false
    };
    let outcome = run(
        TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_FORK_ESR,
            ..TrapFrame::default()
        },
        &mut effect,
    );
    if let Err(error) = outcome {
        carrick_fatal::carrick_fatal!(
            "aarch64::fork_cow",
            "owner Fork transport failed before exact settlement: {error}"
        );
    }
    if let Some(completion) = slot.published() {
        if completion.request != request
            || completion.child.mm() != request.child_mm
            || completion.child.carrier() != request.operation.carrier
            || failure.is_some()
        {
            carrick_fatal::carrick_fatal!(
                "aarch64::fork_cow",
                "owner Fork published an inexact child; physical custody cannot be released"
            );
        }
        return Ok(Ok(PendingOwnerFork {
            slot,
            ticket,
            receipt: Some(OwnerForkReceipt {
                completion,
                retained,
                host_backing,
                selected: selections,
            }),
        }));
    }
    let completion = ticket.take_completion().unwrap_or_else(|| {
        carrick_fatal::carrick_fatal!("aarch64::fork_cow", "owner Fork returned without prepared child or refusal; physical custody cannot be released");
    });
    if let Some(error) = failure {
        return Err(error);
    }
    match completion {
        Err(errno) => Ok(Err(errno)),
        Ok(_) => Err(TrapError::Hypervisor(
            "owner Fork committed without task decision".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn request() -> PortalForkRequest {
        PortalForkRequest {
            operation: carrick_el1_abi::PortalOperation {
                carrier: NonZeroU64::new(1).unwrap(),
                mm: carrick_el1_abi::ReservationMm::new(2).unwrap(),
                incarnation: NonZeroU64::new(3).unwrap(),
                sequence: NonZeroU64::new(4).unwrap(),
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::new(5).unwrap(),
            child_mm: carrick_el1_abi::ReservationMm::new(6).unwrap(),
            kernel_control_ipa: 0x400000,
            child_tables: carrick_el1_abi::PortalForkTableArena::new(0x100000, 0x10000).unwrap(),
            parent_tables: carrick_el1_abi::PortalForkTableArena::new(0x200000, 0x10000).unwrap(),
        }
    }
    fn completion(request: PortalForkRequest) -> PortalForkCompletion {
        PortalForkCompletion {
            request,
            // SAFETY: this fixture models the production owner's successful
            // admission of this exact child, rather than forging a host input.
            child: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.child_mm,
                    NonZeroU64::new(7).unwrap(),
                )
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::new(8).unwrap(),
            child_tables_used: 4096,
            parent_tables_used: 0,
        }
    }
    struct Pin(Arc<AtomicUsize>);
    impl Drop for Pin {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct Physical(Arc<AtomicUsize>);
    impl ForkCustody for Physical {
        type Retention = Pin;
        fn retain(
            &self,
            _: PortalForkRequest,
            selected: PortalForkCustody,
        ) -> Result<Option<Pin>, TrapError> {
            if selected
                != (PortalForkCustody::Frame {
                    shared: false,
                    va: 0x4000,
                    ipa: 0x9000,
                    len: 4096,
                })
            {
                return Ok(None);
            }
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Pin(self.0.clone())))
        }
    }
    #[test]
    fn owner_abort_receipt_preserves_only_the_owner_retained_parent_capacity() {
        let request = request();
        let slot = PortalForkSlot::new();
        let count = Arc::new(AtomicUsize::new(0));
        let physical = Physical(count);
        let initial = completion(request);
        let pending = prepare(request, &slot, &physical, |frame, _| {
            slot.claim().unwrap().publish_detached(initial).unwrap();
            Ok(frame)
        })
        .unwrap()
        .unwrap();
        let aborted = PortalForkCompletion {
            parent_generation: carrick_el1_abi::ReservationGeneration::new(
                initial.parent_generation.raw() + 1,
            )
            .unwrap(),
            child_tables_used: 0,
            parent_tables_used: initial.parent_tables_used,
            ..initial
        };
        let receipt = pending
            .finish(false, |frame, _| {
                assert_eq!(slot.finish_request(), Some((request, false)));
                assert!(slot.complete_finish_receipt(aborted));
                Ok(frame)
            })
            .unwrap();
        assert_eq!(receipt.completion(), aborted);
    }

    #[test]
    fn owner_fork_keeps_exact_physical_retention_until_child_receipt_drops() {
        let request = request();
        let slot = PortalForkSlot::new();
        let count = Arc::new(AtomicUsize::new(0));
        let physical = Physical(count.clone());
        let pending = prepare(request, &slot, &physical, |frame, effect| {
            assert_eq!(frame.esr, carrick_el1_abi::MM_PORTAL_FORK_ESR);
            let service = slot.claim().unwrap();
            assert!(service.retain(
                0,
                PortalForkCustody::Frame {
                    shared: false,
                    va: 0x4000,
                    ipa: 0x9000,
                    len: 4096
                },
                || {
                    assert!(effect());
                }
            ));
            service.publish_detached(completion(request)).unwrap();
            Ok(frame)
        })
        .unwrap()
        .unwrap();
        assert_eq!(pending.completion(), completion(request));
        assert_eq!(pending.retained().len(), 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let receipt = pending
            .finish(true, |frame, _| {
                assert_eq!(frame.esr, carrick_el1_abi::MM_PORTAL_FORK_FINISH_ESR);
                assert_eq!(
                    slot.finish_request().map(|(_, decision)| decision),
                    Some(true)
                );
                assert!(slot.complete_finish(0));
                Ok(frame)
            })
            .unwrap();
        drop(receipt);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
