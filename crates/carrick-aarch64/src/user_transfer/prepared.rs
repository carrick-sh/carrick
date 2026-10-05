//! Aggregate owner permits and their single current-executor loan.
use super::*;
use carrick_el1_abi::{PortalPreparedPermit, PortalTransferSlot};
use carrick_guest_mem::{
    GuestWriteRange, MemoryPrepareError, MemorySupplyRequest, PreparedGuestWrite,
};

/// Physical staging happens before constructing the aggregate service loan.
/// Fields are private to UserTransfer: callers cannot pair an arbitrary pin
/// with a selected operation or an output offset.
pub(super) struct RetainedWritePage<P> {
    pub(super) request: PortalTransferRequest,
    pub(super) pin: P,
    pub(super) output: usize,
    pub(super) offset: usize,
}
struct PreparedPage<P> {
    retained: RetainedWritePage<P>,
    permit: Option<PortalPreparedPermit>,
}

pub(super) trait PreparedService {
    fn slot(&self) -> Result<usize, TrapError>;
    fn run(&mut self, effect: &mut dyn FnMut() -> bool) -> Result<(), TrapError>;
}
pub(super) struct CurrentService<'a, V: Aarch64Vmm> {
    loan: crate::engine::TransferServiceLoan<'a, V>,
}
impl<V: Aarch64Vmm> PreparedService for CurrentService<'_, V> {
    fn slot(&self) -> Result<usize, TrapError> {
        self.loan.slot()
    }
    fn run(&mut self, effect: &mut dyn FnMut() -> bool) -> Result<(), TrapError> {
        self.loan
            .run_user(
                TrapFrame {
                    esr: carrick_el1_abi::MM_PORTAL_SERVICE_ESR,
                    ..TrapFrame::default()
                },
                effect,
            )
            .map(|_| ())
    }
}

pub(super) struct PreparedWrite<'a, S: PreparedService, P: TransferPin> {
    service: S,
    slot: &'a PortalTransferSlot,
    ranges: Vec<GuestWriteRange>,
    pages: Vec<PreparedPage<P>>,
}
impl<'a, V: Aarch64Vmm, P: TransferPin> PreparedWrite<'a, CurrentService<'a, V>, P> {
    pub(super) fn prepare_current(
        engine: &'a Aarch64EngineCore<V>,
        slots: &'a MmPortalSlots,
        ranges: Vec<GuestWriteRange>,
        pages: Vec<RetainedWritePage<P>>,
    ) -> Result<Self, MemoryPrepareError> {
        let loan = engine.transfer_service_loan().map_err(|error| {
            MemoryPrepareError::Fault(carrick_guest_mem::MemoryError::HostMap(error.to_string()))
        })?;
        Self::prepare(CurrentService { loan }, slots, ranges, pages)
    }
}
impl<'a, S: PreparedService, P: TransferPin> PreparedWrite<'a, S, P> {
    fn prepare(
        service: S,
        slots: &'a MmPortalSlots,
        ranges: Vec<GuestWriteRange>,
        pages: Vec<RetainedWritePage<P>>,
    ) -> Result<Self, MemoryPrepareError> {
        let slot = service
            .slot()
            .ok()
            .and_then(|index| slots.slot(index))
            .unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "current executor has no transfer slot"
                )
            });
        let mut prepared = Self {
            service,
            slot,
            ranges,
            pages: pages
                .into_iter()
                .map(|retained| PreparedPage {
                    retained,
                    permit: None,
                })
                .collect(),
        };
        for index in 0..prepared.pages.len() {
            let request = prepared.pages[index].retained.request;
            let mut ticket = slot.submit_prepare(request).unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "exclusive service slot occupied"
                )
            });
            prepared.service.run(&mut || false).unwrap_or_else(|error| {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "unsettled PREPARE service: {error}"
                )
            });
            if let Some(permit) = ticket.take_prepared() {
                prepared.pages[index].permit = Some(permit);
                continue;
            }
            if let Some(suspension) = ticket.take_prepare_suspension() {
                return Err(match suspension {
                    carrick_el1_abi::PortalPrepareSuspension::Owner(observed) => {
                        if observed.cause() == carrick_el1_abi::PortalWaitCause::Metadata {
                            MemoryPrepareError::Supply(MemorySupplyRequest::Metadata {
                                operation: request.operation,
                                observed,
                            })
                        } else {
                            MemoryPrepareError::OwnerWait(observed)
                        }
                    }
                    _ => carrick_fatal::carrick_fatal!(
                        "aarch64::prepared_copy",
                        "admitted PREPARE omitted its producer receipt"
                    ),
                });
            }
            let completion = ticket.take_completion().unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "PREPARE returned no exact outcome"
                )
            });
            if completion.completed != 0 {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "PREPARE unexpectedly copied bytes"
                );
            }
            carrick_observability::probes::guest_internal_write_fault(
                request.range.address(),
                request.range.len(),
                26,
                &format!("owner PREPARE refused: {completion:?}"),
            );
            if completion.errno == 3 {
                // SAFETY: exact owner completion authenticated this operation.
                let handle = unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        request.operation.carrier,
                        request.operation.mm,
                        request.operation.incarnation,
                    )
                };
                return Err(MemoryPrepareError::Fault(
                    carrick_guest_mem::MemoryError::OwnerRetired(handle),
                ));
            }
            if completion.errno != 14 {
                return Err(MemoryPrepareError::Fault(
                    carrick_guest_mem::MemoryError::HostMap(format!(
                        "PREPARE refused before consumption: {completion:?}"
                    )),
                ));
            }
            return Err(MemoryPrepareError::Fault(
                carrick_guest_mem::MemoryError::OutOfBounds {
                    address: request.range.address(),
                    length: request.range.len() as usize,
                },
            ));
        }
        Ok(prepared)
    }
    fn settle(&mut self, index: usize, bytes: Option<&[u8]>) {
        let page = &mut self.pages[index];
        let Some(permit) = page.permit else {
            return;
        };
        let request = page.retained.request;
        let mut ticket = match bytes {
            Some(bytes) => self.slot.submit_commit(request, permit, bytes.len() as u64),
            None => self.slot.submit_cancel(request, permit),
        }
        .unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "prepared settlement lost exclusive transport"
            )
        });
        self.service
            .run(&mut || {
                ticket.copy_requested(|authorization| {
                    let Some(bytes) = bytes else {
                        return false;
                    };
                    page.retained.pin.copy_out(authorization, bytes)
                })
            })
            .unwrap_or_else(|error| {
                carrick_fatal::carrick_fatal!(
                    "aarch64::prepared_copy",
                    "prepared settlement failed: {error}"
                )
            });
        let completion = ticket.take_completion().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "prepared settlement attempted suspension"
            )
        });
        if completion.operation != request.operation
            || completion.retained != request.retained
            || completion.errno != 0
            || completion.completed != bytes.map_or(0, |bytes| bytes.len() as u64)
        {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "prepared settlement identity or count changed"
            );
        }
        page.permit = None;
    }
}
impl<S: PreparedService, P: TransferPin> PreparedGuestWrite for PreparedWrite<'_, S, P> {
    fn commit(mut self: Box<Self>, outputs: &[&[u8]]) {
        if outputs.len() != self.ranges.len()
            || outputs
                .iter()
                .zip(&self.ranges)
                .any(|(bytes, range)| bytes.len() > range.len())
        {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "output exceeds aggregate prepared ranges"
            );
        }
        for index in 0..self.pages.len() {
            let page = &self.pages[index].retained;
            let bytes = outputs[page.output];
            let len = bytes
                .len()
                .saturating_sub(page.offset)
                .min(page.request.range.len() as usize);
            let prefix = (len != 0).then(|| &bytes[page.offset..page.offset + len]);
            self.settle(index, prefix);
        }
    }
}
impl<S: PreparedService, P: TransferPin> Drop for PreparedWrite<'_, S, P> {
    fn drop(&mut self) {
        for index in 0..self.pages.len() {
            self.settle(index, None);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Default)]
    struct State {
        events: RefCell<Vec<(&'static str, u64)>>,
        copied: RefCell<Vec<u8>>,
    }
    struct Service<'a> {
        slots: &'a MmPortalSlots,
        state: Rc<State>,
        fail: Option<u64>,
    }
    impl Drop for Service<'_> {
        fn drop(&mut self) {
            self.state.events.borrow_mut().push(("loan returned", 0));
        }
    }
    impl PreparedService for Service<'_> {
        fn slot(&self) -> Result<usize, TrapError> {
            Ok(0)
        }
        fn run(&mut self, effect: &mut dyn FnMut() -> bool) -> Result<(), TrapError> {
            let service = self.slots.slot(0).unwrap().claim().unwrap();
            let request = service.request();
            let sequence = request.operation.sequence.get();
            use carrick_el1_abi::PortalTransferPhase;
            match service.phase() {
                PortalTransferPhase::Prepare => {
                    self.state.events.borrow_mut().push(("prepare", sequence));
                    if self.fail == Some(sequence) {
                        let handle = unsafe {
                            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                                request.operation.carrier,
                                request.operation.mm,
                                request.operation.incarnation,
                            )
                        };
                        let wait = unsafe {
                            carrick_el1_abi::PortalOwnerWait::from_owner(
                                handle,
                                carrick_el1_abi::PortalWaitCause::Editor,
                                7,
                            )
                        };
                        assert!(service.suspend_prepare(
                            carrick_el1_abi::PortalPrepareSuspension::Owner(wait)
                        ));
                    } else {
                        assert!(service.complete_prepared(PortalPreparedPermit {
                            index: sequence as u32,
                            generation: NonZeroU64::new(1).unwrap(),
                            operation: request.operation,
                        }));
                    }
                }
                PortalTransferPhase::Commit => {
                    self.state.events.borrow_mut().push(("commit", sequence));
                    let len = service.copy_len();
                    assert!(service.copy_with(|| {
                        assert!(effect());
                    }));
                    assert!(service.complete(len, 0));
                }
                PortalTransferPhase::Cancel => {
                    self.state.events.borrow_mut().push(("cancel", sequence));
                    assert!(service.complete(0, 0));
                }
                PortalTransferPhase::Transfer => panic!("aggregate never uses one-shot transport"),
            }
            Ok(())
        }
    }
    struct Pin {
        state: Rc<State>,
        identity: PortalRetainedData,
        sequence: u64,
    }
    impl TransferPin for Pin {
        fn identity(&self) -> PortalRetainedData {
            self.identity
        }
        fn copy(&mut self, _: carrick_el1_abi::PortalCopyRequest<'_>, _: &mut [u8]) -> bool {
            panic!("output never casts immutable bytes mutable")
        }
        fn copy_out(
            &mut self,
            authorization: carrick_el1_abi::PortalCopyRequest<'_>,
            bytes: &[u8],
        ) -> bool {
            let request = authorization.request();
            assert_eq!(request.operation.sequence.get(), self.sequence);
            assert_eq!(request.retained, self.identity);
            assert_eq!(request.range.len(), bytes.len() as u64);
            self.state.copied.borrow_mut().extend_from_slice(bytes);
            true
        }
    }
    fn pages(state: &Rc<State>) -> Vec<RetainedWritePage<Pin>> {
        (0..3)
            .map(|index| {
                let sequence = index + 1;
                let identity = PortalRetainedData {
                    record: NonZeroU64::new(sequence).unwrap(),
                    vm_generation: NonZeroU64::new(1).unwrap(),
                    owner: None,
                };
                let operation = PortalOperation {
                    carrier: NonZeroU64::new(1).unwrap(),
                    mm: ReservationMm::new(2).unwrap(),
                    incarnation: NonZeroU64::new(3).unwrap(),
                    sequence: NonZeroU64::new(sequence).unwrap(),
                };
                let selected = PortalSelectedData {
                    ipa: 0x80000 + index * 4096,
                    executable: false,
                    root_generation: NonZeroU64::new(4).unwrap(),
                    offset: index * 4096,
                };
                RetainedWritePage {
                    request: PortalTransferRequest::new(
                        operation,
                        PortalByteRange::new(0x40000 + index * 4096, 4096).unwrap(),
                        PortalTransferIntent::UserWrite,
                        selected,
                        identity,
                    )
                    .unwrap(),
                    pin: Pin {
                        state: state.clone(),
                        identity,
                        sequence,
                    },
                    output: 0,
                    offset: index as usize * 4096,
                }
            })
            .collect()
    }
    #[test]
    fn aggregate_prepares_every_page_before_consumption_and_commits_short_prefix() {
        let slots = MmPortalSlots::new();
        let state = Rc::new(State::default());
        let service = Service {
            slots: &slots,
            state: state.clone(),
            fail: None,
        };
        let prepared = PreparedWrite::prepare(
            service,
            &slots,
            vec![GuestWriteRange::new(carrick_guest_mem::GuestVa(0x40000), 12288).unwrap()],
            pages(&state),
        )
        .unwrap();
        assert_eq!(
            *state.events.borrow(),
            [("prepare", 1), ("prepare", 2), ("prepare", 3)]
        );
        let consumed = vec![0x5a; 8192 + 23];
        Box::new(prepared).commit(&[&consumed]);
        assert_eq!(*state.copied.borrow(), consumed);
        assert_eq!(
            *state.events.borrow(),
            [
                ("prepare", 1),
                ("prepare", 2),
                ("prepare", 3),
                ("commit", 1),
                ("commit", 2),
                ("commit", 3),
                ("loan returned", 0)
            ]
        );
    }
    #[test]
    fn later_prepare_wait_cancels_prior_pages_before_returning_executor() {
        let slots = MmPortalSlots::new();
        let state = Rc::new(State::default());
        let result = PreparedWrite::prepare(
            Service {
                slots: &slots,
                state: state.clone(),
                fail: Some(2),
            },
            &slots,
            vec![GuestWriteRange::new(carrick_guest_mem::GuestVa(0x40000), 12288).unwrap()],
            pages(&state),
        );
        assert!(matches!(result, Err(MemoryPrepareError::OwnerWait(_))));
        assert!(state.copied.borrow().is_empty());
        assert_eq!(
            *state.events.borrow(),
            [
                ("prepare", 1),
                ("prepare", 2),
                ("cancel", 1),
                ("loan returned", 0)
            ]
        );
    }
    #[test]
    fn unused_pages_cancel_on_short_delivery_and_drop() {
        for delivered in [0, 23] {
            let slots = MmPortalSlots::new();
            let state = Rc::new(State::default());
            let prepared = PreparedWrite::prepare(
                Service {
                    slots: &slots,
                    state: state.clone(),
                    fail: None,
                },
                &slots,
                vec![GuestWriteRange::new(carrick_guest_mem::GuestVa(0x40000), 12288).unwrap()],
                pages(&state),
            )
            .unwrap();
            if delivered == 0 {
                drop(prepared);
            } else {
                Box::new(prepared).commit(&[&vec![9; delivered]]);
            }
            let events = state.events.borrow();
            assert_eq!(
                &events[4..],
                &[("cancel", 2), ("cancel", 3), ("loan returned", 0)]
            );
            assert_eq!(
                events[3],
                (if delivered == 0 { "cancel" } else { "commit" }, 1)
            );
        }
    }
}
