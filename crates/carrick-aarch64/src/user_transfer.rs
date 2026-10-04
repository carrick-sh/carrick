//! Owned host bytes and exact retained-data handshake for the production EL1
//! service. Selection and copy borrow the current executor on its maintenance
//! root; neither installs target user translations or needs a spare CPU.
mod prepared;
mod staging;
use crate::{Aarch64EngineCore, Aarch64Vmm};
use carrick_el1_abi::{
    MmPortalSlots, PortalByteRange, PortalOperation, PortalRetainedData, PortalSelectedData,
    PortalTransferIntent, PortalTransferRequest, ReservationMm, TrapFrame,
};
use carrick_hal::TrapError;
use core::num::NonZeroU64;
pub use staging::prepare_write;

/// Fulfil one exact owner-issued physical request before retrying the same
/// transfer. The request carries the MM incarnation and grant generation;
/// the guest validates both again while applying the descriptor transaction.
pub fn supply<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
    engine: &Aarch64EngineCore<V>,
    custody: &C,
    slots: &MmPortalSlots,
    target: TransferTarget,
    request: carrick_guest_mem::MemorySupplyRequest,
) -> Result<bool, TrapError> {
    use carrick_guest_mem::MemorySupplyRequest;
    let window = match request {
        MemorySupplyRequest::Grant(window) => window,
        MemorySupplyRequest::Cow(window) => return custody.refill_cow(target, window),
        MemorySupplyRequest::Metadata { .. } => return Ok(false),
    };
    if window.operation.carrier != target.handle.carrier()
        || window.operation.mm != target.handle.mm()
        || window.operation.incarnation != target.handle.incarnation()
    {
        return Err(TrapError::Hypervisor(
            "owner grant request differs from selected root".into(),
        ));
    }
    let mut grant = match custody.prepare(target, window)? {
        TransferPreparation::Grant(grant) => grant,
        // A peer installed the exact fault page while this physical request
        // was in flight. No host bytes were delivered; select again under
        // the owner's current root and source authority.
        TransferPreparation::PeerResident => return Ok(true),
        TransferPreparation::Declined => return Ok(false),
    };
    let mut service = engine.transfer_service_loan()?;
    let slot = slots
        .grant(service.slot()?)
        .ok_or_else(|| TrapError::Hypervisor("owner grant slot absent".into()))?;
    if !slot.submit(window, grant.transaction()) {
        return Err(TrapError::Hypervisor(
            "owner grant slot occupied by another request".into(),
        ));
    }
    let result = run_selected_service(
        &mut service,
        TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_GRANT_ESR,
            ..TrapFrame::default()
        },
        target,
        None,
        &mut || false,
    );
    if let Some(receipt) = slot.take_receipt(window, grant.transaction()) {
        let settled = grant.settle(&receipt)?;
        result?;
        Ok(settled)
    } else if slot.withdraw(window, grant.transaction()) {
        result?;
        Ok(false)
    } else {
        carrick_fatal::carrick_fatal!(
            "aarch64::user_transfer",
            "unsettled owner grant retains physical custody"
        );
    }
}

/// Host physical custody, with no permission or VA-translation authority.
pub trait TransferPin {
    fn pending(&self) -> Option<carrick_guest_mem::OwnedMemoryWait> {
        None
    }
    fn identity(&self) -> PortalRetainedData;
    /// Bounded memcpy only. All potentially blocking content revocation must
    /// finish during retention, before EL1 takes the copy editor.
    fn copy(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool;
    fn copy_out(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &[u8]) -> bool;
}
impl TransferPin for Box<dyn TransferPin> {
    fn pending(&self) -> Option<carrick_guest_mem::OwnedMemoryWait> {
        (**self).pending()
    }
    fn identity(&self) -> PortalRetainedData {
        (**self).identity()
    }
    fn copy(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool {
        (**self).copy(request, bytes)
    }
    fn copy_out(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &[u8]) -> bool {
        (**self).copy_out(request, bytes)
    }
}
pub trait TransferGrant {
    fn transaction(&self) -> &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn;
    /// Return true only when exact receipt settlement permits a fresh owner
    /// selection: either the grant applied or EL1 refused a stale root before
    /// publication. Physical custody is released before the caller retries.
    fn settle(
        &mut self,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<bool, TrapError>;
}
pub enum TransferPreparation {
    Grant(Box<dyn TransferGrant>),
    PeerResident,
    Declined,
}
pub trait TransferCustody {
    type Pin: TransferPin;
    fn carrier(&self) -> NonZeroU64;
    fn prepare(
        &self,
        target: TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<TransferPreparation, TrapError>;
    fn publish_executable(
        &self,
        target: TransferTarget,
        request: carrick_el1_abi::PortalExecutablePublication,
    ) -> bool;
    fn refill_cow(
        &self,
        target: TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<bool, TrapError>;
    fn retain(
        &self,
        selected: PortalSelectedData,
        len: usize,
        intent: PortalTransferIntent,
    ) -> Result<Option<Self::Pin>, TrapError>;
}

pub type ErasedPhysicalCustody = dyn TransferCustody<Pin = Box<dyn TransferPin>>;

/// The target binding comes from the admitted production MM and ASID owner.
#[derive(Clone, Copy)]
pub struct TransferTarget {
    handle: carrick_el1_abi::El1MmHandle,
    ttbr0: u64,
}

impl TransferTarget {
    pub fn from_handle(handle: carrick_el1_abi::El1MmHandle, ttbr0: u64) -> Self {
        Self { handle, ttbr0 }
    }
    pub fn handle(self) -> carrick_el1_abi::El1MmHandle {
        self.handle
    }
    pub fn ttbr0(self) -> u64 {
        self.ttbr0
    }
    pub fn bind<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
        engine: &Aarch64EngineCore<V>,
        mm: ReservationMm,
        ttbr0: u64,
        custody: &C,
        slots: &MmPortalSlots,
    ) -> Result<Option<Self>, TrapError> {
        Self::bind_with(engine, mm, ttbr0, custody, slots, None)
    }
    pub fn bind_closed<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
        engine: &Aarch64EngineCore<V>,
        token: carrick_el1_abi::PortalClosedRootBind,
        custody: &C,
        slots: &MmPortalSlots,
    ) -> Result<Option<Self>, TrapError> {
        if token.carrier() != custody.carrier() {
            return Err(TrapError::Hypervisor(
                "closed BIND carrier differs from the transfer custodian".into(),
            ));
        }
        Self::bind_with(
            engine,
            token.mm(),
            token.ttbr0(),
            custody,
            slots,
            Some(token),
        )
    }
    fn bind_with<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
        engine: &Aarch64EngineCore<V>,
        mm: ReservationMm,
        ttbr0: u64,
        custody: &C,
        slots: &MmPortalSlots,
        closed: Option<carrick_el1_abi::PortalClosedRootBind>,
    ) -> Result<Option<Self>, TrapError> {
        let mut service = engine.transfer_service_loan()?;
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0
            || slots as *const MmPortalSlots as usize
                != region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize
            || !slots.bind_carrier(custody.carrier())
        {
            return Err(TrapError::Hypervisor(
                "UserTransfer carrier binding mismatch".into(),
            ));
        }
        let mut frame = TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_BIND_ESR,
            ..TrapFrame::default()
        };
        frame.x[1] = custody.carrier().get();
        frame.x[2] = mm.raw();
        if let Some(token) = closed {
            frame.x[6] = 1;
            frame.x[7] = token.ttbr0();
        }
        let receipt = service.run_user(frame, &mut || false)?;
        carrick_observability::probes::hvpatch_el1_owner_bind_result(receipt.x[0]);
        if receipt.x[0] != 0 {
            return Ok(None);
        }
        let incarnation = NonZeroU64::new(receipt.x[3])
            .ok_or_else(|| TrapError::Hypervisor("EL1 bind returned zero incarnation".into()))?;
        // SAFETY: exact carrier service authenticated the admitted MM root
        // while executing on the carrier maintenance root.
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(custody.carrier(), mm, incarnation)
        };
        Ok(Some(Self { handle, ttbr0 }))
    }
}

pub enum UserTransfer {
    CopyIn {
        address: u64,
        len: usize,
        intent: PortalTransferIntent,
    },
    CopyOut {
        address: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferProgress {
    Retired(carrick_el1_abi::El1MmHandle),
    Physical(carrick_guest_mem::OwnedMemoryWait),
    Complete,
    Advanced,
    Suspended,
    OwnerWait(carrick_el1_abi::PortalOwnerWait),
    Supply(carrick_guest_mem::MemorySupplyRequest),
    Refused(carrick_abi::LinuxErrno),
}

/// A suspension owns its host byte buffer and completed prefix. It carries no
/// root lock, editor or frame pin while scheduler waits. Synchronous grant
/// preparation owns its physical pins until
/// its exact guest receipt settles.
pub struct OwnedUserTransfer {
    target: TransferTarget,
    address: u64,
    intent: PortalTransferIntent,
    bytes: Vec<u8>,
    offset: usize,
    fork_sequence: Option<NonZeroU64>,
}
impl OwnedUserTransfer {
    pub fn new(target: TransferTarget, request: UserTransfer) -> Option<Self> {
        let (address, intent, bytes) = match request {
            UserTransfer::CopyOut { address, bytes } => {
                (address, PortalTransferIntent::UserWrite, bytes)
            }
            UserTransfer::CopyIn {
                address,
                len,
                intent,
            } => {
                if intent == PortalTransferIntent::UserWrite {
                    return None;
                }
                (address, intent, vec![0; len])
            }
        };
        address.checked_add(bytes.len() as u64)?;
        Some(Self {
            target,
            address,
            intent,
            bytes,
            offset: 0,
            fork_sequence: None,
        })
    }
    /// Scope only the fork task-commit copyout to the exact retained parent
    /// operation. Generic transfers remain excluded while Fork is pending.
    pub fn authorize_fork_parent_write(&mut self, operation: PortalOperation) -> bool {
        if operation.carrier != self.target.handle.carrier()
            || operation.mm != self.target.handle.mm()
            || operation.incarnation != self.target.handle.incarnation()
            || !matches!(
                self.intent,
                PortalTransferIntent::UserRead | PortalTransferIntent::UserWrite
            )
        {
            return false;
        }
        self.fork_sequence = Some(operation.sequence);
        true
    }
    pub(crate) fn target_handle(&self) -> carrick_el1_abi::El1MmHandle {
        self.target.handle
    }
    pub(crate) fn address(&self) -> u64 {
        self.address
    }
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// One page per admission; never keeps the editor across the next chunk,
    /// a grant/refill, a scheduler suspension, or host I/O.
    pub fn advance<V: Aarch64Vmm, C: TransferCustody + ?Sized>(
        &mut self,
        engine: &Aarch64EngineCore<V>,
        custody: &C,
        slots: &MmPortalSlots,
    ) -> Result<TransferProgress, TrapError> {
        let error = |message: &str| TrapError::Hypervisor(format!("UserTransfer: {message}"));
        if self.offset == self.bytes.len() {
            return Ok(TransferProgress::Complete);
        }
        let va = self.address + self.offset as u64;
        let len = (self.bytes.len() - self.offset)
            .min(carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize - (va as usize & 4095));
        let page = match staging::stage_page(
            engine,
            custody,
            slots,
            self.target,
            va,
            len,
            0,
            self.offset,
            self.intent,
            self.fork_sequence,
        )? {
            Ok(page) => page,
            Err(carrick_guest_mem::MemoryPrepareError::OwnerWait(wait)) => {
                return Ok(TransferProgress::OwnerWait(wait));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Supply(supply)) => {
                return Ok(TransferProgress::Supply(supply));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Physical(wait)) => {
                return Ok(TransferProgress::Physical(wait));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Limit(limit)) => {
                return Err(TrapError::Hypervisor(format!(
                    "transfer exceeds prepared stream bound: {limit:?}"
                )));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Fault(
                carrick_guest_mem::MemoryError::OwnerRetired(handle),
            )) => {
                return Ok(TransferProgress::Retired(handle));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Fault(
                carrick_guest_mem::MemoryError::OutOfBounds { .. },
            )) => {
                return Ok(TransferProgress::Refused(carrick_abi::LinuxErrno::new(14)));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Fault(error)) => {
                return Err(TrapError::Hypervisor(error.to_string()));
            }
        };
        let mut pin = page.pin;
        let request = page.request;
        let operation = request.operation;
        let mut service = engine.transfer_service_loan()?;
        let slot = slots
            .slot(service.slot()?)
            .ok_or_else(|| error("invalid caller slot"))?;
        let Some(mut ticket) = slot.submit(request) else {
            return Ok(TransferProgress::Suspended);
        };
        let frame = TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_SERVICE_ESR,
            ..TrapFrame::default()
        };
        if let Err(failure) = run_selected_service(
            &mut service,
            frame,
            self.target,
            self.fork_sequence,
            &mut || {
                let handled = ticket.copy_requested(|exact| {
                    pin.copy(exact, &mut self.bytes[self.offset..self.offset + len])
                });
                if !handled && slot.copy_pending() {
                    carrick_fatal::carrick_fatal!(
                        "aarch64::user_transfer",
                        "copy effect identity mismatch; cannot abandon editor"
                    );
                }
                handled
            },
        ) {
            if !ticket.cancel_unclaimed() && ticket.take_completion().is_none() {
                carrick_fatal::carrick_fatal!(
                    "aarch64::user_transfer",
                    "unsettled service retains physical custody: {failure}"
                );
            }
            return Err(failure);
        }
        if let Some(suspension) = ticket.take_prepare_suspension() {
            return Ok(match suspension {
                carrick_el1_abi::PortalPrepareSuspension::Owner(wait) => {
                    TransferProgress::OwnerWait(wait)
                }
                carrick_el1_abi::PortalPrepareSuspension::SelectionChanged
                | carrick_el1_abi::PortalPrepareSuspension::ReservationMetadata => {
                    TransferProgress::Suspended
                }
            });
        }
        let completion = ticket.take_completion().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "aarch64::user_transfer",
                "service returned without exact completion; cannot release physical custody"
            )
        });
        if completion.operation != operation || completion.retained != pin.identity() {
            return Err(error("completion identity mismatch"));
        }
        self.offset += completion.completed as usize;
        match completion.errno {
            0 => Ok(if self.offset == self.bytes.len() {
                TransferProgress::Complete
            } else {
                TransferProgress::Advanced
            }),
            3 => Ok(TransferProgress::Retired(self.target.handle)),
            11 => Ok(TransferProgress::Suspended),
            errno if (1..=4095).contains(&errno) => Ok(TransferProgress::Refused(
                carrick_abi::LinuxErrno::new(errno as i32),
            )),
            _ => Err(error("invalid completion errno")),
        }
    }
}

fn run_selected_service<V: Aarch64Vmm>(
    service: &mut crate::engine::TransferServiceLoan<'_, V>,
    frame: TrapFrame,
    target: TransferTarget,
    fork_sequence: Option<NonZeroU64>,
    effect: &mut dyn FnMut() -> bool,
) -> Result<TrapFrame, TrapError> {
    if let Some(sequence) = fork_sequence {
        service.run_parent(frame, target, sequence, effect)
    } else {
        service.run_user(frame, effect)
    }
}

/// Erase only the retained physical pin type for a backend-owned byte venue.
pub struct ErasedTransferCustody<C>(pub C);
impl<C: TransferCustody> TransferCustody for ErasedTransferCustody<C>
where
    C::Pin: 'static,
{
    type Pin = Box<dyn TransferPin>;
    fn carrier(&self) -> NonZeroU64 {
        self.0.carrier()
    }
    fn prepare(
        &self,
        target: TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<TransferPreparation, TrapError> {
        self.0.prepare(target, window)
    }
    fn publish_executable(
        &self,
        target: TransferTarget,
        request: carrick_el1_abi::PortalExecutablePublication,
    ) -> bool {
        self.0.publish_executable(target, request)
    }
    fn refill_cow(
        &self,
        target: TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<bool, TrapError> {
        self.0.refill_cow(target, window)
    }
    fn retain(
        &self,
        selected: PortalSelectedData,
        len: usize,
        intent: PortalTransferIntent,
    ) -> Result<Option<Self::Pin>, TrapError> {
        self.0
            .retain(selected, len, intent)
            .map(|pin| pin.map(|pin| Box::new(pin) as Box<dyn TransferPin>))
    }
}

#[cfg(test)]
mod fork_parent_tests {
    use super::*;
    #[test]
    fn fresh_parent_copyout_after_finish_has_no_stale_fork_scope() {
        let carrier = NonZeroU64::new(1).unwrap();
        let mm = ReservationMm::new(2).unwrap();
        let incarnation = NonZeroU64::new(3).unwrap();
        // SAFETY: isolated capability fixture, never submitted to production.
        let handle =
            unsafe { carrick_el1_abi::El1MmHandle::from_admitted_owner(carrier, mm, incarnation) };
        let target = TransferTarget::from_handle(handle, 0x4000);
        let output = || UserTransfer::CopyOut {
            address: 0x7000,
            bytes: vec![1],
        };
        let operation = PortalOperation {
            carrier,
            mm,
            incarnation,
            sequence: NonZeroU64::new(4).unwrap(),
        };
        let mut pending = OwnedUserTransfer::new(target, output()).unwrap();
        assert!(pending.authorize_fork_parent_write(operation));
        assert_eq!(pending.fork_sequence, Some(operation.sequence));
        drop(pending);
        let rollback = OwnedUserTransfer::new(target, output()).unwrap();
        assert_eq!(rollback.fork_sequence, None);
        let input = || UserTransfer::CopyIn {
            address: 0x7000,
            len: 4,
            intent: PortalTransferIntent::UserRead,
        };
        let preflight = OwnedUserTransfer::new(target, input()).unwrap();
        assert_eq!(preflight.fork_sequence, None);
        let mut pending_input = OwnedUserTransfer::new(target, input()).unwrap();
        assert!(pending_input.authorize_fork_parent_write(operation));
        assert_eq!(pending_input.fork_sequence, Some(operation.sequence));
    }
}
