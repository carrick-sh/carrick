//! Owned host bytes and exact retained-data handshake for the production EL1
//! service. Selection and copy borrow the driving vCPU; neither runs target EL0.
use crate::vmm::Aarch64Vcpu;
use crate::{Aarch64EngineCore, Aarch64Vmm};
use carrick_el1_abi::{
    MmPortalSlots, PortalByteRange, PortalOperation, PortalRetainedData, PortalSelectedData,
    PortalTransferIntent, PortalTransferRequest, ReservationMm, TrapFrame,
};
use carrick_hal::TrapError;
use core::num::NonZeroU64;

/// Host physical custody, with no permission or VA-translation authority.
pub trait TransferPin {
    fn identity(&self) -> PortalRetainedData;
    /// Bounded memcpy only. All potentially blocking content revocation must
    /// finish during retention, before EL1 takes the copy editor.
    fn copy(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool;
}
impl TransferPin for Box<dyn TransferPin> {
    fn identity(&self) -> PortalRetainedData {
        (**self).identity()
    }
    fn copy(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool {
        (**self).copy(request, bytes)
    }
}
pub trait TransferGrant {
    fn transaction(&self) -> &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn;
    fn settle(
        &mut self,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<bool, TrapError>;
}
pub trait TransferCustody {
    type Pin: TransferPin;
    fn carrier(&self) -> NonZeroU64;
    fn prepare(
        &self,
        target: TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<Option<Box<dyn TransferGrant>>, TrapError>;
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
        engine: &mut Aarch64EngineCore<V>,
        mm: ReservationMm,
        ttbr0: u64,
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
        custody: &C,
        slots: &MmPortalSlots,
    ) -> Result<Option<Self>, TrapError> {
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
        let receipt = engine.run_user_transfer_service(frame, ttbr0, admission, &mut || false)?;
        if receipt.x[0] != 0 {
            return Ok(None);
        }
        let incarnation = NonZeroU64::new(receipt.x[3])
            .ok_or_else(|| TrapError::Hypervisor("EL1 bind returned zero incarnation".into()))?;
        // SAFETY: exact carrier service completed under the borrowed target
        // TTBR0 admission; EL1 authenticated its live root before this receipt.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferProgress {
    Complete,
    Advanced,
    Suspended,
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
        engine: &mut Aarch64EngineCore<V>,
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
        custody: &C,
        slots: &MmPortalSlots,
    ) -> Result<TransferProgress, TrapError> {
        let error = |message: &str| TrapError::Hypervisor(format!("UserTransfer: {message}"));
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0
            || (slots as *const MmPortalSlots as usize)
                != region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize
        {
            return Err(error("slots are not in the installed carrier region"));
        }
        if custody.carrier() != self.target.handle.carrier()
            || !slots.bind_carrier(self.target.handle.carrier())
        {
            return Err(error("carrier custody differs from target"));
        }
        if self.offset == self.bytes.len() {
            return Ok(TransferProgress::Complete);
        }
        let va = self.address + self.offset as u64;
        let len = (self.bytes.len() - self.offset).min(4096 - (va as usize & 4095));
        let mut frame = TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_SELECT_ESR,
            ..TrapFrame::default()
        };
        frame.x[1] = self.target.handle.carrier().get();
        frame.x[2] = self.target.handle.mm().raw();
        frame.x[3] = self.target.handle.incarnation().get();
        frame.x[4] = va;
        frame.x[5] = len as u64;
        frame.x[6] = self.intent.encode();
        frame.x[7] = self.offset as u64;
        frame.x[19] = self.fork_sequence.map_or(0, NonZeroU64::get);
        let caller = engine
            .vcpu()
            .mailbox_slot()
            .ok_or_else(|| error("caller has no slot"))? as usize;
        let executable = slots
            .executable(caller)
            .ok_or_else(|| error("invalid publication slot"))?;
        let selected_frame = run_selected_service(
            engine,
            frame,
            self.target,
            self.fork_sequence,
            admission,
            &mut || executable.handle(|request| custody.publish_executable(self.target, request)),
        )?;
        match selected_frame.x[0] {
            11 => {
                if matches!(selected_frame.x[14], 1 | 2) {
                    let nz = |value| {
                        NonZeroU64::new(value).ok_or_else(|| error("invalid supply receipt"))
                    };
                    let window = carrick_el1_abi::PortalGrantWindow {
                        operation: PortalOperation {
                            carrier: self.target.handle.carrier(),
                            mm: self.target.handle.mm(),
                            incarnation: self.target.handle.incarnation(),
                            sequence: nz(selected_frame.x[8])?,
                        },
                        generation: carrick_el1_abi::ReservationGeneration::new(
                            selected_frame.x[9],
                        )
                        .ok_or_else(|| error("invalid supply generation"))?,
                        range: carrick_el1_abi::ReservationRange::new(
                            selected_frame.x[10],
                            selected_frame.x[11],
                        )
                        .ok_or_else(|| error("invalid supply range"))?,
                        protection: carrick_el1_abi::ReservationProtection::from_bits(
                            selected_frame.x[12],
                        )
                        .ok_or_else(|| error("invalid supply permission"))?,
                        fault_page: selected_frame.x[13],
                        fork_sequence: self.fork_sequence,
                        host_backing: if selected_frame.x[16] == 0 {
                            if selected_frame.x[17] != 0 || selected_frame.x[18] != 0 {
                                return Err(error("invalid backing receipt"));
                            }
                            None
                        } else {
                            Some(carrick_el1_abi::HostBackingIdentity::new(
                                nz(selected_frame.x[16])?,
                                nz(selected_frame.x[17])?,
                                selected_frame.x[18],
                            ))
                        },
                    };
                    if selected_frame.x[14] == 2 {
                        return Ok(if custody.refill_cow(self.target, window)? {
                            TransferProgress::Advanced
                        } else {
                            TransferProgress::Refused(carrick_abi::LinuxErrno::new(12))
                        });
                    }
                    let access = match self.intent {
                        PortalTransferIntent::UserWrite => 2,
                        PortalTransferIntent::ReadInstruction => 4,
                        _ => 1,
                    };
                    let mailbox = carrick_el1_abi::frame_grant_mailbox_host_for_slot(
                        selected_frame.slot as usize,
                    )
                    .ok_or_else(|| error("missing supply mailbox"))?;
                    // Selection already issued this exact request. Withdraw its
                    // scheduler-fault transport before the isolated service;
                    // the owner receipt continues to carry its authorization.
                    if !mailbox.cancel_request_for_fault(self.target.handle.mm().raw(), va, access)
                    {
                        return Ok(TransferProgress::Suspended);
                    }
                    if let Some(mut grant) = custody.prepare(self.target, window)? {
                        let slot = slots
                            .grant(selected_frame.slot as usize)
                            .ok_or_else(|| error("invalid grant slot"))?;
                        if slot.submit(window, grant.transaction()) {
                            let frame = TrapFrame {
                                esr: carrick_el1_abi::MM_PORTAL_GRANT_ESR,
                                ..TrapFrame::default()
                            };
                            let outcome = run_selected_service(
                                engine,
                                frame,
                                self.target,
                                self.fork_sequence,
                                admission,
                                &mut || false,
                            );
                            if let Some(receipt) = slot.take_receipt(window, grant.transaction()) {
                                if grant.settle(&receipt)? {
                                    outcome?;
                                    return Ok(TransferProgress::Advanced);
                                }
                            } else if !slot.withdraw(window, grant.transaction()) {
                                carrick_fatal::carrick_fatal!(
                                    "aarch64::user_transfer",
                                    "unsettled grant service"
                                );
                            }
                            outcome?;
                        }
                    }
                }
                return Ok(TransferProgress::Suspended);
            }
            0 => {}
            errno if (1..=4095).contains(&errno) => {
                return Ok(TransferProgress::Refused(carrick_abi::LinuxErrno::new(
                    errno as i32,
                )));
            }
            _ => return Err(error("invalid selection errno")),
        }
        let operation = PortalOperation {
            carrier: self.target.handle.carrier(),
            mm: self.target.handle.mm(),
            incarnation: self.target.handle.incarnation(),
            sequence: NonZeroU64::new(selected_frame.x[8])
                .ok_or_else(|| error("missing operation sequence"))?,
        };
        let selected = PortalSelectedData {
            ipa: selected_frame.x[10],
            executable: selected_frame.x[15] == 1,
            root_generation: NonZeroU64::new(selected_frame.x[9])
                .ok_or_else(|| error("missing root generation"))?,
            offset: self.offset as u64,
        };
        let Some(mut pin) = custody.retain(selected, len, self.intent)? else {
            return Ok(TransferProgress::Suspended);
        };
        let mut request = PortalTransferRequest::new(
            operation,
            PortalByteRange::new(va, len as u64).ok_or_else(|| error("invalid range"))?,
            self.intent,
            selected,
            pin.identity(),
        )
        .ok_or_else(|| error("invalid retained request"))?;
        request.fork_sequence = self.fork_sequence;
        let slot = slots
            .slot(selected_frame.slot as usize)
            .ok_or_else(|| error("invalid caller slot"))?;
        let Some(mut ticket) = slot.submit(request) else {
            return Ok(TransferProgress::Suspended);
        };
        frame = TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_SERVICE_ESR,
            ..TrapFrame::default()
        };
        if let Err(failure) = run_selected_service(
            engine,
            frame,
            self.target,
            self.fork_sequence,
            admission,
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
            11 => Ok(TransferProgress::Suspended),
            errno if (1..=4095).contains(&errno) => Ok(TransferProgress::Refused(
                carrick_abi::LinuxErrno::new(errno as i32),
            )),
            _ => Err(error("invalid completion errno")),
        }
    }
}

fn run_selected_service<V: Aarch64Vmm>(
    engine: &mut Aarch64EngineCore<V>,
    frame: TrapFrame,
    target: TransferTarget,
    fork_sequence: Option<NonZeroU64>,
    admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    effect: &mut dyn FnMut() -> bool,
) -> Result<TrapFrame, TrapError> {
    if let Some(sequence) = fork_sequence {
        engine.run_owner_parent_transfer(frame, target, sequence, effect)
    } else {
        engine.run_user_transfer_service(frame, target.ttbr0, admission, effect)
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
    ) -> Result<Option<Box<dyn TransferGrant>>, TrapError> {
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
