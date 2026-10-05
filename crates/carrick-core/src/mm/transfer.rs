//! Exact transfer position and prefix custody, independent of ISA and Linux errno.
use carrick_core_abi::{El1MmHandle, PortalTransferIntent as TransferIntent};
use carrick_sched_core::SpaceEditor;
use core::num::NonZeroU64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    Stale,
    Invalid,
}
/// Guest address, never a physical extent or a host pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestVa(u64);
impl GuestVa {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Owned request position. Suspension never discards already copied bytes.
pub struct TransferContinuation {
    pub handle: El1MmHandle,
    pub intent: TransferIntent,
    address: GuestVa,
    len: u64,
    offset: u64,
    sequence: NonZeroU64,
    fork_sequence: Option<NonZeroU64>,
}

impl TransferContinuation {
    pub const fn address(&self) -> GuestVa {
        self.address
    }
    pub const fn len(&self) -> u64 {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }
    pub const fn fork_sequence(&self) -> Option<NonZeroU64> {
        self.fork_sequence
    }
    /// # Safety
    /// The exact pending-fork owner must authenticate this sequence.
    pub unsafe fn with_fork_sequence(mut self, sequence: NonZeroU64) -> Self {
        self.fork_sequence = Some(sequence);
        self
    }
    /// # Safety
    /// Candidate request only: the owner must revalidate before effects.
    pub unsafe fn from_request(
        request: carrick_core_abi::PortalTransferRequest,
    ) -> Result<Self, TransferError> {
        let handle = unsafe {
            carrick_core_abi::El1MmHandle::from_admitted_owner(
                request.operation.carrier,
                request.operation.mm,
                request.operation.incarnation,
            )
        };
        let address = request
            .range
            .address()
            .checked_sub(request.selected.offset)
            .ok_or(TransferError::Invalid)?;
        let len = request
            .selected
            .offset
            .checked_add(request.range.len())
            .ok_or(TransferError::Invalid)?;
        Ok(Self {
            handle,
            intent: request.intent,
            address: GuestVa::new(address),
            len,
            offset: request.selected.offset,
            sequence: request.operation.sequence,
            fork_sequence: request.fork_sequence,
        })
    }

    /// # Safety
    /// The sequence must come from this handle's exact admitted owner.
    pub unsafe fn from_owner_sequence(
        handle: El1MmHandle,
        address: GuestVa,
        len: u64,
        intent: TransferIntent,
        sequence: NonZeroU64,
    ) -> Result<Self, TransferError> {
        address
            .raw()
            .checked_add(len)
            .ok_or(TransferError::Invalid)?;
        Ok(Self {
            handle,
            intent,
            address,
            len,
            offset: 0,
            sequence,
            fork_sequence: None,
        })
    }
    pub fn settle(
        &mut self,
        request: carrick_core_abi::PortalTransferRequest,
        receipt: carrick_core_abi::PortalTransferCompletion,
    ) -> Result<(), TransferError> {
        if receipt.operation != request.operation
            || receipt.retained != request.retained
            || request.operation.carrier != self.handle.carrier()
            || request.operation.mm != self.handle.mm()
            || request.operation.incarnation != self.handle.incarnation()
            || request.operation.sequence != self.sequence
            || request.selected.offset != self.offset
            || request.range.address() != self.address.raw() + self.offset
            || receipt.completed > request.range.len()
            || receipt.completed > self.len - self.offset
        {
            return Err(TransferError::Stale);
        }
        self.offset += receipt.completed;
        Ok(())
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn is_complete(&self) -> bool {
        self.offset == self.len
    }
}

/// EL1-selected data, not metadata storage. Host enriches this with its exact
/// physical record identity and retains the matching stage-2 pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedChunk {
    pub(crate) retry: Option<carrick_core_abi::PortalOwnerWait>,
    fork_sequence: Option<NonZeroU64>,
    handle: El1MmHandle,
    sequence: NonZeroU64,
    pub(crate) generation: u64,
    offset: u64,
    pub va: GuestVa,
    pub ipa: u64,
    pub executable: bool,
    pub len: u64,
}

/// Exact-MM authorization for one bounded copy. A host custodian must retain
/// the selected physical identities before obtaining this fence. Drop before
/// any host I/O, lazy supply, suspension, or selection of the next chunk.
pub struct ValidatedChunk<'a> {
    pub(crate) selected: SelectedChunk,
    pub(crate) _editor: SpaceEditor<'a>,
}
impl ValidatedChunk<'_> {
    pub fn selected(&self) -> SelectedChunk {
        self.selected
    }
    pub fn complete(self, continuation: &mut TransferContinuation) -> Result<(), TransferError> {
        if continuation.handle != self.selected.handle
            || continuation.sequence != self.selected.sequence
            || continuation.offset != self.selected.offset
        {
            return Err(TransferError::Stale);
        }
        continuation.offset += self.selected.len;
        Ok(())
    }
}

impl SelectedChunk {
    pub const fn handle(&self) -> El1MmHandle {
        self.handle
    }
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }
    pub const fn retry(&self) -> Option<carrick_core_abi::PortalOwnerWait> {
        self.retry
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// # Safety
    /// Candidate receipt only; exact live revalidation must precede every effect.
    pub unsafe fn from_request(request: carrick_core_abi::PortalTransferRequest) -> Self {
        Self {
            retry: None,
            fork_sequence: request.fork_sequence,
            handle: unsafe {
                El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.operation.mm,
                    request.operation.incarnation,
                )
            },
            sequence: request.operation.sequence,
            generation: request.selected.root_generation.get(),
            offset: request.selected.offset,
            va: GuestVa::new(request.range.address()),
            ipa: request.selected.ipa,
            executable: request.selected.executable,
            len: request.range.len(),
        }
    }
    /// # Safety
    /// The caller must hold the exact MM editor and authenticate the selected mapping.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn from_owner_selection(
        handle: El1MmHandle,
        sequence: NonZeroU64,
        generation: u64,
        offset: u64,
        va: GuestVa,
        ipa: u64,
        executable: bool,
        len: u64,
        fork_sequence: Option<NonZeroU64>,
        retry: Option<carrick_core_abi::PortalOwnerWait>,
    ) -> Self {
        Self {
            handle,
            sequence,
            generation,
            offset,
            va,
            ipa,
            executable,
            len,
            fork_sequence,
            retry,
        }
    }
    pub fn matches(&self, continuation: &TransferContinuation) -> bool {
        self.fork_sequence == continuation.fork_sequence
            && self.handle == continuation.handle
            && self.sequence == continuation.sequence
            && self.offset == continuation.offset
    }
}
impl SelectedChunk {
    pub fn request(
        self,
        intent: TransferIntent,
        retained: carrick_core_abi::PortalRetainedData,
    ) -> Result<carrick_core_abi::PortalTransferRequest, TransferError> {
        use carrick_core_abi::{
            PortalByteRange, PortalOperation, PortalSelectedData, PortalTransferRequest,
        };
        PortalTransferRequest::new(
            PortalOperation {
                carrier: self.handle.carrier(),
                mm: self.handle.mm(),
                incarnation: self.handle.incarnation(),
                sequence: self.sequence,
            },
            PortalByteRange::new(self.va.raw(), self.len).ok_or(TransferError::Invalid)?,
            intent,
            PortalSelectedData {
                ipa: self.ipa,
                executable: self.executable,
                root_generation: NonZeroU64::new(self.generation).ok_or(TransferError::Stale)?,
                offset: self.offset,
            },
            retained,
        )
        .map(|mut request| {
            request.fork_sequence = self.fork_sequence;
            request
        })
        .ok_or(TransferError::Invalid)
    }
}
