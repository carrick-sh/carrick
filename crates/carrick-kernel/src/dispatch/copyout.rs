//! Typed syscall copyout: prepare every user output before the first side
//! effect, commit it after.
//!
//! An admitted EL1 owner may refuse a host copyout transiently: its editor is
//! busy with a sibling thread's edit (`OwnerWait`), the page needs a physical
//! grant or COW (`Supply`), or a retained writer must drain (`Physical`). Each
//! refusal asks the runtime to park and redispatch the saved syscall, so it is
//! only correct while the handler has done nothing irrevocable. A direct
//! `write_bytes` after side effects can only lower that refusal to EFAULT on a
//! valid pointer (#708, #711).
//!
//! This module makes the order a type: [`prepare`] is the only step that can
//! ask for a retry, and it returns a [`PreparedCopyout`] that borrows the
//! memory until [`PreparedCopyout::commit`]. A prepared permit cannot suspend.
//! On the legacy venue preparation costs nothing and the commit is the
//! existing direct write.
//!
//! An invalid pointer is not a retry: on both venues it surfaces at the
//! commit as [`CopyoutFault`] (EFAULT), after the side effect, which is where
//! Linux reports it (`pipe2` creates and then frees its files). Only a
//! retryable owner wait refuses preparation.
//!
//! The order relative to side effects is the handler's obligation: call
//! `prepare` before creating or installing anything, and treat a
//! [`CopyoutRefusal`] as "return now". Consuming syscalls require retained
//! operation authority; bounded array consumers reserve their whole-record
//! destination before dequeuing.
//! Side-effect-free handlers (stat, clock reads) may prepare immediately
//! before committing.

use carrick_abi::{KernelAbi, LINUX_EFAULT};
use carrick_guest_mem::{
    CurrentMmMemory, GuestVa, GuestWriteRange, PreparedGuestWrite, UserMemoryVenue,
};

use super::{DispatchError, DispatchOutcome};
use crate::kernel::KernelContext;
pub(crate) type OwnerEffect =
    carrick_core::cancellation::ProcessEffect<crate::kernel::objects::ThreadLifecycleLease>;

pub(crate) fn admit_effect(context: &KernelContext) -> Result<OwnerEffect, CopyoutRefusal> {
    use crate::kernel::continuation::OwnerWaitCancellation;
    use carrick_core::cancellation::ProcessCancellation;
    OwnerEffect::acquire(context.lifecycle_page()).map_err(|cause| {
        let reason = if context.thread().control_slot().native_signal_owner() {
            OwnerWaitCancellation::NativeFatal
        } else {
            match cause {
                ProcessCancellation::FatalSignal => OwnerWaitCancellation::Carrier,
                ProcessCancellation::GroupExit | ProcessCancellation::Exec => {
                    OwnerWaitCancellation::GroupExit
                }
            }
        };
        CopyoutRefusal(Box::new(DispatchOutcome::OwnerCancelled(reason)))
    })
}

/// The largest total output one copyout prepares: one owner portal permit.
/// Fixed records are checked at compile time; variable outputs must clamp
/// their capacity before preparing.
pub(crate) const COPYOUT_MAX_BYTES: usize = carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize;

/// One guest output: an address and the most bytes the handler may commit
/// there. A zero capacity names no output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserSlot {
    address: u64,
    capacity: usize,
}

impl UserSlot {
    pub(crate) const fn new(address: u64, capacity: usize) -> Self {
        Self { address, capacity }
    }

    /// The exact Linux wire size of one `T` at `address`.
    pub(crate) const fn of<T: KernelAbi>(address: u64) -> Self {
        Self::new(address, T::ABI_SIZE)
    }

    /// An optional out-parameter: a NULL pointer names no output.
    pub(crate) const fn optional(address: u64, capacity: usize) -> Option<Self> {
        if address == 0 {
            None
        } else {
            Some(Self::new(address, capacity))
        }
    }

    pub(crate) const fn capacity(self) -> usize {
        self.capacity
    }
}

/// A retryable owner refusal: the editor is busy, or the output needs physical
/// supply or a retained writer to drain. Nothing was written; the handler
/// returns this outcome before its first side effect and the runtime parks,
/// serves the dependency and redispatches the saved syscall.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a refused copyout must be returned before any side effect"]
/// Boxed: a refusal is the rare path, and the outcome is large.
pub(crate) struct CopyoutRefusal(Box<DispatchOutcome>);

impl DispatchOutcome {
    /// Preserve the owner preparation verdict across runtime copyout boundaries.
    pub fn from_owner_memory_prepare_error(error: carrick_guest_mem::MemoryPrepareError) -> Self {
        crate::el1_delegation::owner_prepare_refusal(error)
    }

    /// A typed read dependency always has a canonical suspension outcome.
    pub fn from_owner_memory_read_wait(wait: carrick_guest_mem::MemoryReadWait) -> Self {
        use carrick_guest_mem::{MemoryReadWait, MemorySupplyRequest};
        match wait {
            MemoryReadWait::Owner(wait) => Self::OwnerMemoryWait { wait, committed: 0 },
            MemoryReadWait::Physical(wait) => Self::OwnerPhysicalWait { wait, committed: 0 },
            MemoryReadWait::Supply(MemorySupplyRequest::Metadata { observed, .. }) => {
                Self::OwnerMemoryWait {
                    wait: observed,
                    committed: 0,
                }
            }
            MemoryReadWait::Supply(request) => Self::OwnerMemorySupply {
                request,
                committed: 0,
            },
        }
    }

    /// Convert a retryable owner memory refusal into the canonical dispatch
    /// outcome that parks or supplies the dependency before redispatching.
    pub fn from_owner_memory_error(error: carrick_guest_mem::MemoryError) -> Option<Self> {
        use carrick_guest_mem::{MemoryError, MemorySupplyRequest};
        let outcome = match error {
            MemoryError::ReadSuspended(suspension) => {
                Self::from_owner_memory_read_wait(suspension.wait)
            }
            MemoryError::OwnerWait(wait) => Self::OwnerMemoryWait { wait, committed: 0 },
            MemoryError::Physical(wait) => Self::OwnerPhysicalWait { wait, committed: 0 },
            MemoryError::Supply(request) => match *request {
                MemorySupplyRequest::Metadata { observed, .. } => Self::OwnerMemoryWait {
                    wait: observed,
                    committed: 0,
                },
                request => Self::OwnerMemorySupply {
                    request,
                    committed: 0,
                },
            },
            _ => return None,
        };
        Some(outcome)
    }
}

impl CopyoutRefusal {
    pub(crate) fn into_outcome(self) -> DispatchOutcome {
        *self.0
    }

    pub(crate) fn from_read_error(error: carrick_guest_mem::MemoryError) -> Option<Self> {
        DispatchOutcome::from_owner_memory_error(error).map(|outcome| Self(Box::new(outcome)))
    }
}

impl From<CopyoutRefusal> for DispatchOutcome {
    fn from(refusal: CopyoutRefusal) -> Self {
        refusal.into_outcome()
    }
}

/// Read a 4-byte guest length (`socklen_t`) before any side effect: a
/// transient owner read suspension returns [`CopyoutRefusal`] so the runtime
/// parks and retries, while an invalid pointer returns [`CopyoutFault`].
pub(crate) fn read_u32_before_effects(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<Result<u32, CopyoutFault>, CopyoutRefusal> {
    if address == 0 {
        return Ok(Err(CopyoutFault));
    }
    match memory.read_bytes(address, 4) {
        Ok(bytes) => Ok(Ok(u32::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        Err(error) => match CopyoutRefusal::from_read_error(error) {
            Some(refusal) => Err(refusal),
            None => Ok(Err(CopyoutFault)),
        },
    }
}

/// A commit hit an invalid guest pointer: EFAULT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CopyoutFault;

impl CopyoutFault {
    pub(crate) fn outcome(self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_EFAULT)
    }
}

impl From<CopyoutFault> for DispatchError {
    fn from(_: CopyoutFault) -> Self {
        DispatchError::Errno(LINUX_EFAULT)
    }
}

enum Venue<'m, M: CurrentMmMemory> {
    Owner {
        permit: Option<Box<dyn PreparedGuestWrite + 'm>>,
        valid_present: usize,
        faulted: bool,
    },
    Legacy(&'m mut M),
}

/// Destination authority for up to `N` outputs, obtained before any side
/// effect. It borrows the memory until it is committed or dropped; dropping it
/// unused cancels the owner permit.
#[must_use = "a prepared copyout writes nothing until it is committed"]
pub(crate) struct PreparedCopyout<'m, M: CurrentMmMemory, const N: usize> {
    slots: [Option<UserSlot>; N],
    venue: Venue<'m, M>,
    effect: Option<OwnerEffect>,
}

/// Prepare every output of one syscall. `None` slots (a NULL optional
/// pointer) and zero-capacity slots write nothing.
pub(crate) fn prepare<'m, M: CurrentMmMemory, const N: usize>(
    context: &KernelContext,
    memory: &'m mut M,
    slots: [Option<UserSlot>; N],
) -> Result<PreparedCopyout<'m, M, N>, CopyoutRefusal> {
    let owner = memory.user_memory_venue() == UserMemoryVenue::Owner;
    let mut output = prepare_memory(memory, slots)?;
    if owner {
        output.effect = Some(admit_effect(context)?);
    }
    Ok(output)
}

fn prepare_memory<M: CurrentMmMemory, const N: usize>(
    memory: &mut M,
    slots: [Option<UserSlot>; N],
) -> Result<PreparedCopyout<'_, M, N>, CopyoutRefusal> {
    let slots = slots.map(|slot| slot.filter(|slot| slot.capacity > 0));
    // The legacy venue has no permit and prepares nothing: a guest-sized
    // output commits exactly as the direct write it replaces and never meets
    // the owner bound below.
    if memory.user_memory_venue() == UserMemoryVenue::Legacy {
        return Ok(PreparedCopyout {
            slots,
            effect: None,
            venue: Venue::Legacy(memory),
        });
    }
    let Some(empty) = GuestWriteRange::new(GuestVa::new(0), 0) else {
        return Ok(PreparedCopyout {
            slots,
            effect: None,
            venue: Venue::Owner {
                permit: None,
                valid_present: 0,
                faulted: true,
            },
        });
    };
    let mut ranges = [empty; N];
    let mut count = 0usize;
    let mut total = 0usize;
    let mut faulted = false;
    for slot in slots.iter().flatten() {
        let Some(next_total) = total.checked_add(slot.capacity) else {
            debug_assert!(false, "owner copyout overflows permit size");
            faulted = true;
            break;
        };
        if next_total > COPYOUT_MAX_BYTES {
            // Owner capacities are fixed records (checked at compile time) or
            // carrick-sized values, so no guest length reaches this. A larger permit would be refused as a Limit,
            // which the owner refusal path treats as fatal; report EFAULT at
            // the commit instead and never abort the carrier.
            debug_assert!(
                false,
                "owner copyout exceeds one permit: {next_total} bytes"
            );
            faulted = true;
            break;
        }
        let Some(range) = GuestWriteRange::new(GuestVa::new(slot.address), slot.capacity) else {
            faulted = true;
            break;
        };
        ranges[count] = range;
        count += 1;
        total = next_total;
    }
    if count == 0 {
        return Ok(PreparedCopyout {
            slots,
            effect: None,
            venue: Venue::Owner {
                permit: None,
                valid_present: 0,
                faulted,
            },
        });
    }
    // Preserve sequential valid-prefix writes when a later slot is invalid:
    // if preparing the full prefix faults (`EFAULT`), step back to the longest
    // valid prefix so earlier slots still commit before reporting `EFAULT`,
    // matching the legacy venue and Linux (`wait4`, `gettimeofday`, `sockaddr`,
    // `getsockopt`). Any transient refusal returns immediately before effects.
    let memory_ptr: *mut M = memory;
    let mut prefix = count;
    while prefix > 0 {
        // SAFETY: NLL Problem Case #3 workaround: on `Err`, `prepare_write`
        // drops its borrow of `*memory` before returning `Err`, so no borrow
        // escapes a failed iteration; on `Ok`, the function returns immediately
        // with the single active `PreparedGuestWrite` tied to `'m`.
        let attempt = unsafe { &mut *memory_ptr }.prepare_write(&ranges[..prefix]);
        match attempt {
            Ok(permit) => {
                return Ok(PreparedCopyout {
                    slots,
                    effect: None,
                    venue: Venue::Owner {
                        permit: Some(permit),
                        valid_present: prefix,
                        faulted,
                    },
                });
            }
            Err(error) => match crate::el1_delegation::owner_prepare_refusal(error) {
                outcome if outcome == DispatchOutcome::errno(LINUX_EFAULT) => {
                    faulted = true;
                    prefix -= 1;
                }
                outcome => return Err(CopyoutRefusal(Box::new(outcome))),
            },
        }
    }
    Ok(PreparedCopyout {
        slots,
        effect: None,
        venue: Venue::Owner {
            permit: None,
            valid_present: 0,
            faulted: true,
        },
    })
}

impl<M: CurrentMmMemory, const N: usize> PreparedCopyout<'_, M, N> {
    /// The prepared capacity of output `index` (0 for an absent slot).
    pub(crate) fn capacity(&self, index: usize) -> usize {
        self.slots
            .get(index)
            .copied()
            .flatten()
            .map_or(0, UserSlot::capacity)
    }

    /// Capacity already secured for a consuming operation. A faulted owner
    /// slot accepts no bytes: the source must not consume on a failed copy.
    pub(crate) fn secured_capacity(&self, index: usize) -> usize {
        match &self.venue {
            Venue::Owner { valid_present, .. } => {
                let present = self.slots.iter().take(index + 1).flatten().count();
                if present > *valid_present {
                    0
                } else {
                    self.capacity(index)
                }
            }
            Venue::Legacy(_) => self.capacity(index),
        }
    }

    /// Release an unused destination while retaining metadata-effect custody.
    /// EOF and would-block never access the destination, even if it is invalid.
    pub(crate) fn cancel_retaining(mut self) -> Option<OwnerEffect> {
        self.effect.take()
    }

    /// Keep effect custody through metadata publication following copyout.
    pub(crate) fn commit_retaining(
        mut self,
        outputs: [&[u8]; N],
    ) -> (Result<(), CopyoutFault>, Option<OwnerEffect>) {
        let effect = self.effect.take();
        (self.commit(outputs), effect)
    }

    /// Write one prefix per slot; the output for an absent slot (a NULL
    /// optional pointer) is ignored. On both venues the first invalid pointer
    /// stops the commit with [`CopyoutFault`] after any earlier valid slots
    /// were written.
    pub(crate) fn commit(self, outputs: [&[u8]; N]) -> Result<(), CopyoutFault> {
        for (slot, output) in self.slots.iter().zip(outputs) {
            let Some(capacity) = slot.map(UserSlot::capacity) else {
                continue;
            };
            if output.len() > capacity {
                // A handler bug, never guest-sized: write nothing and report
                // EFAULT rather than overrun the prepared range.
                debug_assert!(
                    false,
                    "copyout output of {} bytes exceeds its prepared {capacity}",
                    output.len()
                );
                return Err(CopyoutFault);
            }
        }
        match self.venue {
            Venue::Owner {
                permit,
                valid_present,
                faulted,
            } => {
                if let Some(permit) = permit {
                    let mut present: [&[u8]; N] = [&[]; N];
                    let mut count = 0;
                    for (slot, output) in self.slots.iter().zip(outputs) {
                        if slot.is_some() {
                            if count == valid_present {
                                break;
                            }
                            present[count] = output;
                            count += 1;
                        }
                    }
                    permit.commit(&present[..count]);
                }
                if faulted { Err(CopyoutFault) } else { Ok(()) }
            }
            Venue::Legacy(memory) => {
                for (slot, output) in self.slots.iter().zip(outputs) {
                    if let Some(slot) = slot
                        && !output.is_empty()
                    {
                        memory
                            .write_bytes(slot.address, output)
                            .map_err(|_| CopyoutFault)?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// A bounded destination for whole records. The secured capacity is the
/// consumption budget; no source may be advanced beyond it.
pub(crate) struct PreparedArrayOut<'m, M: CurrentMmMemory> {
    inner: PreparedCopyout<'m, M, 1>,
    records: usize,
}

impl<M: CurrentMmMemory> PreparedArrayOut<'_, M> {
    pub(crate) fn records(&self) -> usize {
        self.records
    }

    pub(crate) fn commit(self, bytes: &[u8]) -> Result<(), CopyoutFault> {
        self.commit_retaining(bytes).0
    }

    /// Keep cancellation custody through source/cursor publication after copyout.
    pub(crate) fn commit_retaining(
        self,
        bytes: &[u8],
    ) -> (Result<(), CopyoutFault>, Option<OwnerEffect>) {
        if bytes.is_empty() {
            return (Ok(()), self.inner.cancel_retaining());
        }
        self.inner.commit_retaining([bytes])
    }
}

/// Secure a writable whole-record prefix, bounded by one portal.
/// Valid destinations require one prepare. Real faults reduce the attempted
/// window geometrically. Retain the first valid permit: releasing it to probe
/// again would cache stale authority if a sibling changes the mapping.
/// Transient refusals escape immediately, including during prefix selection.
pub(crate) fn prepare_array<'m, M: CurrentMmMemory>(
    context: &KernelContext,
    memory: &'m mut M,
    address: GuestVa,
    records: usize,
    record_size: usize,
) -> Result<PreparedArrayOut<'m, M>, CopyoutRefusal> {
    let address = address.raw();
    assert!((1..=COPYOUT_MAX_BYTES).contains(&record_size));
    let mut records = records.min(COPYOUT_MAX_BYTES / record_size);
    // Each failed probe drops its borrow before the next attempt. Only the
    // final successful permit escapes, exactly as in `prepare_memory`.
    let memory_ptr: *mut M = memory;
    loop {
        // SAFETY: previous probes are dropped before another borrow; returning
        // transfers the sole live borrow to the returned prepared destination.
        let memory = unsafe { &mut *memory_ptr };
        let legacy_valid = memory.user_memory_venue() != UserMemoryVenue::Legacy
            || memory.guest_range_is_writable(address, records * record_size);
        let out = prepare(
            context,
            memory,
            [Some(UserSlot::new(address, records * record_size))],
        )?;
        if records == 0 || (legacy_valid && out.secured_capacity(0) == records * record_size) {
            return Ok(PreparedArrayOut {
                inner: out,
                records,
            });
        }
        drop(out);
        records /= 2;
    }
}

/// Copy bytes from a side-effect-free query, preserving transient refusals.
pub(crate) fn copyout_bytes(
    context: &KernelContext,
    memory: &mut impl CurrentMmMemory,
    address: GuestVa,
    bytes: &[u8],
    success: DispatchOutcome,
) -> DispatchOutcome {
    let address = address.raw();
    for (index, chunk) in bytes.chunks(COPYOUT_MAX_BYTES).enumerate() {
        let Some(address) = address.checked_add((index * COPYOUT_MAX_BYTES) as u64) else {
            return CopyoutFault.outcome();
        };
        let out = match prepare(context, memory, [Some(UserSlot::new(address, chunk.len()))]) {
            Ok(out) => out,
            Err(refusal) => return refusal.into_outcome(),
        };
        if let Err(fault) = out.commit([chunk]) {
            return fault.outcome();
        }
    }
    success
}

/// One typed output record: exactly `T::ABI_SIZE` bytes at a guest address.
pub(crate) struct UserOut<T: KernelAbi> {
    slot: UserSlot,
    _record: core::marker::PhantomData<fn(&T)>,
}

impl<T: KernelAbi> UserOut<T> {
    pub(crate) const fn new(address: u64) -> Self {
        const {
            assert!(T::ABI_SIZE <= COPYOUT_MAX_BYTES);
        }
        Self {
            slot: UserSlot::of::<T>(address),
            _record: core::marker::PhantomData,
        }
    }

    pub(crate) fn prepare<'m, M: CurrentMmMemory>(
        self,
        context: &KernelContext,
        memory: &'m mut M,
    ) -> Result<PreparedOut<'m, M, T>, CopyoutRefusal> {
        Ok(PreparedOut {
            inner: prepare(context, memory, [Some(self.slot)])?,
            _record: core::marker::PhantomData,
        })
    }
}

/// A prepared [`UserOut`]: commit the record after side effects.
#[must_use = "a prepared copyout writes nothing until it is committed"]
pub(crate) struct PreparedOut<'m, M: CurrentMmMemory, T: KernelAbi> {
    inner: PreparedCopyout<'m, M, 1>,
    _record: core::marker::PhantomData<fn(&T)>,
}

impl<M: CurrentMmMemory, T: KernelAbi> PreparedOut<'_, M, T> {
    pub(crate) fn commit(self, value: &T) -> Result<(), CopyoutFault> {
        self.inner.commit([value.abi_bytes()])
    }

    /// Commit, then report `success`; a legacy fault reports EFAULT.
    pub(crate) fn commit_returning(self, value: &T, success: DispatchOutcome) -> DispatchOutcome {
        match self.commit(value) {
            Ok(()) => success,
            Err(fault) => fault.outcome(),
        }
    }
}

/// Prepare and commit one record from a handler with nothing irrevocable
/// behind it: a refusal or fault is the whole syscall's answer.
pub(crate) fn copyout_record<T: KernelAbi>(
    context: &KernelContext,
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: &T,
    success: DispatchOutcome,
) -> DispatchOutcome {
    match UserOut::<T>::new(address).prepare(context, memory) {
        Ok(out) => out.commit_returning(value, success),
        Err(refusal) => refusal.into_outcome(),
    }
}

/// An admitted-owner test memory that, like `Aarch64EngineCore`, routes every
/// user write through one prepared permit, and refuses the first prepare with
/// an Editor `OwnerWait`. An unmigrated direct write therefore sees the
/// refusal as a `MemoryError` and lowers it to EFAULT, which is the defect;
/// a migrated handler reports the wait, writes nothing and retries cleanly.
#[cfg(test)]
pub(crate) mod owner_fixture {
    use super::super::LinearMemory;
    use carrick_el1_abi::{El1MmHandle, PortalOwnerWait, PortalWaitCause, ReservationMm};
    use carrick_guest_mem::{
        CurrentMmMemory, GuestMemory, GuestVa, GuestWriteRange, MemoryError, MemoryPrepareError,
        PreparedGuestWrite, UserMemoryVenue,
    };
    use std::num::NonZeroU64;

    pub(crate) fn editor_wait() -> PortalOwnerWait {
        // SAFETY: the fixture models the exact admitted owner whose editor a
        // sibling's edit holds at this revision.
        unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(1).unwrap(),
                    ReservationMm::new(2).unwrap(),
                    NonZeroU64::new(3).unwrap(),
                ),
                PortalWaitCause::Editor,
                7,
            )
        }
    }

    pub(crate) struct OwnerRefusingMemory {
        pub(crate) inner: LinearMemory,
        refuse: Option<PortalOwnerWait>,
        refuse_after: usize,
        supply: Option<carrick_guest_mem::MemorySupplyRequest>,
        refuse_read: std::cell::Cell<Option<PortalOwnerWait>>,
        readonly: Vec<(u64, usize)>,
        pub(crate) prepares: usize,
    }

    impl OwnerRefusingMemory {
        /// Every byte starts as `fill` so an untouched output is visible.
        pub(crate) fn new(base: u64, len: usize, fill: u8) -> Self {
            Self {
                inner: LinearMemory::new(base, vec![fill; len]),
                refuse: None,
                refuse_after: 0,
                supply: None,
                refuse_read: std::cell::Cell::new(None),
                readonly: Vec::new(),
                prepares: 0,
            }
        }

        /// Refuse the next prepare with an Editor wait.
        pub(crate) fn refuse_next(&mut self) -> PortalOwnerWait {
            self.refuse_after_prepares(0)
        }

        /// Refuse after `count` further preparation calls, for multi-window copies.
        pub(crate) fn refuse_after_prepares(&mut self, count: usize) -> PortalOwnerWait {
            let wait = editor_wait();
            self.refuse = Some(wait);
            self.refuse_after = count;
            wait
        }

        /// Model first-touch backing supply for an untouched private page.
        pub(crate) fn refuse_next_supply_grant(
            &mut self,
        ) -> carrick_guest_mem::MemorySupplyRequest {
            let request = carrick_guest_mem::MemorySupplyRequest::Grant(
                carrick_el1_abi::PortalGrantWindow::decode([
                    1, 2, 3, 1, 1, 0x1000, 0x2000, 3, 0x1000, 0, 0, 0, 0,
                ])
                .unwrap(),
            );
            self.supply = Some(request);
            request
        }

        /// Refuse the next guest read with an Editor wait.
        pub(crate) fn refuse_next_read(&self) -> PortalOwnerWait {
            let wait = editor_wait();
            self.refuse_read.set(Some(wait));
            wait
        }

        /// Mark `[address, address + len)` readable but not writable (`PROT_READ`).
        pub(crate) fn protect_readonly(&mut self, address: u64, len: usize) {
            self.readonly.push((address, len));
        }

        /// Write fixture input without consuming a refusal.
        pub(crate) fn seed(&mut self, address: u64, bytes: &[u8]) {
            self.inner.write_bytes_raw(address, bytes).unwrap();
        }
    }

    struct Permit<'a> {
        memory: &'a mut LinearMemory,
        ranges: Vec<GuestWriteRange>,
    }

    impl PreparedGuestWrite for Permit<'_> {
        fn commit(self: Box<Self>, outputs: &[&[u8]]) {
            assert_eq!(outputs.len(), self.ranges.len(), "one prefix per range");
            for (range, output) in self.ranges.iter().zip(outputs) {
                assert!(output.len() <= range.len(), "prefix exceeds its range");
                self.memory
                    .write_bytes_raw(range.address().raw(), output)
                    .expect("prepared range is inside the fixture");
            }
        }
    }

    impl GuestMemory for OwnerRefusingMemory {
        fn user_memory_venue(&self) -> UserMemoryVenue {
            UserMemoryVenue::Owner
        }

        fn prepare_write(
            &mut self,
            ranges: &[GuestWriteRange],
        ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
            self.prepares += 1;
            if self.refuse_after != 0 {
                self.refuse_after -= 1;
            } else if let Some(wait) = self.refuse.take() {
                return Err(MemoryPrepareError::OwnerWait(wait));
            }
            if let Some(request) = self.supply.take() {
                return Err(MemoryPrepareError::Supply(request));
            }
            for range in ranges {
                if !self.guest_range_is_writable(range.address().raw(), range.len()) {
                    return Err(MemoryPrepareError::Fault(MemoryError::OutOfBounds {
                        address: range.address().raw(),
                        length: range.len(),
                    }));
                }
            }
            Ok(Box::new(Permit {
                memory: &mut self.inner,
                ranges: ranges.to_vec(),
            }))
        }

        fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
            if !self.inner.guest_range_is_writable(address, length) {
                return false;
            }
            let Some(end) = address.checked_add(length as u64) else {
                return false;
            };
            !self.readonly.iter().any(|&(ro_addr, ro_len)| {
                let ro_end = ro_addr.saturating_add(ro_len as u64);
                address < ro_end && ro_addr < end
            })
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            if let Some(wait) = self.refuse_read.take() {
                return Err(MemoryError::ReadSuspended(Box::new(
                    carrick_guest_mem::MemoryReadSuspension {
                        wait: carrick_guest_mem::MemoryReadWait::Owner(wait),
                        continuation: carrick_guest_mem::OwnedReadContinuation::new((
                            address, length,
                        )),
                    },
                )));
            }
            self.inner.read_bytes_raw(address, length)
        }

        fn resume_read(
            &self,
            continuation: carrick_guest_mem::OwnedReadContinuation,
        ) -> Result<Vec<u8>, MemoryError> {
            let (address, length) = continuation
                .take::<(u64, usize)>()
                .expect("fixture read continuation belongs to this memory");
            self.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            let range = GuestWriteRange::new(GuestVa::new(address), bytes.len()).ok_or(
                MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                },
            )?;
            match self.prepare_write(&[range]) {
                Ok(permit) => {
                    permit.commit(&[bytes]);
                    Ok(())
                }
                Err(MemoryPrepareError::OwnerWait(wait)) => Err(MemoryError::OwnerWait(wait)),
                Err(MemoryPrepareError::Fault(error)) => Err(error),
                Err(MemoryPrepareError::Supply(request)) => {
                    Err(MemoryError::Supply(Box::new(request)))
                }
                Err(_) => Err(MemoryError::Unsupported),
            }
        }
    }

    impl CurrentMmMemory for OwnerRefusingMemory {}
}

#[cfg(test)]
mod tests {
    use super::owner_fixture::OwnerRefusingMemory;
    use super::*;
    use crate::dispatch::LinearMemory;
    use carrick_abi::LinuxTimespec;
    use carrick_guest_mem::GuestMemory;

    const BASE: u64 = 0x1_0000;

    fn context() -> crate::kernel::KernelContext {
        crate::dispatch::SyscallDispatcher::new()
            .capture_one_task_context()
            .unwrap()
    }

    #[test]
    fn s1_array_keeps_first_valid_permit_across_mapping_changes() {
        struct ShrinkingMemory(OwnerRefusingMemory);
        impl GuestMemory for ShrinkingMemory {
            fn user_memory_venue(&self) -> UserMemoryVenue {
                UserMemoryVenue::Owner
            }
            fn prepare_write(
                &mut self,
                ranges: &[GuestWriteRange],
            ) -> Result<Box<dyn PreparedGuestWrite + '_>, carrick_guest_mem::MemoryPrepareError>
            {
                assert!(
                    self.0.prepares < 12,
                    "prefix selection must not revisit released authority indefinitely"
                );
                if self.0.prepares >= 2 {
                    // An editor retires the previously valid prefix after its
                    // permit was released to probe a larger destination.
                    self.0.protect_readonly(BASE, 64);
                }
                self.0.prepare_write(ranges)
            }
            fn read_bytes_raw(
                &self,
                address: u64,
                length: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                self.0.read_bytes_raw(address, length)
            }
            fn write_bytes_raw(
                &mut self,
                address: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                self.0.write_bytes_raw(address, bytes)
            }
        }
        impl CurrentMmMemory for ShrinkingMemory {}
        let mut memory = ShrinkingMemory(OwnerRefusingMemory::new(BASE, 64, 0xa5));
        let out = prepare_array(&context(), &mut memory, GuestVa::new(BASE), 8, 16).unwrap();
        assert_eq!(out.records(), 4);
        out.commit(&[7; 64]).unwrap();
        assert_eq!(
            memory.0.prepares, 2,
            "retain the first valid permit instead of releasing it to probe again"
        );
    }

    #[test]
    fn s1_arrays_secure_only_whole_records_and_bound_preparation_work() {
        for size in [12, 16, 32, 128] {
            let mut memory = OwnerRefusingMemory::new(BASE, COPYOUT_MAX_BYTES * 2, 0xa5);
            let out = prepare_array(
                &context(),
                &mut memory,
                GuestVa::new(BASE),
                usize::MAX,
                size,
            )
            .unwrap();
            assert_eq!(out.records(), COPYOUT_MAX_BYTES / size);
            out.commit(&vec![7; (COPYOUT_MAX_BYTES / size) * size])
                .unwrap();
            assert_eq!(
                memory.prepares, 1,
                "valid bounded window uses exactly one permit"
            );
            let mut memory = OwnerRefusingMemory::new(BASE, COPYOUT_MAX_BYTES, 0xa5);
            memory.protect_readonly(BASE + (3 * size) as u64, COPYOUT_MAX_BYTES - 3 * size);
            let out = prepare_array(
                &context(),
                &mut memory,
                GuestVa::new(BASE),
                usize::MAX,
                size,
            )
            .unwrap();
            assert_eq!(out.records(), 2);
            out.commit(&vec![7; 2 * size]).unwrap();
            assert!(
                memory.prepares <= 12,
                "fault selection is logarithmic in the bounded record count"
            );
            assert_eq!(
                memory
                    .inner
                    .read_bytes(BASE + (3 * size) as u64, size)
                    .unwrap(),
                vec![0xa5; size]
            );
        }
    }

    #[test]
    fn s1_arrays_preserve_empty_and_faulted_destinations() {
        let mut memory = OwnerRefusingMemory::new(BASE, 128, 0xa5);
        let _ = memory.refuse_next();
        prepare_array(&context(), &mut memory, GuestVa::new(0), 0, 128)
            .unwrap()
            .commit(&[])
            .unwrap();
        assert_eq!(memory.prepares, 0);
        // The zero-output reservation did not consume the refusal.
        assert!(prepare_array(&context(), &mut memory, GuestVa::new(BASE), 1, 128).is_err());
        let out =
            prepare_array(&context(), &mut memory, GuestVa::new(BASE + 0x2000), 1, 128).unwrap();
        assert_eq!(out.records(), 0);
        out.commit(&[]).unwrap();
        let mut legacy = LinearMemory::new(BASE, vec![0; 128]);
        let out =
            prepare_array(&context(), &mut legacy, GuestVa::new(BASE + 0x2000), 1, 128).unwrap();
        assert_eq!(out.records(), 0);
    }

    #[test]
    fn owner_refusal_is_the_wait_outcome_and_writes_nothing() {
        let mut memory = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        let wait = memory.refuse_next();
        let refused = UserOut::<LinuxTimespec>::new(BASE + 0x10)
            .prepare(&context(), &mut memory)
            .err()
            .expect("first prepare is refused");
        assert_eq!(
            refused.into_outcome(),
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
        );
        assert_eq!(memory.read_bytes(BASE + 0x10, 16).unwrap(), [0xa5; 16]);

        let value = LinuxTimespec::new(5, 7);
        UserOut::new(BASE + 0x10)
            .prepare(&context(), &mut memory)
            .unwrap()
            .commit(&value)
            .unwrap();
        assert_eq!(
            memory.read_bytes(BASE + 0x10, 16).unwrap(),
            value.abi_bytes()
        );
    }

    #[test]
    fn owner_fault_surfaces_at_commit_like_legacy() {
        let mut memory = OwnerRefusingMemory::new(BASE, 0x1000, 0);
        let Ok(prepared) =
            UserOut::<LinuxTimespec>::new(BASE + 0x2000).prepare(&context(), &mut memory)
        else {
            panic!("an invalid pointer is not a retryable refusal");
        };
        assert_eq!(
            prepared.commit(&LinuxTimespec::new(1, 1)),
            Err(CopyoutFault)
        );
    }

    #[test]
    fn absent_slots_are_skipped_on_both_venues() {
        let mut owner = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        prepare(
            &context(),
            &mut owner,
            [UserSlot::optional(0, 4), UserSlot::optional(BASE, 4)],
        )
        .unwrap()
        .commit([&[], &[1, 2, 3, 4]])
        .unwrap();
        assert_eq!(owner.read_bytes(BASE, 4).unwrap(), [1, 2, 3, 4]);

        let mut legacy = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
        let prepared = prepare(
            &context(),
            &mut legacy,
            [UserSlot::optional(BASE, 4), UserSlot::optional(0, 4)],
        )
        .unwrap();
        assert_eq!((prepared.capacity(0), prepared.capacity(1)), (4, 0));
        prepared.commit([&[9, 9], &[]]).unwrap();
        assert_eq!(legacy.read_bytes(BASE, 4).unwrap(), [9, 9, 0xa5, 0xa5]);
    }

    #[test]
    fn legacy_fault_surfaces_at_commit_as_before() {
        let mut legacy = LinearMemory::new(BASE, vec![0; 0x100]);
        let prepared = UserOut::<LinuxTimespec>::new(BASE + 0x1000)
            .prepare(&context(), &mut legacy)
            .expect("legacy preparation is free");
        assert_eq!(
            prepared.commit(&LinuxTimespec::new(1, 1)),
            Err(CopyoutFault)
        );
    }

    #[test]
    fn zero_outputs_make_zero_owner_prepares_and_never_suspend() {
        let mut owner = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        let _wait = owner.refuse_next();
        prepare(
            &context(),
            &mut owner,
            [UserSlot::optional(0, 8), Some(UserSlot::new(BASE, 0))],
        )
        .expect("no-output preparation must not touch the owner or suspend")
        .commit([&[], &[]])
        .unwrap();
        assert_eq!(
            owner.prepares, 0,
            "all-None / zero-capacity copyout must issue zero prepare_write calls"
        );
    }

    #[test]
    fn later_invalid_slot_commits_valid_prefix_on_both_venues() {
        let mut owner = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        let prepared = prepare(
            &context(),
            &mut owner,
            [
                Some(UserSlot::new(BASE + 0x10, 4)),
                Some(UserSlot::new(BASE + 0x2000, 8)),
            ],
        )
        .expect("invalid second slot is reported at commit, not as a retry");
        assert_eq!(prepared.commit([&[1, 2, 3, 4], &[5; 8]]), Err(CopyoutFault));
        assert_eq!(
            owner.read_bytes(BASE + 0x10, 4).unwrap(),
            [1, 2, 3, 4],
            "owner venue must commit the valid prefix before reporting EFAULT on the later slot",
        );

        let mut legacy = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
        let prepared = prepare(
            &context(),
            &mut legacy,
            [
                Some(UserSlot::new(BASE + 0x10, 4)),
                Some(UserSlot::new(BASE + 0x2000, 8)),
            ],
        )
        .unwrap();
        assert_eq!(prepared.commit([&[1, 2, 3, 4], &[5; 8]]), Err(CopyoutFault));
        assert_eq!(legacy.read_bytes(BASE + 0x10, 4).unwrap(), [1, 2, 3, 4]);
    }
}

// BEGIN S2 value-result output admission.
/// Addresses of a Linux length-prefixed output pair.
#[derive(Clone, Copy)]
pub(crate) struct ValueResultAddresses {
    pub(crate) value: GuestVa,
    pub(crate) length: GuestVa,
}

impl ValueResultAddresses {
    pub(crate) const fn new(value: GuestVa, length: GuestVa) -> Self {
        Self { value, length }
    }
}

/// Ordinary value-result errors must complete before output admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueResultFault {
    Memory(CopyoutFault),
    NegativeLength,
}

impl ValueResultFault {
    pub(crate) fn outcome(self) -> DispatchOutcome {
        match self {
            Self::Memory(fault) => fault.outcome(),
            Self::NegativeLength => DispatchOutcome::errno(carrick_abi::LINUX_EINVAL),
        }
    }
}

/// Both destinations are secured by one permit before either is published.
pub(crate) struct PreparedValueResult<'m, M: CurrentMmMemory> {
    inner: PreparedCopyout<'m, M, 2>,
}

/// Read the input length before preparing exactly the available value prefix
/// and its length. An unreadable length is a real fault, distinct from refusal.
/// `value_len` is a bounded kernel wire size, never the caller's capacity.
pub(crate) fn prepare_value_result<'m, M: CurrentMmMemory>(
    context: &KernelContext,
    memory: &'m mut M,
    addresses: ValueResultAddresses,
    value_len: usize,
) -> Result<Result<PreparedValueResult<'m, M>, ValueResultFault>, CopyoutRefusal> {
    let capacity = match ValueResultCapacity::capture(memory, addresses.length)? {
        Ok(capacity) => capacity,
        Err(fault) => return Ok(Err(fault)),
    };
    capacity
        .prepare(context, memory, addresses, value_len)
        .map(Ok)
}

/// A validated input snapshot shared by a query and its output admission.
/// Preparing from it never consults the caller's mutable length word again.
pub(crate) struct ValueResultCapacity(usize);

impl ValueResultCapacity {
    pub(crate) fn capture<M: CurrentMmMemory>(
        memory: &M,
        length: GuestVa,
    ) -> Result<Result<Self, ValueResultFault>, CopyoutRefusal> {
        Ok(match read_u32_before_effects(memory, length.raw())? {
            Ok(capacity) if (capacity as i32) < 0 => Err(ValueResultFault::NegativeLength),
            Ok(capacity) => Ok(Self(capacity as usize)),
            Err(fault) => Err(ValueResultFault::Memory(fault)),
        })
    }

    pub(crate) fn bounded_len(&self, value_len: usize) -> usize {
        self.0.min(value_len)
    }

    pub(crate) fn prepare<'m, M: CurrentMmMemory>(
        self,
        context: &KernelContext,
        memory: &'m mut M,
        addresses: ValueResultAddresses,
        value_len: usize,
    ) -> Result<PreparedValueResult<'m, M>, CopyoutRefusal> {
        Ok(PreparedValueResult {
            inner: prepare(
                context,
                memory,
                [
                    Some(UserSlot::new(
                        addresses.value.raw(),
                        self.bounded_len(value_len),
                    )),
                    Some(UserSlot::new(
                        addresses.length.raw(),
                        std::mem::size_of::<u32>(),
                    )),
                ],
            )?,
        })
    }
}

impl<M: CurrentMmMemory> PreparedValueResult<'_, M> {
    pub(crate) fn capacity(&self) -> usize {
        self.inner.capacity(0)
    }

    /// Values are published before the length, including overlapping buffers.
    /// A genuine later fault preserves the valid prefix; a refusal wrote nothing.
    pub(crate) fn commit(self, value: &[u8], reported_len: u32) -> Result<(), CopyoutFault> {
        let written = self.capacity().min(value.len());
        self.inner
            .commit([&value[..written], &reported_len.to_ne_bytes()])
    }

    pub(crate) fn commit_clamped(self, value: &[u8]) -> Result<(), CopyoutFault> {
        let written = self.capacity().min(value.len()) as u32;
        self.commit(value, written)
    }
}
// END S2 value-result output admission.
