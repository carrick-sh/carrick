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
//! Linux reports it (`pipe2` creates and then frees its files; `accept` still
//! answers EAGAIN on an empty queue). Only a retryable owner wait refuses
//! preparation.
//!
//! The order relative to side effects is the handler's obligation: call
//! `prepare` before creating, consuming or installing anything, and treat a
//! [`CopyoutRefusal`] as "return now". Side-effect-free handlers (stat,
//! clock reads) may prepare immediately before committing.

use carrick_abi::{KernelAbi, LINUX_EFAULT};
use carrick_fatal::carrick_fatal;
use carrick_guest_mem::{
    CurrentMmMemory, GuestVa, GuestWriteRange, PreparedGuestWrite, UserMemoryVenue,
};

use super::{DispatchError, DispatchOutcome};

/// The largest total output one copyout prepares: one owner portal permit.
/// Fixed records are checked at compile time; variable outputs bound their
/// capacity with [`bounded_capacity`] before preparing.
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

/// Cap a variable-length output (a directory batch, an address or option
/// value) at what one prepared permit can hold on this venue. Linux allows
/// these syscalls to return less than the caller's buffer. The legacy venue
/// has no permit bound and keeps the caller's length.
pub(crate) fn bounded_capacity(memory: &impl CurrentMmMemory, requested: usize) -> usize {
    match memory.user_memory_venue() {
        UserMemoryVenue::Owner => requested.min(COPYOUT_MAX_BYTES),
        UserMemoryVenue::Legacy => requested,
    }
}

/// A retryable owner refusal: the editor is busy, or the output needs physical
/// supply or a retained writer to drain. Nothing was written; the handler
/// returns this outcome before its first side effect and the runtime parks,
/// serves the dependency and redispatches the saved syscall.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a refused copyout must be returned before any side effect"]
pub(crate) struct CopyoutRefusal(DispatchOutcome);

impl CopyoutRefusal {
    pub(crate) fn into_outcome(self) -> DispatchOutcome {
        self.0
    }
}

impl From<CopyoutRefusal> for DispatchOutcome {
    fn from(refusal: CopyoutRefusal) -> Self {
        refusal.into_outcome()
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
    Owner(Box<dyn PreparedGuestWrite + 'm>),
    Legacy(&'m mut M),
    /// The owner rejected an output range as invalid; the commit reports it.
    Faulted,
}

/// Destination authority for up to `N` outputs, obtained before any side
/// effect. It borrows the memory until it is committed or dropped; dropping it
/// unused cancels the owner permit.
#[must_use = "a prepared copyout writes nothing until it is committed"]
pub(crate) struct PreparedCopyout<'m, M: CurrentMmMemory, const N: usize> {
    slots: [Option<UserSlot>; N],
    venue: Venue<'m, M>,
}

/// Prepare every output of one syscall. `None` slots (a NULL optional
/// pointer) and zero-capacity slots write nothing.
pub(crate) fn prepare<M: CurrentMmMemory, const N: usize>(
    memory: &mut M,
    slots: [Option<UserSlot>; N],
) -> Result<PreparedCopyout<'_, M, N>, CopyoutRefusal> {
    let slots = slots.map(|slot| slot.filter(|slot| slot.capacity > 0));
    let total = slots
        .iter()
        .flatten()
        .try_fold(0usize, |total, slot| total.checked_add(slot.capacity));
    if total.is_none_or(|total| total > COPYOUT_MAX_BYTES) {
        // Capacities come from fixed records or `bounded_capacity`; a larger
        // permit would be refused as a Limit after the source was chosen.
        carrick_fatal!(
            "dispatch::copyout",
            "copyout exceeds one prepared permit: {total:?} bytes"
        );
    }
    if memory.user_memory_venue() == UserMemoryVenue::Legacy {
        return Ok(PreparedCopyout {
            slots,
            venue: Venue::Legacy(memory),
        });
    }
    let mut ranges = [GuestWriteRange::new(GuestVa::new(0), 0).unwrap_or_else(|| {
        carrick_fatal!("dispatch::copyout", "empty write range is unrepresentable")
    }); N];
    let faulted = PreparedCopyout {
        slots,
        venue: Venue::Faulted,
    };
    let mut count = 0;
    for slot in slots.iter().flatten() {
        let Some(range) = GuestWriteRange::new(GuestVa::new(slot.address), slot.capacity) else {
            return Ok(faulted);
        };
        ranges[count] = range;
        count += 1;
    }
    match memory.prepare_write(&ranges[..count]) {
        Ok(permit) => Ok(PreparedCopyout {
            slots,
            venue: Venue::Owner(permit),
        }),
        Err(error) => match crate::el1_delegation::owner_prepare_refusal(error) {
            // `owner_prepare_refusal` has recorded the fault probe; the
            // commit reports EFAULT at Linux's point.
            outcome if outcome == DispatchOutcome::errno(LINUX_EFAULT) => Ok(faulted),
            outcome => Err(CopyoutRefusal(outcome)),
        },
    }
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

    /// Write one prefix per slot; the output for an absent slot (a NULL
    /// optional pointer) is ignored. An owner permit cannot fail here; an
    /// output the owner rejected reports [`CopyoutFault`]. On the legacy
    /// venue the first invalid pointer stops the commit with [`CopyoutFault`]
    /// after any earlier slots were written, as the sequential direct writes
    /// did.
    pub(crate) fn commit(self, outputs: [&[u8]; N]) -> Result<(), CopyoutFault> {
        for (slot, output) in self.slots.iter().zip(outputs) {
            let Some(capacity) = slot.map(UserSlot::capacity) else {
                continue;
            };
            if output.len() > capacity {
                carrick_fatal!(
                    "dispatch::copyout",
                    "copyout output of {} bytes exceeds its prepared {capacity}",
                    output.len()
                );
            }
        }
        match self.venue {
            Venue::Owner(permit) => {
                let mut present: [&[u8]; N] = [&[]; N];
                let mut count = 0;
                for (slot, output) in self.slots.iter().zip(outputs) {
                    if slot.is_some() {
                        present[count] = output;
                        count += 1;
                    }
                }
                permit.commit(&present[..count]);
                Ok(())
            }
            Venue::Faulted => Err(CopyoutFault),
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

    pub(crate) fn prepare<M: CurrentMmMemory>(
        self,
        memory: &mut M,
    ) -> Result<PreparedOut<'_, M, T>, CopyoutRefusal> {
        Ok(PreparedOut {
            inner: prepare(memory, [Some(self.slot)])?,
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
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: &T,
    success: DispatchOutcome,
) -> DispatchOutcome {
    match UserOut::<T>::new(address).prepare(memory) {
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
        pub(crate) prepares: usize,
    }

    impl OwnerRefusingMemory {
        /// Every byte starts as `fill` so an untouched output is visible.
        pub(crate) fn new(base: u64, len: usize, fill: u8) -> Self {
            Self {
                inner: LinearMemory::new(base, vec![fill; len]),
                refuse: None,
                prepares: 0,
            }
        }

        /// Refuse the next prepare with an Editor wait.
        pub(crate) fn refuse_next(&mut self) -> PortalOwnerWait {
            let wait = editor_wait();
            self.refuse = Some(wait);
            wait
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
            if let Some(wait) = self.refuse.take() {
                return Err(MemoryPrepareError::OwnerWait(wait));
            }
            for range in ranges {
                if !self
                    .inner
                    .guest_range_is_writable(range.address().raw(), range.len())
                {
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
            self.inner.guest_range_is_writable(address, length)
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
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

    #[test]
    fn owner_refusal_is_the_wait_outcome_and_writes_nothing() {
        let mut memory = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        let wait = memory.refuse_next();
        let refused = UserOut::<LinuxTimespec>::new(BASE + 0x10)
            .prepare(&mut memory)
            .err()
            .expect("first prepare is refused");
        assert_eq!(
            refused.into_outcome(),
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
        );
        assert_eq!(memory.read_bytes(BASE + 0x10, 16).unwrap(), [0xa5; 16]);

        let value = LinuxTimespec::new(5, 7);
        UserOut::new(BASE + 0x10)
            .prepare(&mut memory)
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
        let prepared = UserOut::<LinuxTimespec>::new(BASE + 0x2000)
            .prepare(&mut memory)
            .ok()
            .expect("an invalid pointer is not a retryable refusal");
        assert_eq!(
            prepared.commit(&LinuxTimespec::new(1, 1)),
            Err(CopyoutFault)
        );
    }

    #[test]
    fn absent_slots_are_skipped_on_both_venues() {
        let mut owner = OwnerRefusingMemory::new(BASE, 0x1000, 0xa5);
        prepare(
            &mut owner,
            [UserSlot::optional(0, 4), UserSlot::optional(BASE, 4)],
        )
        .unwrap()
        .commit([&[], &[1, 2, 3, 4]])
        .unwrap();
        assert_eq!(owner.read_bytes(BASE, 4).unwrap(), [1, 2, 3, 4]);

        let mut legacy = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
        let prepared = prepare(
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
            .prepare(&mut legacy)
            .expect("legacy preparation is free");
        assert_eq!(
            prepared.commit(&LinuxTimespec::new(1, 1)),
            Err(CopyoutFault)
        );
    }

    #[test]
    fn variable_outputs_bound_to_one_owner_permit() {
        let owner = OwnerRefusingMemory::new(BASE, 0x1000, 0);
        let legacy = LinearMemory::new(BASE, vec![0; 0x100]);
        assert_eq!(bounded_capacity(&owner, 1 << 20), COPYOUT_MAX_BYTES);
        assert_eq!(bounded_capacity(&owner, 12), 12);
        assert_eq!(bounded_capacity(&legacy, 1 << 20), 1 << 20);
    }
}
