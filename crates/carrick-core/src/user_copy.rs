//! Neutral bounded guest-memory transfers and owner preparation requests.

use carrick_guest_arch::{Access, GuestLen, UserVa};

/// A bounded user transfer. NotYet retains the exact access for the memory
/// owner's wait protocol; it is never an errno or permission to poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum CopyOutcome {
    Done,
    Fault,
    NotYet(GuestCopyRequest),
}

/// The access that must become available before a refused copy can resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestCopyRequest {
    pub address: UserVa,
    pub len: GuestLen,
    pub access: Access,
}

impl CopyOutcome {
    pub const fn from_completed(done: bool) -> Self {
        if done { Self::Done } else { Self::Fault }
    }
    pub const fn is_done(self) -> bool {
        matches!(self, Self::Done)
    }
}

/// The neutral guest-copy interface for personality lifecycle and call servicing.
///
/// A refused transfer must retain its owning operation before leaving the lane.
/// `Fault` means the address or access is invalid; `NotYet` means the memory
/// owner must make the exact access available before redispatch or completion.
pub trait UserCopy {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> CopyOutcome;
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> CopyOutcome;

    /// Load one aligned 32-bit word atomically, with acquire ordering.
    /// `value` changes only on `Done`. Byte copies cannot implement this
    /// operation: concurrent users may otherwise observe a torn futex value.
    /// A byte-only provider defers to its memory owner without touching memory.
    fn atomic_load_u32(&mut self, address: UserVa, value: &mut u32) -> CopyOutcome {
        let _ = value;
        atomic_word_refusal(address, Access::Read)
    }

    /// Atomically compare one aligned word with `expected` and, if equal,
    /// replace it with `desired`, with acquire/release ordering on success
    /// and acquire ordering on mismatch. `observed` changes only on `Done`;
    /// equality with `expected` then means the exchange succeeded. A mismatch
    /// is `Done`, not a fault or an owner wait. `NotYet` performs no store.
    /// Callers must release object/bucket locks before waiting on the owner,
    /// then repeat the comparison under the lock after resumption.
    fn atomic_compare_exchange_u32(
        &mut self,
        address: UserVa,
        expected: u32,
        desired: u32,
        observed: &mut u32,
    ) -> CopyOutcome {
        let _ = (expected, desired, observed);
        atomic_word_refusal(address, Access::Write)
    }

    /// Read a padding-free typed ABI record from guest memory.
    ///
    /// Records with explicit padding compile cleanly:
    ///
    /// ```
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    /// use zerocopy::{FromBytes, IntoBytes};
    ///
    /// #[repr(C)]
    /// #[derive(FromBytes, IntoBytes)]
    /// struct ExplicitPad {
    ///     a: u16,
    ///     __pad: u16,
    ///     b: u32,
    /// }
    ///
    /// fn load<C: UserCopy>(copy: &mut C, src: UserVa) -> Option<ExplicitPad> {
    ///     copy.read_val(src)
    /// }
    /// ```
    ///
    /// Records with implicit compiler-inserted padding are rejected at compile time:
    ///
    /// ```compile_fail
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    /// use zerocopy::{FromBytes, IntoBytes};
    ///
    /// #[repr(C)]
    /// #[derive(FromBytes, IntoBytes)]
    /// struct ImplicitPad {
    ///     a: u16,
    ///     b: u32,
    /// }
    ///
    /// fn load<C: UserCopy>(copy: &mut C, src: UserVa) -> Option<ImplicitPad> {
    ///     copy.read_val(src)
    /// }
    /// ```
    ///
    /// Plain `Copy` structs without `FromBytes + IntoBytes` are also rejected:
    ///
    /// ```compile_fail
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    ///
    /// #[repr(C)]
    /// #[derive(Clone, Copy)]
    /// struct UncheckedCopy {
    ///     a: u16,
    ///     b: u32,
    /// }
    ///
    /// fn load<C: UserCopy>(copy: &mut C, src: UserVa) -> Option<UncheckedCopy> {
    ///     copy.read_val(src)
    /// }
    /// ```
    #[inline]
    fn read_val<T: zerocopy::FromBytes + zerocopy::IntoBytes>(&mut self, src: UserVa) -> Option<T>
    where
        Self: Sized,
    {
        let mut val = T::new_zeroed();
        self.copy_in(val.as_mut_bytes(), src)
            .is_done()
            .then_some(val)
    }

    /// Write a padding-free typed ABI record to guest memory.
    ///
    /// Records with explicit padding compile cleanly:
    ///
    /// ```
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    /// use zerocopy::{Immutable, IntoBytes};
    ///
    /// #[repr(C)]
    /// #[derive(IntoBytes, Immutable)]
    /// struct ExplicitPad {
    ///     a: u16,
    ///     __pad: u16,
    ///     b: u32,
    /// }
    ///
    /// fn publish<C: UserCopy>(copy: &mut C, dst: UserVa, val: &ExplicitPad) -> bool {
    ///     copy.write_val(dst, val)
    /// }
    /// ```
    ///
    /// Records with implicit compiler-inserted padding are rejected at compile time:
    ///
    /// ```compile_fail
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    /// use zerocopy::{Immutable, IntoBytes};
    ///
    /// #[repr(C)]
    /// #[derive(IntoBytes, Immutable)]
    /// struct ImplicitPad {
    ///     a: u16,
    ///     b: u32,
    /// }
    ///
    /// fn publish<C: UserCopy>(copy: &mut C, dst: UserVa, val: &ImplicitPad) -> bool {
    ///     copy.write_val(dst, val)
    /// }
    /// ```
    ///
    /// Plain `Copy` structs without `IntoBytes + Immutable` are also rejected:
    ///
    /// ```compile_fail
    /// use carrick_core::user_copy::UserCopy;
    /// use carrick_guest_arch::UserVa;
    ///
    /// #[repr(C)]
    /// #[derive(Clone, Copy)]
    /// struct UncheckedCopy {
    ///     a: u16,
    ///     b: u32,
    /// }
    ///
    /// fn publish<C: UserCopy>(copy: &mut C, dst: UserVa, val: &UncheckedCopy) -> bool {
    ///     copy.write_val(dst, val)
    /// }
    /// ```
    #[inline]
    fn write_val<T: zerocopy::IntoBytes + zerocopy::Immutable>(
        &mut self,
        dst: UserVa,
        val: &T,
    ) -> bool
    where
        Self: Sized,
    {
        self.copy_out(dst, val.as_bytes()).is_done()
    }
}

/// An unavailable atomic operand must be prepared by its exact memory owner.
/// Alignment and canonical-range failures are already authoritative faults.
pub fn atomic_word_refusal(address: UserVa, access: Access) -> CopyOutcome {
    if address.raw() & 3 != 0 || !carrick_guest_arch::lower_half_range(address.raw(), 4) {
        return CopyOutcome::Fault;
    }
    CopyOutcome::NotYet(GuestCopyRequest {
        address,
        len: GuestLen::new(4),
        access,
    })
}

impl<U: UserCopy + ?Sized> UserCopy for &mut U {
    fn atomic_load_u32(&mut self, address: UserVa, value: &mut u32) -> CopyOutcome {
        (**self).atomic_load_u32(address, value)
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        address: UserVa,
        expected: u32,
        desired: u32,
        observed: &mut u32,
    ) -> CopyOutcome {
        (**self).atomic_compare_exchange_u32(address, expected, desired, observed)
    }

    #[inline]
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> CopyOutcome {
        (**self).copy_in(dst, src)
    }

    #[inline]
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> CopyOutcome {
        (**self).copy_out(dst, src)
    }
}
