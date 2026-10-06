//! Borrowed admission for loading content into an owner-reserved mapping.

use crate::{GuestVa, GuestVaRange};
use carrick_el1_abi::El1MmHandle;
use std::marker::PhantomData;
use std::rc::Rc;

/// One exact host mapping operation's admitted, inaccessible destination.
/// This proof cannot be copied, sent to another thread, or retained after the
/// operation. It grants no authority to ordinary guest reads or writes.
#[derive(Debug)]
pub struct OwnerReservedWrite<'scope> {
    owner: El1MmHandle,
    range: GuestVaRange,
    _scope: PhantomData<&'scope ()>,
    _host: PhantomData<Rc<()>>,
}

impl OwnerReservedWrite<'_> {
    /// # Safety
    /// Hold the exact MM mutation admission and authenticate the complete
    /// range against that carrier's admitted root and its open host venue.
    /// Every destination page must be an opaque, inaccessible reservation.
    /// Do not settle or replace the venue until `operation` returns. Release
    /// metadata/root guards before entering the backend.
    pub unsafe fn with_scope<R>(
        owner: El1MmHandle,
        range: GuestVaRange,
        operation: impl for<'scope> FnOnce(&OwnerReservedWrite<'scope>) -> R,
    ) -> R {
        fn borrowed<'a>(
            owner: El1MmHandle,
            range: GuestVaRange,
            _: &'a (),
        ) -> OwnerReservedWrite<'a> {
            OwnerReservedWrite {
                owner,
                range,
                _scope: PhantomData,
                _host: PhantomData,
            }
        }
        let scope = ();
        operation(&borrowed(owner, range, &scope))
    }

    pub const fn owner(&self) -> El1MmHandle {
        self.owner
    }

    pub const fn range(&self) -> GuestVaRange {
        self.range
    }

    pub fn contains(&self, address: GuestVa, len: usize) -> bool {
        let Some(limit) = self.range.start_raw().checked_add(self.range.len() as u64) else {
            return false;
        };
        !self.range.is_empty()
            && address.raw() >= self.range.start_raw()
            && address
                .raw()
                .checked_add(len as u64)
                .is_some_and(|end| end <= limit)
    }
}
