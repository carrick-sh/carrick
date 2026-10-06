//! Bounded physical cache publication while the guest retains its COW editor.
use crate::CowGrant;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalExecutablePublication {
    pub grant: CowGrant,
    pub ipa: u64,
    pub len: u64,
}
impl PortalExecutablePublication {
    pub fn valid(self) -> bool {
        self.len != 0
            && self.len <= crate::COW_GRANT_SIZE
            && self.ipa.is_multiple_of(4096)
            && self.len.is_multiple_of(4096)
            && self.ipa >= self.grant.physical_ipa
            && self.ipa.checked_add(self.len).is_some_and(|end| {
                end <= self
                    .grant
                    .physical_ipa
                    .saturating_add(crate::COW_GRANT_SIZE)
            })
    }
}
#[repr(C)]
pub struct PortalExecutableSlot {
    state: AtomicU64,
    request: UnsafeCell<Option<PortalExecutablePublication>>,
}
// SAFETY: the release/acquire state machine gives the sole guest writer and
// host service disjoint access; only the guest resets after host completion.
unsafe impl Sync for PortalExecutableSlot {}
impl Default for PortalExecutableSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl PortalExecutableSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            request: UnsafeCell::new(None),
        }
    }
    pub fn publish_with(&self, request: PortalExecutablePublication, host: impl FnOnce()) -> bool {
        if !request.valid()
            || self
                .state
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return false;
        }
        unsafe { *self.request.get() = Some(request) };
        self.state.store(2, Ordering::Release);
        host();
        let state = self.state.load(Ordering::Acquire);
        assert!(
            matches!(state, 4 | 5),
            "physical publication returned without acknowledgement"
        );
        unsafe { *self.request.get() = None };
        self.state.store(0, Ordering::Release);
        state == 4
    }
    pub fn handle(&self, publish: impl FnOnce(PortalExecutablePublication) -> bool) -> bool {
        if self
            .state
            .compare_exchange(2, 3, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let request = unsafe { *self.request.get() };
        let success = request.is_some_and(|request| request.valid() && publish(request));
        self.state
            .store(if success { 4 } else { 5 }, Ordering::Release);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    #[test]
    fn publication_is_bounded_and_acknowledges_cancellation_before_reuse() {
        let nz = |n| NonZeroU64::new(n).unwrap();
        let pool = crate::CowGrantPool::new();
        pool.publish(
            7,
            0x90000000,
            carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                frame_id: nz(1),
                mapping_id: nz(2),
                owner_generation: nz(3),
                inventory_revision: nz(4),
            },
        )
        .unwrap();
        let grant = pool.claim(7).unwrap();
        assert!(pool.authenticates_claimed(&grant));
        let slot = PortalExecutableSlot::new();
        let request = PortalExecutablePublication {
            grant,
            ipa: grant.physical_ipa,
            len: 4096,
        };
        assert!(!slot.publish_with(
            PortalExecutablePublication {
                len: crate::COW_GRANT_SIZE + 4096,
                ..request
            },
            || panic!("unbounded callback")
        ));
        assert!(!slot.publish_with(request, || assert!(slot.handle(|seen| {
            assert_eq!(seen, request);
            false
        }))));
        assert!(slot.publish_with(request, || assert!(
            slot.handle(|seen| pool.authenticates_claimed(&seen.grant))
        )));
        assert!(pool.abandon(&grant));
        assert!(!pool.authenticates_claimed(&grant));
        assert!(!slot.handle(|_| panic!("completed publication replayed")));
    }
}

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn portal_executable_publication() {
        assert_eq!(
            (
                size_of::<PortalExecutablePublication>(),
                align_of::<PortalExecutablePublication>()
            ),
            (80, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |PortalExecutablePublication {
                     grant: _,
                     ipa: _,
                     len: _,
                 }: PortalExecutablePublication| {};
        field!(PortalExecutablePublication, grant, CowGrant, 0, 64, 8);
        field!(PortalExecutablePublication, ipa, u64, 64, 8, 8);
        field!(PortalExecutablePublication, len, u64, 72, 8, 8);
    }

    #[test]
    fn portal_executable_slot() {
        assert_eq!(
            (
                size_of::<PortalExecutableSlot>(),
                align_of::<PortalExecutableSlot>()
            ),
            (88, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |PortalExecutableSlot {
                     state: _,
                     request: _,
                 }: PortalExecutableSlot| {};
        field!(PortalExecutableSlot, state, AtomicU64, 0, 8, 8);
        field!(
            PortalExecutableSlot,
            request,
            UnsafeCell<Option<PortalExecutablePublication>>,
            8,
            80,
            8
        );
    }
}
