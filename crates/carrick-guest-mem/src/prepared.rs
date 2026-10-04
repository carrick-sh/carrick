//! Destination authority obtained before a source can be consumed.
use crate::{GuestVa, MemoryError};
use carrick_el1_abi::{PortalGrantWindow, PortalOperation, PortalOwnerWait};

/// One output range. Empty outputs are valid; overflowing ranges are not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestWriteRange {
    address: GuestVa,
    len: usize,
}
impl GuestWriteRange {
    pub fn new(address: GuestVa, len: usize) -> Option<Self> {
        address.raw().checked_add(u64::try_from(len).ok()?)?;
        Some(Self { address, len })
    }
    pub fn address(self) -> GuestVa {
        self.address
    }
    pub fn len(self) -> usize {
        self.len
    }
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Construction-time memory authority. Owner refusal never selects Legacy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserMemoryVenue {
    Legacy,
    Owner,
}

/// The public stream PREPARE request cannot exceed one existing transfer
/// chunk. Atomic records need a separate socket-derived bound before they can
/// enter this service; a large arbitrary vector is not that authority.
pub struct PreparedStreamRanges<'a>(&'a [GuestWriteRange]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedWriteLimit {
    RangePopulation,
    ByteCount,
}
impl<'a> PreparedStreamRanges<'a> {
    pub fn new(ranges: &'a [GuestWriteRange]) -> Result<Self, PreparedWriteLimit> {
        let limit = carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize;
        // Also bounds all-empty vectors without scanning their population.
        if ranges.len() > limit {
            return Err(PreparedWriteLimit::RangePopulation);
        }
        let mut remaining = limit;
        for range in ranges {
            remaining = remaining
                .checked_sub(range.len())
                .ok_or(PreparedWriteLimit::ByteCount)?;
        }
        Ok(Self(ranges))
    }
    pub fn ranges(&self) -> &'a [GuestWriteRange] {
        self.0
    }
}

/// A retained pre-permit physical dependency. Enrollment always precedes the
/// readiness probe; cancellation drops its physical writer exclusion.
pub trait PhysicalMemoryWait: std::fmt::Debug + Send + Sync {
    fn is_ready(&self) -> bool;
    fn enroll(
        &self,
        wake: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool);
}
#[derive(Clone, Debug)]
pub struct OwnedMemoryWait(pub std::sync::Arc<dyn PhysicalMemoryWait>);
impl PartialEq for OwnedMemoryWait {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OwnedMemoryWait {}

/// One-shot owned read progress. Clones share custody rather than clone the
/// operation's completed prefix. Only the producing backend can recover its
/// private state type; mismatched recovery leaves the original state intact.
#[derive(Clone)]
pub struct OwnedReadContinuation(
    std::sync::Arc<parking_lot::Mutex<Option<Box<dyn std::any::Any + Send + Sync>>>>,
);
impl OwnedReadContinuation {
    pub fn new<T: std::any::Any + Send + Sync>(state: T) -> Self {
        Self(std::sync::Arc::new(parking_lot::Mutex::new(Some(
            Box::new(state),
        ))))
    }
    pub fn take<T: std::any::Any + Send + Sync>(&self) -> Option<T> {
        let mut state = self.0.lock();
        if !state.as_ref()?.is::<T>() {
            return None;
        }
        state.take()?.downcast::<T>().ok().map(|state| *state)
    }
}
impl std::fmt::Debug for OwnedReadContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedReadContinuation")
            .finish_non_exhaustive()
    }
}
impl PartialEq for OwnedReadContinuation {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OwnedReadContinuation {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryReadWait {
    Owner(PortalOwnerWait),
    Supply(MemorySupplyRequest),
    Physical(OwnedMemoryWait),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryReadSuspension {
    pub wait: MemoryReadWait,
    pub continuation: OwnedReadContinuation,
}

/// No resource permit, execution loan or guest pointer crosses a supply wait.
/// The continuation owns the operation and these exact owner-issued receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemorySupplyRequest {
    Grant(PortalGrantWindow),
    Cow(PortalGrantWindow),
    Metadata {
        operation: PortalOperation,
        observed: PortalOwnerWait,
    },
}
#[derive(Debug)]
pub enum MemoryPrepareError {
    /// The caller must split a stream before source consumption. This is not
    /// an invalid guest address and must not be lowered to EFAULT.
    Limit(PreparedWriteLimit),
    Fault(MemoryError),
    Physical(OwnedMemoryWait),
    OwnerWait(PortalOwnerWait),
    Supply(MemorySupplyRequest),
}

/// All output pages and the current service executor remain exclusively owned
/// until commit or cancellation. The consumer supplies one prefix per range.
/// Each prefix may be shorter than its prepared capacity (for a short read).
/// Commit neither suspends nor returns a recoverable failure after consumption.
/// Dropping an unused capability cancels every page through the same executor.
pub trait PreparedGuestWrite {
    fn commit(self: Box<Self>, outputs: &[&[u8]]);
}

/// Root-shared authority. Admission drops the legacy mirror in every existing
/// task projection and foreign-MM holder, rather than replacing one clone.
#[derive(Clone)]
pub struct UserMemoryAuthority(std::sync::Arc<parking_lot::RwLock<UserMemoryAuthorityState>>);
enum UserMemoryAuthorityState {
    Legacy(std::sync::Arc<crate::protections::MemoryProtections>),
    Owner(carrick_el1_abi::El1MmHandle),
}

/// A legacy mirror borrow cannot escape the authority transition. Other
/// backends keep their existing borrowed mirror without an extra allocation.
pub struct LegacyProtectionRead<'a>(LegacyProtectionReadInner<'a>);
enum LegacyProtectionReadInner<'a> {
    Borrowed(&'a crate::protections::MemoryProtections),
    Shared(parking_lot::MappedRwLockReadGuard<'a, crate::protections::MemoryProtections>),
}
impl<'a> LegacyProtectionRead<'a> {
    pub fn borrowed(protections: &'a crate::protections::MemoryProtections) -> Self {
        Self(LegacyProtectionReadInner::Borrowed(protections))
    }
}
impl std::ops::Deref for LegacyProtectionRead<'_> {
    type Target = crate::protections::MemoryProtections;
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            LegacyProtectionReadInner::Borrowed(value) => value,
            LegacyProtectionReadInner::Shared(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserMemoryAdmissionError {
    LegacyReadActive,
    OwnerMismatch,
}
impl UserMemoryAuthority {
    pub fn from_legacy(protections: std::sync::Arc<crate::protections::MemoryProtections>) -> Self {
        Self(std::sync::Arc::new(parking_lot::RwLock::new(
            UserMemoryAuthorityState::Legacy(protections),
        )))
    }
    pub fn from_owner(handle: carrick_el1_abi::El1MmHandle) -> Self {
        Self(std::sync::Arc::new(parking_lot::RwLock::new(
            UserMemoryAuthorityState::Owner(handle),
        )))
    }
    // Nested legacy validation is safe: admission uses only try_write and
    // never queues a writer behind the outer read borrow.
    pub fn legacy(&self) -> Option<LegacyProtectionRead<'_>> {
        parking_lot::RwLockReadGuard::try_map(self.0.read(), |state| match state {
            UserMemoryAuthorityState::Legacy(protections) => Some(protections.as_ref()),
            UserMemoryAuthorityState::Owner(_) => None,
        })
        .ok()
        .map(|guard| LegacyProtectionRead(LegacyProtectionReadInner::Shared(guard)))
    }
    pub fn owner(&self) -> Option<carrick_el1_abi::El1MmHandle> {
        match &*self.0.read() {
            UserMemoryAuthorityState::Legacy(_) => None,
            UserMemoryAuthorityState::Owner(handle) => Some(*handle),
        }
    }
    /// Initial admission is one nonblocking transition. A live legacy borrow
    /// refuses admission before execution; never queue a writer behind a
    /// nested legacy operation or wait on a guest executor.
    pub fn admit_owner(
        &self,
        handle: carrick_el1_abi::El1MmHandle,
    ) -> Result<(), UserMemoryAdmissionError> {
        let Some(mut state) = self.0.try_write() else {
            return Err(UserMemoryAdmissionError::LegacyReadActive);
        };
        match &*state {
            UserMemoryAuthorityState::Owner(current) if *current != handle => {
                Err(UserMemoryAdmissionError::OwnerMismatch)
            }
            UserMemoryAuthorityState::Owner(_) => Ok(()),
            UserMemoryAuthorityState::Legacy(_) => {
                let retired =
                    std::mem::replace(&mut *state, UserMemoryAuthorityState::Owner(handle));
                drop(state);
                drop(retired);
                Ok(())
            }
        }
    }
    pub fn same_authority(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
            || self
                .owner()
                .is_some_and(|handle| other.owner() == Some(handle))
    }
}

impl std::fmt::Debug for UserMemoryAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.owner() {
            Some(handle) => formatter.debug_tuple("Owner").field(&handle).finish(),
            None => formatter.write_str("Legacy"),
        }
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use std::num::NonZeroU64;

    fn handle(incarnation: u64) -> carrick_el1_abi::El1MmHandle {
        // SAFETY: this fixture represents the owner's completed admission,
        // not a host permission decision or an input accepted from a guest.
        unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                NonZeroU64::new(3).unwrap(),
                carrick_el1_abi::ReservationMm::new(5).unwrap(),
                NonZeroU64::new(incarnation).unwrap(),
            )
        }
    }

    #[test]
    fn admission_deletes_mirror_storage_from_existing_root_holders() {
        let mirror = std::sync::Arc::new(crate::protections::MemoryProtections::default());
        mirror.set_unmapped(0x4000, 0x1000, true);
        let weak = std::sync::Arc::downgrade(&mirror);
        let authority = UserMemoryAuthority::from_legacy(mirror);
        let parked_task = authority.clone();
        let foreign_mm = authority.clone();
        assert!(parked_task.legacy().unwrap().range_unmapped(0x4000, 1));
        authority.admit_owner(handle(7)).unwrap();
        assert!(
            weak.upgrade().is_none(),
            "admitted holders retained mirror storage"
        );
        for holder in [&authority, &parked_task, &foreign_mm] {
            assert_eq!(holder.owner(), Some(handle(7)));
            assert!(holder.legacy().is_none());
            assert!(holder.same_authority(&authority));
        }
    }

    #[test]
    fn active_legacy_borrow_refuses_admission_without_waiting() {
        let authority = UserMemoryAuthority::from_legacy(std::sync::Arc::new(
            crate::protections::MemoryProtections::default(),
        ));
        let borrow = authority.legacy().unwrap();
        assert_eq!(
            authority.admit_owner(handle(7)),
            Err(UserMemoryAdmissionError::LegacyReadActive)
        );
        assert!(authority.owner().is_none());
        assert!(
            authority.legacy().is_some(),
            "nested legacy validation remains available"
        );
        drop(borrow);
        authority.admit_owner(handle(7)).unwrap();
        assert_eq!(authority.owner(), Some(handle(7)));
    }

    #[test]
    fn admitted_root_cannot_change_owner_incarnation() {
        let authority = UserMemoryAuthority::from_owner(handle(7));
        assert_eq!(
            authority.admit_owner(handle(8)),
            Err(UserMemoryAdmissionError::OwnerMismatch)
        );
        assert_eq!(authority.owner(), Some(handle(7)));
        assert!(authority.same_authority(&UserMemoryAuthority::from_owner(handle(7))));
        assert!(!authority.same_authority(&UserMemoryAuthority::from_owner(handle(8))));
    }
}

#[cfg(test)]
mod read_continuation_tests {
    use super::*;
    #[test]
    fn stream_preparation_bounds_bytes_and_empty_range_population() {
        let limit = carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize;
        let range = |len| GuestWriteRange::new(GuestVa(0x4001), len).unwrap();
        assert!(PreparedStreamRanges::new(&[range(limit)]).is_ok());
        assert!(matches!(
            PreparedStreamRanges::new(&[range(limit), range(1)]),
            Err(PreparedWriteLimit::ByteCount)
        ));
        assert!(matches!(
            PreparedStreamRanges::new(&[range(usize::MAX - 0x4001)]),
            Err(PreparedWriteLimit::ByteCount)
        ));
        assert!(matches!(
            PreparedStreamRanges::new(&vec![range(0); limit + 1]),
            Err(PreparedWriteLimit::RangePopulation)
        ));
        assert!(PreparedStreamRanges::new(&vec![range(1); limit]).is_ok());
    }
    #[test]
    fn read_progress_custody_is_one_shot_and_wrong_backend_cannot_consume() {
        let progress = OwnedReadContinuation::new((vec![1u8, 2, 3], 3usize));
        let other = progress.clone();
        assert!(other.take::<u64>().is_none());
        assert_eq!(
            progress.take::<(Vec<u8>, usize)>(),
            Some((vec![1, 2, 3], 3))
        );
        assert!(other.take::<(Vec<u8>, usize)>().is_none());
    }
}
