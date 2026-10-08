//! Pure identity allocation shared by host and native process consumers.
//! Consumers provide exclusion and own role-preserving claim lifetimes.
use alloc::collections::BTreeMap;
use core::num::{NonZeroI32, NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicU64, Ordering};

/// Internal collision-domain number; not a visible PID/TID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalIdentity(NonZeroI32);
impl InternalIdentity {
    pub const fn get(self) -> i32 {
        self.0.get()
    }
    pub const fn nonzero(self) -> NonZeroI32 {
        self.0
    }
}

/// Exact root namespace numbering domain, distinct from task IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct VisibleNamespace {
    id: NonZeroU32,
    incarnation: NonZeroU32,
}
impl VisibleNamespace {
    pub const fn new(id: NonZeroU32, incarnation: NonZeroU32) -> Self {
        Self { id, incarnation }
    }
}
/// Linux-visible PID/TID; never an internal registry key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisibleIdentity(NonZeroU32);
impl VisibleIdentity {
    /// Carry an already admitted namespace member, including its root.
    /// This constructor does not reserve or issue another visible number.
    pub const fn from_existing_member(raw: NonZeroU32) -> Self {
        Self(raw)
    }
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Namespace authority. A transferred source retains only refusal accounting.
#[derive(Debug)]
pub struct NamespaceState {
    owner: Option<NamespaceAllocation>,
    refused: u64,
}
#[derive(Debug)]
struct NamespaceAllocation {
    first: i32,
    last: i32,
    next: i32,
    claims: BTreeMap<i32, ClaimCounts>,
    visible_next: BTreeMap<VisibleNamespace, u32>,
}
/// Owned claims and cursors, moved once rather than mirrored at the source.
#[derive(Debug)]
pub struct TransferredNamespaceState {
    owner: NamespaceAllocation,
}
impl TransferredNamespaceState {
    pub fn into_owner(self) -> NamespaceState {
        NamespaceState {
            owner: Some(self.owner),
            refused: 0,
        }
    }
}
impl NamespaceState {
    pub fn new(first: i32, last: i32, next: i32) -> Self {
        Self {
            owner: Some(NamespaceAllocation::new(first, last, next)),
            refused: 0,
        }
    }
    fn refuse(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }
    pub fn refused_attempts(&self) -> Option<u64> {
        (self.refused != u64::MAX).then_some(self.refused)
    }
    pub fn transfer(&mut self) -> Option<TransferredNamespaceState> {
        match self.owner.take() {
            Some(owner) => Some(TransferredNamespaceState { owner }),
            None => {
                self.refuse();
                None
            }
        }
    }
    fn allocation(&mut self) -> Result<&mut NamespaceAllocation, IdError> {
        if self.owner.is_none() {
            self.refuse();
            return Err(IdError::AuthorityTransferred);
        }
        self.owner.as_mut().ok_or(IdError::AuthorityTransferred)
    }
    pub fn reserve_next(&mut self, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        self.allocation()?.reserve_next(kind)
    }
    pub fn reserve_exact(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        self.allocation()?.reserve_exact(raw, kind)
    }
    pub fn claim_related(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        self.allocation()?.claim_related(raw, kind)
    }
    pub fn reserve_visible(&mut self, namespace: VisibleNamespace) -> Option<VisibleIdentity> {
        self.allocation().ok()?.reserve_visible(namespace)
    }
    /// Admit an existing visible member without issuing it again. This only
    /// advances its exact namespace cursor; it does not create a claim.
    pub fn advance_visible_past(
        &mut self,
        namespace: VisibleNamespace,
        member: VisibleIdentity,
    ) -> Option<()> {
        let owner = self.allocation().ok()?;
        let next = member.get().checked_add(1)?;
        if member.get() > i32::MAX as u32 {
            return None;
        }
        let cursor = owner.visible_next.entry(namespace).or_insert(2);
        *cursor = (*cursor).max(next);
        Some(())
    }
    pub fn set_next(&mut self, raw: i32) {
        if let Ok(owner) = self.allocation() {
            owner.set_next(raw);
        }
    }
    pub fn release(&mut self, raw: InternalIdentity, kind: ClaimKind) {
        if let Some(owner) = self.owner.as_mut() {
            owner.release(raw, kind);
        }
    }
    pub fn retire_visible_namespace(&mut self, namespace: VisibleNamespace) {
        if let Some(owner) = self.owner.as_mut() {
            owner.retire_visible_namespace(namespace);
        }
    }
    pub fn is_reserved_number(&self, raw: i32) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.is_reserved_number(raw))
    }
    pub fn counts(&self) -> IdRegistryCounts {
        self.owner
            .as_ref()
            .map_or_else(IdRegistryCounts::default, NamespaceAllocation::counts)
    }
    pub fn visible_namespace_count(&self) -> usize {
        self.owner
            .as_ref()
            .map_or(0, NamespaceAllocation::visible_namespace_count)
    }
}

impl NamespaceAllocation {
    fn advance(&mut self) {
        self.next = if self.next == self.last {
            self.first
        } else {
            self.next + 1
        };
    }

    pub fn release(&mut self, raw: InternalIdentity, kind: ClaimKind) {
        let key = raw.get();
        let remove = {
            let Some(claims) = self.claims.get_mut(&key) else {
                debug_assert!(false, "live identity token lost its registry claim");
                return;
            };
            if !claims.decrement(kind) {
                debug_assert!(false, "identity claim reference count underflow");
                return;
            }
            claims.is_empty()
        };
        if remove {
            self.claims.remove(&key);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ClaimKind {
    Task,
    Thread,
    ProcessGroup,
    Session,
}

#[derive(Debug, Default)]
struct ClaimCounts {
    tasks: u32,
    threads: u32,
    process_groups: u32,
    sessions: u32,
}

impl ClaimCounts {
    fn counter(&mut self, kind: ClaimKind) -> &mut u32 {
        match kind {
            ClaimKind::Task => &mut self.tasks,
            ClaimKind::Thread => &mut self.threads,
            ClaimKind::ProcessGroup => &mut self.process_groups,
            ClaimKind::Session => &mut self.sessions,
        }
    }

    fn increment(&mut self, kind: ClaimKind) -> bool {
        let counter = self.counter(kind);
        let Some(next) = counter.checked_add(1) else {
            return false;
        };
        *counter = next;
        true
    }

    fn decrement(&mut self, kind: ClaimKind) -> bool {
        let counter = self.counter(kind);
        let Some(next) = counter.checked_sub(1) else {
            return false;
        };
        *counter = next;
        true
    }

    fn is_empty(&self) -> bool {
        self.tasks == 0 && self.threads == 0 && self.process_groups == 0 && self.sessions == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdRegistryCounts {
    pub reserved_numbers: usize,
    pub task_claims: usize,
    pub thread_claims: usize,
    pub process_group_claims: usize,
    pub session_claims: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    AuthorityTransferred,
    Exhausted,
    OutOfRange(i32),
    AlreadyReserved(i32),
    UnknownNamespaceId(i32),
    ClaimCountExhausted(i32),
}

impl NamespaceAllocation {
    pub fn new(first: i32, last: i32, next: i32) -> Self {
        assert!(first > 0);
        assert!(last >= first);
        assert!((first..=last).contains(&next));
        Self {
            first,
            last,
            next,
            claims: BTreeMap::new(),
            visible_next: BTreeMap::new(),
        }
    }
    /// Preparation burns its visible number even when birth rolls back.
    /// PID1 is reserved for the root seed, not allocated here.
    pub fn reserve_visible(&mut self, namespace: VisibleNamespace) -> Option<VisibleIdentity> {
        let next = self.visible_next.entry(namespace).or_insert(2);
        if *next >= i32::MAX as u32 {
            return None;
        }
        let value = NonZeroU32::new(*next)?;
        *next += 1;
        Some(VisibleIdentity(value))
    }
    pub fn visible_namespace_count(&self) -> usize {
        self.visible_next.len()
    }
    /// Exact namespace retirement discards only its visible-number cursor.
    pub fn retire_visible_namespace(&mut self, namespace: VisibleNamespace) {
        self.visible_next.remove(&namespace);
    }
    pub fn set_next(&mut self, raw: i32) {
        assert!((self.first..=self.last).contains(&raw));
        self.next = raw;
    }
    pub fn is_reserved_number(&self, raw: i32) -> bool {
        self.claims.contains_key(&raw)
    }
    pub fn counts(&self) -> IdRegistryCounts {
        self.claims
            .values()
            .fold(IdRegistryCounts::default(), |mut counts, claim| {
                counts.reserved_numbers += 1;
                counts.task_claims += claim.tasks as usize;
                counts.thread_claims += claim.threads as usize;
                counts.process_group_claims += claim.process_groups as usize;
                counts.session_claims += claim.sessions as usize;
                counts
            })
    }
    pub fn reserve_next(&mut self, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        let start = self.next;
        loop {
            let candidate = self.next;
            self.advance();
            if !self.claims.contains_key(&candidate) {
                let Some(candidate) = NonZeroI32::new(candidate) else {
                    return Err(IdError::OutOfRange(candidate));
                };
                let incremented = self
                    .claims
                    .entry(candidate.get())
                    .or_default()
                    .increment(kind);
                if !incremented {
                    return Err(IdError::ClaimCountExhausted(candidate.get()));
                }
                return Ok(InternalIdentity(candidate));
            }
            if self.next == start {
                return Err(IdError::Exhausted);
            }
        }
    }
    pub fn reserve_exact(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        if raw < self.first || raw > self.last {
            return Err(IdError::OutOfRange(raw));
        }
        if self.claims.contains_key(&raw) {
            return Err(IdError::AlreadyReserved(raw));
        }
        let Some(raw) = NonZeroI32::new(raw) else {
            return Err(IdError::OutOfRange(raw));
        };
        if !self.claims.entry(raw.get()).or_default().increment(kind) {
            return Err(IdError::ClaimCountExhausted(raw.get()));
        }
        Ok(InternalIdentity(raw))
    }
    pub fn claim_related(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        let Some(nonzero) = NonZeroI32::new(raw) else {
            return Err(IdError::OutOfRange(raw));
        };
        let Some(claims) = self.claims.get_mut(&raw) else {
            return Err(IdError::UnknownNamespaceId(raw));
        };
        if !claims.increment(kind) {
            return Err(IdError::ClaimCountExhausted(raw));
        }
        Ok(InternalIdentity(nonzero))
    }
}

impl core::fmt::Display for IdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthorityTransferred => {
                f.write_str("Linux namespace authority has been transferred")
            }
            Self::Exhausted => f.write_str("Linux PID namespace is exhausted"),
            Self::OutOfRange(raw) => write!(
                f,
                "Linux namespace identity {raw} is outside the allocator range"
            ),
            Self::AlreadyReserved(raw) => {
                write!(f, "Linux namespace identity {raw} is already reserved")
            }
            Self::UnknownNamespaceId(raw) => write!(
                f,
                "Linux namespace identity {raw} has no live task or object"
            ),
            Self::ClaimCountExhausted(raw) => {
                write!(f, "Linux namespace identity {raw} has too many live claims")
            }
        }
    }
}
impl core::error::Error for IdError {}

/// Monotonic, non-reusing object serials. The caller retains the allocator's
/// scope: a kernel for task/object serials, the carrier for MM serials.
#[derive(Debug)]
pub struct SerialAllocator {
    next: AtomicU64,
    refused: AtomicU64,
}

/// Owned allocation cursor removed from its source. This value is deliberately
/// neither Copy nor Clone: only its receiver can reopen the allocation owner.
#[derive(Debug)]
pub struct TransferredSerialAllocator {
    next: NonZeroU64,
}

impl TransferredSerialAllocator {
    pub fn into_allocator(self) -> SerialAllocator {
        SerialAllocator::starting_at(self.next)
    }
}
impl Default for SerialAllocator {
    fn default() -> Self {
        Self::new()
    }
}
impl SerialAllocator {
    pub const fn new() -> Self {
        Self::starting_at(NonZeroU64::MIN)
    }
    pub const fn starting_at(next: NonZeroU64) -> Self {
        Self {
            next: AtomicU64::new(next.get()),
            refused: AtomicU64::new(0),
        }
    }
    /// Move the cursor once. Zero is a terminal source state, never a serial.
    /// Atomic exchange settles concurrent allocation before or after transfer.
    pub fn transfer(&self) -> Option<TransferredSerialAllocator> {
        match NonZeroU64::new(self.next.swap(0, Ordering::AcqRel)) {
            Some(next) => Some(TransferredSerialAllocator { next }),
            None => {
                self.record_refusal();
                None
            }
        }
    }
    pub fn is_transferred(&self) -> bool {
        self.next.load(Ordering::Acquire) == 0
    }
    /// MAX is an explicit unknown/overflow receipt, never a wrapped count.
    pub fn refused_attempts(&self) -> Option<u64> {
        let count = self.refused.load(Ordering::Acquire);
        (count != u64::MAX).then_some(count)
    }
    fn record_refusal(&self) {
        let _ = self
            .refused
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
    }
    fn advance_owned_to(&self, next: NonZeroU64) -> Option<()> {
        match self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current != 0).then_some(current.max(next.get()))
            }) {
            Ok(_) => Some(()),
            Err(_) => {
                self.record_refusal();
                None
            }
        }
    }
    /// Import an already-established lower bound without reusing a serial.
    pub fn advance_to(&self, next: NonZeroU64) {
        let _ = self.advance_owned_to(next);
    }
    pub fn advance_past(&self, value: NonZeroU64) -> Option<()> {
        let Some(next) = value.get().checked_add(1).and_then(NonZeroU64::new) else {
            if self.is_transferred() {
                self.record_refusal();
            }
            return None;
        };
        self.advance_owned_to(next)
    }
    pub fn allocate(&self) -> Option<NonZeroU64> {
        match self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                NonZeroU64::new(current)?;
                current.checked_add(1)
            }) {
            Ok(raw) => NonZeroU64::new(raw),
            Err(0) => {
                self.record_refusal();
                None
            }
            Err(_) => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transferred_serial_source_never_reopens_or_reuses_issued_values() {
        let source = SerialAllocator::new();
        for expected in 1..=5 {
            assert_eq!(source.allocate().unwrap().get(), expected);
        }
        let native = source.transfer().unwrap().into_allocator();
        assert_eq!(native.allocate().unwrap().get(), 6);
        assert_eq!(source.allocate(), None);
        assert_eq!(source.allocate(), None);
        source.advance_to(NonZeroU64::new(100).unwrap());
        assert_eq!(source.allocate(), None);
        assert_eq!(source.advance_past(NonZeroU64::new(200).unwrap()), None);
        assert!(source.transfer().is_none());
        assert!(source.is_transferred());
        assert_eq!(source.refused_attempts(), Some(6));
        assert!(!native.is_transferred());
        assert_eq!(native.refused_attempts(), Some(0));
        assert_eq!(native.allocate().unwrap().get(), 7);
    }

    #[test]
    fn transfer_preserves_imported_floor_and_exhaustion() {
        let source = SerialAllocator::new();
        source.advance_to(NonZeroU64::new(100).unwrap());
        source.advance_past(NonZeroU64::new(200).unwrap()).unwrap();
        let native = source.transfer().unwrap().into_allocator();
        assert_eq!(native.allocate().unwrap().get(), 201);
        let exhausted = SerialAllocator::starting_at(NonZeroU64::MAX);
        assert_eq!(exhausted.allocate(), None);
        let native = exhausted.transfer().unwrap().into_allocator();
        assert_eq!(native.allocate(), None);
        assert_eq!(exhausted.allocate(), None);
        assert_eq!(exhausted.refused_attempts(), Some(1));
        assert_eq!(native.refused_attempts(), Some(0));
    }

    #[test]
    fn transferred_source_counts_calls_from_a_retained_peer() {
        use std::sync::mpsc;
        use std::time::Duration;
        let source = SerialAllocator::new();
        let (issued_tx, issued_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let peer_source = &source;
            let peer = scope.spawn(move || {
                issued_tx.send(peer_source.allocate().unwrap()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                for _ in 0..64 {
                    assert_eq!(peer_source.allocate(), None);
                }
            });
            assert_eq!(
                issued_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .get(),
                1
            );
            let native = source.transfer().unwrap().into_allocator();
            release_tx.send(()).unwrap();
            assert_eq!(native.allocate().unwrap().get(), 2);
            peer.join().unwrap();
            assert_eq!(source.refused_attempts(), Some(64));
        });
    }

    #[test]
    fn refusal_receipt_reports_overflow_without_wrapping() {
        let source = SerialAllocator::new();
        let _native = source.transfer().unwrap();
        source.refused.store(u64::MAX - 1, Ordering::Relaxed);
        assert_eq!(source.allocate(), None);
        assert_eq!(source.refused_attempts(), None);
        assert_eq!(source.allocate(), None);
        assert_eq!(source.refused_attempts(), None);
    }

    #[test]
    fn transferred_namespace_cannot_restart_visible_numbering() {
        let mut source = NamespaceState::new(1, 8, 1);
        let namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let root = source.reserve_next(ClaimKind::Task).unwrap();
        source.claim_related(root.get(), ClaimKind::Thread).unwrap();
        source
            .claim_related(root.get(), ClaimKind::ProcessGroup)
            .unwrap();
        source
            .claim_related(root.get(), ClaimKind::Session)
            .unwrap();
        assert_eq!(source.reserve_visible(namespace).unwrap().get(), 2);
        let mut native = source.transfer().unwrap().into_owner();
        assert_eq!(source.reserve_visible(namespace), None);
        assert_eq!(
            source.reserve_next(ClaimKind::Task),
            Err(IdError::AuthorityTransferred)
        );
        assert_eq!(
            source.reserve_next(ClaimKind::Thread),
            Err(IdError::AuthorityTransferred)
        );
        assert_eq!(
            source.reserve_exact(7, ClaimKind::Task),
            Err(IdError::AuthorityTransferred)
        );
        assert_eq!(
            source.claim_related(root.get(), ClaimKind::Session),
            Err(IdError::AuthorityTransferred)
        );
        source.set_next(7);
        assert!(source.transfer().is_none());
        assert_eq!(source.refused_attempts(), Some(7));
        assert_eq!(source.counts(), IdRegistryCounts::default());
        assert_eq!(native.counts().thread_claims, 1);
        assert_eq!(native.counts().process_group_claims, 1);
        assert_eq!(native.counts().session_claims, 1);

        assert_eq!(native.reserve_visible(namespace).unwrap().get(), 3);
        assert_eq!(native.reserve_next(ClaimKind::Task).unwrap().get(), 2);
        source.release(root, ClaimKind::Task);
        source.retire_visible_namespace(namespace);
        assert_eq!(native.counts().task_claims, 2);
        assert_eq!(native.reserve_visible(namespace).unwrap().get(), 4);
    }

    #[test]
    fn namespace_refusal_overflow_remains_unknown() {
        let mut source = NamespaceState::new(1, 8, 1);
        let _native = source.transfer().unwrap();
        source.refused = u64::MAX - 1;
        assert_eq!(
            source.reserve_next(ClaimKind::Task),
            Err(IdError::AuthorityTransferred)
        );
        assert_eq!(source.refused_attempts(), None);
        assert!(source.transfer().is_none());
        assert_eq!(source.refused_attempts(), None);
    }

    #[test]
    fn admitted_visible_root_advances_only_its_namespace_cursor() {
        let mut owner = NamespaceState::new(1, 100, 1);
        let namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let other = VisibleNamespace::new(NonZeroU32::new(2).unwrap(), NonZeroU32::MIN);
        let root = VisibleIdentity::from_existing_member(NonZeroU32::new(41).unwrap());
        assert_eq!(owner.advance_visible_past(namespace, root), Some(()));
        assert_eq!(owner.reserve_visible(namespace).unwrap().get(), 42);
        assert_eq!(owner.reserve_visible(other).unwrap().get(), 2);
        assert_eq!(owner.advance_visible_past(namespace, root), Some(()));
        assert_eq!(owner.reserve_visible(namespace).unwrap().get(), 43);
        assert_eq!(owner.counts().reserved_numbers, 0);
    }

    #[test]
    fn visible_root_admission_refuses_overflow_and_preserves_exhaustion() {
        let mut owner = NamespaceState::new(1, 100, 1);
        let namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let invalid = VisibleIdentity::from_existing_member(NonZeroU32::MAX);
        assert_eq!(owner.advance_visible_past(namespace, invalid), None);
        assert_eq!(owner.visible_namespace_count(), 0);
        let last = VisibleIdentity::from_existing_member(NonZeroU32::new(i32::MAX as u32).unwrap());
        assert_eq!(owner.advance_visible_past(namespace, last), Some(()));
        assert_eq!(owner.reserve_visible(namespace), None);
        let root = VisibleIdentity::from_existing_member(NonZeroU32::MIN);
        assert_eq!(owner.advance_visible_past(namespace, root), Some(()));
        assert_eq!(owner.reserve_visible(namespace), None);
        let transferred = owner.transfer().unwrap();
        assert_eq!(owner.advance_visible_past(namespace, root), None);
        assert_eq!(owner.refused_attempts(), Some(1));
        assert_eq!(transferred.into_owner().reserve_visible(namespace), None);
    }

    #[test]
    fn reused_namespace_number_has_distinct_incarnation_custody() {
        let mut owner = NamespaceState::new(1, 8, 1);
        let old = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let new = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::new(2).unwrap());
        assert_eq!(owner.reserve_visible(old).unwrap().get(), 2);
        assert_eq!(owner.reserve_visible(new).unwrap().get(), 2);
        owner.retire_visible_namespace(old);
        assert_eq!(owner.reserve_visible(new).unwrap().get(), 3);
        assert_eq!(owner.owner.as_mut().unwrap().visible_next.len(), 1);
    }

    #[test]
    fn aborted_birth_burns_visible_number_but_recycles_internal_number() {
        let mut owner = NamespaceState::new(1, 1, 1);
        let namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let internal = owner.reserve_next(ClaimKind::Task).unwrap();
        let visible = owner.reserve_visible(namespace).unwrap();
        assert_eq!(visible.get(), 2);
        owner.release(internal, ClaimKind::Task);
        assert_eq!(owner.reserve_next(ClaimKind::Task).unwrap(), internal);
        assert_eq!(owner.reserve_visible(namespace).unwrap().get(), 3);
        let other = VisibleNamespace::new(NonZeroU32::new(2).unwrap(), NonZeroU32::MIN);
        assert_eq!(owner.reserve_visible(other).unwrap().get(), 2);
        owner
            .owner
            .as_mut()
            .unwrap()
            .visible_next
            .insert(namespace, i32::MAX as u32 - 1);
        assert_eq!(
            owner.reserve_visible(namespace).unwrap().get(),
            i32::MAX as u32 - 1
        );
        assert_eq!(owner.reserve_visible(namespace), None);
        owner.retire_visible_namespace(namespace);
        assert_eq!(owner.owner.as_mut().unwrap().visible_next.len(), 1);
        assert_eq!(owner.reserve_visible(other).unwrap().get(), 3);
    }

    #[test]
    fn nested_domains_keep_ancestor_collisions_and_child_numbers_distinct() {
        // A descendant has its own local number while retaining an ancestor
        // claim for the same task; cousins must still collide in that ancestor.
        let mut ancestor = NamespaceState::new(1, 4, 1);
        let mut child = NamespaceState::new(1, 4, 1);
        let ancestor_id = ancestor.reserve_next(ClaimKind::Task).unwrap();
        let child_id = child.reserve_next(ClaimKind::Task).unwrap();
        assert_eq!((ancestor_id.get(), child_id.get()), (1, 1));
        assert_eq!(
            ancestor.reserve_exact(1, ClaimKind::Task),
            Err(IdError::AlreadyReserved(1))
        );
        assert_eq!(
            child.reserve_exact(1, ClaimKind::Task),
            Err(IdError::AlreadyReserved(1))
        );
        ancestor.claim_related(1, ClaimKind::Thread).unwrap();
        ancestor.release(ancestor_id, ClaimKind::Task);
        child.release(child_id, ClaimKind::Task);
        assert!(ancestor.is_reserved_number(1));
        assert!(!child.is_reserved_number(1));
        ancestor.release(ancestor_id, ClaimKind::Thread);
        assert!(!ancestor.is_reserved_number(1));
    }

    #[test]
    fn reap_reuses_number_only_after_all_roles_release_with_new_serial() {
        let mut numbers = NamespaceState::new(1, 1, 1);
        let serials = SerialAllocator::new();
        let id = numbers.reserve_next(ClaimKind::Task).unwrap();
        let old_serial = serials.allocate().unwrap();
        numbers
            .claim_related(id.get(), ClaimKind::ProcessGroup)
            .unwrap();
        numbers.claim_related(id.get(), ClaimKind::Session).unwrap();
        numbers.release(id, ClaimKind::Task);
        assert_eq!(
            numbers.reserve_next(ClaimKind::Task),
            Err(IdError::Exhausted)
        );
        numbers.release(id, ClaimKind::ProcessGroup);
        assert_eq!(
            numbers.reserve_next(ClaimKind::Task),
            Err(IdError::Exhausted)
        );
        numbers.release(id, ClaimKind::Session);
        let reused = numbers.reserve_next(ClaimKind::Task).unwrap();
        let new_serial = serials.allocate().unwrap();
        assert_eq!(reused, id);
        assert!(new_serial > old_serial);
        assert_eq!(numbers.counts().task_claims, 1);
    }

    #[test]
    fn serials_are_monotonic_and_exhaustion_never_wraps() {
        let serials = SerialAllocator::new();
        for expected in 1..=128 {
            assert_eq!(serials.allocate().unwrap().get(), expected);
        }
        let exhausted = SerialAllocator::starting_at(NonZeroU64::MAX);
        assert_eq!(exhausted.allocate(), None);
        assert_eq!(exhausted.allocate(), None);
    }
}
