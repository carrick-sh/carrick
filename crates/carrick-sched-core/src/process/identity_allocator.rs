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
pub struct VisibleNamespace(NonZeroU32);
impl VisibleNamespace {
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }
}
/// Linux-visible PID/TID; never an internal registry key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisibleIdentity(NonZeroU32);
impl VisibleIdentity {
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Debug)]
pub struct NamespaceState {
    first: i32,
    last: i32,
    next: i32,
    claims: BTreeMap<i32, ClaimCounts>,
    visible_next: BTreeMap<VisibleNamespace, u32>,
}

impl NamespaceState {
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
    Exhausted,
    OutOfRange(i32),
    AlreadyReserved(i32),
    UnknownNamespaceId(i32),
    ClaimCountExhausted(i32),
}

impl NamespaceState {
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
        }
    }
    /// Import an already-established lower bound without reusing a serial.
    pub fn advance_to(&self, next: NonZeroU64) {
        self.next.fetch_max(next.get(), Ordering::Relaxed);
    }
    pub fn advance_past(&self, value: NonZeroU64) -> Option<()> {
        let next = value.get().checked_add(1)?;
        self.next.fetch_max(next, Ordering::Relaxed);
        Some(())
    }
    pub fn allocate(&self) -> Option<NonZeroU64> {
        let raw = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .ok()?;
        NonZeroU64::new(raw)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aborted_birth_burns_visible_number_but_recycles_internal_number() {
        let mut owner = NamespaceState::new(1, 1, 1);
        let namespace = VisibleNamespace::new(NonZeroU32::MIN);
        let internal = owner.reserve_next(ClaimKind::Task).unwrap();
        let visible = owner.reserve_visible(namespace).unwrap();
        assert_eq!(visible.get(), 2);
        owner.release(internal, ClaimKind::Task);
        assert_eq!(owner.reserve_next(ClaimKind::Task).unwrap(), internal);
        assert_eq!(owner.reserve_visible(namespace).unwrap().get(), 3);
        let other = VisibleNamespace::new(NonZeroU32::new(2).unwrap());
        assert_eq!(owner.reserve_visible(other).unwrap().get(), 2);
        owner.visible_next.insert(namespace, i32::MAX as u32 - 1);
        assert_eq!(
            owner.reserve_visible(namespace).unwrap().get(),
            i32::MAX as u32 - 1
        );
        assert_eq!(owner.reserve_visible(namespace), None);
        owner.retire_visible_namespace(namespace);
        assert_eq!(owner.visible_next.len(), 1);
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
