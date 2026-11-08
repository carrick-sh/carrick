//! Pure identity allocation shared by host and native process consumers.
//! Consumers provide exclusion and own role-preserving claim lifetimes.
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::num::{NonZeroI32, NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// Linux numbering domain: unmapped claims or an exact root namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct VisibleNamespace(NonZeroU64);
impl VisibleNamespace {
    /// No PID remapping: visible identities are the shared internal claims.
    /// ID zero cannot name an arena namespace, so this domain needs no cursor.
    pub const fn unmapped() -> Self {
        Self(NonZeroU64::MIN)
    }
    const fn is_unmapped(self) -> bool {
        self.0.get() == 1
    }
    pub const fn new(id: NonZeroU32, incarnation: NonZeroU32) -> Self {
        let raw = ((id.get() as u64) << 32) | (incarnation.get() as u64);
        match NonZeroU64::new(raw) {
            Some(nz) => Self(nz),
            None => unreachable!(),
        }
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
/// Venue-local owner of relocatable storage. Only the node array and header
/// are mapped; this Vec is never interpreted through a foreign address alias.
#[derive(Debug)]
struct NamespaceAllocation {
    header: NamespaceHeader,
    nodes: Vec<NamespaceNode>,
}

/// Pointer-free allocator control, protected by the consumer's authority lock.
/// All links index the separately retained node array; zero is the null link.
#[derive(Debug)]
#[repr(C)]
pub struct NamespaceHeader {
    first: i32,
    last: i32,
    next: i32,
    root: u32,
    free: u32,
    used: u32,
    visible_count: u32,
    counts: [u64; 5],
}

/// One relocatable AVL node. A node is either an internal-number claim or an
/// exact visible-namespace cursor; unused nodes belong to the header's free list.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct NamespaceNode {
    key: u64,
    namespace: u64,
    claims: ClaimCounts,
    visible_next: u32,
    left: u32,
    right: u32,
    height: u32,
}

/// One allocator implementation over either local or mapped storage. The
/// caller retains both allocations and exclusive authority for this borrow.
/// Neither header nor nodes contain an address into the allocating venue.
pub struct NamespaceView<'a> {
    header: &'a mut NamespaceHeader,
    nodes: &'a mut [NamespaceNode],
}

/// Shared namespace storage protocol, included in the image ABI fingerprint.
pub const NAMESPACE_TABLE_PROTOCOL: u64 = 2;
/// Includes the null-link sentinel; 8191 nodes are available for claims/cursors.
pub const NAMESPACE_TABLE_NODES: usize = 8192;

/// Carrier-owned, pointer-free namespace authority. Zero bytes denote a fresh
/// table. Its leaf lock must never enclose allocation, crossing, or wake work.
#[repr(C)]
pub struct NamespaceTable {
    lock: AtomicU32,
    header: UnsafeCell<NamespaceHeader>,
    nodes: UnsafeCell<[NamespaceNode; NAMESPACE_TABLE_NODES]>,
}

// SAFETY: the leaf lock exclusively protects both UnsafeCells across aliases.
unsafe impl Sync for NamespaceTable {}

#[cfg(any(test, feature = "host-test"))]
static OBSERVED_NAMESPACE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
#[cfg(any(test, feature = "host-test"))]
static NAMESPACE_CONTENDED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Fixture observation of an actual failed acquisition, without changing the
/// table layout or the production wait policy. Only one observer may be armed.
#[cfg(any(test, feature = "host-test"))]
pub struct NamespaceContentionProbe<'a>(&'a NamespaceTable);
#[cfg(any(test, feature = "host-test"))]
impl NamespaceContentionProbe<'_> {
    pub fn observed(&self) -> bool {
        NAMESPACE_CONTENDED.load(Ordering::Acquire)
    }
}
#[cfg(any(test, feature = "host-test"))]
impl Drop for NamespaceContentionProbe<'_> {
    fn drop(&mut self) {
        let _ = OBSERVED_NAMESPACE.compare_exchange(
            core::ptr::from_ref(self.0).addr(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

impl NamespaceTable {
    #[cfg(any(test, feature = "host-test"))]
    pub fn contention_probe(&self) -> Option<NamespaceContentionProbe<'_>> {
        OBSERVED_NAMESPACE
            .compare_exchange(
                0,
                core::ptr::from_ref(self).addr(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        NAMESPACE_CONTENDED.store(false, Ordering::Release);
        Some(NamespaceContentionProbe(self))
    }
    /// The view cannot escape the closure. Callers perform only bounded
    /// allocator operations here and retain all outer custody until return.
    pub fn with_view<R>(
        &self,
        wait: &impl crate::ShortLockWait,
        f: impl FnOnce(&mut NamespaceView<'_>) -> R,
    ) -> R {
        let mut attempt = 0_u32;
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            #[cfg(any(test, feature = "host-test"))]
            if OBSERVED_NAMESPACE.load(Ordering::Acquire) == core::ptr::from_ref(self).addr() {
                NAMESPACE_CONTENDED.store(true, Ordering::Release);
            }
            wait.wait_short(attempt);
            attempt = attempt.saturating_add(1);
        }
        struct Unlock<'a>(&'a AtomicU32);
        impl Drop for Unlock<'_> {
            fn drop(&mut self) {
                self.0.store(0, Ordering::Release);
            }
        }
        let _unlock = Unlock(&self.lock);
        // SAFETY: exclusive leaf-lock custody lasts through the closure and
        // its unwind. Zero storage is valid for every header and node field.
        let (header, nodes) = unsafe { (&mut *self.header.get(), &mut *self.nodes.get()) };
        if header.first == 0 {
            *header = NamespaceHeader::new(1, i32::MAX, 1);
        }
        f(&mut header.view(nodes))
    }
}

impl NamespaceHeader {
    pub fn new(first: i32, last: i32, next: i32) -> Self {
        assert!(first > 0);
        assert!(last >= first);
        assert!((first..=last).contains(&next));
        Self {
            first,
            last,
            next,
            root: 0,
            free: 0,
            used: 0,
            visible_count: 0,
            counts: [0; 5],
        }
    }

    /// Borrow an authenticated storage allocation. The consumer must map the
    /// complete same node array, with initialized spare nodes, at either alias.
    pub fn view<'a>(&'a mut self, nodes: &'a mut [NamespaceNode]) -> NamespaceView<'a> {
        NamespaceView {
            header: self,
            nodes,
        }
    }
}

impl NamespaceHeader {
    fn counts(&self) -> IdRegistryCounts {
        IdRegistryCounts {
            reserved_numbers: self.counts[0] as usize,
            task_claims: self.counts[1] as usize,
            thread_claims: self.counts[2] as usize,
            process_group_claims: self.counts[3] as usize,
            session_claims: self.counts[4] as usize,
        }
    }
    fn find(&self, nodes: &[NamespaceNode], key: u64) -> Option<usize> {
        let mut index = self.root;
        while index != 0 {
            let node = nodes[index as usize];
            match key.cmp(&node.key) {
                core::cmp::Ordering::Less => index = node.left,
                core::cmp::Ordering::Greater => index = node.right,
                core::cmp::Ordering::Equal => return Some(index as usize),
            }
        }
        None
    }
}

impl NamespaceView<'_> {
    fn height(&self, index: u32) -> u32 {
        if index == 0 {
            0
        } else {
            self.nodes[index as usize].height
        }
    }
    fn update(&mut self, index: u32) {
        let node = self.nodes[index as usize];
        self.nodes[index as usize].height = 1 + self.height(node.left).max(self.height(node.right));
    }
    fn rotate_left(&mut self, index: u32) -> u32 {
        let right = self.nodes[index as usize].right;
        self.nodes[index as usize].right = self.nodes[right as usize].left;
        self.nodes[right as usize].left = index;
        self.update(index);
        self.update(right);
        right
    }
    fn rotate_right(&mut self, index: u32) -> u32 {
        let left = self.nodes[index as usize].left;
        self.nodes[index as usize].left = self.nodes[left as usize].right;
        self.nodes[left as usize].right = index;
        self.update(index);
        self.update(left);
        left
    }
    fn balance(&mut self, index: u32) -> u32 {
        self.update(index);
        let node = self.nodes[index as usize];
        if self.height(node.left) > self.height(node.right) + 1 {
            let left = self.nodes[node.left as usize];
            if self.height(left.right) > self.height(left.left) {
                self.nodes[index as usize].left = self.rotate_left(node.left);
            }
            return self.rotate_right(index);
        }
        if self.height(node.right) > self.height(node.left) + 1 {
            let right = self.nodes[node.right as usize];
            if self.height(right.left) > self.height(right.right) {
                self.nodes[index as usize].right = self.rotate_right(node.right);
            }
            return self.rotate_left(index);
        }
        index
    }
    fn find(&self, key: u64) -> Option<usize> {
        self.header.find(self.nodes, key)
    }
    // An AVL tree with u32 node indices has height below 48. The fixed path
    // keeps insert/remove off the recursive EL1/CPL0 stack budget entirely.
    fn rebalance_path(&mut self, path: &[u32]) {
        for depth in (0..path.len()).rev() {
            let old = path[depth];
            let new = self.balance(old);
            if depth == 0 {
                self.header.root = new;
            } else {
                let parent = path[depth - 1] as usize;
                if self.nodes[parent].left == old {
                    self.nodes[parent].left = new;
                } else {
                    self.nodes[parent].right = new;
                }
            }
        }
    }
    fn insert(&mut self, index: u32) {
        let mut path = [0_u32; 48];
        let mut depth = 0;
        let key = self.nodes[index as usize].key;
        let mut root = self.header.root;
        while root != 0 {
            path[depth] = root;
            depth += 1;
            root = if key < self.nodes[root as usize].key {
                self.nodes[root as usize].left
            } else {
                self.nodes[root as usize].right
            };
        }
        if depth == 0 {
            self.header.root = index;
        } else {
            let parent = path[depth - 1] as usize;
            if key < self.nodes[parent].key {
                self.nodes[parent].left = index;
            } else {
                self.nodes[parent].right = index;
            }
            self.rebalance_path(&path[..depth]);
        }
    }
    fn entry(&mut self, key: u64) -> Result<usize, IdError> {
        if let Some(index) = self.find(key) {
            return Ok(index);
        }
        let index = if self.header.free != 0 {
            let index = self.header.free;
            self.header.free = self.nodes[index as usize].left;
            index
        } else {
            let index = self
                .header
                .used
                .checked_add(1)
                .ok_or(IdError::StorageRequired)?;
            if index as usize >= self.nodes.len() {
                return Err(IdError::StorageRequired);
            }
            self.header.used = index;
            index
        };
        self.nodes[index as usize] = NamespaceNode {
            key,
            height: 1,
            ..NamespaceNode::default()
        };
        self.insert(index);
        Ok(index as usize)
    }
    fn free(&mut self, index: u32) {
        self.nodes[index as usize] = NamespaceNode {
            left: self.header.free,
            ..NamespaceNode::default()
        };
        self.header.free = index;
    }
    fn remove(&mut self, key: u64) {
        let mut path = [0_u32; 48];
        let mut depth = 0;
        let mut index = self.header.root;
        while index != 0 && self.nodes[index as usize].key != key {
            path[depth] = index;
            depth += 1;
            index = if key < self.nodes[index as usize].key {
                self.nodes[index as usize].left
            } else {
                self.nodes[index as usize].right
            };
        }
        if index == 0 {
            return;
        }
        let node = self.nodes[index as usize];
        if node.left != 0 && node.right != 0 {
            // Remove the successor, retaining the original index and links.
            let target = index as usize;
            path[depth] = index;
            depth += 1;
            index = node.right;
            while self.nodes[index as usize].left != 0 {
                path[depth] = index;
                depth += 1;
                index = self.nodes[index as usize].left;
            }
            let successor = self.nodes[index as usize];
            self.nodes[target].key = successor.key;
            self.nodes[target].namespace = successor.namespace;
            self.nodes[target].claims = successor.claims;
            self.nodes[target].visible_next = successor.visible_next;
        }
        let node = self.nodes[index as usize];
        let replacement = if node.left == 0 {
            node.right
        } else {
            node.left
        };
        if depth == 0 {
            self.header.root = replacement;
        } else {
            let parent = path[depth - 1] as usize;
            if self.nodes[parent].left == index {
                self.nodes[parent].left = replacement;
            } else {
                self.nodes[parent].right = replacement;
            }
        }
        self.free(index);
        self.rebalance_path(&path[..depth]);
    }
    fn internal_key(raw: i32) -> u64 {
        raw as u32 as u64
    }
    // Remapped namespace incarnations occupy all 64 bits. Their cursor keys
    // have nonzero IDs; internal numbers use id=0. Unmapped domains have no
    // cursor node and must never be looked up as a namespace key.
    fn namespace_key(namespace: VisibleNamespace) -> u64 {
        namespace.0.get()
    }
    fn visible_entry(&mut self, namespace: VisibleNamespace) -> Result<usize, IdError> {
        if namespace.is_unmapped() {
            return Err(IdError::AuthorityTransferred);
        }
        let key = Self::namespace_key(namespace);
        if let Some(index) = self.find(key) {
            return Ok(index);
        }
        let index = self.entry(key)?;
        self.nodes[index].visible_next = 2;
        self.header.visible_count += 1;
        Ok(index)
    }
    fn advance(&mut self) {
        self.header.next = if self.header.next == self.header.last {
            self.header.first
        } else {
            self.header.next + 1
        };
    }
    /// Attach the host-admitted visible namespace to an existing claim.
    pub fn bind_visible_domain(
        &mut self,
        raw: i32,
        namespace: VisibleNamespace,
    ) -> Result<(), IdError> {
        let index = self
            .find(Self::internal_key(raw))
            .ok_or(IdError::UnknownNamespaceId(raw))?;
        let old = self.nodes[index].namespace;
        if old != 0 && old != namespace.0.get() {
            return Err(IdError::AlreadyReserved(raw));
        }
        if !namespace.is_unmapped() {
            self.visible_entry(namespace)?;
        }
        self.nodes[index].namespace = namespace.0.get();
        Ok(())
    }
    /// Bind a live internal claim and issue its Linux-visible identity.
    /// Unmapped launches use that claim itself, never a second counter.
    pub fn assign_visible(
        &mut self,
        number: InternalIdentity,
        namespace: VisibleNamespace,
    ) -> Result<VisibleIdentity, IdError> {
        self.bind_visible_domain(number.get(), namespace)?;
        if namespace.is_unmapped() {
            Ok(VisibleIdentity(
                NonZeroU32::new(number.get() as u32).ok_or(IdError::OutOfRange(number.get()))?,
            ))
        } else {
            self.reserve_visible(namespace)
        }
    }
    pub fn visible_domain(&self, raw: i32) -> Option<VisibleNamespace> {
        let index = self.find(Self::internal_key(raw))?;
        NonZeroU64::new(self.nodes[index].namespace).map(VisibleNamespace)
    }
    pub fn release(&mut self, raw: InternalIdentity, kind: ClaimKind) {
        let key = Self::internal_key(raw.get());
        let Some(index) = self.find(key) else {
            debug_assert!(false, "live identity token lost its registry claim");
            return;
        };
        if !self.nodes[index].claims.decrement(kind) {
            debug_assert!(false, "identity claim reference count underflow");
            return;
        }
        self.header.counts[1 + kind.index()] -= 1;
        if self.nodes[index].claims.is_empty() {
            self.remove(key);
            self.header.counts[0] -= 1;
        }
    }
    pub fn reserve_next(&mut self, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        let start = self.header.next;
        loop {
            let candidate = self.header.next;
            // A storage refusal keeps the cursor and every claim unchanged.
            if !self.is_reserved_number(candidate) {
                let index = match self.entry(Self::internal_key(candidate)) {
                    Ok(index) => index,
                    Err(error) => {
                        self.header.next = start;
                        return Err(error);
                    }
                };
                let incremented = self.nodes[index].claims.increment(kind);
                debug_assert!(incremented);
                self.header.counts[0] += 1;
                self.header.counts[1 + kind.index()] += 1;
                self.advance();
                return Ok(InternalIdentity(
                    NonZeroI32::new(candidate).ok_or(IdError::OutOfRange(candidate))?,
                ));
            }
            self.advance();
            if self.header.next == start {
                return Err(IdError::Exhausted);
            }
        }
    }
    pub fn reserve_exact(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        if raw < self.header.first || raw > self.header.last {
            return Err(IdError::OutOfRange(raw));
        }
        if self.is_reserved_number(raw) {
            return Err(IdError::AlreadyReserved(raw));
        }
        let index = self.entry(Self::internal_key(raw))?;
        let incremented = self.nodes[index].claims.increment(kind);
        debug_assert!(incremented);
        self.header.counts[0] += 1;
        self.header.counts[1 + kind.index()] += 1;
        Ok(InternalIdentity(
            NonZeroI32::new(raw).ok_or(IdError::OutOfRange(raw))?,
        ))
    }
    pub fn claim_related(
        &mut self,
        raw: i32,
        kind: ClaimKind,
    ) -> Result<InternalIdentity, IdError> {
        let nonzero = NonZeroI32::new(raw).ok_or(IdError::OutOfRange(raw))?;
        let index = self
            .find(Self::internal_key(raw))
            .ok_or(IdError::UnknownNamespaceId(raw))?;
        if !self.nodes[index].claims.increment(kind) {
            return Err(IdError::ClaimCountExhausted(raw));
        }
        self.header.counts[1 + kind.index()] += 1;
        Ok(InternalIdentity(nonzero))
    }
    /// Preparation burns the visible number even when birth rolls back.
    /// PID1 belongs to the root seed. StorageRequired is a provision request,
    /// distinct from exhaustion, with no partially issued visible identity.
    pub fn reserve_visible(
        &mut self,
        namespace: VisibleNamespace,
    ) -> Result<VisibleIdentity, IdError> {
        let index = self.visible_entry(namespace)?;
        let next = &mut self.nodes[index].visible_next;
        if *next >= i32::MAX as u32 {
            return Err(IdError::Exhausted);
        }
        let value = NonZeroU32::new(*next).ok_or(IdError::Exhausted)?;
        *next += 1;
        Ok(VisibleIdentity(value))
    }
    pub fn advance_visible_past(
        &mut self,
        namespace: VisibleNamespace,
        member: VisibleIdentity,
    ) -> Result<(), IdError> {
        if member.get() > i32::MAX as u32 {
            return Err(IdError::Exhausted);
        }
        let next = member.get().checked_add(1).ok_or(IdError::Exhausted)?;
        let index = self.visible_entry(namespace)?;
        self.nodes[index].visible_next = self.nodes[index].visible_next.max(next);
        Ok(())
    }
    pub fn set_next(&mut self, raw: i32) {
        assert!((self.header.first..=self.header.last).contains(&raw));
        self.header.next = raw;
    }
    pub fn retire_visible_namespace(&mut self, namespace: VisibleNamespace) {
        if namespace.is_unmapped() {
            return;
        }
        let key = Self::namespace_key(namespace);
        if self.find(key).is_some() {
            self.remove(key);
            self.header.visible_count -= 1;
        }
    }
    pub fn is_reserved_number(&self, raw: i32) -> bool {
        self.find(Self::internal_key(raw)).is_some()
    }
    pub fn visible_namespace_count(&self) -> usize {
        self.header.visible_count as usize
    }
    pub fn counts(&self) -> IdRegistryCounts {
        self.header.counts()
    }
}

impl NamespaceAllocation {
    fn new(first: i32, last: i32, next: i32) -> Self {
        Self {
            header: NamespaceHeader::new(first, last, next),
            nodes: alloc::vec![NamespaceNode::default(); 16],
        }
    }
    fn provision(&mut self) -> Result<(), IdError> {
        if self.header.free == 0 && self.header.used as usize + 1 == self.nodes.len() {
            let next = self
                .nodes
                .len()
                .checked_mul(2)
                .filter(|next| *next <= u32::MAX as usize)
                .ok_or(IdError::StorageRequired)?;
            self.nodes
                .try_reserve_exact(next - self.nodes.len())
                .map_err(|_| IdError::StorageRequired)?;
            self.nodes.resize(next, NamespaceNode::default());
        }
        Ok(())
    }
    fn view(&mut self) -> NamespaceView<'_> {
        self.header.view(&mut self.nodes)
    }
    fn reserve_next(&mut self, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        if self.header.counts[0] < (self.header.last - self.header.first + 1) as u64 {
            self.provision()?;
        }
        self.view().reserve_next(kind)
    }
    fn reserve_exact(&mut self, raw: i32, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        if (self.header.first..=self.header.last).contains(&raw) && !self.is_reserved_number(raw) {
            self.provision()?;
        }
        self.view().reserve_exact(raw, kind)
    }
    fn claim_related(&mut self, raw: i32, kind: ClaimKind) -> Result<InternalIdentity, IdError> {
        self.view().claim_related(raw, kind)
    }
    fn release(&mut self, raw: InternalIdentity, kind: ClaimKind) {
        self.view().release(raw, kind);
    }
    fn reserve_visible(&mut self, namespace: VisibleNamespace) -> Option<VisibleIdentity> {
        if self
            .header
            .find(&self.nodes, NamespaceView::namespace_key(namespace))
            .is_none()
        {
            self.provision().ok()?;
        }
        self.view().reserve_visible(namespace).ok()
    }
    fn advance_visible_past(
        &mut self,
        namespace: VisibleNamespace,
        member: VisibleIdentity,
    ) -> Option<()> {
        if member.get() > i32::MAX as u32 {
            return None;
        }
        if self
            .header
            .find(&self.nodes, NamespaceView::namespace_key(namespace))
            .is_none()
        {
            self.provision().ok()?;
        }
        self.view().advance_visible_past(namespace, member).ok()
    }
    fn set_next(&mut self, raw: i32) {
        self.view().set_next(raw);
    }
    fn retire_visible_namespace(&mut self, namespace: VisibleNamespace) {
        self.view().retire_visible_namespace(namespace);
    }
    fn is_reserved_number(&self, raw: i32) -> bool {
        self.header
            .find(&self.nodes, NamespaceView::internal_key(raw))
            .is_some()
    }
    fn counts(&self) -> IdRegistryCounts {
        self.header.counts()
    }
    fn visible_namespace_count(&self) -> usize {
        self.header.visible_count as usize
    }
}
/// Owned claims and cursors, moved once rather than mirrored at the source.
#[derive(Debug)]
pub struct TransferredNamespaceState {
    owner: NamespaceAllocation,
}
impl TransferredNamespaceState {
    /// Consume local allocation custody into separately mappable, pointer-free
    /// storage. The caller owns synchronization, mapping and node-array growth;
    /// the allocator algorithm remains NamespaceView at both aliases.
    pub fn into_storage(self) -> (NamespaceHeader, Vec<NamespaceNode>) {
        (self.owner.header, self.owner.nodes)
    }

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
    /// Adopt all bootstrap claims and visible cursors into retained zone
    /// storage. The caller excludes local issuance and revokes local custody
    /// after success, before dropping that exclusion. No allocation occurs.
    pub fn adopt_into(&self, destination: &mut NamespaceView<'_>) -> Result<(), IdError> {
        let source = self.owner.as_ref().ok_or(IdError::AuthorityTransferred)?;
        let mut needed = 0_usize;
        for node in source.nodes.iter().filter(|node| node.height != 0) {
            if destination.find(node.key).is_some() {
                if node.key >> 32 == 0 {
                    return Err(IdError::AlreadyReserved(node.key as i32));
                }
            } else {
                needed += 1;
            }
        }
        let occupied =
            destination.header.counts[0] as usize + destination.header.visible_count as usize;
        if needed > destination.nodes.len().saturating_sub(occupied + 1) {
            return Err(IdError::StorageRequired);
        }
        // Preflight above makes all following entry operations infallible:
        // there are enough free slots and exclusion prevents intervening use.
        for node in source.nodes.iter().filter(|node| node.height != 0) {
            let existing = destination.find(node.key).is_some();
            let index = destination.entry(node.key)?;
            if node.key >> 32 == 0 {
                destination.nodes[index].namespace = node.namespace;
                destination.nodes[index].claims = node.claims;
            } else {
                destination.nodes[index].visible_next =
                    destination.nodes[index].visible_next.max(node.visible_next);
                if !existing {
                    destination.header.visible_count += 1;
                }
            }
        }
        for (target, count) in destination
            .header
            .counts
            .iter_mut()
            .zip(source.header.counts)
        {
            *target += count;
        }
        destination.header.next = destination.header.next.max(source.header.next);
        Ok(())
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
    pub fn bind_visible_domain(
        &mut self,
        raw: i32,
        namespace: VisibleNamespace,
    ) -> Result<(), IdError> {
        let allocation = self.allocation()?;
        if !namespace.is_unmapped()
            && allocation
                .header
                .find(&allocation.nodes, NamespaceView::namespace_key(namespace))
                .is_none()
        {
            allocation.provision()?;
        }
        allocation.view().bind_visible_domain(raw, namespace)
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
        self.allocation()
            .ok()?
            .advance_visible_past(namespace, member)
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

#[derive(Clone, Copy, Debug)]
pub enum ClaimKind {
    Task,
    Thread,
    ProcessGroup,
    Session,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
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
#[repr(C)]
pub struct IdRegistryCounts {
    pub reserved_numbers: usize,
    pub task_claims: usize,
    pub thread_claims: usize,
    pub process_group_claims: usize,
    pub session_claims: usize,
}

impl ClaimKind {
    fn index(self) -> usize {
        match self {
            Self::Task => 0,
            Self::Thread => 1,
            Self::ProcessGroup => 2,
            Self::Session => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    /// The view has no spare node. Fixed zone tables treat this as exhaustion;
    /// local owners may provision storage before lending a new view.
    StorageRequired,
    AuthorityTransferred,
    Exhausted,
    OutOfRange(i32),
    AlreadyReserved(i32),
    UnknownNamespaceId(i32),
    ClaimCountExhausted(i32),
}

impl core::fmt::Display for IdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageRequired => f.write_str("namespace metadata storage requires growth"),
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

/// Shared birth-issuer protocol: one atomic last-issued word, initially zero.
/// Included in the image ABI hash independently of the word's layout.
pub const SERIAL_ISSUER_PROTOCOL: u64 = 3;

/// Carrier-owned birth serial storage. All-zero bytes are a valid initial
/// state; MAX is terminal. Unlike [`SerialAllocator`], this shared word cannot
/// be transferred, reset or reopened. Revocation belongs to the host handle,
/// never to storage that other graphs may still use.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct SerialIssuerWord {
    last_issued: AtomicU64,
}

impl SerialIssuerWord {
    pub const fn new() -> Self {
        Self {
            last_issued: AtomicU64::new(0),
        }
    }

    /// Borrow this exact source. The reference is not a mapping, carrier
    /// authentication or retention grant: the caller must already own those.
    pub const fn issuer(&self) -> SerialIssuer<'_> {
        SerialIssuer { word: self }
    }
}

/// An issuance capability borrowed from one retained word. Copying the borrow
/// shares the same atomic source; it never copies a cursor or extends custody.
///
/// ```compile_fail
/// use carrick_sched_core::process::identity_allocator::{SerialIssuer, SerialIssuerWord};
/// fn dangling() -> SerialIssuer<'static> {
///     let word = SerialIssuerWord::new();
///     word.issuer()
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct SerialIssuer<'a> {
    word: &'a SerialIssuerWord,
}

impl SerialIssuer<'_> {
    /// Issue once, burning the value even if later preparation rolls back.
    /// Relaxed ordering proves uniqueness only. The birth record has its own
    /// publication protocol, and the owner publishes initialized source custody.
    pub fn allocate(self) -> Option<NonZeroU64> {
        self.word
            .last_issued
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .ok()
            .and_then(|last| NonZeroU64::new(last + 1))
    }

    /// Exclusive first-host handoff. An active source can never admit another
    /// independently seeded local registry, even if its visible population is empty.
    pub fn adopt_initial(self, issued: NonZeroU64) -> bool {
        self.word
            .last_issued
            .compare_exchange(0, issued.get(), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Observe an already-issued serial, including MAX, without reopening an
    /// exhausted source. This is idempotent admission accounting, NOT a safe
    /// way to merge an independent live issuer: collisions may predate it.
    pub fn advance_past(self, issued: NonZeroU64) {
        self.word
            .last_issued
            .fetch_max(issued.get(), Ordering::Relaxed);
    }
}

const _: () = {
    assert!(core::mem::size_of::<SerialIssuerWord>() == core::mem::size_of::<AtomicU64>());
    assert!(core::mem::align_of::<SerialIssuerWord>() == core::mem::align_of::<AtomicU64>());
};

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
    fn zero_valid_issuer_burns_unpublished_births_and_never_wraps() {
        // This is the representation actually present in a zeroed zone.
        let word: SerialIssuerWord = unsafe { core::mem::zeroed() };
        let first_graph = word.issuer();
        let second_graph = word.issuer();
        assert_eq!(first_graph.allocate(), NonZeroU64::new(1));
        let abandoned = first_graph.allocate().unwrap();
        assert_eq!(second_graph.allocate(), NonZeroU64::new(3));
        second_graph.advance_past(abandoned);
        assert_eq!(first_graph.allocate(), NonZeroU64::new(4));

        first_graph.advance_past(NonZeroU64::new(u64::MAX - 1).unwrap());
        assert_eq!(second_graph.allocate(), Some(NonZeroU64::MAX));
        assert_eq!(first_graph.allocate(), None);
        second_graph.advance_past(NonZeroU64::MIN);
        assert_eq!(second_graph.allocate(), None);
        second_graph.advance_past(NonZeroU64::MAX);
        assert_eq!(first_graph.allocate(), None);
    }

    #[test]
    fn issuer_imports_reserved_births_idempotently_including_terminal_value() {
        let word = SerialIssuerWord::new();
        let issuer = word.issuer();
        let reserved = NonZeroU64::new(103).unwrap();
        issuer.advance_past(reserved);
        issuer.advance_past(reserved);
        assert_eq!(issuer.allocate(), NonZeroU64::new(104));
        issuer.advance_past(NonZeroU64::MIN);
        assert_eq!(issuer.allocate(), NonZeroU64::new(105));

        let terminal = SerialIssuerWord::default();
        terminal.issuer().advance_past(NonZeroU64::MAX);
        assert_eq!(terminal.issuer().allocate(), None);
        assert_eq!(terminal.issuer().allocate(), None);
    }

    #[test]
    fn shared_issuer_reserves_before_publication() {
        use std::sync::mpsc;
        use std::time::Duration;

        // Withhold an allocated ticket while a peer issues another birth.
        // This proves word behavior, not production fork/registration binding.
        let word = SerialIssuerWord::new();
        let (prepared_tx, prepared_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let issuer = word.issuer();
            let prepared = scope.spawn(move || {
                let ticket = issuer.allocate().unwrap();
                prepared_tx.send(ticket).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                ticket
            });
            let unpublished = prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let peer = word.issuer().allocate().unwrap();
            assert_ne!(unpublished, peer);
            release_tx.send(()).unwrap();
            assert_eq!(prepared.join().unwrap(), unpublished);
            assert!(word.issuer().allocate().unwrap() > peer);
        });
    }

    #[test]
    fn shared_issuer_concurrent_borrowers_have_one_complete_population() {
        let word = SerialIssuerWord::new();
        std::thread::scope(|scope| {
            let workers: alloc::vec::Vec<_> = (0..4)
                .map(|_| {
                    let issuer = word.issuer();
                    scope.spawn(move || {
                        (0..256)
                            .map(|_| issuer.allocate().unwrap())
                            .collect::<alloc::vec::Vec<_>>()
                    })
                })
                .collect();
            let mut issued = alloc::collections::BTreeSet::new();
            for worker in workers {
                for serial in worker.join().unwrap() {
                    assert!(issued.insert(serial));
                }
            }
            assert_eq!(issued.len(), 1024);
            assert_eq!(issued.first(), Some(&NonZeroU64::MIN));
            assert_eq!(issued.last(), NonZeroU64::new(1024).as_ref());
            assert_eq!(word.issuer().allocate(), NonZeroU64::new(1025));
        });
    }

    #[test]
    fn late_observation_cannot_repair_independently_issued_tickets() {
        // Negative control: advancing a private cursor after a prepared fork
        // cannot revoke its already-issued identity. No admission scan fixes it.
        let host = SerialAllocator::new();
        host.advance_to(NonZeroU64::new(103).unwrap());
        let reserved_host_birth = host.allocate().unwrap();
        let native = SerialAllocator::new();
        native.advance_to(NonZeroU64::new(103).unwrap());
        let unpublished_fork = native.allocate().unwrap();
        native.advance_past(reserved_host_birth).unwrap();
        assert_eq!(reserved_host_birth, unpublished_fork);
        assert!(native.allocate().unwrap() > reserved_host_birth);
    }

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
    fn unmapped_domain_uses_claims_without_allocating_or_retiring_a_cursor() {
        let mut owner = NamespaceState::new(1, 100, 1);
        let unmapped = VisibleNamespace::unmapped();
        let first = owner.reserve_next(ClaimKind::Task).unwrap();
        let second = owner.reserve_next(ClaimKind::Thread).unwrap();
        for number in [first, second] {
            let mut view = owner.allocation().unwrap().view();
            let visible = view.assign_visible(number, unmapped).unwrap();
            assert_eq!(visible.get(), number.get() as u32);
            assert_eq!(view.visible_domain(number.get()), Some(unmapped));
        }
        assert_eq!(owner.visible_namespace_count(), 0);
        assert_eq!(owner.reserve_visible(unmapped), None);
        owner.retire_visible_namespace(unmapped);
        assert!(owner.is_reserved_number(first.get()));
        assert!(owner.is_reserved_number(second.get()));
        assert_eq!(owner.counts().reserved_numbers, 2);
        let mapped = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        assert_eq!(owner.reserve_visible(mapped).unwrap().get(), 2);
        assert_eq!(owner.visible_namespace_count(), 1);
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
        assert_eq!(owner.visible_namespace_count(), 1);
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
            .advance_visible_past(
                namespace,
                VisibleIdentity::from_existing_member(
                    NonZeroU32::new(i32::MAX as u32 - 2).unwrap(),
                ),
            )
            .unwrap();
        assert_eq!(
            owner.reserve_visible(namespace).unwrap().get(),
            i32::MAX as u32 - 1
        );
        assert_eq!(owner.reserve_visible(namespace), None);
        owner.retire_visible_namespace(namespace);
        assert_eq!(owner.visible_namespace_count(), 1);
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

/// Separate carrier-wide MM identity domain, never a task/thread birth cursor.
///
/// ```compile_fail
/// use carrick_sched_core::process::identity_allocator::MmIssuerWord;
/// let word = MmIssuerWord::new();
/// let birth: core::num::NonZeroU64 = word.issuer().allocate().unwrap();
/// ```
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct MmIssuerWord(SerialIssuerWord);
impl MmIssuerWord {
    pub const fn new() -> Self {
        Self(SerialIssuerWord::new())
    }
    pub const fn issuer(&self) -> MmIssuer<'_> {
        MmIssuer(self.0.issuer())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct MmIssuer<'a>(SerialIssuer<'a>);
impl MmIssuer<'_> {
    pub fn allocate(self) -> Option<carrick_guest_arch::MmGeneration> {
        self.0.allocate().map(carrick_guest_arch::MmGeneration::new)
    }
    pub fn adopt_initial(self, issued: carrick_guest_arch::MmGeneration) -> bool {
        self.0.adopt_initial(issued.raw())
    }
    /// Fixture/import accounting only; active producers must share this source
    /// before issuance. Never a merge protocol for escaped independent tickets.
    #[cfg(any(test, feature = "host-test"))]
    pub fn observe_existing(self, issued: carrick_guest_arch::MmGeneration) {
        self.0.advance_past(issued.raw());
    }
}

#[cfg(test)]
mod mm_issuer_tests {
    use super::MmIssuerWord;
    use carrick_guest_arch::MmGeneration;
    use core::num::NonZeroU64;
    #[test]
    fn mm_word_is_distinct_zero_valid_and_terminal_without_reopening() {
        let mm = MmIssuerWord::new();
        assert_eq!(mm.issuer().allocate().unwrap().raw(), NonZeroU64::MIN);
        assert!(
            !mm.issuer()
                .adopt_initial(MmGeneration::new(NonZeroU64::MIN))
        );
        mm.issuer()
            .observe_existing(MmGeneration::new(NonZeroU64::new(u64::MAX - 1).unwrap()));
        assert_eq!(mm.issuer().allocate().unwrap().raw(), NonZeroU64::MAX);
        assert!(mm.issuer().allocate().is_none());
        mm.issuer()
            .observe_existing(MmGeneration::new(NonZeroU64::MIN));
        assert!(mm.issuer().allocate().is_none());
    }
}
