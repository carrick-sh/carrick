//! Shared anonymous Linux reservation authority. Both venues borrow the same
//! records; persisted links are node indices, never pointers or Rust containers.
//! Proposals reserve metadata but do not change the committed tree. T2 owns
//! descriptor/backing work; only an exact completion commits the proposal.

use carrick_el1_abi::*;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[path = "reservations/storage.rs"]
mod storage;
pub use storage::ResolvedReservationNodes;

const ROOTS: usize = carrick_sched_core::spaces::ADDRESS_SPACES;
const NODES: usize = 1024;
/// Bootstrap metadata only. Exhaustion is a capacity request, never Linux
/// ENOMEM. Existing reservations can still be observed and retired.
pub const RESERVATIONS_OFFSET: usize = EL1_RESERVATIONS_OFFSET as usize;
const VERSION: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Busy,
    Stale,
    Invalid,
    Collision,
    Hole,
    ForeignMapping,
    Limit,
    MetadataRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    /// Non-anonymous mappings participate in placement but cannot be edited.
    pub anonymous: bool,
    /// Insertion-time attributes; anything but plain private anonymous is
    /// host-owned and every EL1 edit touching it forwards.
    pub flags: ReservationNodeFlags,
    pub generation: ReservationGeneration,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Layout {
    pub heap: ReservationRange,
    pub arena: ReservationRange,
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    /// Charges outside this admitted anonymous arena/heap.
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Anywhere,
    Hint(u64),
    Fixed(u64),
    NoReplace(u64),
}

/// `mremap(2)` destination policy for [`Reservations::mremap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveTarget {
    /// No `MREMAP_MAYMOVE`: resize in place or fail with ENOMEM.
    InPlace,
    /// `MREMAP_MAYMOVE`: resize in place when the following range is free,
    /// otherwise relocate to a first-fit arena range.
    MayMove,
    /// `MREMAP_MAYMOVE | MREMAP_FIXED`: relocate to exactly this address,
    /// replacing root-editable anonymous nodes there.
    Fixed(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Complete(u64),
    Work(ReservationRequest),
}

/// Replacement for a host FirstTouchArming-derived frame-grant plan. The host
/// service must revalidate this exact generation before publishing its receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationFaultPlan {
    pub mm: ReservationMm,
    pub generation: ReservationGeneration,
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub fault_page: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Pending {
    request: ReservationRequest,
    result: u64,
    new_brk: u64,
    /// Spare nodes: split at each edited range boundary (two for `range`,
    /// two more for a `Move` source) plus the new node.
    nodes: [u32; 5],
}

#[repr(C)]
struct State {
    version: u64,
    generation: u64,
    sequence: u64,
    tree: u32,
    layout: Layout,
    pending: Option<Pending>,
    admitted: bool,
}

#[repr(C)]
struct Root {
    key: AtomicU64,
    locked: AtomicU64,
    epoch: AtomicU64,
    state: UnsafeCell<MaybeUninit<State>>,
}
// Access to state requires the root's nonblocking exclusive guard.
unsafe impl Sync for Root {}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct NodeData {
    start: u64,
    end: u64,
    prot: u64,
    first: u64,
    last: u64,
    gap: u64,
    bytes: u64,
    data: u64,
    left: u32,
    right: u32,
    height: u32,
    flags: u32,
}
impl NodeData {
    fn flags(&self) -> ReservationNodeFlags {
        // Nodes are only written from validated flags.
        ReservationNodeFlags::from_bits(self.flags).unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(&self) -> ReservationProtection {
        ReservationProtection::from_bits(self.prot).unwrap_or(ReservationProtection::NONE)
    }
    fn charged_data(&self) -> u64 {
        if self.flags().charges_data(self.protection()) {
            self.end - self.start
        } else {
            0
        }
    }
}

#[derive(Default)]
struct CopyList {
    head: u32,
    tail: u32,
    len: usize,
}

/// Pre-allocated nodes for one committed edit. Every split consumes at most
/// one; the caller proves sufficiency before the first mutation.
struct Spares([u32; 5]);
impl Spares {
    fn available(&self) -> usize {
        self.0.iter().filter(|id| **id != 0).count()
    }
    fn take(&mut self) -> u32 {
        let slot = self.0.iter_mut().find(|id| **id != 0);
        core::mem::take(slot.expect("spare sufficiency proven before mutation"))
    }
}
#[repr(C)]
struct Node {
    next_free: AtomicU32,
    data: UnsafeCell<NodeData>,
}
// A live node belongs to exactly one locked root. Free nodes are handed over
// using the generation-qualified free list's release/acquire operations.
unsafe impl Sync for Node {}

#[repr(C)]
pub struct SharedReservations {
    layout_hash: AtomicU64,
    roots: [Root; ROOTS],
    allocated: AtomicU32,
    free: AtomicU64,
    nodes: [Node; NODES],
    storage: storage::Storage,
}

const LAYOUT_HASH: u64 = {
    let words = [
        VERSION,
        core::mem::size_of::<SharedReservations>() as u64,
        core::mem::size_of::<Root>() as u64,
        core::mem::size_of::<State>() as u64,
        core::mem::size_of::<Node>() as u64,
        core::mem::size_of::<Pending>() as u64,
        core::mem::offset_of!(SharedReservations, roots) as u64,
        core::mem::offset_of!(SharedReservations, nodes) as u64,
        core::mem::offset_of!(SharedReservations, storage) as u64,
        core::mem::offset_of!(Root, state) as u64,
        core::mem::offset_of!(State, pending) as u64,
        core::mem::offset_of!(State, layout) as u64,
        core::mem::offset_of!(Node, data) as u64,
    ];
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut i = 0;
    while i < words.len() {
        hash = (hash ^ words[i]).wrapping_mul(0x100_0000_01b3);
        i += 1;
    }
    hash
};

const _: () = assert!(core::mem::size_of::<Counters>() <= 0x20000);
const _: () = assert!(
    RESERVATIONS_OFFSET + core::mem::size_of::<SharedReservations>()
        <= EL1_RESERVATIONS_END as usize
);

/// Holds one MM's metadata authority. Drop releases it; never carry this guard
/// across host service, a context switch or descriptor/backing allocation.
pub struct Reservations<'a> {
    table: &'a SharedReservations,
    root: &'a Root,
    mm: ReservationMm,
    pub work: usize,
    banks: Option<&'a dyn storage::NodeBanks>,
    node_capacity: u32,
}
impl Drop for Reservations<'_> {
    fn drop(&mut self) {
        self.root.locked.store(0, Ordering::Release);
    }
}

impl SharedReservations {
    /// Install in the slot of the matching closed AddressSpaces entry. The
    /// region must initially be zeroed. A published MM key is never reused.
    pub fn publish(&self, index: usize, mm: ReservationMm, layout: Layout) -> Result<(), Refusal> {
        match self
            .layout_hash
            .compare_exchange(0, LAYOUT_HASH, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(found) if found == LAYOUT_HASH => {}
            Err(_) => return Err(Refusal::Stale),
        }
        let root = self.roots.get(index).ok_or(Refusal::Invalid)?;
        root.locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Refusal::Busy)?;
        let result = if root.key.load(Ordering::Acquire) != 0 {
            Err(Refusal::Collision)
        } else if !layout.heap.contains(layout.brk) && layout.brk != layout.heap.end() {
            Err(Refusal::Invalid)
        } else if root.epoch.load(Ordering::Relaxed) == u64::MAX {
            Err(Refusal::Stale)
        } else {
            // SAFETY: exclusive unpublished root; no state reference exists.
            unsafe {
                (*root.state.get()).write(State {
                    version: VERSION,
                    generation: root.epoch.load(Ordering::Relaxed) + 1,
                    sequence: 0,
                    tree: 0,
                    layout,
                    pending: None,
                    admitted: false,
                });
            }
            root.key.store(mm.raw(), Ordering::Release);
            Ok(())
        };
        root.locked.store(0, Ordering::Release);
        result
    }

    pub fn lock(&self, index: usize, mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
        self.lock_using(index, mm, None, cfg!(target_os = "none"))
    }

    fn lock_using<'a>(
        &'a self,
        index: usize,
        mm: ReservationMm,
        banks: Option<&'a dyn storage::NodeBanks>,
        identity: bool,
    ) -> Result<Reservations<'a>, Refusal> {
        if self.layout_hash.load(Ordering::Acquire) != LAYOUT_HASH {
            return Err(Refusal::Stale);
        }
        let root = self.roots.get(index).ok_or(Refusal::Invalid)?;
        root.locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Refusal::Busy)?;
        if root.key.load(Ordering::Acquire) != mm.raw() {
            root.locked.store(0, Ordering::Release);
            return Err(Refusal::Stale);
        }
        let guard = Reservations {
            table: self,
            root,
            mm,
            work: 0,
            banks,
            node_capacity: self.storage.capacity(),
        };
        if (banks.is_none() && !identity && self.storage.capacity() > NODES as u32)
            || banks.is_some_and(|banks| banks.count() < self.storage.bank_count())
        {
            return Err(Refusal::MetadataRequired);
        }
        if guard.state().version != VERSION {
            return Err(Refusal::Stale);
        }
        Ok(guard)
    }

    fn allocate(
        &self,
        banks: Option<&dyn storage::NodeBanks>,
        capacity: u32,
    ) -> Result<u32, Refusal> {
        // One bounded attempt: contention/capacity must unwind to admission,
        // not spin on another MM while retaining this MM's authority.

        let head = self.free.load(Ordering::Acquire);
        let index = head as u32;
        if index > capacity {
            return Err(Refusal::MetadataRequired);
        }
        if index != 0 {
            let next = self.node(index, banks).next_free.load(Ordering::Relaxed);
            let generation = (head >> 32)
                .checked_add(1)
                .filter(|v| *v <= u32::MAX as u64)
                .ok_or(Refusal::MetadataRequired)?;
            let tag = generation << 32;
            self.free
                .compare_exchange(head, tag | next as u64, Ordering::AcqRel, Ordering::Relaxed)
                .map_err(|_| Refusal::Busy)?;
            return Ok(index);
        }
        self.allocated
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                (n < capacity).then_some(n + 1)
            })
            .map(|n| n + 1)
            .map_err(|_| Refusal::MetadataRequired)
    }

    fn release(&self, index: u32, banks: Option<&dyn storage::NodeBanks>) {
        if index == 0 {
            return;
        }
        let node = self.node(index, banks);
        // Return uses a lock-free stack. Failed CAS reflects another completed
        // return, not polling for a guest/host event while holding a worker.
        let mut head = self.free.load(Ordering::Acquire);
        loop {
            node.next_free.store(head as u32, Ordering::Relaxed);
            let generation = ((head >> 32) + 1).min(u32::MAX as u64);
            let next = (generation << 32) | index as u64;
            match self
                .free
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => head = actual,
            }
        }
    }
}

/// The host and guest translate this same offset, never persist either venue's
/// pointer. The carrier owns the zeroed region throughout every borrowed view.
pub fn shared_host() -> Option<&'static SharedReservations> {
    let base = get_el1_region_host_ptr();
    if base == 0 {
        return None;
    }
    Some(unsafe { &*((base + RESERVATIONS_OFFSET) as *const SharedReservations) })
}

#[cfg(target_os = "none")]
pub fn shared_guest() -> &'static SharedReservations {
    unsafe { &*((EL1_REGION_BASE as usize + RESERVATIONS_OFFSET) as *const SharedReservations) }
}

impl Reservations<'_> {
    fn state(&self) -> &State {
        unsafe { (&*self.root.state.get()).assume_init_ref() }
    }
    fn state_mut(&mut self) -> &mut State {
        unsafe { (&mut *self.root.state.get()).assume_init_mut() }
    }
    pub fn mm(&self) -> ReservationMm {
        self.mm
    }
    pub fn generation(&self) -> ReservationGeneration {
        ReservationGeneration::new(self.state().generation).expect("published generation")
    }
    pub fn brk_current(&self) -> u64 {
        self.state().layout.brk
    }
    pub fn pending(&self) -> Option<ReservationRequest> {
        self.state().pending.map(|p| p.request)
    }
    fn read(&mut self, id: u32) -> NodeData {
        self.work += 1;
        if id == 0 {
            return NodeData::default();
        }
        // SAFETY: indices are private to the admitted tree and root guard.
        unsafe { *self.table.node(id, self.banks).data.get() }
    }
    fn write(&mut self, id: u32, node: NodeData) {
        self.work += 1;
        unsafe {
            *self.table.node(id, self.banks).data.get() = node;
        }
    }
    pub fn mapping(&mut self, address: u64) -> Option<Mapping> {
        if !self.is_admitted() {
            return None;
        }
        let mut id = self.state().tree;
        while id != 0 {
            let n = self.read(id);
            if address < n.start {
                id = n.left;
            } else if address >= n.end {
                id = n.right;
            } else {
                return Some(Mapping {
                    range: ReservationRange::new(n.start, n.end)?,
                    protection: ReservationProtection::from_bits(n.prot)?,
                    anonymous: n.flags().contains(ReservationNodeFlags::ANONYMOUS),
                    flags: n.flags(),
                    generation: self.generation(),
                });
            }
        }
        None
    }
    /// Observe one committed generation in address order, with one node read
    /// per mapping. The root guard excludes publication for the whole walk;
    /// a pending proposal is not part of this committed observation.
    pub fn observe_mappings(&mut self, visit: &mut dyn FnMut(Mapping)) -> Result<(), Refusal> {
        if !self.is_admitted() {
            return Err(Refusal::Stale);
        }
        self.observe_tree(self.state().tree, visit);
        Ok(())
    }

    fn observe_tree(&mut self, id: u32, visit: &mut dyn FnMut(Mapping)) {
        if id == 0 {
            return;
        }
        let node = self.read(id);
        self.observe_tree(node.left, visit);
        // Nodes are only constructed from validated ABI ranges/protections.
        visit(Mapping {
            range: ReservationRange::new(node.start, node.end).expect("reservation range"),
            protection: ReservationProtection::from_bits(node.prot)
                .expect("reservation protection"),
            anonymous: node.flags().contains(ReservationNodeFlags::ANONYMOUS),
            flags: node.flags(),
            generation: self.generation(),
        });
        self.observe_tree(node.right, visit);
    }

    pub fn fault_plan(
        &mut self,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<ReservationFaultPlan, Refusal> {
        if !self.is_admitted() {
            return Err(Refusal::Stale);
        }
        if max_len == 0 || !max_len.is_multiple_of(4096) || access.bits() == 0 {
            return Err(Refusal::Invalid);
        }
        let page = address & !4095;
        if self.pending().is_some_and(|p| p.range.contains(page)) {
            return Err(Refusal::Busy);
        }
        let mapping = self.mapping(page).ok_or(Refusal::Hole)?;
        if !mapping.anonymous {
            return Err(Refusal::ForeignMapping);
        }
        if !mapping.protection.permits(access) {
            return Err(Refusal::Limit);
        }
        let window = page - page % max_len;
        let end = window
            .checked_add(max_len)
            .ok_or(Refusal::Invalid)?
            .min(mapping.range.end());
        let range = ReservationRange::new(window.max(mapping.range.start()), end)
            .ok_or(Refusal::Invalid)?;
        Ok(ReservationFaultPlan {
            mm: self.mm,
            generation: mapping.generation,
            range,
            protection: mapping.protection,
            fault_page: page,
        })
    }
    pub fn authenticate_fault(&mut self, plan: ReservationFaultPlan) -> bool {
        plan.mm == self.mm
            && plan.generation == self.generation()
            && self.pending().is_none_or(|p| {
                p.range.end() <= plan.range.start() || p.range.start() >= plan.range.end()
            })
            && self.mapping(plan.fault_page).is_some_and(|m| {
                m.anonymous
                    && m.protection == plan.protection
                    && m.range.start() <= plan.range.start()
                    && m.range.end() >= plan.range.end()
            })
    }

    fn fix(&mut self, id: u32) -> u32 {
        let mut n = self.read(id);
        let l = self.read(n.left);
        let r = self.read(n.right);
        n.height = 1 + l.height.max(r.height);
        n.first = if n.left == 0 { n.start } else { l.first };
        n.last = if n.right == 0 { n.end } else { r.last };
        n.gap = l
            .gap
            .max(r.gap)
            .max(if n.left == 0 { 0 } else { n.start - l.last })
            .max(if n.right == 0 { 0 } else { r.first - n.end });
        n.bytes = l.bytes + r.bytes + n.end - n.start;
        n.data = l.data + r.data + n.charged_data();
        self.write(id, n);
        id
    }
    fn rotate_left(&mut self, id: u32) -> u32 {
        let mut n = self.read(id);
        let top = n.right;
        let mut r = self.read(top);
        n.right = r.left;
        r.left = id;
        self.write(id, n);
        self.write(top, r);
        self.fix(id);
        self.fix(top)
    }
    fn rotate_right(&mut self, id: u32) -> u32 {
        let mut n = self.read(id);
        let top = n.left;
        let mut l = self.read(top);
        n.left = l.right;
        l.right = id;
        self.write(id, n);
        self.write(top, l);
        self.fix(id);
        self.fix(top)
    }
    fn balance(&mut self, id: u32) -> u32 {
        if id == 0 {
            return 0;
        }
        self.fix(id);
        let mut n = self.read(id);
        let l = self.read(n.left);
        let r = self.read(n.right);
        if l.height > r.height + 1 {
            if self.read(l.left).height < self.read(l.right).height {
                n.left = self.rotate_left(n.left);
                self.write(id, n);
            }
            return self.rotate_right(id);
        }
        if r.height > l.height + 1 {
            if self.read(r.right).height < self.read(r.left).height {
                n.right = self.rotate_right(n.right);
                self.write(id, n);
            }
            return self.rotate_left(id);
        }
        id
    }
    fn insert(&mut self, root: u32, id: u32) -> u32 {
        if root == 0 {
            return self.fix(id);
        }
        let mut n = self.read(root);
        if self.read(id).start < n.start {
            n.left = self.insert(n.left, id);
        } else {
            n.right = self.insert(n.right, id);
        }
        self.write(root, n);
        self.balance(root)
    }
    fn erase(&mut self, root: u32, start: u64) -> (u32, u32) {
        let mut n = self.read(root);
        let freed;
        if start < n.start {
            (n.left, freed) = self.erase(n.left, start);
        } else if start > n.start {
            (n.right, freed) = self.erase(n.right, start);
        } else {
            if n.left == 0 {
                return (n.right, root);
            }
            if n.right == 0 {
                return (n.left, root);
            }
            let mut successor = self.read(n.right);
            while successor.left != 0 {
                successor = self.read(successor.left);
            }
            n.start = successor.start;
            n.end = successor.end;
            n.prot = successor.prot;
            n.flags = successor.flags;
            (n.right, freed) = self.erase(n.right, successor.start);
        }
        self.write(root, n);
        (self.balance(root), freed)
    }
    fn next(&mut self, address: u64) -> Option<NodeData> {
        let mut id = self.state().tree;
        let mut found = None;
        while id != 0 {
            let n = self.read(id);
            if n.end <= address {
                id = n.right;
            } else {
                found = Some(n);
                id = n.left;
            }
        }
        found
    }
    fn gap(&mut self, id: u32, cursor: &mut u64, len: u64, end: u64) -> Option<u64> {
        if id == 0 {
            return None;
        }
        let n = self.read(id);
        if n.last <= *cursor {
            return None;
        }
        if *cursor <= n.first {
            if n.first.min(end).saturating_sub(*cursor) >= len {
                return Some(*cursor);
            }
            if n.gap < len {
                *cursor = n.last;
                return None;
            }
        }
        if let Some(found) = self.gap(n.left, cursor, len, end) {
            return Some(found);
        }
        if n.start.min(end).saturating_sub(*cursor) >= len {
            return Some(*cursor);
        }
        *cursor = (*cursor).max(n.end);
        self.gap(n.right, cursor, len, end)
    }
    fn first_fit(&mut self, len: u64) -> Option<u64> {
        let arena = self.state().layout.arena;
        let mut cursor = arena.start();
        let root = self.state().tree;
        self.gap(root, &mut cursor, len, arena.end())
            .or_else(|| (arena.end().saturating_sub(cursor) >= len).then_some(cursor))
    }
    fn in_layout(&self, range: ReservationRange) -> bool {
        let layout = self.state().layout;
        [layout.heap, layout.arena]
            .iter()
            .any(|r| r.start() <= range.start() && range.end() <= r.end())
    }
    /// Whether one node straddles `address` (so an edit boundary there splits it).
    fn straddles(&mut self, address: u64) -> bool {
        self.next(address).is_some_and(|n| n.start < address)
    }
    fn splits_needed(&mut self, range: ReservationRange) -> usize {
        usize::from(self.straddles(range.start())) + usize::from(self.straddles(range.end()))
    }
    #[allow(clippy::too_many_arguments)]
    fn proposal(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        operation: ReservationOperation,
        result: u64,
        new_brk: u64,
        require_coverage: bool,
        source: Option<ReservationRange>,
    ) -> Result<Decision, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        if !self.in_layout(range) {
            return Err(Refusal::ForeignMapping);
        }
        let mut cursor = range.start();
        let mut bytes = 0;
        let mut data = 0;
        while let Some(n) = self.next(cursor) {
            if n.start >= range.end() {
                break;
            }
            // Opaque and attributed nodes are host-owned: forward the edit.
            if !n.flags().root_editable() {
                return Err(Refusal::ForeignMapping);
            }
            if require_coverage && n.start > cursor {
                return Err(Refusal::Hole);
            }
            let overlap = n.end.min(range.end()) - n.start.max(cursor);
            bytes += overlap;
            if n.flags().charges_data(n.protection()) {
                data += overlap;
            }
            cursor = n.end.min(range.end());
            if cursor == range.end() {
                break;
            }
        }
        if require_coverage && cursor != range.end() {
            return Err(Refusal::Hole);
        }
        // A move retires its whole source (one root-editable node, checked
        // by the caller) in the same proposal.
        if let Some(source) = source {
            bytes += source.len();
            if ReservationNodeFlags::ANONYMOUS_PRIVATE.charges_data(prot) {
                data += source.len();
            }
        }
        let added = if operation == ReservationOperation::Retire {
            0
        } else {
            range.len()
        };
        let added_data = if ReservationNodeFlags::ANONYMOUS_PRIVATE.charges_data(prot) {
            added
        } else {
            0
        };
        let tree = self.read(self.state().tree);
        let layout = self.state().layout;
        let total = tree.bytes - bytes;
        let total_data = tree.data - data;
        if total
            .checked_add(added)
            .and_then(|n| n.checked_add(layout.external_address_bytes))
            .is_none_or(|n| n > layout.address_limit)
            || total_data
                .checked_add(added_data)
                .and_then(|n| n.checked_add(layout.external_data_bytes))
                .is_none_or(|n| n > layout.data_limit)
        {
            // Retire/shrink must be possible even after a limit was lowered.
            if added > bytes || added_data > data {
                return Err(Refusal::Limit);
            }
        }
        let sequence = self.state().sequence.checked_add(1).ok_or(Refusal::Stale)?;
        self.state()
            .generation
            .checked_add(1)
            .ok_or(Refusal::Stale)?;
        let needed = if source.is_some() {
            // Four boundaries plus the destination node; a shared straddler
            // between source and destination may need a split at each.
            5
        } else {
            self.splits_needed(range) + usize::from(operation != ReservationOperation::Retire)
        };
        let nodes = self.allocate_spares(needed)?;
        let request = ReservationRequest {
            mm: self.mm,
            generation: self.generation(),
            sequence: ReservationSequence::new(sequence).ok_or(Refusal::Stale)?,
            range,
            protection: prot,
            operation,
            source,
        };
        self.state_mut().sequence = sequence;
        self.state_mut().pending = Some(Pending {
            request,
            result,
            new_brk,
            nodes,
        });
        Ok(Decision::Work(request))
    }
    /// One bounded allocation attempt per spare; failure returns every node.
    fn allocate_spares(&mut self, needed: usize) -> Result<[u32; 5], Refusal> {
        let mut nodes = [0; 5];
        for slot in nodes.iter_mut().take(needed) {
            match self.table.allocate(self.banks, self.node_capacity) {
                Ok(node) => *slot = node,
                Err(reason) => {
                    self.release_spares(nodes);
                    return Err(reason);
                }
            }
        }
        Ok(nodes)
    }
    fn release_spares(&mut self, nodes: [u32; 5]) {
        for node in nodes {
            self.table.release(node, self.banks);
        }
    }
    /// Where [`Self::mmap`] places `len` bytes, without proposing anything.
    /// The host venue places the mappings it serves itself (file, shared,
    /// attributed) here and commits them as opaque nodes, so both venues
    /// share one placement answer. `Collision` is `MAP_FIXED_NOREPLACE`'s
    /// EEXIST; `ForeignMapping` is a hint outside the layout (the host serves
    /// it); `Limit` is no fitting arena gap.
    pub fn place(&mut self, placement: Placement, len: u64) -> Result<ReservationRange, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if len == 0
            || matches!(placement, Placement::Fixed(addr) | Placement::NoReplace(addr) if !addr.is_multiple_of(4096))
        {
            return Err(Refusal::Invalid);
        }
        let len = len
            .checked_add(4095)
            .map(|v| v & !4095)
            .ok_or(Refusal::Limit)?;
        let address = match placement {
            Placement::Fixed(addr) | Placement::NoReplace(addr) => addr,
            Placement::Anywhere => self.first_fit(len).ok_or(Refusal::Limit)?,
            Placement::Hint(addr) => {
                let addr = addr & !4095;
                match addr
                    .checked_add(len)
                    .and_then(|end| ReservationRange::new(addr, end))
                {
                    Some(r) if self.in_layout(r) => {
                        if self.next(addr).is_none_or(|n| n.start >= r.end()) {
                            addr
                        } else {
                            self.first_fit(len).ok_or(Refusal::Limit)?
                        }
                    }
                    // Linux honours a free hint anywhere; the host serves
                    // out-of-arena hints (Go's 0xc000000000 probe) with alias
                    // VAs. Relocating here would give a second answer.
                    _ => return Err(Refusal::ForeignMapping),
                }
            }
        };
        let end = address.checked_add(len).ok_or(Refusal::Limit)?;
        let range = ReservationRange::new(address, end).ok_or(Refusal::Invalid)?;
        if matches!(placement, Placement::NoReplace(_))
            && self.next(address).is_some_and(|n| n.start < range.end())
        {
            return Err(Refusal::Collision);
        }
        Ok(range)
    }
    /// Visit the committed mappings overlapping `range` in address order:
    /// one bounded descent per mapping, independent of the population
    /// outside `range`.
    pub fn observe_range(
        &mut self,
        range: ReservationRange,
        visit: &mut dyn FnMut(Mapping),
    ) -> Result<(), Refusal> {
        if !self.is_admitted() {
            return Err(Refusal::Stale);
        }
        let generation = self.generation();
        let mut cursor = range.start();
        while let Some(n) = self.next(cursor) {
            if n.start >= range.end() {
                break;
            }
            // Nodes are only constructed from validated ABI ranges/protections.
            visit(Mapping {
                range: ReservationRange::new(n.start, n.end).ok_or(Refusal::Invalid)?,
                protection: n.protection(),
                anonymous: n.flags().contains(ReservationNodeFlags::ANONYMOUS),
                flags: n.flags(),
                generation,
            });
            cursor = n.end;
        }
        Ok(())
    }
    pub fn mmap(
        &mut self,
        placement: Placement,
        len: u64,
        prot: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        let range = self.place(placement, len)?;
        let address = range.start();
        self.proposal(
            range,
            prot,
            ReservationOperation::Prepare,
            address,
            self.brk_current(),
            false,
            None,
        )
    }
    pub fn munmap(&mut self, range: ReservationRange) -> Result<Decision, Refusal> {
        self.proposal(
            range,
            ReservationProtection::NONE,
            ReservationOperation::Retire,
            0,
            self.brk_current(),
            false,
            None,
        )
    }
    pub fn mprotect(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        self.proposal(
            range,
            prot,
            ReservationOperation::Protect,
            0,
            self.brk_current(),
            true,
            None,
        )
    }
    /// `mremap(2)` of an anonymous range as one proposal. `source` must lie in
    /// one root-editable node (`Hole` otherwise: the decoder's EFAULT);
    /// host-owned sources and out-of-layout growth are `ForeignMapping`.
    /// Shrink retires the tail, in-place growth prepares the extension, and a
    /// relocation is one `Move` whose completion retires the source and
    /// prepares the destination atomically.
    pub fn mremap(
        &mut self,
        source: ReservationRange,
        new_len: u64,
        target: MoveTarget,
    ) -> Result<Decision, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        if new_len == 0 || matches!(target, MoveTarget::Fixed(addr) if !addr.is_multiple_of(4096)) {
            return Err(Refusal::Invalid);
        }
        let new_len = new_len
            .checked_add(4095)
            .map(|v| v & !4095)
            .ok_or(Refusal::Limit)?;
        let node = self
            .next(source.start())
            .filter(|n| n.start <= source.start() && n.end >= source.end())
            .ok_or(Refusal::Hole)?;
        if !node.flags().root_editable() {
            return Err(Refusal::ForeignMapping);
        }
        let prot = node.protection();
        let brk = self.brk_current();
        if let MoveTarget::Fixed(address) = target {
            let range = address
                .checked_add(new_len)
                .and_then(|end| ReservationRange::new(address, end))
                .ok_or(Refusal::Invalid)?;
            if range.start() < source.end() && source.start() < range.end() {
                return Err(Refusal::Invalid);
            }
            return self.proposal(
                range,
                prot,
                ReservationOperation::Move,
                address,
                brk,
                false,
                Some(source),
            );
        }
        if new_len <= source.len() {
            if new_len == source.len() {
                return Ok(Decision::Complete(source.start()));
            }
            let tail = ReservationRange::new(source.start() + new_len, source.end())
                .ok_or(Refusal::Invalid)?;
            return self.proposal(
                tail,
                ReservationProtection::NONE,
                ReservationOperation::Retire,
                source.start(),
                brk,
                false,
                None,
            );
        }
        let extension = source
            .start()
            .checked_add(new_len)
            .and_then(|end| ReservationRange::new(source.end(), end));
        let free =
            extension.is_some_and(|r| self.next(r.start()).is_none_or(|n| n.start >= r.end()));
        if let Some(extension) = extension.filter(|_| free) {
            if !self.in_layout(extension) {
                return Err(Refusal::ForeignMapping);
            }
            return self.proposal(
                extension,
                prot,
                ReservationOperation::Prepare,
                source.start(),
                brk,
                false,
                None,
            );
        }
        if target == MoveTarget::InPlace {
            return Err(Refusal::Limit);
        }
        let address = self.first_fit(new_len).ok_or(Refusal::Limit)?;
        let range = ReservationRange::new(address, address + new_len).ok_or(Refusal::Invalid)?;
        self.proposal(
            range,
            prot,
            ReservationOperation::Move,
            address,
            brk,
            false,
            Some(source),
        )
    }
    pub fn brk(&mut self, requested: u64) -> Result<Decision, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        let old = self.brk_current();
        let heap = self.state().layout.heap;
        if requested == 0 || requested < heap.start() || requested > heap.end() {
            return Ok(Decision::Complete(old));
        }
        let old_end = old.checked_add(4095).ok_or(Refusal::Invalid)? & !4095;
        let new_end = requested.checked_add(4095).ok_or(Refusal::Invalid)? & !4095;
        if old_end == new_end {
            if old != requested {
                let generation = self
                    .state()
                    .generation
                    .checked_add(1)
                    .ok_or(Refusal::Stale)?;
                self.state_mut().layout.brk = requested;
                self.state_mut().generation = generation;
            }
            return Ok(Decision::Complete(requested));
        }
        if new_end > old_end && self.next(old_end).is_some_and(|n| n.start < new_end) {
            return Ok(Decision::Complete(old));
        }
        let range = ReservationRange::new(old_end.min(new_end), old_end.max(new_end))
            .ok_or(Refusal::Invalid)?;
        let (prot, op) = if new_end > old_end {
            (
                ReservationProtection::READ_WRITE,
                ReservationOperation::Prepare,
            )
        } else {
            (ReservationProtection::NONE, ReservationOperation::Retire)
        };
        match self.proposal(range, prot, op, requested, requested, false, None) {
            Err(Refusal::Limit | Refusal::ForeignMapping) => Ok(Decision::Complete(old)),
            result => result,
        }
    }
    /// Split the node straddling `address`, both halves keeping its attributes.
    fn split_at(&mut self, address: u64, spares: &mut Spares) {
        let Some(n) = self.next(address).filter(|n| n.start < address) else {
            return;
        };
        let (tree, freed) = self.erase(self.state().tree, n.start);
        self.state_mut().tree = tree;
        let mut low = n;
        low.end = address;
        low.left = 0;
        low.right = 0;
        let mut high = low;
        high.start = address;
        high.end = n.end;
        self.write(freed, low);
        let tree = self.insert(self.state().tree, freed);
        self.state_mut().tree = tree;
        let id = spares.take();
        self.write(id, high);
        let tree = self.insert(self.state().tree, id);
        self.state_mut().tree = tree;
    }
    /// Remove every node inside `range`, keeping straddlers' outside pieces.
    fn remove_range(&mut self, range: ReservationRange, spares: &mut Spares) {
        self.split_at(range.start(), spares);
        self.split_at(range.end(), spares);
        while let Some(n) = self.next(range.start()) {
            if n.start >= range.end() {
                break;
            }
            let (tree, freed) = self.erase(self.state().tree, n.start);
            self.state_mut().tree = tree;
            self.table.release(freed, self.banks);
        }
    }
    pub fn complete(&mut self, completion: ReservationCompletion) -> Result<u64, Refusal> {
        let pending = self.state().pending.ok_or(Refusal::Stale)?;
        if !completion.authenticates(pending.request)
            || pending.request.mm != self.mm
            || pending.request.generation != self.generation()
        {
            return Err(Refusal::Stale);
        }
        let range = pending.request.range;
        let creates = pending.request.operation != ReservationOperation::Retire;
        let mut spares = Spares(pending.nodes);
        // The pending proposal excluded every other edit, so these are the
        // splits counted at proposal time; prove it before mutating.
        let required = pending.request.source.map_or(0, |s| self.splits_needed(s))
            + self.splits_needed(range)
            + usize::from(creates);
        if spares.available() < required {
            return Err(Refusal::Stale);
        }
        if let Some(source) = pending.request.source {
            self.remove_range(source, &mut spares);
        }
        self.remove_range(range, &mut spares);
        if creates {
            let id = spares.take();
            self.write(
                id,
                NodeData {
                    start: range.start(),
                    end: range.end(),
                    prot: pending.request.protection.bits(),
                    flags: ReservationNodeFlags::ANONYMOUS_PRIVATE.bits(),
                    ..NodeData::default()
                },
            );
            self.insert_coalescing(id);
        }
        self.release_spares(spares.0);
        self.state_mut().layout.brk = pending.new_brk;
        self.state_mut().generation += 1;
        self.state_mut().pending = None;
        Ok(pending.result)
    }
    pub fn refuse(&mut self, request: ReservationRequest) -> Result<(), Refusal> {
        let pending = self.state().pending.ok_or(Refusal::Stale)?;
        if pending.request != request {
            return Err(Refusal::Stale);
        }
        self.release_spares(pending.nodes);
        self.state_mut().pending = None;
        Ok(())
    }
    /// Push the host's current `RLIMIT_AS`/`RLIMIT_DATA` (bytes; `u64::MAX`
    /// for infinity). Later proposals that grow past them refuse with
    /// `Limit` (ENOMEM; brk keeps the old break); shrinking stays possible.
    /// Existing mappings and fault grants are unaffected, so no new generation.
    pub fn set_limits(&mut self, address_limit: u64, data_limit: u64) {
        let layout = &mut self.state_mut().layout;
        layout.address_limit = address_limit;
        layout.data_limit = data_limit;
    }
    /// Push the current charges of mappings this root does not model (the
    /// host-owned VMAs), so `set_limits` compares the whole mm against its
    /// limits. Like `set_limits`, no mapping changes and no new generation.
    pub fn set_external_charges(&mut self, address_bytes: u64, data_bytes: u64) {
        let layout = &mut self.state_mut().layout;
        layout.external_address_bytes = address_bytes;
        layout.external_data_bytes = data_bytes;
    }
    /// Host admission of an existing mapping, before the guest lane is opened.
    /// The caller supplies the complete current snapshot and exact limits.
    /// This is not a second mutable VMA model: guest/host operations thereafter
    /// use proposals on this same root. Opaque entries are placement obstacles.
    pub fn import(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        anonymous: bool,
    ) -> Result<(), Refusal> {
        self.import_with(
            range,
            prot,
            if anonymous {
                ReservationNodeFlags::ANONYMOUS_PRIVATE
            } else {
                ReservationNodeFlags::EMPTY
            },
        )
    }
    /// [`Self::import`] with exact insertion-time attributes.
    pub fn import_with(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
    ) -> Result<(), Refusal> {
        if self.state().admitted {
            return Err(Refusal::Stale);
        }
        self.insert_node(range, prot, flags)
    }
    fn insert_node(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
    ) -> Result<(), Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        if self
            .next(range.start())
            .is_some_and(|n| n.start < range.end())
        {
            return Err(Refusal::Collision);
        }
        let id = self.table.allocate(self.banks, self.node_capacity)?;
        self.write(
            id,
            NodeData {
                start: range.start(),
                end: range.end(),
                prot: prot.bits(),
                flags: flags.bits(),
                ..NodeData::default()
            },
        );
        self.insert_coalescing(id);
        Ok(())
    }
    fn host_edit_admitted(&mut self) -> Result<u64, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        self.state().generation.checked_add(1).ok_or(Refusal::Stale)
    }
    /// Host commit of a mapping it served itself (file, shared, stack, device,
    /// out-of-arena alias): an opaque placement obstacle that EL1 never edits.
    /// `ANONYMOUS` is stripped; `flags` carry `PRIVATE`/attributes for
    /// `RLIMIT_DATA` and fork. The range must be free: the host retires what
    /// its edit replaced first (`retire_opaque`).
    pub fn insert_opaque(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
    ) -> Result<(), Refusal> {
        let generation = self.host_edit_admitted()?;
        self.insert_node(
            range,
            prot,
            flags.difference(ReservationNodeFlags::ANONYMOUS),
        )?;
        self.state_mut().generation = generation;
        Ok(())
    }
    /// Host commit of a retirement it served itself: removes every node in
    /// `range`, whatever its kind, keeping straddlers' outside pieces.
    pub fn retire_opaque(&mut self, range: ReservationRange) -> Result<(), Refusal> {
        let generation = self.host_edit_admitted()?;
        let needed = self.splits_needed(range);
        let mut spares = Spares(self.allocate_spares(needed)?);
        self.remove_range(range, &mut spares);
        self.release_spares(spares.0);
        self.state_mut().generation = generation;
        Ok(())
    }
    /// Host commit of an attribute edit (`mlock`, `MADV_DONTFORK`,
    /// `MADV_WIPEONFORK`, `MADV_DONTDUMP` and their inverses) over a fully
    /// mapped range. Only [`ReservationNodeFlags::ATTRIBUTES`] may change.
    pub fn set_flags(
        &mut self,
        range: ReservationRange,
        set: ReservationNodeFlags,
        clear: ReservationNodeFlags,
    ) -> Result<(), Refusal> {
        let attributes = ReservationNodeFlags::ATTRIBUTES;
        if !attributes.contains(set) || !attributes.contains(clear) || set.intersects(clear) {
            return Err(Refusal::Invalid);
        }
        let generation = self.host_edit_admitted()?;
        let mut cursor = range.start();
        while let Some(n) = self.next(cursor).filter(|n| n.start < range.end()) {
            if n.start > cursor {
                return Err(Refusal::Hole);
            }
            cursor = n.end.min(range.end());
            if cursor == range.end() {
                break;
            }
        }
        if cursor != range.end() {
            return Err(Refusal::Hole);
        }
        let needed = self.splits_needed(range);
        let mut spares = Spares(self.allocate_spares(needed)?);
        self.split_at(range.start(), &mut spares);
        self.split_at(range.end(), &mut spares);
        self.release_spares(spares.0);
        let mut cursor = range.start();
        while cursor < range.end() {
            let Some(n) = self.next(cursor) else {
                break;
            };
            let flags = n.flags().union(set).difference(clear);
            if flags != n.flags() {
                let (tree, freed) = self.erase(self.state().tree, n.start);
                self.state_mut().tree = tree;
                let mut edited = n;
                edited.flags = flags.bits();
                edited.left = 0;
                edited.right = 0;
                self.write(freed, edited);
                self.insert_coalescing(freed);
            }
            cursor = n.end.min(range.end());
        }
        self.state_mut().generation = generation;
        Ok(())
    }
    /// Fork: populate the unadmitted, empty `child` root of the same table
    /// with this committed generation. `DONTFORK` nodes are skipped;
    /// `WIPEONFORK` nodes are copied with their flag so T2 installs no
    /// residency for them. Linear in parent nodes: one in-order read each,
    /// then a balanced build from the copied sequence. The child keeps its own
    /// generation; later edits of either MM never change the other.
    pub fn clone_into(&mut self, child: &mut Reservations<'_>) -> Result<(), Refusal> {
        if !core::ptr::eq(self.table, child.table) || core::ptr::eq(self.root, child.root) {
            return Err(Refusal::Invalid);
        }
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        if child.state().admitted || child.state().tree != 0 || child.pending().is_some() {
            return Err(Refusal::Stale);
        }
        child
            .state()
            .generation
            .checked_add(1)
            .ok_or(Refusal::Stale)?;
        let mut list = CopyList::default();
        if let Err(reason) = self.copy_in_order(self.state().tree, &mut list) {
            let mut id = list.head;
            while id != 0 {
                let next = self.read(id).right;
                self.table.release(id, self.banks);
                id = next;
            }
            return Err(reason);
        }
        let mut cursor = list.head;
        let tree = self.build_balanced(list.len, &mut cursor);
        let layout = self.state().layout;
        let state = child.state_mut();
        state.tree = tree;
        state.layout = layout;
        state.admitted = true;
        state.generation += 1;
        Ok(())
    }
    fn copy_in_order(&mut self, id: u32, list: &mut CopyList) -> Result<(), Refusal> {
        if id == 0 {
            return Ok(());
        }
        let n = self.read(id);
        self.copy_in_order(n.left, list)?;
        if !n.flags().contains(ReservationNodeFlags::DONTFORK) {
            let copy = self.table.allocate(self.banks, self.node_capacity)?;
            let mut data = n;
            data.left = 0;
            data.right = 0;
            self.write(copy, data);
            if list.tail == 0 {
                list.head = copy;
            } else {
                let mut tail = self.read(list.tail);
                tail.right = copy;
                self.write(list.tail, tail);
            }
            list.tail = copy;
            list.len += 1;
        }
        self.copy_in_order(n.right, list)
    }
    /// Consume `len` nodes of a `right`-linked sorted list into a perfectly
    /// balanced subtree (a valid AVL tree), constant work per node.
    fn build_balanced(&mut self, len: usize, cursor: &mut u32) -> u32 {
        if len == 0 {
            return 0;
        }
        let left = self.build_balanced(len / 2, cursor);
        let id = *cursor;
        let mut n = self.read(id);
        *cursor = n.right;
        let right = self.build_balanced(len - len / 2 - 1, cursor);
        n.left = left;
        n.right = right;
        self.write(id, n);
        self.fix(id)
    }
    fn insert_coalescing(&mut self, id: u32) {
        let mut n = self.read(id);
        if let Some(left) = n.start.checked_sub(1).and_then(|va| self.next(va))
            && left.end == n.start
            && left.prot == n.prot
            && left.flags == n.flags
        {
            let (tree, freed) = self.erase(self.state().tree, left.start);
            self.state_mut().tree = tree;
            self.table.release(freed, self.banks);
            n.start = left.start;
        }
        if let Some(right) = self.next(n.end)
            && right.start == n.end
            && right.prot == n.prot
            && right.flags == n.flags
        {
            let (tree, freed) = self.erase(self.state().tree, right.start);
            self.state_mut().tree = tree;
            self.table.release(freed, self.banks);
            n.end = right.end;
        }
        self.write(id, n);
        let tree = self.insert(self.state().tree, id);
        self.state_mut().tree = tree;
    }
    /// Seal the host's complete import before serving any decision. Imports
    /// cannot later overwrite an independently evolving guest authority.
    pub fn finish_import(&mut self) -> Result<(), Refusal> {
        if self.state().admitted {
            return Err(Refusal::Stale);
        }
        self.state_mut().admitted = true;
        Ok(())
    }
    pub fn is_admitted(&self) -> bool {
        self.state().admitted
    }
    pub fn layout(&self) -> Layout {
        self.state().layout
    }
    pub fn configure_import(&mut self, layout: Layout) -> Result<(), Refusal> {
        if self.state().admitted || self.state().tree != 0 {
            return Err(Refusal::Stale);
        }
        self.state_mut().layout = layout;
        Ok(())
    }
    pub fn abort_import(&mut self) -> Result<(), Refusal> {
        if self.state().admitted {
            return Err(Refusal::Stale);
        }
        self.release_tree(self.state().tree);
        self.state_mut().tree = 0;
        Ok(())
    }
    /// Called after final-MM descriptor/backing settlement, never sibling exit.
    pub fn retire(mut self) -> Result<(), Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        self.release_tree(self.state().tree);
        self.state_mut().tree = 0;
        self.root
            .epoch
            .store(self.state().generation, Ordering::Relaxed);
        self.root.key.store(0, Ordering::Release);
        Ok(())
    }
    fn release_tree(&mut self, id: u32) {
        if id == 0 {
            return;
        }
        let n = self.read(id);
        self.release_tree(n.left);
        self.release_tree(n.right);
        self.table.release(id, self.banks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    fn table() -> Box<SharedReservations> {
        // All atomic integers/NodeData are zero-valid; State is MaybeUninit.
        let ptr =
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        unsafe { Box::from_raw(ptr.cast()) }
    }
    fn layout() -> Layout {
        Layout {
            heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
            arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
            brk: 0x1000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        }
    }
    fn complete(guard: &mut Reservations<'_>, decision: Decision) -> u64 {
        let Decision::Work(request) = decision else {
            panic!("expected transaction")
        };
        let receipt = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        guard.complete(receipt).unwrap()
    }
    #[test]
    fn reservation_observer_walk_is_linear_and_generation_exact_for_two_mms() {
        let table = table();
        for index in 0..2 {
            let mm = ReservationMm::new(index as u64 + 91).unwrap();
            table.publish(index, mm, layout()).unwrap();
            let mut model = table.lock(index, mm).unwrap();
            for page in 0..128 {
                let start = 0x100000 + page * 8192;
                model
                    .import(
                        ReservationRange::new(start, start + 4096).unwrap(),
                        if index == 0 {
                            ReservationProtection::READ_WRITE
                        } else {
                            ReservationProtection::NONE
                        },
                        true,
                    )
                    .unwrap();
            }
            let mut visits = 0;
            assert_eq!(
                model.observe_mappings(&mut |_| visits += 1),
                Err(Refusal::Stale)
            );
            assert_eq!(visits, 0);
            model.finish_import().unwrap();
            let generation = model.generation();
            let before = model.work;
            let mut previous_end = 0;
            model
                .observe_mappings(&mut |mapping| {
                    assert!(mapping.range.start() >= previous_end);
                    previous_end = mapping.range.end();
                    assert_eq!(mapping.generation, generation);
                    assert_eq!(
                        mapping.protection,
                        if index == 0 {
                            ReservationProtection::READ_WRITE
                        } else {
                            ReservationProtection::NONE
                        }
                    );
                    visits += 1;
                })
                .unwrap();
            assert_eq!(visits, 128);
            assert_eq!(model.work - before, 128, "one node read per output mapping");
        }
    }

    #[test]
    fn reservation_metadata_required_does_not_become_linux_enomem() {
        let table = table();
        let mm = ReservationMm::new(71).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut model = table.lock(0, mm).unwrap();
        model.finish_import().unwrap();
        for page in 0..NODES {
            let decision = model
                .mmap(
                    Placement::Fixed(0x100000 + page as u64 * 8192),
                    4096,
                    ReservationProtection::READ_WRITE,
                )
                .unwrap();
            complete(&mut model, decision);
        }
        assert_eq!(
            model.mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE),
            Err(Refusal::MetadataRequired)
        );
        assert!(model.pending().is_none());
        let mut backing = vec![0u8; 2 * 1024 * 1024];
        let allocator = crate::alloc::MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        model.provision_metadata(&allocator).unwrap();
        let mut model = table.lock_identity_for_test(0, mm).unwrap();
        let decision = model
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        let request = match decision {
            Decision::Work(request) => request,
            _ => panic!(),
        };
        assert!(model.mapping(request.range.start()).is_none());
        complete(&mut model, decision);
        assert!(model.mapping(request.range.start()).is_some());
    }

    #[test]
    fn reservation_two_mm_shared_observers_and_refusal() {
        let table = table();
        let a = ReservationMm::new(17).unwrap();
        let b = ReservationMm::new(18).unwrap();
        table.publish(17, a, layout()).unwrap();
        table.publish(18, b, layout()).unwrap();
        let mut guest = table.lock(17, a).unwrap();
        guest.finish_import().unwrap();
        let decision = guest
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        let Decision::Work(request) = decision else {
            panic!()
        };
        assert!(guest.mapping(0x100000).is_none());
        guest.refuse(request).unwrap();
        assert!(guest.mapping(0x100000).is_none());
        let decision = guest
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        assert_eq!(complete(&mut guest, decision), 0x100000);
        let generation = guest.mapping(0x100000).unwrap().generation;
        drop(guest);
        let mut host = table.lock(17, a).unwrap();
        assert_eq!(host.mapping(0x100000).unwrap().generation, generation);
        let mut peer = table.lock(18, b).unwrap();
        peer.finish_import().unwrap();
        assert!(peer.mapping(0x100000).is_none());
        let decision = peer
            .mmap(Placement::Anywhere, 4096, ReservationProtection::NONE)
            .unwrap();
        assert_eq!(complete(&mut peer, decision), 0x100000);
        assert_eq!(
            host.mapping(0x100000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert_eq!(
            peer.mapping(0x100000).unwrap().protection,
            ReservationProtection::NONE
        );
    }
    #[test]
    fn reservation_fixed_refusal_stale_receipt_and_fault_generation() {
        let table = table();
        let mm = ReservationMm::new(31).unwrap();
        table.publish(31, mm, layout()).unwrap();
        let mut g = table.lock(31, mm).unwrap();
        g.finish_import().unwrap();
        let d = g
            .mmap(
                Placement::Anywhere,
                0x3000,
                ReservationProtection::READ_WRITE,
            )
            .unwrap();
        complete(&mut g, d);
        let plan = g
            .fault_plan(0x101234, 0x200000, ReservationProtection::READ_WRITE)
            .unwrap();
        assert_eq!(
            plan.range,
            ReservationRange::new(0x100000, 0x103000).unwrap()
        );
        assert!(g.authenticate_fault(plan));
        assert_eq!(
            g.mmap(
                Placement::NoReplace(0x101000),
                0x1000,
                ReservationProtection::NONE
            ),
            Err(Refusal::Collision)
        );
        let Decision::Work(request) = g
            .mmap(
                Placement::Fixed(0x101000),
                0x1000,
                ReservationProtection::NONE,
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            g.mapping(0x101000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert!(!g.authenticate_fault(plan));
        assert_eq!(
            g.fault_plan(0x101000, 4096, ReservationProtection::READ_WRITE),
            Err(Refusal::Busy)
        );
        g.refuse(request).unwrap();
        assert!(g.authenticate_fault(plan));
        let d = g
            .mmap(
                Placement::Fixed(0x101000),
                0x1000,
                ReservationProtection::NONE,
            )
            .unwrap();
        let stale = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        assert_eq!(g.complete(stale), Err(Refusal::Stale));
        complete(&mut g, d);
        assert!(!g.authenticate_fault(plan));
        assert_eq!(
            g.mapping(0x100000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert_eq!(
            g.mapping(0x101000).unwrap().protection,
            ReservationProtection::NONE
        );
        assert_eq!(
            g.mapping(0x102000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert_eq!(
            g.fault_plan(0x101000, 4096, ReservationProtection::READ_WRITE),
            Err(Refusal::Limit)
        );
    }
    #[test]
    fn reservation_holes_limits_byte_break_and_prepared_protection() {
        let table = table();
        let mm = ReservationMm::new(1).unwrap();
        let mut config = layout();
        config.data_limit = 0x5000;
        table.publish(1, mm, config).unwrap();
        let mut g = table.lock(1, mm).unwrap();
        g.finish_import().unwrap();
        let d = g.brk(0x2001).unwrap();
        assert_eq!(g.brk_current(), 0x1000);
        complete(&mut g, d);
        assert_eq!(g.brk_current(), 0x2001);
        assert_eq!(g.brk(0x2002), Ok(Decision::Complete(0x2002)));
        assert_eq!(g.brk(0x7000), Ok(Decision::Complete(0x2002)));
        let d = g.brk(0x1001).unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Retire);
        assert_eq!(
            request.range,
            ReservationRange::new(0x2000, 0x3000).unwrap()
        );
        complete(&mut g, d);
        let d = g.brk(0x2001).unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(
            request.operation,
            ReservationOperation::Prepare,
            "T2 owes fresh-zero backing, not resurrection"
        );
        complete(&mut g, d);
        let d = g
            .mmap(Placement::Anywhere, 0x3000, ReservationProtection::NONE)
            .unwrap();
        complete(&mut g, d);
        let middle = ReservationRange::new(0x101000, 0x102000).unwrap();
        let d = g
            .mprotect(middle, ReservationProtection::READ_WRITE)
            .unwrap();
        complete(&mut g, d);
        let d = g.munmap(middle).unwrap();
        complete(&mut g, d);
        assert!(g.mapping(middle.start()).is_none());
        assert_eq!(
            g.mprotect(
                ReservationRange::new(0x100000, 0x103000).unwrap(),
                ReservationProtection::READ_WRITE
            ),
            Err(Refusal::Hole)
        );
        let d = g
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        assert_eq!(complete(&mut g, d), middle.start());
        let d = g
            .munmap(ReservationRange::new(0x100000, 0x104000).unwrap())
            .unwrap();
        complete(&mut g, d);
        assert!(g.mapping(0x100000).is_none());
    }
    #[test]
    fn reservation_lookup_and_placement_are_logarithmic_at_three_scales() {
        for count in [8, 64, 512] {
            let table = table();
            let mm = ReservationMm::new(1).unwrap();
            table.publish(1, mm, layout()).unwrap();
            let mut g = table.lock(1, mm).unwrap();
            for i in 0..count {
                let start = 0x100000 + i * 0x2000;
                g.import(
                    ReservationRange::new(start, start + 4096).unwrap(),
                    ReservationProtection::READ_WRITE,
                    true,
                )
                .unwrap();
            }
            g.finish_import().unwrap();
            let height = g.read(g.state().tree).height as usize;
            assert!(height <= 2 * (count.ilog2() as usize + 1));
            g.work = 0;
            assert!(g.mapping(0x100000 + (count - 1) * 0x2000).is_some());
            assert!(g.work <= height);
            g.work = 0;
            // No 8KiB internal gap: augmented gap maxima skip the entire
            // populated subtree instead of visiting each unrelated mapping.
            let d = g
                .mmap(Placement::Anywhere, 8192, ReservationProtection::NONE)
                .unwrap();
            assert!(
                g.work <= 12 * (height + 1),
                "{} visits at {} mappings",
                g.work,
                count
            );
            assert_eq!(complete(&mut g, d), 0x100000 + (count - 1) * 0x2000 + 4096);
            g.retire().unwrap();
            assert!(matches!(table.lock(1, mm), Err(Refusal::Stale)));
            table
                .publish(1, ReservationMm::new(2).unwrap(), layout())
                .unwrap();
        }
    }
    #[test]
    fn reservation_churn_coalesces_and_returns_metadata() {
        let table = table();
        let mm = ReservationMm::new(1).unwrap();
        table.publish(1, mm, layout()).unwrap();
        let mut g = table.lock(1, mm).unwrap();
        g.finish_import().unwrap();
        for i in 0..512 {
            let d = g
                .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
                .unwrap();
            assert_eq!(complete(&mut g, d), 0x100000 + i * 4096);
        }
        assert_eq!(g.read(g.state().tree).height, 1);
        assert!(table.allocated.load(Ordering::Relaxed) <= 4);
        let d = g
            .munmap(ReservationRange::new(0x100000, 0x300000).unwrap())
            .unwrap();
        complete(&mut g, d);
        assert_eq!(g.state().tree, 0);
        assert_eq!(
            g.import(
                ReservationRange::new(0x100000, 0x101000).unwrap(),
                ReservationProtection::READ_WRITE,
                true
            ),
            Err(Refusal::Stale)
        );
    }
    #[test]
    fn reservation_decoder_counts_completion_only_and_keeps_two_mm_origins() {
        use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
        for rounds in [1, 8, 64] {
            let table = table();
            let counters = Counters::default();
            for slot in 0..2 {
                let mm = ReservationMm::new(slot as u64 + 17).unwrap();
                table.publish(slot, mm, layout()).unwrap();
                table.lock(slot, mm).unwrap().finish_import().unwrap();
            }
            for _ in 0..rounds {
                for slot in 0..2 {
                    let mm = ReservationMm::new(slot as u64 + 17).unwrap();
                    let mut model = table.lock(slot, mm).unwrap();
                    let mut frame = TrapFrame {
                        slot: slot as u64,
                        elr: 0x40004,
                        ..TrapFrame::default()
                    };
                    frame.x[8] = 222;
                    frame.x[..6].copy_from_slice(&[0x100000, 4096, 3, 0x32, u64::MAX, 0]);
                    let current = CurrentTask::new();
                    current.task_id.store(slot as u64 + 1, Ordering::Relaxed);
                    current.thread_serial.store(11, Ordering::Relaxed);
                    current.zone_mm.store(mm.raw(), Ordering::Relaxed);
                    let before = counters.served[222].load(Ordering::Relaxed);
                    let AnonymousReservationRoute::Work(mut pending) =
                        dispatch_anonymous_with_reservations(
                            &mut frame, &counters, &current, &mut model,
                        )
                    else {
                        panic!("expected shared decision")
                    };
                    assert_eq!(counters.served[222].load(Ordering::Relaxed), before);
                    let receipt = unsafe {
                        ReservationCompletion::after_descriptor_and_backing_commit(
                            pending.request(),
                            ReservationBackingReceipt {
                                receipt: 1,
                                granted_bytes: 4096,
                                returned_bytes: 0,
                            },
                        )
                    }
                    .unwrap();
                    pending
                        .complete(&mut frame, &current, &counters, &mut model, receipt)
                        .unwrap();
                    assert_eq!(frame.x[0], 0x100000);
                    assert_eq!(counters.served[222].load(Ordering::Relaxed), before + 1);
                    assert_eq!(model.complete(receipt), Err(Refusal::Stale));
                    assert_eq!(
                        model.mapping(0x100000).unwrap().generation,
                        model.generation()
                    );
                }
            }
            assert_eq!(counters.served[222].load(Ordering::Relaxed), rounds * 2);
            assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn reservation_mmap_overflow_preserves_linux_errno() {
        use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
        let table = table();
        let mm = ReservationMm::new(17).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut model = table.lock(0, mm).unwrap();
        model.finish_import().unwrap();
        let current = CurrentTask::new();
        current.task_id.store(1, Ordering::Relaxed);
        current.thread_serial.store(11, Ordering::Relaxed);
        current.zone_mm.store(mm.raw(), Ordering::Relaxed);
        let counters = Counters::default();
        for (address, length, flags, errno) in [
            (0, 0, 0x22, 22),
            (0, u64::MAX, 0x22, 12),
            (0x100001, 4096, 0x32, 22),
            (!4095u64, 8192, 0x32, 12),
        ] {
            let mut frame = TrapFrame::default();
            frame.x[8] = 222;
            frame.x[..6].copy_from_slice(&[address, length, 3, flags, u64::MAX, 0]);
            assert!(matches!(
                dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model),
                AnonymousReservationRoute::Action(Action::Served)
            ));
            assert_eq!(frame.x[0] as i64, -errno);
            assert!(model.pending().is_none());
        }
        assert_eq!(counters.served[222].load(Ordering::Relaxed), 4);
        assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reservation_unadmitted_root_never_serves_a_syscall() {
        use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
        let table = table();
        let mm = ReservationMm::new(17).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut model = table.lock(0, mm).unwrap();
        let current = CurrentTask::new();
        current.task_id.store(1, Ordering::Relaxed);
        current.thread_serial.store(11, Ordering::Relaxed);
        current.zone_mm.store(mm.raw(), Ordering::Relaxed);
        let counters = Counters::default();
        let mut frame = TrapFrame::default();
        frame.x[8] = 222;
        frame.x[3] = 0x22;
        assert!(matches!(
            dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model),
            AnonymousReservationRoute::Unavailable(Refusal::Stale)
        ));
        assert_eq!(counters.served[222].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reservation_continuation_rejects_rebound_task_without_losing_owner() {
        use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
        let table = table();
        let mm = ReservationMm::new(17).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut model = table.lock(0, mm).unwrap();
        model.finish_import().unwrap();
        let current = CurrentTask::new();
        current.task_id.store(1, Ordering::Relaxed);
        current.thread_serial.store(11, Ordering::Relaxed);
        current.zone_mm.store(mm.raw(), Ordering::Relaxed);
        let counters = Counters::default();
        let mut frame = TrapFrame::default();
        frame.x[8] = 222;
        frame.x[..6].copy_from_slice(&[0x100000, 4096, 3, 0x32, u64::MAX, 0]);
        let AnonymousReservationRoute::Work(mut pending) =
            dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model)
        else {
            panic!()
        };
        let receipt = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                pending.request(),
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 4096,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        current.thread_serial.store(12, Ordering::Relaxed);
        assert_eq!(
            pending.complete(&mut frame, &current, &counters, &mut model, receipt),
            Err(Refusal::Stale)
        );
        assert!(model.mapping(0x100000).is_none());
        assert_eq!(counters.served[222].load(Ordering::Relaxed), 0);
        current.thread_serial.store(11, Ordering::Relaxed);
        frame.slot = 7; // The original thread may resume on a different vCPU.
        pending
            .complete(&mut frame, &current, &counters, &mut model, receipt)
            .unwrap();
        assert_eq!(counters.served[222].load(Ordering::Relaxed), 1);
        let AnonymousReservationRoute::Work(mut pending) =
            dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model)
        else {
            panic!()
        };
        pending
            .refuse(&mut frame, &current, &counters, &mut model)
            .unwrap();
        assert_eq!(frame.x[0] as i64, -12);
        assert_eq!(counters.served[222].load(Ordering::Relaxed), 2);
        assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reservation_fragmented_edits_match_page_reference_and_reused_mm_is_stale() {
        let table = table();
        let mm = ReservationMm::new(91).unwrap();
        table.publish(4, mm, layout()).unwrap();
        let mut model = table.lock(4, mm).unwrap();
        model.finish_import().unwrap();
        let mut pages = [None; 64];
        let mut random = 17u64;
        for step in 0..1024 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let first = (random >> 32) as usize % pages.len();
            let count = 1 + ((random >> 24) as usize % (pages.len() - first));
            let range = ReservationRange::new(
                0x100000 + first as u64 * 4096,
                0x100000 + (first + count) as u64 * 4096,
            )
            .unwrap();
            let prot = ReservationProtection::from_bits((random >> 16) & 7).unwrap();
            let operation = step % 3;
            let decision = match operation {
                0 => model.mmap(Placement::Fixed(range.start()), range.len(), prot),
                1 => model.munmap(range),
                _ => model.mprotect(range, prot),
            };
            if operation == 2 && pages[first..first + count].contains(&None) {
                assert_eq!(decision, Err(Refusal::Hole));
            } else {
                complete(&mut model, decision.unwrap());
                pages[first..first + count].fill(if operation == 1 { None } else { Some(prot) });
            }
            for (page, expected) in pages.iter().enumerate() {
                assert_eq!(
                    model
                        .mapping(0x100000 + page as u64 * 4096)
                        .map(|m| m.protection),
                    *expected
                );
            }
        }
        let decision = model
            .mmap(
                Placement::Fixed(0x100000),
                4096,
                ReservationProtection::READ_WRITE,
            )
            .unwrap();
        complete(&mut model, decision);
        let old = model
            .fault_plan(0x100000, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        model.retire().unwrap();
        table.publish(4, mm, layout()).unwrap();
        let mut model = table.lock(4, mm).unwrap();
        model.finish_import().unwrap();
        let decision = model
            .mmap(
                Placement::Fixed(0x100000),
                4096,
                ReservationProtection::READ_WRITE,
            )
            .unwrap();
        complete(&mut model, decision);
        assert!(
            !model.authenticate_fault(old),
            "reused MM key and slot cannot revive a grant"
        );
    }

    fn admitted(table: &SharedReservations, index: usize, raw: u64) -> Reservations<'_> {
        let mm = ReservationMm::new(raw).unwrap();
        table.publish(index, mm, layout()).unwrap();
        let mut g = table.lock(index, mm).unwrap();
        g.finish_import().unwrap();
        g
    }
    fn range(start: u64, end: u64) -> ReservationRange {
        ReservationRange::new(start, end).unwrap()
    }
    fn decide(model: &mut Reservations<'_>, nr: u64, args: [u64; 6]) -> AnonymousRouteKind {
        use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
        let current = CurrentTask::new();
        current.task_id.store(1, Ordering::Relaxed);
        current.thread_serial.store(11, Ordering::Relaxed);
        current.zone_mm.store(model.mm().raw(), Ordering::Relaxed);
        let counters = Counters::default();
        let mut frame = TrapFrame::default();
        frame.x[8] = nr;
        frame.x[..6].copy_from_slice(&args);
        match dispatch_anonymous_with_reservations(&mut frame, &counters, &current, model) {
            AnonymousReservationRoute::Action(Action::Forward) => AnonymousRouteKind::Forward,
            AnonymousReservationRoute::Action(Action::Served) => {
                AnonymousRouteKind::Return(frame.x[0] as i64)
            }
            AnonymousReservationRoute::Work(mut pending) => {
                pending
                    .refuse(&mut frame, &current, &counters, model)
                    .unwrap();
                AnonymousRouteKind::Work
            }
            _ => AnonymousRouteKind::Other,
        }
    }
    #[derive(Debug, PartialEq, Eq)]
    enum AnonymousRouteKind {
        Forward,
        Return(i64),
        Work,
        Other,
    }

    #[test]
    fn reservation_decoder_forwards_out_of_layout_hint() {
        let table = table();
        let mut g = admitted(&table, 0, 17);
        // mmap(0xc000000000, 64 KiB, RW, MAP_PRIVATE|MAP_ANONYMOUS)
        assert_eq!(
            decide(&mut g, 222, [0xc0_0000_0000, 0x10000, 3, 0x22, u64::MAX, 0]),
            AnonymousRouteKind::Forward
        );
        assert!(g.pending().is_none());
        assert_eq!(
            decide(&mut g, 222, [0x200000, 0x10000, 3, 0x22, u64::MAX, 0]),
            AnonymousRouteKind::Work
        );
    }

    /// Documents (does not bless) decoder behavior that differs from the host
    /// dispatcher: unknown PROT bits on mmap and a misaligned offset on an
    /// anonymous mmap are EINVAL here, while host `mmap.rs` ignores both. The
    /// Docker oracle decides which answer is Linux before either changes.
    #[test]
    fn reservation_decoder_prot_and_anonymous_offset_current_behavior() {
        let table = table();
        let mut g = admitted(&table, 0, 17);
        assert_eq!(
            decide(&mut g, 222, [0, 4096, 3 | (1 << 28), 0x22, u64::MAX, 0]),
            AnonymousRouteKind::Return(-22),
            "unknown mmap prot bit"
        );
        assert_eq!(
            decide(&mut g, 222, [0, 4096, 3, 0x22, u64::MAX, 0x800]),
            AnonymousRouteKind::Return(-22),
            "misaligned offset on MAP_ANONYMOUS"
        );
        assert_eq!(
            decide(&mut g, 226, [0x100000, 4096, 1 << 28, 0, 0, 0]),
            AnonymousRouteKind::Return(-22),
            "unknown mprotect prot bit"
        );
        assert!(g.pending().is_none());
    }

    #[test]
    fn reservation_place_answers_like_mmap_without_proposing_and_ranges_are_bounded() {
        let table = table();
        let mm = ReservationMm::new(7).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut g = table.lock(0, mm).unwrap();
        assert_eq!(g.place(Placement::Anywhere, 0x1000), Err(Refusal::Stale));
        g.finish_import().unwrap();
        let rw = ReservationProtection::READ_WRITE;
        let generation = g.generation();
        let placed = g.place(Placement::Anywhere, 0x1800).unwrap();
        assert_eq!(placed.len(), 0x2000, "page-rounded like mmap");
        assert!(g.pending().is_none(), "placement proposes nothing");
        assert_eq!(g.generation(), generation);
        // The host commits its own mapping there as an opaque node; the next
        // placement (either venue) goes around it.
        g.insert_opaque(placed, rw, ReservationNodeFlags::PRIVATE)
            .unwrap();
        let d = g.mmap(Placement::Anywhere, 0x1000, rw).unwrap();
        let Decision::Work(request) = d else {
            panic!("expected work")
        };
        assert_eq!(request.range.start(), placed.end());
        complete(&mut g, d);
        assert_eq!(
            g.place(Placement::NoReplace(placed.start()), 0x1000),
            Err(Refusal::Collision)
        );
        let mut seen = Vec::new();
        g.observe_range(
            range(placed.start() + 0x1000, placed.end() + 0x1000),
            &mut |mapping| seen.push((mapping.range, mapping.anonymous)),
        )
        .unwrap();
        assert_eq!(
            seen,
            [
                (placed, false),
                (range(placed.end(), placed.end() + 0x1000), true)
            ]
        );
    }

    #[test]
    fn reservation_external_charges_count_against_pushed_limits() {
        let table = table();
        let mm = ReservationMm::new(6).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut g = table.lock(0, mm).unwrap();
        g.finish_import().unwrap();
        let rw = ReservationProtection::READ_WRITE;
        let generation = g.generation();
        g.set_limits(u64::MAX, 0x4000);
        // Host-owned data the root does not model consumes the budget.
        g.set_external_charges(0x3000, 0x3000);
        assert_eq!(g.generation(), generation, "no mapping changed");
        assert_eq!(g.mmap(Placement::Anywhere, 0x2000, rw), Err(Refusal::Limit));
        let d = g.mmap(Placement::Anywhere, 0x1000, rw).unwrap();
        complete(&mut g, d);
        g.set_external_charges(0x3000, 0);
        let d = g.mmap(Placement::Anywhere, 0x2000, rw).unwrap();
        complete(&mut g, d);
        g.set_limits(0x4000, u64::MAX);
        assert_eq!(g.mmap(Placement::Anywhere, 0x1000, rw), Err(Refusal::Limit));
    }

    #[test]
    fn reservation_data_limit_charges_only_private_writable_non_stack_nodes() {
        let table = table();
        let mm = ReservationMm::new(5).unwrap();
        let mut config = layout();
        config.data_limit = 0x4000;
        table.publish(0, mm, config).unwrap();
        let mut g = table.lock(0, mm).unwrap();
        let rw = ReservationProtection::READ_WRITE;
        // Shared writable opaque, anonymous stack and read-only private: none
        // is RLIMIT_DATA, so none consumes the 16 KiB budget.
        g.import_with(range(0x100000, 0x110000), rw, ReservationNodeFlags::EMPTY)
            .unwrap();
        g.import_with(
            range(0x110000, 0x120000),
            rw,
            ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::GROWSDOWN),
        )
        .unwrap();
        g.import_with(
            range(0x120000, 0x130000),
            ReservationProtection::from_bits(1).unwrap(),
            ReservationNodeFlags::PRIVATE,
        )
        .unwrap();
        g.finish_import().unwrap();
        let d = g.mmap(Placement::Anywhere, 0x4000, rw).unwrap();
        assert_eq!(complete(&mut g, d), 0x130000);
        assert_eq!(g.mmap(Placement::Anywhere, 0x1000, rw), Err(Refusal::Limit));
        // Read-only anonymous growth is not data either.
        let d = g
            .mmap(Placement::Anywhere, 0x1000, ReservationProtection::NONE)
            .unwrap();
        complete(&mut g, d);
        // A host-placed private writable file mapping IS charged.
        let d = g.munmap(range(0x130000, 0x134000)).unwrap();
        complete(&mut g, d);
        g.insert_opaque(range(0x200000, 0x204000), rw, ReservationNodeFlags::PRIVATE)
            .unwrap();
        assert_eq!(g.mmap(Placement::Anywhere, 0x1000, rw), Err(Refusal::Limit));
        g.retire_opaque(range(0x200000, 0x204000)).unwrap();
        let d = g.mmap(Placement::Anywhere, 0x1000, rw).unwrap();
        complete(&mut g, d);
    }

    #[test]
    fn reservation_set_limits_refuses_growth_and_keeps_shrink() {
        let table = table();
        let mut g = admitted(&table, 0, 6);
        let rw = ReservationProtection::READ_WRITE;
        let d = g.mmap(Placement::Anywhere, 0x8000, rw).unwrap();
        complete(&mut g, d);
        let generation = g.generation();
        g.set_limits(0x8000, u64::MAX);
        assert_eq!(g.generation(), generation, "limits do not revoke grants");
        assert_eq!(
            g.mmap(Placement::Anywhere, 0x1000, ReservationProtection::NONE),
            Err(Refusal::Limit),
            "RLIMIT_AS"
        );
        // brk growth under the limit keeps the old break (Linux brk(2)).
        assert_eq!(g.brk(0x3000), Ok(Decision::Complete(0x1000)));
        g.set_limits(u64::MAX, 0x4000);
        assert_eq!(
            g.mmap(Placement::Anywhere, 0x1000, rw),
            Err(Refusal::Limit),
            "RLIMIT_DATA"
        );
        assert_eq!(
            decide(&mut g, 222, [0, 4096, 3, 0x22, u64::MAX, 0]),
            AnonymousRouteKind::Return(-12)
        );
        assert_eq!(
            decide(&mut g, 214, [0x3000, 0, 0, 0, 0, 0]),
            AnonymousRouteKind::Return(0x1000)
        );
        // Shrinking below a lowered limit stays possible.
        let d = g.munmap(range(0x100000, 0x102000)).unwrap();
        complete(&mut g, d);
        let d = g
            .mprotect(range(0x102000, 0x108000), ReservationProtection::NONE)
            .unwrap();
        complete(&mut g, d);
        let d = g.mmap(Placement::Anywhere, 0x4000, rw).unwrap();
        complete(&mut g, d);
    }

    #[test]
    fn reservation_flagged_and_opaque_nodes_force_forward() {
        let table = table();
        let mut g = admitted(&table, 0, 7);
        let rw = ReservationProtection::READ_WRITE;
        let d = g.mmap(Placement::Fixed(0x100000), 0x4000, rw).unwrap();
        complete(&mut g, d);
        for flag in [
            ReservationNodeFlags::LOCKED,
            ReservationNodeFlags::DONTFORK,
            ReservationNodeFlags::WIPEONFORK,
            ReservationNodeFlags::DONTDUMP,
            ReservationNodeFlags::GROWSDOWN,
        ] {
            let before = g.generation();
            g.set_flags(range(0x101000, 0x102000), flag, ReservationNodeFlags::EMPTY)
                .unwrap();
            assert!(g.generation().raw() > before.raw());
            assert!(g.mapping(0x101000).unwrap().flags.contains(flag));
            assert!(g.mapping(0x100000).unwrap().flags.root_editable());
            assert!(g.mapping(0x102000).unwrap().flags.root_editable());
            let generation = g.generation();
            assert_eq!(
                g.munmap(range(0x100000, 0x104000)),
                Err(Refusal::ForeignMapping)
            );
            assert_eq!(
                g.mprotect(range(0x101000, 0x102000), ReservationProtection::NONE),
                Err(Refusal::ForeignMapping)
            );
            assert_eq!(
                g.mmap(Placement::Fixed(0x101000), 0x1000, rw),
                Err(Refusal::ForeignMapping)
            );
            assert_eq!(
                g.mremap(range(0x101000, 0x102000), 0x2000, MoveTarget::MayMove),
                Err(Refusal::ForeignMapping)
            );
            assert_eq!(
                decide(&mut g, 215, [0x100000, 0x4000, 0, 0, 0, 0]),
                AnonymousRouteKind::Forward
            );
            assert_eq!(
                decide(&mut g, 226, [0x101000, 0x1000, 1, 0, 0, 0]),
                AnonymousRouteKind::Forward
            );
            assert_eq!(g.generation(), generation);
            assert!(g.pending().is_none());
            // Edits not touching the flagged node remain EL1's.
            let d = g
                .mprotect(range(0x103000, 0x104000), ReservationProtection::NONE)
                .unwrap();
            complete(&mut g, d);
            let d = g.mprotect(range(0x103000, 0x104000), rw).unwrap();
            complete(&mut g, d);
            g.set_flags(range(0x101000, 0x102000), ReservationNodeFlags::EMPTY, flag)
                .unwrap();
            let mut nodes = 0;
            g.observe_mappings(&mut |_| nodes += 1).unwrap();
            assert_eq!(nodes, 1, "clearing the attribute coalesces again");
        }
        // Opaque host obstacle: placement skips it and every edit forwards.
        g.insert_opaque(
            range(0x104000, 0x106000),
            rw,
            ReservationNodeFlags::ANONYMOUS,
        )
        .unwrap();
        assert!(!g.mapping(0x104000).unwrap().anonymous);
        assert_eq!(
            g.fault_plan(0x104000, 4096, rw),
            Err(Refusal::ForeignMapping)
        );
        assert_eq!(
            g.insert_opaque(range(0x105000, 0x107000), rw, ReservationNodeFlags::EMPTY),
            Err(Refusal::Collision)
        );
        let d = g.mmap(Placement::Anywhere, 0x1000, rw).unwrap();
        assert_eq!(complete(&mut g, d), 0x106000);
        assert_eq!(
            decide(&mut g, 215, [0x104000, 0x1000, 0, 0, 0, 0]),
            AnonymousRouteKind::Forward
        );
        assert_eq!(
            g.set_flags(
                range(0x100000, 0x108000),
                ReservationNodeFlags::LOCKED,
                ReservationNodeFlags::EMPTY
            ),
            Err(Refusal::Hole)
        );
        assert_eq!(
            g.set_flags(
                range(0x100000, 0x101000),
                ReservationNodeFlags::PRIVATE,
                ReservationNodeFlags::EMPTY
            ),
            Err(Refusal::Invalid)
        );
        // The host retires across both kinds after serving the munmap itself.
        g.retire_opaque(range(0x103000, 0x105000)).unwrap();
        assert!(g.mapping(0x103000).is_none());
        assert!(g.mapping(0x104000).is_none());
        assert!(!g.mapping(0x105000).unwrap().anonymous);
        assert!(g.mapping(0x102000).unwrap().anonymous);
    }

    #[test]
    fn reservation_mremap_is_one_proposal_per_shape() {
        let table = table();
        let mut g = admitted(&table, 0, 8);
        let rw = ReservationProtection::READ_WRITE;
        let d = g.mmap(Placement::Fixed(0x100000), 0x4000, rw).unwrap();
        complete(&mut g, d);
        // Same size: no transaction.
        assert_eq!(
            g.mremap(range(0x100000, 0x104000), 0x4000, MoveTarget::InPlace),
            Ok(Decision::Complete(0x100000))
        );
        // Shrink: retire the tail.
        let d = g
            .mremap(range(0x100000, 0x104000), 0x2000, MoveTarget::InPlace)
            .unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Retire);
        assert_eq!(request.range, range(0x102000, 0x104000));
        assert_eq!(complete(&mut g, d), 0x100000);
        // Grow in place into free space: prepare the extension, one node.
        let d = g
            .mremap(range(0x100000, 0x102000), 0x6000, MoveTarget::InPlace)
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x100000);
        assert_eq!(
            g.mapping(0x105000).unwrap().range,
            range(0x100000, 0x106000)
        );
        // Blocked growth: InPlace is ENOMEM, MayMove relocates as one Move.
        let d = g
            .mmap(
                Placement::Fixed(0x106000),
                0x1000,
                ReservationProtection::NONE,
            )
            .unwrap();
        complete(&mut g, d);
        assert_eq!(
            g.mremap(range(0x100000, 0x106000), 0x8000, MoveTarget::InPlace),
            Err(Refusal::Limit)
        );
        let d = g
            .mremap(range(0x100000, 0x106000), 0x8000, MoveTarget::MayMove)
            .unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Move);
        assert_eq!(request.source, Some(range(0x100000, 0x106000)));
        assert_eq!(request.range, range(0x107000, 0x10f000));
        assert!(
            g.mapping(0x100000).is_some(),
            "uncommitted until completion"
        );
        assert_eq!(complete(&mut g, d), 0x107000);
        assert!(g.mapping(0x100000).is_none());
        assert_eq!(g.mapping(0x107000).unwrap().protection, rw);
        // Fixed move of the middle of a node over part of another node.
        let d = g
            .mremap(
                range(0x109000, 0x10b000),
                0x3000,
                MoveTarget::Fixed(0x105000),
            )
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x105000);
        let mut seen = std::vec::Vec::new();
        g.observe_mappings(&mut |m| seen.push((m.range.start(), m.range.end(), m.protection)))
            .unwrap();
        // The destination coalesces with the source node's surviving piece.
        assert_eq!(seen, [(0x105000, 0x109000, rw), (0x10b000, 0x10f000, rw)]);
        // Overlapping fixed target, cross-node source and a hole are refused.
        assert_eq!(
            g.mremap(
                range(0x105000, 0x106000),
                0x1000,
                MoveTarget::Fixed(0x105000)
            ),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            g.mremap(range(0x108000, 0x10c000), 0x1000, MoveTarget::MayMove),
            Err(Refusal::Hole)
        );
        let generation = g.generation();
        assert!(g.pending().is_none());
        assert_eq!(g.generation(), generation);
    }

    #[test]
    fn reservation_clone_is_linear_skips_dontfork_and_keeps_generations_independent() {
        #[derive(Clone, Copy, Debug)]
        enum Row {
            Plain,
            AllDontfork,
            AlternatingDontforkWipeonfork,
            OpaqueMix,
        }
        let rw = ReservationProtection::READ_WRITE;
        for count in [1u64, 64, 1024] {
            for row in [
                Row::Plain,
                Row::AllDontfork,
                Row::AlternatingDontforkWipeonfork,
                Row::OpaqueMix,
            ] {
                let table = table();
                let a = ReservationMm::new(40).unwrap();
                let b = ReservationMm::new(41).unwrap();
                table.publish(0, a, layout()).unwrap();
                table.publish(1, b, layout()).unwrap();
                // Parent + child exceed the bootstrap pool at 1024 nodes.
                let mut backing = vec![0u8; 2 * 1024 * 1024];
                let allocator = crate::alloc::MetadataStorage::new();
                allocator
                    .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
                    .unwrap();
                table
                    .lock(0, a)
                    .unwrap()
                    .provision_metadata(&allocator)
                    .unwrap();
                let mut parent = table.lock_identity_for_test(0, a).unwrap();
                let flags_for = |i: u64| match row {
                    Row::Plain => ReservationNodeFlags::ANONYMOUS_PRIVATE,
                    Row::AllDontfork => ReservationNodeFlags::ANONYMOUS_PRIVATE
                        .union(ReservationNodeFlags::DONTFORK),
                    Row::AlternatingDontforkWipeonfork => ReservationNodeFlags::ANONYMOUS_PRIVATE
                        .union(if i.is_multiple_of(2) {
                            ReservationNodeFlags::DONTFORK
                        } else {
                            ReservationNodeFlags::WIPEONFORK
                        }),
                    Row::OpaqueMix if i.is_multiple_of(3) => ReservationNodeFlags::EMPTY,
                    Row::OpaqueMix => ReservationNodeFlags::ANONYMOUS_PRIVATE,
                };
                for i in 0..count {
                    let start = 0x100000 + i * 0x2000;
                    parent
                        .import_with(range(start, start + 0x1000), rw, flags_for(i))
                        .unwrap();
                }
                parent.finish_import().unwrap();
                let parent_generation = parent.generation();
                let mut child = table.lock_identity_for_test(1, b).unwrap();
                let child_generation = child.generation();
                parent.work = 0;
                parent.clone_into(&mut child).unwrap();
                let work = parent.work;
                assert!(
                    work <= 12 * count as usize + 4,
                    "{row:?}: {work} visits for {count} parent nodes"
                );
                assert_eq!(parent.generation(), parent_generation);
                assert!(child.is_admitted());
                let kept: std::vec::Vec<u64> = (0..count)
                    .filter(|i| !flags_for(*i).contains(ReservationNodeFlags::DONTFORK))
                    .collect();
                let mut seen = std::vec::Vec::new();
                child
                    .observe_mappings(&mut |m| seen.push((m.range.start(), m.flags)))
                    .unwrap();
                assert_eq!(
                    seen,
                    kept.iter()
                        .map(|i| (0x100000 + i * 0x2000, flags_for(*i)))
                        .collect::<std::vec::Vec<_>>(),
                    "{row:?}"
                );
                let root = child.read(child.state().tree);
                assert!(root.height as u64 <= (kept.len() as u64 + 1).ilog2() as u64 + 1);
                assert_eq!(root.bytes, kept.len() as u64 * 0x1000);
                let child_generation = {
                    assert_ne!(child.generation(), child_generation);
                    child.generation()
                };
                // Independent generations: a parent edit is invisible to the
                // child and vice versa.
                parent
                    .retire_opaque(range(0x100000, 0x100000 + count * 0x2000))
                    .unwrap();
                assert!(parent.mapping(0x100000).is_none());
                assert_eq!(child.generation(), child_generation);
                if let Some(first) = kept.first() {
                    let va = 0x100000 + first * 0x2000;
                    assert!(child.mapping(va).is_some());
                    child.retire_opaque(range(va, va + 0x1000)).unwrap();
                    assert!(child.mapping(va).is_none());
                }
                assert!(parent.observe_mappings(&mut |_| panic!()).is_ok());
            }
        }
    }

    #[test]
    fn reservation_clone_refuses_busy_parent_or_populated_child() {
        let table = table();
        let mut parent = admitted(&table, 0, 50);
        let mut child = admitted(&table, 1, 51);
        assert_eq!(parent.clone_into(&mut child), Err(Refusal::Stale));
        drop(child);
        let mm = ReservationMm::new(52).unwrap();
        table.publish(2, mm, layout()).unwrap();
        let mut child = table.lock(2, mm).unwrap();
        let d = parent
            .mmap(
                Placement::Anywhere,
                0x1000,
                ReservationProtection::READ_WRITE,
            )
            .unwrap();
        assert_eq!(parent.clone_into(&mut child), Err(Refusal::Busy));
        complete(&mut parent, d);
        parent.clone_into(&mut child).unwrap();
        assert!(child.mapping(0x100000).is_some());
    }
    #[test]
    fn reservation_out_of_layout_hint_forwards_instead_of_relocating() {
        let table = table();
        let mm = ReservationMm::new(1).unwrap();
        table.publish(1, mm, layout()).unwrap();
        let mut g = table.lock(1, mm).unwrap();
        g.finish_import().unwrap();
        // Go's arena probe: the host honours free hints outside Carrick's
        // arenas with alias VAs, so the root must not pick a first-fit VA.
        for hint in [0xc0_0000_0000u64, 0x0fff_f000, !4095u64] {
            assert_eq!(
                g.mmap(
                    Placement::Hint(hint),
                    0x4000,
                    ReservationProtection::READ_WRITE
                ),
                Err(Refusal::ForeignMapping),
                "hint {hint:#x}"
            );
            assert!(g.pending().is_none());
        }
        // A free in-layout hint is still honoured exactly.
        let d = g
            .mmap(
                Placement::Hint(0x200000),
                0x4000,
                ReservationProtection::READ_WRITE,
            )
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x200000);
    }

    #[test]
    fn reservation_metadata_pressure_preserves_old_mapping_and_retirement_progress() {
        let table = table();
        let mm = ReservationMm::new(1).unwrap();
        table.publish(1, mm, layout()).unwrap();
        let mut model = table.lock(1, mm).unwrap();
        model
            .import(
                ReservationRange::new(0x100000, 0x103000).unwrap(),
                ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
        model.finish_import().unwrap();
        // Represent an exhausted metadata grant: no semantic allocation limit
        // changes, and the pending operation must never become Linux ENOMEM.
        table.allocated.store(NODES as u32, Ordering::Relaxed);
        let generation = model.generation();
        assert_eq!(
            model.munmap(ReservationRange::new(0x101000, 0x102000).unwrap()),
            Err(Refusal::MetadataRequired)
        );
        assert_eq!(model.generation(), generation);
        assert!(model.pending().is_none());
        assert!(model.mapping(0x101000).is_some());
        let d = model
            .munmap(ReservationRange::new(0x100000, 0x103000).unwrap())
            .unwrap();
        complete(&mut model, d);
        let d = model
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        assert_eq!(complete(&mut model, d), 0x100000);
    }
}
