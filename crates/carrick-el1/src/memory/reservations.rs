//! Shared anonymous Linux reservation authority. Both venues borrow the same
//! records; persisted links are node indices, never pointers or Rust containers.
//! Proposals reserve metadata but do not change the committed tree. T2 owns
//! descriptor/backing work; only an exact completion commits the proposal.

use carrick_el1_abi::*;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

mod storage;
pub use storage::ResolvedReservationNodes;

const ROOTS: usize = carrick_sched_core::spaces::ADDRESS_SPACES;
const NODES: usize = 1024;
/// Bootstrap metadata only. Exhaustion is a capacity request, never Linux
/// ENOMEM. Existing reservations can still be observed and retired.
pub const RESERVATIONS_OFFSET: usize = EL1_RESERVATIONS_OFFSET as usize;
const VERSION: u64 = 2;

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
    nodes: [u32; 3],
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
    anonymous: u32,
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
                    anonymous: n.anonymous != 0,
                    generation: self.generation(),
                });
            }
        }
        None
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
        n.data = l.data
            + r.data
            + if n.anonymous != 0 && n.prot & 2 != 0 {
                n.end - n.start
            } else {
                0
            };
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
            n.anonymous = successor.anonymous;
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
    #[allow(clippy::too_many_arguments)]
    fn proposal(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        operation: ReservationOperation,
        result: u64,
        new_brk: u64,
        require_coverage: bool,
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
            if n.anonymous == 0 {
                return Err(Refusal::ForeignMapping);
            }
            if require_coverage && n.start > cursor {
                return Err(Refusal::Hole);
            }
            let overlap = n.end.min(range.end()) - n.start.max(cursor);
            bytes += overlap;
            if n.prot & 2 != 0 {
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
        let added = if operation == ReservationOperation::Retire {
            0
        } else {
            range.len()
        };
        let added_data = if prot.bits() & 2 != 0 { added } else { 0 };
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
        let mut nodes = [0; 3];
        let needed = [
            self.next(range.start())
                .is_some_and(|n| n.start < range.start() && n.end > range.start()),
            self.next(range.end() - 1)
                .is_some_and(|n| n.start < range.end() && n.end > range.end()),
            operation != ReservationOperation::Retire,
        ];
        for slot in 0..nodes.len() {
            if !needed[slot] {
                continue;
            }
            let node = match self.table.allocate(self.banks, self.node_capacity) {
                Ok(node) => node,
                Err(reason) => {
                    for node in nodes {
                        self.table.release(node, self.banks);
                    }
                    return Err(reason);
                }
            };
            nodes[slot] = node;
        }
        let request = ReservationRequest {
            mm: self.mm,
            generation: self.generation(),
            sequence: ReservationSequence::new(sequence).ok_or(Refusal::Stale)?,
            range,
            protection: prot,
            operation,
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
    pub fn mmap(
        &mut self,
        placement: Placement,
        len: u64,
        prot: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
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
                let hinted = addr
                    .checked_add(len)
                    .and_then(|end| ReservationRange::new(addr, end));
                if hinted.is_some_and(|r| {
                    self.in_layout(r) && self.next(addr).is_none_or(|n| n.start >= r.end())
                }) {
                    addr
                } else {
                    self.first_fit(len).ok_or(Refusal::Limit)?
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
        self.proposal(
            range,
            prot,
            ReservationOperation::Prepare,
            address,
            self.brk_current(),
            false,
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
        match self.proposal(range, prot, op, requested, requested, false) {
            Err(Refusal::Limit | Refusal::ForeignMapping) => Ok(Decision::Complete(old)),
            result => result,
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
        let first = self
            .next(range.start())
            .filter(|n| n.start < range.start() && n.end > range.start());
        let last = self
            .next(range.end() - 1)
            .filter(|n| n.start < range.end() && n.end > range.end());
        while let Some(n) = self.next(range.start()) {
            if n.start >= range.end() {
                break;
            }
            let (tree, freed) = self.erase(self.state().tree, n.start);
            self.state_mut().tree = tree;
            self.table.release(freed, self.banks);
        }
        let mut pieces = [None; 3];
        pieces[0] = first.map(|mut n| {
            n.end = range.start();
            n
        });
        pieces[1] = last.map(|mut n| {
            n.start = range.end();
            n
        });
        if pending.request.operation != ReservationOperation::Retire {
            pieces[2] = Some(NodeData {
                start: range.start(),
                end: range.end(),
                prot: pending.request.protection.bits(),
                anonymous: 1,
                ..NodeData::default()
            });
        }
        for (id, piece) in pending.nodes.into_iter().zip(pieces) {
            if let Some(mut n) = piece {
                n.left = 0;
                n.right = 0;
                self.write(id, n);
                self.insert_coalescing(id);
            } else {
                self.table.release(id, self.banks);
            }
        }
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
        for node in pending.nodes {
            self.table.release(node, self.banks);
        }
        self.state_mut().pending = None;
        Ok(())
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
        if self.state().admitted {
            return Err(Refusal::Stale);
        }
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
                anonymous: u32::from(anonymous),
                ..NodeData::default()
            },
        );
        self.insert_coalescing(id);
        Ok(())
    }
    fn insert_coalescing(&mut self, id: u32) {
        let mut n = self.read(id);
        if let Some(left) = n.start.checked_sub(1).and_then(|va| self.next(va))
            && left.end == n.start
            && left.prot == n.prot
            && left.anonymous == n.anonymous
        {
            let (tree, freed) = self.erase(self.state().tree, left.start);
            self.state_mut().tree = tree;
            self.table.release(freed, self.banks);
            n.start = left.start;
        }
        if let Some(right) = self.next(n.end)
            && right.start == n.end
            && right.prot == n.prot
            && right.anonymous == n.anonymous
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
