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
const VERSION: u64 = 6;
/// Nodes each root keeps for its host venue: enough for the net growth of
/// any one host syscall's mirror (at most two straddler splits per edit
/// boundary pair, demotion and placeholder included).
pub const HOST_RESERVE: u32 = 8;
/// Retired resident extents one root can hold between EL1 retirement and the
/// host's stage-2/inventory receipt. A full journal forwards the next
/// resident retirement, so the host drains before serving it.
pub const DEFERRED_RETURNS: usize = 8;
/// Table-wide journal slots shared by every root (at most
/// [`DEFERRED_RETURNS`] each). Per-root state has no room to grow.
const DEFERRED_SLOTS: usize = 64;

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
    pub host_backing: Option<carrick_el1_abi::HostBackingIdentity>,
}

/// Byte charges of committed nodes, whole-root or within one range: every
/// node (`RLIMIT_AS`), `RLIMIT_DATA` nodes, and `LOCKED` anonymous nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charges {
    pub bytes: u64,
    pub data: u64,
    pub locked: u64,
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
    /// `MREMAP_MAYMOVE | MREMAP_DONTUNMAP` (with `MREMAP_FIXED` when
    /// `Some`): the source mapping stays, and a same-size destination is
    /// prepared with the source's protection and attributes.
    KeepSource(Option<u64>),
}

/// A resident extent EL1 retired at stage-1 (its terminals keep their output
/// as `SW_RETIRED`) whose stage-2 and frame-inventory return is still owed.
/// The frames stay unreusable, and no `Prepare` may hand the range out again,
/// until the host venue reconciles the extent and acknowledges `sequence`
/// ([`Reservations::acknowledge_deferred_returns`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredReturn {
    pub range: ReservationRange,
    /// The newest completed request whose retirement this extent covers.
    pub sequence: ReservationSequence,
}

/// One root's journal slot, reserved by [`Reservations::reserve_return`]
/// before a retirement's descriptor step and consumed by its commit or
/// released by its refusal.
#[must_use]
#[derive(Debug)]
pub struct ReturnSlot {
    index: usize,
    /// Joins the owed extent already in the slot.
    merge: bool,
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
    /// Node attributes of a created (`Prepare`/`Move`) node: plain for
    /// `mmap`/`brk`, the source's for an `mremap` extension or destination.
    flags: u32,
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
    /// Head of this root's host-venue node reserve (linked through
    /// `Node::next_free`, private to this root while reserved).
    host_reserve_head: u32,
    layout: Layout,
    pending: Option<Pending>,
    admitted: bool,
    /// Nodes in the host-venue reserve.
    host_reserved: u32,
    /// Last minted [`ReservationIncarnation`].
    minted: u64,
    /// Every incarnation at or below this one has had anonymous memory
    /// retired; a new node may join (adopt) only a younger incarnation.
    retired_below: u64,
}

/// Who holds a root's guard, as its lock word spells it (0: free).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootHolder {
    /// A host thread (host venue, publication, final settlement).
    Host,
    /// Guest EL1 on this vCPU slot.
    El1Slot(u32),
}

impl RootHolder {
    const fn word(self) -> u64 {
        match self {
            Self::Host => 1,
            Self::El1Slot(slot) => 2 + slot as u64,
        }
    }

    /// The holder a nonzero lock word names.
    fn of_word(word: u64) -> Self {
        match word.checked_sub(2) {
            Some(slot) => Self::El1Slot(slot as u32),
            None => Self::Host,
        }
    }
}

/// How an acquisition waits for a held root: shown the holder after each
/// failed attempt, it waits and answers whether to try again.
pub trait RootWait {
    fn wait(&self, attempt: u32, holder: RootHolder) -> bool;
}

/// One attempt: a held root answers `Busy` (guest EL1, which forwards).
pub struct NoRootWait;

impl RootWait for NoRootWait {
    fn wait(&self, _attempt: u32, _holder: RootHolder) -> bool {
        false
    }
}

#[repr(C)]
struct Root {
    key: AtomicU64,
    /// The holder's [`RootHolder::word`], 0 when free.
    locked: AtomicU64,
    epoch: AtomicU64,
    state: UnsafeCell<MaybeUninit<State>>,
}

/// One owed return ([`DeferredReturn`]). `mm` is the owning root's published
/// key (never reused), 0 when free. A slot is claimed, written, edited and
/// freed only under its owner's root guard; other roots read `mm` alone.
#[repr(C)]
struct DeferredSlot {
    mm: AtomicU64,
    start: AtomicU64,
    end: AtomicU64,
    sequence: AtomicU64,
}
// Access to state requires the root's nonblocking exclusive guard.
unsafe impl Sync for Root {}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct NodeData {
    start: u64,
    end: u64,
    first: u64,
    last: u64,
    gap: u64,
    bytes: u64,
    data: u64,
    /// Subtree bytes of `LOCKED` anonymous nodes.
    locked: u64,
    /// This node's [`ReservationIncarnation`]; zero never names one.
    incarnation: u64,
    left: u32,
    right: u32,
    height: u32,
    /// [`ReservationProtection`] bits (three) and [`ReservationNodeFlags`]
    /// bits (seven), packed so the bootstrap table fits its region.
    prot: u16,
    flags: u16,
    host_backing: Option<carrick_el1_abi::HostBackingIdentity>,
}
/// Lossless: validated protections use three bits.
const fn pack_prot(prot: ReservationProtection) -> u16 {
    prot.bits() as u16
}
/// Lossless: validated node flags use seven bits.
const fn pack_flags(flags: ReservationNodeFlags) -> u16 {
    flags.bits() as u16
}
impl NodeData {
    fn flags(&self) -> ReservationNodeFlags {
        // Nodes are only written from validated flags.
        ReservationNodeFlags::from_bits(u32::from(self.flags))
            .unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(&self) -> ReservationProtection {
        ReservationProtection::from_bits(u64::from(self.prot))
            .unwrap_or(ReservationProtection::NONE)
    }
    fn charged_data(&self) -> u64 {
        if self.flags().charges_data(self.protection()) {
            self.end - self.start
        } else {
            0
        }
    }
    fn charged_locked(&self) -> u64 {
        if self.flags().contains(ReservationNodeFlags::ANONYMOUS)
            && self.flags().contains(ReservationNodeFlags::LOCKED)
        {
            self.end - self.start
        } else {
            0
        }
    }
    /// Charges of the part of this one node inside `[start, end)`.
    fn charges_within(&self, start: u64, end: u64) -> Charges {
        let bytes = self.end.min(end).saturating_sub(self.start.max(start));
        Charges {
            bytes,
            data: if self.charged_data() != 0 { bytes } else { 0 },
            locked: if self.charged_locked() != 0 { bytes } else { 0 },
        }
    }
    fn mapping(&self, generation: ReservationGeneration) -> Mapping {
        // Nodes are only constructed from validated ABI ranges/protections.
        Mapping {
            range: ReservationRange::new(self.start, self.end).expect("reservation range"),
            protection: self.protection(),
            anonymous: self.flags().contains(ReservationNodeFlags::ANONYMOUS),
            flags: self.flags(),
            generation,
            host_backing: self.host_backing,
        }
    }
    /// Whether an adjacent node is the same Linux mapping (a VMA boundary
    /// the tree keeps only to separate incarnations).
    fn same_mapping(&self, other: &NodeData) -> bool {
        self.prot == other.prot
            && self.flags == other.flags
            && match (self.host_backing, other.host_backing) {
                (None, None) => true,
                (Some(a), Some(b)) if self.start <= other.start => {
                    a.advance(other.start - self.start) == Some(b)
                }
                (Some(a), Some(b)) => b.advance(self.start - other.start) == Some(a),
                _ => false,
            }
    }
}

#[derive(Default)]
struct CopyList {
    head: u32,
    tail: u32,
    len: usize,
}

/// Merges adjacent nodes of one Linux mapping (same protection and
/// attributes, differing only in incarnation) into one observed [`Mapping`].
struct Runs<'v> {
    run: Option<NodeData>,
    generation: ReservationGeneration,
    visit: &'v mut dyn FnMut(Mapping),
}
impl<'v> Runs<'v> {
    fn new(generation: ReservationGeneration, visit: &'v mut dyn FnMut(Mapping)) -> Self {
        Self {
            run: None,
            generation,
            visit,
        }
    }
    fn push(&mut self, node: NodeData) {
        match &mut self.run {
            Some(run) if run.end == node.start && run.same_mapping(&node) => run.end = node.end,
            _ => {
                if let Some(done) = self.run.replace(node) {
                    (self.visit)(done.mapping(self.generation));
                }
            }
        }
    }
    fn finish(mut self) {
        if let Some(done) = self.run.take() {
            (self.visit)(done.mapping(self.generation));
        }
    }
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
    /// Lock-free mirror of each root's `State::admitted`, one bit per root:
    /// set at admission, cleared at publish and retirement. Lets the guest
    /// venue route an unadmitted MM exactly as before without the guard,
    /// whose own `admitted` stays the authority.
    admitted: [AtomicU64; ROOTS / 64],
    deferred: [DeferredSlot; DEFERRED_SLOTS],
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
        core::mem::offset_of!(SharedReservations, admitted) as u64,
        core::mem::offset_of!(SharedReservations, deferred) as u64,
        core::mem::size_of::<DeferredSlot>() as u64,
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

const _: () = assert!(
    core::mem::size_of::<Counters>()
        <= (EL1_RESERVATIONS_OFFSET - carrick_el1_abi::EL1_COUNTERS_OFFSET) as usize
);
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
    /// This guard serves the host venue: nodes it frees refill the root's
    /// host reserve before the shared pool, so a host commit that retires
    /// and re-inserts cannot lose its own nodes to another MM in between.
    host_venue: bool,
    /// The guard is a host thread's: its shared-pool pops retry a lost
    /// free-list race (another allocation completed) until they win or the
    /// pool is empty. EL1's take one attempt and forward on `Busy`.
    host_holder: bool,
    host_proposal: bool,
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
            .compare_exchange(
                0,
                RootHolder::Host.word(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
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
                    host_reserve_head: 0,
                    layout,
                    pending: None,
                    admitted: false,
                    host_reserved: 0,
                    minted: 0,
                    retired_below: 0,
                });
            }
            self.set_admitted(index, false);
            root.key.store(mm.raw(), Ordering::Release);
            Ok(())
        };
        root.locked.store(0, Ordering::Release);
        result
    }

    /// Whether `mm`'s published root at `index` has been admitted, read
    /// without the guard. A hint: `true` routes the syscall to the root
    /// (whose guard rechecks); `false` means no root owns the MM's anonymous
    /// memory yet, so the caller keeps its pre-delegation path.
    pub fn admitted(&self, index: usize, mm: ReservationMm) -> bool {
        self.layout_hash.load(Ordering::Acquire) == LAYOUT_HASH
            && self.roots.get(index).is_some_and(|root| {
                self.admitted[index / 64].load(Ordering::Acquire) & (1 << (index % 64)) != 0
                    && root.key.load(Ordering::Acquire) == mm.raw()
            })
    }
    fn set_admitted(&self, index: usize, admitted: bool) {
        let bit = 1u64 << (index % 64);
        if admitted {
            self.admitted[index / 64].fetch_or(bit, Ordering::AcqRel);
        } else {
            self.admitted[index / 64].fetch_and(!bit, Ordering::AcqRel);
        }
    }

    /// EL1's acquisition on vCPU slot `slot`: one attempt. A held root
    /// answers `Busy` and the syscall or fault goes to the host, which serves
    /// it on its own venue. The lock word names the slot while it is held
    /// ([`Self::el1_slot_holding`]).
    pub fn lock_el1(
        &self,
        index: usize,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'_>, Refusal> {
        self.lock_using(
            index,
            mm,
            None,
            cfg!(target_os = "none"),
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
        )
    }

    /// A host thread's single attempt (final settlement, model fixtures).
    pub fn lock(&self, index: usize, mm: ReservationMm) -> Result<Reservations<'_>, Refusal> {
        self.lock_waiting(index, mm, &NoRootWait)
    }

    /// A host thread's acquisition, `wait` deciding whether to retry a held
    /// root.
    pub fn lock_waiting(
        &self,
        index: usize,
        mm: ReservationMm,
        wait: &dyn RootWait,
    ) -> Result<Reservations<'_>, Refusal> {
        self.lock_using(
            index,
            mm,
            None,
            cfg!(target_os = "none"),
            wait,
            RootHolder::Host.word(),
        )
    }

    /// The root EL1 on vCPU slot `slot` holds, read without any guard: the
    /// host asks at an exit that slot took from inside the EL1 image, which
    /// must never leave a root held (an EL1 critical section is resumed to
    /// completion; one that leaves its image while holding a root would make
    /// a host waiter wait on a vCPU that is not running).
    pub fn el1_slot_holding(&self, slot: u32) -> Option<usize> {
        let word = RootHolder::El1Slot(slot).word();
        self.roots
            .iter()
            .position(|root| root.locked.load(Ordering::Acquire) == word)
    }

    fn lock_using<'a>(
        &'a self,
        index: usize,
        mm: ReservationMm,
        banks: Option<&'a dyn storage::NodeBanks>,
        identity: bool,
        wait: &dyn RootWait,
        holder: u64,
    ) -> Result<Reservations<'a>, Refusal> {
        if self.layout_hash.load(Ordering::Acquire) != LAYOUT_HASH {
            return Err(Refusal::Stale);
        }
        let root = self.roots.get(index).ok_or(Refusal::Invalid)?;
        // The root lock's holders: EL1 on some vCPU (a critical section that
        // never blocks and is resumed to completion) or one host thread (the
        // host serializes its own venues per MM first). EL1 gives up at once;
        // the host waits the holder out.
        let mut attempt = 0u32;
        while let Err(held) =
            root.locked
                .compare_exchange(0, holder, Ordering::Acquire, Ordering::Acquire)
        {
            if held != 0 && !wait.wait(attempt, RootHolder::of_word(held)) {
                return Err(Refusal::Busy);
            }
            attempt = attempt.saturating_add(1);
        }
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
            host_venue: false,
            host_holder: holder == RootHolder::Host.word(),
            host_proposal: false,
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
        #[cfg(test)]
        if index != 0 && tests::lose_pop_race() {
            return Err(Refusal::Busy);
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
    /// Allocate a transfer identity from the admitted owner, never from a
    /// portal-local MM vector or caller-reusable counter.
    pub fn next_transfer_sequence(&mut self) -> Result<core::num::NonZeroU64, Refusal> {
        let next = self.state().sequence.checked_add(1).ok_or(Refusal::Stale)?;
        self.state_mut().sequence = next;
        core::num::NonZeroU64::new(next).ok_or(Refusal::Stale)
    }
    /// Stable occupancy identity. Policy edits change `generation`, while
    /// this value changes only when a retired slot is published again.
    pub fn incarnation(&self) -> ReservationGeneration {
        ReservationGeneration::new(self.root.epoch.load(Ordering::Acquire) + 1)
            .expect("published root incarnation")
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
    fn node_at(&mut self, address: u64) -> Option<NodeData> {
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
                return Some(n);
            }
        }
        None
    }
    /// The committed node holding `address`: one incarnation of one mapping
    /// (a Linux mapping may span several adjacent nodes; see
    /// [`Self::observe_range`]).
    pub fn mapping(&mut self, address: u64) -> Option<Mapping> {
        let generation = self.generation();
        self.node_at(address).map(|n| n.mapping(generation))
    }
    /// The committed node holding `address`, with its incarnation.
    pub fn node(&mut self, address: u64) -> Option<(Mapping, ReservationIncarnation)> {
        let generation = self.generation();
        let n = self.node_at(address)?;
        Some((
            n.mapping(generation),
            ReservationIncarnation::new(n.incarnation)?,
        ))
    }
    /// Observe one committed generation in address order, one node read per
    /// node, adjacent nodes of one Linux mapping merged into one visit. The
    /// root guard excludes publication for the whole walk; a pending proposal
    /// is not part of this committed observation.
    pub fn observe_mappings(&mut self, visit: &mut dyn FnMut(Mapping)) -> Result<(), Refusal> {
        if !self.is_admitted() {
            return Err(Refusal::Stale);
        }
        let mut runs = Runs::new(self.generation(), visit);
        self.observe_tree(self.state().tree, &mut runs);
        runs.finish();
        Ok(())
    }

    fn observe_tree(&mut self, id: u32, runs: &mut Runs<'_>) {
        if id == 0 {
            return;
        }
        let node = self.read(id);
        self.observe_tree(node.left, runs);
        runs.push(node);
        self.observe_tree(node.right, runs);
    }
    /// The committed nodes overlapping `range`, each with its incarnation,
    /// in address order: one bounded descent per node, independent of the
    /// population outside `range`.
    pub fn observe_nodes(
        &mut self,
        range: ReservationRange,
        visit: &mut dyn FnMut(Mapping, ReservationIncarnation),
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
            let incarnation = ReservationIncarnation::new(n.incarnation).ok_or(Refusal::Invalid)?;
            visit(n.mapping(generation), incarnation);
            cursor = n.end;
        }
        Ok(())
    }
    /// Charges of every committed node: one read of the root's aggregates.
    pub fn charges(&mut self) -> Charges {
        let root = self.read(self.state().tree);
        Charges {
            bytes: root.bytes,
            data: root.data,
            locked: root.locked,
        }
    }
    /// Charges of the committed nodes' parts inside `range`: O(tree height),
    /// independent of how many nodes lie inside or outside it.
    pub fn charges_within(&mut self, range: ReservationRange) -> Charges {
        self.charges_in(self.state().tree, range.start(), range.end())
    }
    fn charges_in(&mut self, id: u32, start: u64, end: u64) -> Charges {
        if id == 0 {
            return Charges::default();
        }
        let n = self.read(id);
        if n.last <= start || n.first >= end {
            return Charges::default();
        }
        if start <= n.first && n.last <= end {
            return Charges {
                bytes: n.bytes,
                data: n.data,
                locked: n.locked,
            };
        }
        let left = self.charges_in(n.left, start, end);
        let right = self.charges_in(n.right, start, end);
        let own = n.charges_within(start, end);
        Charges {
            bytes: left.bytes + own.bytes + right.bytes,
            data: left.data + own.data + right.data,
            locked: left.locked + own.locked + right.locked,
        }
    }
    /// The highest committed node overlapping `range`: one descent.
    pub fn last_mapping_within(&mut self, range: ReservationRange) -> Option<Mapping> {
        if !self.is_admitted() {
            return None;
        }
        let mut id = self.state().tree;
        let mut found = None;
        while id != 0 {
            let n = self.read(id);
            if n.start < range.end() {
                found = Some(n);
                id = n.right;
            } else {
                id = n.left;
            }
        }
        let generation = self.generation();
        found
            .filter(|n| n.end > range.start())
            .map(|n| n.mapping(generation))
    }

    pub fn fault_plan(
        &mut self,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<ReservationFaultPlan, Refusal> {
        self.fault_plan_for_source(address, max_len, access, false)
    }
    /// Transfer materialization may consume an explicitly retained byte
    /// source. Ordinary anonymous fault planning keeps its existing boundary.
    pub fn transfer_fault_plan(
        &mut self,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
    ) -> Result<ReservationFaultPlan, Refusal> {
        self.fault_plan_for_source(address, max_len, access, true)
    }
    fn fault_plan_for_source(
        &mut self,
        address: u64,
        max_len: u64,
        access: ReservationProtection,
        allow_backing: bool,
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
        if !mapping.anonymous && !(allow_backing && mapping.host_backing.is_some()) {
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
        self.authenticate_transfer_fault(plan, None)
    }
    pub fn authenticate_transfer_fault(
        &mut self,
        plan: ReservationFaultPlan,
        backing: Option<HostBackingIdentity>,
    ) -> bool {
        plan.mm == self.mm
            && plan.generation == self.generation()
            && self.pending().is_none_or(|p| {
                p.range.end() <= plan.range.start() || p.range.start() >= plan.range.end()
            })
            && self.mapping(plan.fault_page).is_some_and(|m| {
                (if let Some(backing) = backing {
                    plan.range
                        .start()
                        .checked_sub(m.range.start())
                        .and_then(|offset| m.host_backing.and_then(|source| source.advance(offset)))
                        == Some(backing)
                } else {
                    m.anonymous && m.host_backing.is_none()
                }) && m.protection == plan.protection
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
        n.locked = l.locked + r.locked + n.charged_locked();
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
            n.incarnation = successor.incarnation;
            n.host_backing = successor.host_backing;
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
        flags: ReservationNodeFlags,
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
        // A retired resident extent's frames are unreusable until the
        // host's inventory receipt: its VA is not handed out again first.
        if matches!(
            operation,
            ReservationOperation::Prepare | ReservationOperation::Move
        ) && self.return_owed_within(range)
        {
            return Err(Refusal::Busy);
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
            flags: flags.bits(),
            nodes,
        });
        Ok(Decision::Work(request))
    }
    /// One node from the shared pool. A lost free-list race means another
    /// allocation completed: a host guard retries it (lock-free progress,
    /// no wait on any event), EL1 answers `Busy` and forwards. Only an
    /// empty pool ends a host pop (`MetadataRequired`).
    fn pool_node(&self) -> Result<u32, Refusal> {
        loop {
            match self.table.allocate(self.banks, self.node_capacity) {
                Err(Refusal::Busy) if self.host_holder => core::hint::spin_loop(),
                result => return result,
            }
        }
    }
    /// One bounded allocation attempt per spare; failure returns every node.
    fn allocate_spares(&mut self, needed: usize) -> Result<[u32; 5], Refusal> {
        if self.host_proposal {
            return self.host_spares(needed);
        }
        let mut nodes = [0; 5];
        for slot in nodes.iter_mut().take(needed) {
            match self.pool_node() {
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
            self.free_node(node);
        }
    }
    /// Return a node: refill this root's host reserve first, then the
    /// shared pool.
    fn free_node(&mut self, id: u32) {
        if id == 0 {
            return;
        }
        if self.host_venue && self.state().host_reserved < HOST_RESERVE {
            let head = self.state().host_reserve_head;
            self.table
                .node(id, self.banks)
                .next_free
                .store(head, Ordering::Relaxed);
            self.state_mut().host_reserve_head = id;
            self.state_mut().host_reserved += 1;
        } else {
            self.table.release(id, self.banks);
        }
    }
    /// One node for a host-venue commit: the shared pool, else this root's
    /// reserve. Pool exhaustion or contention never fails a host commit the
    /// reserve covers.
    fn host_node(&mut self) -> Result<u32, Refusal> {
        if let Ok(id) = self.pool_node() {
            return Ok(id);
        }
        let head = self.state().host_reserve_head;
        if head == 0 {
            return Err(Refusal::MetadataRequired);
        }
        let next = self
            .table
            .node(head, self.banks)
            .next_free
            .load(Ordering::Relaxed);
        self.state_mut().host_reserve_head = next;
        self.state_mut().host_reserved -= 1;
        Ok(head)
    }
    /// [`Self::allocate_spares`] for a host-venue commit ([`Self::host_node`]).
    fn host_spares(&mut self, needed: usize) -> Result<[u32; 5], Refusal> {
        let mut nodes = [0; 5];
        for slot in nodes.iter_mut().take(needed) {
            match self.host_node() {
                Ok(node) => *slot = node,
                Err(reason) => {
                    self.release_spares(nodes);
                    return Err(reason);
                }
            }
        }
        Ok(nodes)
    }
    /// Before a host syscall does any backend work: fill this root's host
    /// reserve from the shared pool as far as it goes, then require
    /// `needed` reserved nodes (the most the syscall's host commits may net
    /// consume; see [`HOST_RESERVE`]). `MetadataRequired` is the syscall's
    /// ENOMEM (a map-count exhaustion), answered before anything changed. A
    /// lost free-list race means another allocation completed, so the
    /// attempt is repeated; exhaustion ends it.
    pub fn secure_host_nodes(&mut self, needed: u32) -> Result<(), Refusal> {
        self.host_venue = true;
        while self.state().host_reserved < HOST_RESERVE {
            let Ok(id) = self.pool_node() else {
                break;
            };
            self.free_node(id);
        }
        if self.state().host_reserved < needed.min(HOST_RESERVE) {
            return Err(Refusal::MetadataRequired);
        }
        Ok(())
    }
    /// A host-forwarded proposal consumes the same nodes secured by host
    /// admission. Guest proposals must never consume that reserved capacity.
    pub fn begin_host_proposal(&mut self) -> Result<(), Refusal> {
        if !self.host_holder || self.pending().is_some() {
            return Err(Refusal::Invalid);
        }
        self.host_venue = true;
        self.host_proposal = true;
        Ok(())
    }
    /// Nodes a host retire of `range` needs: one per node straddling an end.
    pub fn retire_nodes_needed(&mut self, range: ReservationRange) -> u32 {
        self.splits_needed(range) as u32
    }
    /// Nodes currently in this root's host reserve.
    pub fn host_reserve(&self) -> u32 {
        self.state().host_reserved
    }
    fn drain_host_reserve(&mut self) {
        while self.state().host_reserve_head != 0 {
            let head = self.state().host_reserve_head;
            let next = self
                .table
                .node(head, self.banks)
                .next_free
                .load(Ordering::Relaxed);
            self.state_mut().host_reserve_head = next;
            self.state_mut().host_reserved -= 1;
            self.table.release(head, self.banks);
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
        let mut runs = Runs::new(self.generation(), visit);
        let mut cursor = range.start();
        while let Some(n) = self.next(cursor) {
            if n.start >= range.end() {
                break;
            }
            runs.push(n);
            cursor = n.end;
        }
        runs.finish();
        Ok(())
    }
    /// The Linux mapping around `[start, end)`: the adjacent run of nodes of
    /// one mapping starting with the node holding `start`, extended until it
    /// covers `end`. `None` when a hole or another mapping comes first.
    fn run_covering(&mut self, start: u64, end: u64) -> Option<NodeData> {
        let mut run = self.next(start).filter(|n| n.start <= start)?;
        while run.end < end {
            let n = self
                .next(run.end)
                .filter(|n| n.start == run.end && n.same_mapping(&run))?;
            run.end = n.end;
        }
        Some(run)
    }
    /// The incarnation a node created as `node` takes: a younger adjacent
    /// incarnation of the same mapping (then the two coalesce), else a fresh
    /// one. Joining an incarnation that ever had memory retired could make a
    /// fact about the retired pages look live, so that is never allowed.
    fn incarnation_for(&mut self, node: &NodeData) -> u64 {
        let floor = self.state().retired_below;
        let joinable = |n: &NodeData| n.same_mapping(node) && n.incarnation > floor;
        if let Some(left) = node
            .start
            .checked_sub(1)
            .and_then(|va| self.next(va))
            .filter(|l| l.end == node.start && joinable(l))
        {
            return left.incarnation;
        }
        if let Some(right) = self
            .next(node.end)
            .filter(|r| r.start == node.end && joinable(r))
        {
            return right.incarnation;
        }
        let minted = self.state().minted + 1;
        self.state_mut().minted = minted;
        minted
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
            ReservationNodeFlags::ANONYMOUS_PRIVATE,
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
            ReservationNodeFlags::EMPTY,
        )
    }
    /// Change the protection of every node in `range`; each keeps its own
    /// [`ReservationNodeFlags::CARRIED`] attributes.
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
            ReservationNodeFlags::EMPTY,
        )
    }
    /// `mremap(2)` of an anonymous range as one proposal. `source` must lie in
    /// one root-editable node (`Hole` otherwise: the decoder's EFAULT); a
    /// host-owned source is `ForeignMapping`. Shrink retires the tail;
    /// in-place growth prepares the extension when nothing (of any owner, or
    /// the layout's end) is in the way, else `Limit` without
    /// `MREMAP_MAYMOVE`; a relocation is one `Move` whose completion retires
    /// the source and prepares the destination atomically; `KeepSource`
    /// prepares a same-size destination and keeps the source. Every created
    /// node carries the source's protection and attributes. Growing a
    /// `LOCKED` source is subject to `RLIMIT_MEMLOCK`, which this root does
    /// not hold: the host venue admits it before proposing (the EL1 decoder
    /// forwards `mremap`).
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
        let fixed = match target {
            MoveTarget::Fixed(address) | MoveTarget::KeepSource(Some(address)) => Some(address),
            _ => None,
        };
        if new_len == 0 || fixed.is_some_and(|address| !address.is_multiple_of(4096)) {
            return Err(Refusal::Invalid);
        }
        let new_len = new_len
            .checked_add(4095)
            .map(|v| v & !4095)
            .ok_or(Refusal::Limit)?;
        let keep_source = matches!(target, MoveTarget::KeepSource(_));
        if keep_source && new_len != source.len() {
            return Err(Refusal::Invalid);
        }
        let node = self
            .run_covering(source.start(), source.end())
            .ok_or(Refusal::Hole)?;
        if !node.flags().root_editable() {
            return Err(Refusal::ForeignMapping);
        }
        let prot = node.protection();
        let flags = node.flags();
        let brk = self.brk_current();
        let (operation, moved) = if keep_source {
            (ReservationOperation::Prepare, None)
        } else {
            (ReservationOperation::Move, Some(source))
        };
        if let Some(address) = fixed {
            let range = address
                .checked_add(new_len)
                .and_then(|end| ReservationRange::new(address, end))
                .ok_or(Refusal::Invalid)?;
            if range.start() < source.end() && source.start() < range.end() {
                return Err(Refusal::Invalid);
            }
            return self.proposal(range, prot, operation, address, brk, false, moved, flags);
        }
        if !keep_source {
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
                    ReservationNodeFlags::EMPTY,
                );
            }
            let extension = source
                .start()
                .checked_add(new_len)
                .and_then(|end| ReservationRange::new(source.end(), end))
                .filter(|r| self.in_layout(*r));
            let free =
                extension.is_some_and(|r| self.next(r.start()).is_none_or(|n| n.start >= r.end()));
            if let Some(extension) = extension.filter(|_| free) {
                return self.proposal(
                    extension,
                    prot,
                    ReservationOperation::Prepare,
                    source.start(),
                    brk,
                    false,
                    None,
                    flags,
                );
            }
            if target == MoveTarget::InPlace {
                return Err(Refusal::Limit);
            }
        }
        let address = self.first_fit(new_len).ok_or(Refusal::Limit)?;
        let range = ReservationRange::new(address, address + new_len).ok_or(Refusal::Invalid)?;
        self.proposal(range, prot, operation, address, brk, false, moved, flags)
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
        match self.proposal(
            range,
            prot,
            op,
            requested,
            requested,
            false,
            None,
            ReservationNodeFlags::ANONYMOUS_PRIVATE,
        ) {
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
        high.host_backing = n
            .host_backing
            .and_then(|backing| backing.advance(address - n.start));
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
            if n.flags().contains(ReservationNodeFlags::ANONYMOUS) {
                // Anonymous memory is gone: no incarnation minted so far may
                // be joined again.
                self.state_mut().retired_below = self.state().minted;
            }
            let (tree, freed) = self.erase(self.state().tree, n.start);
            self.state_mut().tree = tree;
            self.free_node(freed);
        }
    }
    /// Rewrite the protection of every node inside the fully covered `range`,
    /// splitting straddlers at its bounds and keeping each node's flags.
    fn reprotect_range(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        spares: &mut Spares,
    ) {
        self.split_at(range.start(), spares);
        self.split_at(range.end(), spares);
        let mut cursor = range.start();
        while cursor < range.end() {
            let Some(n) = self.next(cursor).filter(|n| n.start < range.end()) else {
                break;
            };
            let (tree, freed) = self.erase(self.state().tree, n.start);
            self.state_mut().tree = tree;
            let mut edited = n;
            edited.prot = pack_prot(prot);
            edited.left = 0;
            edited.right = 0;
            self.write(freed, edited);
            self.insert_coalescing(freed);
            cursor = n.end;
        }
    }
    pub fn complete(&mut self, completion: ReservationCompletion) -> Result<u64, Refusal> {
        self.complete_as(completion, false)
    }
    /// Complete a pending `Prepare` whose memory the host venue ended up
    /// serving itself (a host alias install): the range is replaced exactly
    /// as the proposal said, but by one opaque, host-owned node the guest
    /// venue never edits. Uses only the proposal's own spares.
    pub fn complete_host_owned(
        &mut self,
        completion: ReservationCompletion,
    ) -> Result<u64, Refusal> {
        if self
            .pending()
            .is_none_or(|request| request.operation != ReservationOperation::Prepare)
        {
            return Err(Refusal::Invalid);
        }
        self.complete_as(completion, true)
    }
    fn complete_as(
        &mut self,
        completion: ReservationCompletion,
        host_owned: bool,
    ) -> Result<u64, Refusal> {
        let pending = self.state().pending.ok_or(Refusal::Stale)?;
        if !completion.authenticates(pending.request)
            || pending.request.mm != self.mm
            || pending.request.generation != self.generation()
        {
            return Err(Refusal::Stale);
        }
        let range = pending.request.range;
        let mut created_flags =
            ReservationNodeFlags::from_bits(pending.flags).ok_or(Refusal::Stale)?;
        if host_owned {
            created_flags = created_flags.difference(ReservationNodeFlags::ANONYMOUS);
        }
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
        if pending.request.operation == ReservationOperation::Protect {
            // Each covered node keeps its own carried attributes.
            self.reprotect_range(range, pending.request.protection, &mut spares);
        } else {
            self.remove_range(range, &mut spares);
        }
        if creates && pending.request.operation != ReservationOperation::Protect {
            let id = spares.take();
            let mut node = NodeData {
                start: range.start(),
                end: range.end(),
                prot: pack_prot(pending.request.protection),
                flags: pack_flags(created_flags),
                ..NodeData::default()
            };
            node.incarnation = self.incarnation_for(&node);
            self.write(id, node);
            self.insert_coalescing(id);
        }
        self.release_spares(spares.0);
        self.state_mut().layout.brk = pending.new_brk;
        self.state_mut().generation += 1;
        self.state_mut().pending = None;
        Ok(pending.result)
    }
    fn index(&self) -> usize {
        // SAFETY-free arithmetic: `root` borrows an element of `roots`.
        (self.root as *const Root as usize - self.table.roots.as_ptr() as usize)
            / core::mem::size_of::<Root>()
    }
    fn mark_admitted(&self) {
        self.table.set_admitted(self.index(), true);
    }
    /// This root's journal slots. Only this root's guard edits them.
    fn deferred_slots(&self) -> impl Iterator<Item = &DeferredSlot> + '_ {
        let mm = self.mm.raw();
        self.table
            .deferred
            .iter()
            .filter(move |slot| slot.mm.load(Ordering::Acquire) == mm)
    }
    fn deferred(&self) -> impl Iterator<Item = DeferredReturn> + '_ {
        self.deferred_slots().filter_map(|slot| {
            Some(DeferredReturn {
                range: ReservationRange::new(
                    slot.start.load(Ordering::Relaxed),
                    slot.end.load(Ordering::Relaxed),
                )?,
                sequence: ReservationSequence::new(slot.sequence.load(Ordering::Relaxed))?,
            })
        })
    }
    fn return_owed_within(&self, range: ReservationRange) -> bool {
        self.deferred()
            .any(|owed| owed.range.start() < range.end() && range.start() < owed.range.end())
    }
    /// The slot `range` would join (abutting or overlapping an owed extent),
    /// else a free slot when this root is under its share. `None`: full.
    fn deferred_slot_for(&self, range: ReservationRange) -> Option<(usize, bool)> {
        let mm = self.mm.raw();
        let mut owned = 0;
        for (index, slot) in self.table.deferred.iter().enumerate() {
            if slot.mm.load(Ordering::Acquire) != mm {
                continue;
            }
            owned += 1;
            let (start, end) = (
                slot.start.load(Ordering::Relaxed),
                slot.end.load(Ordering::Relaxed),
            );
            if start <= range.end() && range.start() <= end {
                return Some((index, true));
            }
        }
        if owned >= DEFERRED_RETURNS {
            return None;
        }
        self.table
            .deferred
            .iter()
            .position(|slot| slot.mm.load(Ordering::Acquire) == 0)
            .map(|index| (index, false))
    }
    /// Reserve the journal slot for one resident retirement of `range`
    /// BEFORE its descriptor step, so the commit after that step cannot
    /// fail for lack of room. `Busy` when this root's share or the table is
    /// full: the retirement is then forwarded and the host drains first.
    pub fn reserve_return(&mut self, range: ReservationRange) -> Result<ReturnSlot, Refusal> {
        let mm = self.mm.raw();
        loop {
            let (index, merge) = self.deferred_slot_for(range).ok_or(Refusal::Busy)?;
            // A free slot may be claimed by another root first; rescan (each
            // lost race is another root's progress, and the table is
            // bounded). The claimed slot's empty range is not yet an extent.
            if merge
                || self.table.deferred[index]
                    .mm
                    .compare_exchange(0, mm, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                return Ok(ReturnSlot { index, merge });
            }
        }
    }
    /// Give back a reservation whose retirement was not committed.
    pub fn release_return(&mut self, slot: ReturnSlot) {
        let entry = &self.table.deferred[slot.index];
        if !slot.merge && entry.mm.load(Ordering::Acquire) == self.mm.raw() {
            entry.mm.store(0, Ordering::Release);
        }
    }
    /// Host venue, at its next boundary for this MM: every extent whose
    /// stage-1 terminals EL1 retired and whose stage-2/inventory return is
    /// owed. The extents are disjoint.
    pub fn observe_deferred_returns(&self, visit: &mut dyn FnMut(DeferredReturn)) {
        for owed in self.deferred() {
            visit(owed);
        }
    }
    /// Host venue: stage-1 retired leaves, stage-2 and the frame inventory
    /// of every owed extent up to `through` were reconciled as one
    /// transaction. Only then do those frames and VAs become reusable.
    /// Returns the number of extents released.
    pub fn acknowledge_deferred_returns(
        &mut self,
        through: ReservationSequence,
    ) -> Result<usize, Refusal> {
        if !self.state().admitted {
            return Err(Refusal::Stale);
        }
        let mut released = 0;
        for slot in self.deferred_slots() {
            if slot.sequence.load(Ordering::Relaxed) <= through.raw() {
                slot.start.store(0, Ordering::Relaxed);
                slot.end.store(0, Ordering::Relaxed);
                slot.sequence.store(0, Ordering::Relaxed);
                slot.mm.store(0, Ordering::Release);
                released += 1;
            }
        }
        Ok(released)
    }
    /// Complete a pending `Retire` (or a `Prepare` replacing resident memory)
    /// whose stage-1 terminals the guest venue retired, and journal the
    /// range as an owed return in `slot` ([`Self::reserve_return`]).
    /// `completion.backing()` returned nothing yet: the frames stay in the
    /// inventory, unreusable, until the host acknowledges this request's
    /// sequence. A refusal releases `slot`.
    pub fn complete_deferring_return(
        &mut self,
        completion: ReservationCompletion,
        slot: ReturnSlot,
    ) -> Result<u64, Refusal> {
        let request = match self.pending() {
            Some(request)
                if matches!(
                    request.operation,
                    ReservationOperation::Retire | ReservationOperation::Prepare
                ) && completion.backing().returned_bytes == 0 =>
            {
                request
            }
            Some(_) => {
                self.release_return(slot);
                return Err(Refusal::Invalid);
            }
            None => {
                self.release_return(slot);
                return Err(Refusal::Stale);
            }
        };
        let result = match self.complete(completion) {
            Ok(result) => result,
            Err(refusal) => {
                self.release_return(slot);
                return Err(refusal);
            }
        };
        let (range, sequence) = (request.range, request.sequence.raw());
        let entry = &self.table.deferred[slot.index];
        if slot.merge {
            // Abutting or overlapping: one extent, owed until the newer
            // sequence is acknowledged.
            entry.start.fetch_min(range.start(), Ordering::Relaxed);
            entry.end.fetch_max(range.end(), Ordering::Relaxed);
            entry.sequence.fetch_max(sequence, Ordering::Relaxed);
        } else {
            entry.start.store(range.start(), Ordering::Relaxed);
            entry.end.store(range.end(), Ordering::Relaxed);
            entry.sequence.store(sequence, Ordering::Relaxed);
        }
        Ok(result)
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
    /// Import a retained byte source before admission. Fork and node splits
    /// preserve this identity; it is never reconstructed from a host VMA.
    pub fn import_with_backing(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
        backing: carrick_el1_abi::HostBackingIdentity,
    ) -> Result<(), Refusal> {
        if self.state().admitted {
            return Err(Refusal::Stale);
        }
        self.insert_backed_node(range, prot, flags, Some(backing))
    }
    fn insert_node(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
    ) -> Result<(), Refusal> {
        self.insert_backed_node(range, prot, flags, None)
    }
    fn insert_backed_node(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
        host_backing: Option<carrick_el1_abi::HostBackingIdentity>,
    ) -> Result<(), Refusal> {
        if host_backing.is_some_and(|backing| backing.advance(range.len()).is_none()) {
            return Err(Refusal::Invalid);
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
        let id = self.host_node()?;
        let mut node = NodeData {
            start: range.start(),
            end: range.end(),
            prot: pack_prot(prot),
            flags: pack_flags(flags),
            host_backing,
            ..NodeData::default()
        };
        node.incarnation = self.incarnation_for(&node);
        self.write(id, node);
        self.insert_coalescing(id);
        Ok(())
    }
    fn host_edit_admitted(&mut self) -> Result<u64, Refusal> {
        self.host_venue = true;
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
        self.insert_opaque_backed(range, prot, flags, None)
    }
    pub fn insert_opaque_backed(
        &mut self,
        range: ReservationRange,
        prot: ReservationProtection,
        flags: ReservationNodeFlags,
        backing: Option<HostBackingIdentity>,
    ) -> Result<(), Refusal> {
        let generation = self.host_edit_admitted()?;
        self.insert_backed_node(
            range,
            prot,
            flags.difference(ReservationNodeFlags::ANONYMOUS),
            backing,
        )?;
        self.state_mut().generation = generation;
        Ok(())
    }
    /// Host commit of a retirement it served itself: removes every node in
    /// `range`, whatever its kind, keeping straddlers' outside pieces.
    pub fn retire_opaque(&mut self, range: ReservationRange) -> Result<(), Refusal> {
        let generation = self.host_edit_admitted()?;
        let needed = self.splits_needed(range);
        let mut spares = Spares(self.host_spares(needed)?);
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
        let mut spares = Spares(self.host_spares(needed)?);
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
                edited.flags = pack_flags(flags);
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
        // Fork plans from settled memory only: retired extents whose
        // frames the host has not reconciled are not settled.
        if self.pending().is_some() || self.deferred().next().is_some() {
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
        // Admission must not publish a child that cannot forward even one
        // host request. This reserve remains private across the copy.
        if let Err(reason) = child.secure_host_nodes(HOST_RESERVE) {
            child.drain_host_reserve();
            return Err(reason);
        }
        let mut list = CopyList::default();
        if let Err(reason) = self.copy_in_order(self.state().tree, &mut list) {
            let mut id = list.head;
            while id != 0 {
                let next = self.read(id).right;
                self.table.release(id, self.banks);
                id = next;
            }
            child.drain_host_reserve();
            return Err(reason);
        }
        let mut cursor = list.head;
        let tree = self.build_balanced(list.len, &mut cursor);
        let layout = self.state().layout;
        let (minted, retired_below) = (self.state().minted, self.state().retired_below);
        let state = child.state_mut();
        state.tree = tree;
        state.layout = layout;
        state.minted = minted;
        state.retired_below = retired_below;
        state.admitted = true;
        state.generation += 1;
        child.mark_admitted();
        Ok(())
    }
    fn copy_in_order(&mut self, id: u32, list: &mut CopyList) -> Result<(), Refusal> {
        if id == 0 {
            return Ok(());
        }
        let n = self.read(id);
        self.copy_in_order(n.left, list)?;
        if !n.flags().contains(ReservationNodeFlags::DONTFORK) {
            let copy = self.pool_node()?;
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
            && left.same_mapping(&n)
            && left.incarnation == n.incarnation
        {
            let (tree, freed) = self.erase(self.state().tree, left.start);
            self.state_mut().tree = tree;
            self.free_node(freed);
            n.start = left.start;
            n.host_backing = left.host_backing;
        }
        if let Some(right) = self.next(n.end)
            && right.start == n.end
            && right.same_mapping(&n)
            && right.incarnation == n.incarnation
        {
            let (tree, freed) = self.erase(self.state().tree, right.start);
            self.state_mut().tree = tree;
            self.free_node(freed);
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
        if let Err(reason) = self.secure_host_nodes(HOST_RESERVE) {
            self.drain_host_reserve();
            return Err(reason);
        }
        self.state_mut().admitted = true;
        self.mark_admitted();
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
        self.drain_host_reserve();
        Ok(())
    }
    /// Called after final-MM descriptor/backing settlement, never sibling exit.
    /// Owed returns must be reconciled first: the MM's frames are only
    /// settled once every EL1-retired extent has its inventory receipt.
    pub fn retire(mut self) -> Result<(), Refusal> {
        if self.pending().is_some() || self.deferred().next().is_some() {
            return Err(Refusal::Busy);
        }
        for slot in self.deferred_slots() {
            slot.mm.store(0, Ordering::Release);
        }
        self.release_tree(self.state().tree);
        self.state_mut().tree = 0;
        self.drain_host_reserve();
        self.root
            .epoch
            .store(self.state().generation, Ordering::Relaxed);
        self.table.set_admitted(self.index(), false);
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

    /// A lost free-list race (another allocation won the CAS) is not an
    /// answer a host guard may give: it retries the pop. EL1 declines with
    /// its one attempt and forwards.
    #[test]
    fn a_host_pool_pop_retries_a_lost_race_and_el1_declines() {
        let table = table();
        let mm = ReservationMm::new(61).unwrap();
        table.publish(0, mm, layout()).unwrap();
        table.lock(0, mm).unwrap().finish_import().unwrap();
        // Put two nodes on the shared free list.
        {
            let model = table.lock(0, mm).unwrap();
            let (a, b) = (model.pool_node().unwrap(), model.pool_node().unwrap());
            model.table.release(a, model.banks);
            model.table.release(b, model.banks);
        }
        LOSE_POPS.with(|lose| lose.set(2));
        let host = table.lock(0, mm).unwrap();
        assert!(host.pool_node().is_ok(), "the host retries past lost races");
        drop(host);
        LOSE_POPS.with(|lose| lose.set(1));
        let guest = table.lock_el1(0, mm, 4).unwrap();
        assert_eq!(
            guest.pool_node(),
            Err(Refusal::Busy),
            "EL1 takes one attempt"
        );
        LOSE_POPS.with(|lose| lose.set(0));
    }

    thread_local! {
        static LOSE_POPS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// Test hook: the next pops of this thread lose their free-list race.
    pub(super) fn lose_pop_race() -> bool {
        LOSE_POPS.with(|lose| {
            let left = lose.get();
            lose.set(left.saturating_sub(1));
            left != 0
        })
    }

    /// The root's lock word names its holder: the host asks, at an exit a
    /// vCPU took from inside the EL1 image, whether EL1 on that slot still
    /// holds a root, and only that slot's EL1 guard answers yes.
    #[test]
    fn an_el1_root_guard_is_named_by_its_slot_until_released() {
        let table = table();
        let a = ReservationMm::new(41).unwrap();
        let b = ReservationMm::new(42).unwrap();
        table.publish(3, a, layout()).unwrap();
        table.publish(4, b, layout()).unwrap();
        assert_eq!(
            table.el1_slot_holding(5),
            None,
            "nothing held after publish"
        );
        {
            let _guest = table.lock_el1(3, a, 5).unwrap();
            assert_eq!(table.el1_slot_holding(5), Some(3));
            assert_eq!(
                table.el1_slot_holding(6),
                None,
                "another slot holds nothing"
            );
            assert!(
                matches!(table.lock_el1(3, a, 6), Err(Refusal::Busy)),
                "EL1 gives up on a held root at once"
            );
            let _host = table.lock(4, b).unwrap();
            assert_eq!(
                table.el1_slot_holding(5),
                Some(3),
                "a host guard is never an EL1 slot's"
            );
        }
        assert_eq!(table.el1_slot_holding(5), None, "released with the guard");
    }

    #[test]
    fn reservation_metadata_required_does_not_become_linux_enomem() {
        let table = table();
        let mm = ReservationMm::new(71).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut model = table.lock(0, mm).unwrap();
        model.finish_import().unwrap();
        assert_eq!(model.host_reserve(), HOST_RESERVE);
        for page in 0..NODES - HOST_RESERVE as usize {
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
        // Admission's private forwarding reserve is not tree churn.
        assert!(table.allocated.load(Ordering::Relaxed) - g.host_reserve() <= 4);
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

    /// mmap ignores protection bits outside its vocabulary: the committed
    /// memflagmatrix oracle records mmap_invalid_prot_result=success. Keep
    /// that route separate from mprotect unknown-bit validation and the
    /// existing anonymous-offset validation.
    #[test]
    fn reservation_decoder_prot_and_anonymous_offset_linux_routes() {
        let table = table();
        let mut g = admitted(&table, 0, 17);
        assert_eq!(
            decide(&mut g, 222, [0, 4096, 3 | (1 << 28), 0x22, u64::MAX, 0]),
            AnonymousRouteKind::Forward,
            "unknown mmap prot bits retain host mmap decoding"
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
        // A grow-down stack is host-owned, locked or not: every edit touching
        // it forwards. (The carried attributes alone ride EL1 edits; see
        // `reservation_carried_attributes_ride_el1_edits`.)
        for flag in [
            ReservationNodeFlags::GROWSDOWN,
            ReservationNodeFlags::GROWSDOWN.union(ReservationNodeFlags::LOCKED),
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
        // Grow in place into free space: prepare the extension. The shrink
        // retired memory, so the extension is its own incarnation (its node
        // stays apart) but one Linux mapping with the source.
        let d = g
            .mremap(range(0x100000, 0x102000), 0x6000, MoveTarget::InPlace)
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x100000);
        assert_eq!(
            g.mapping(0x105000).unwrap().range,
            range(0x102000, 0x106000)
        );
        let mut grown = std::vec::Vec::new();
        g.observe_range(range(0x100000, 0x106000), &mut |m| grown.push(m.range))
            .unwrap();
        assert_eq!(grown, [range(0x100000, 0x106000)]);
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

    /// Every attribute set on one node, in address order.
    fn nodes(g: &mut Reservations<'_>) -> std::vec::Vec<(u64, u64, u64, u32)> {
        let mut seen = std::vec::Vec::new();
        g.observe_mappings(&mut |m| {
            seen.push((
                m.range.start(),
                m.range.end(),
                m.protection.bits(),
                m.flags.bits(),
            ))
        })
        .unwrap();
        seen
    }

    #[test]
    fn reservation_carried_attributes_ride_el1_edits() {
        let table = table();
        let mut g = admitted(&table, 0, 9);
        let rw = ReservationProtection::READ_WRITE;
        let r = ReservationProtection::from_bits(1).unwrap();
        let anon = ReservationNodeFlags::ANONYMOUS_PRIVATE.bits();
        for flag in [
            ReservationNodeFlags::LOCKED,
            ReservationNodeFlags::DONTFORK,
            ReservationNodeFlags::WIPEONFORK,
            ReservationNodeFlags::DONTDUMP,
        ] {
            let d = g.mmap(Placement::Fixed(0x100000), 0x4000, rw).unwrap();
            complete(&mut g, d);
            g.set_flags(range(0x101000, 0x103000), flag, ReservationNodeFlags::EMPTY)
                .unwrap();
            let flagged = anon | flag.bits();
            // mlock(2)/madvise(2) attributes stay with the VMA across
            // mprotect(2): the range is still EL1's, and the edit keeps
            // each node's attributes while changing its protection.
            let d = g.mprotect(range(0x100000, 0x102000), r).unwrap();
            complete(&mut g, d);
            assert_eq!(
                nodes(&mut g),
                [
                    (0x100000, 0x101000, 1, anon),
                    (0x101000, 0x102000, 1, flagged),
                    (0x102000, 0x103000, 3, flagged),
                    (0x103000, 0x104000, 3, anon),
                ]
            );
            assert!(g.fault_plan(0x101000, 4096, r).is_ok());
            assert_eq!(
                decide(&mut g, 226, [0x101000, 0x1000, 3, 0, 0, 0]),
                AnonymousRouteKind::Work
            );
            // mmap(MAP_FIXED) replaces the attributed VMA with a plain one.
            let d = g.mmap(Placement::Fixed(0x101000), 0x1000, r).unwrap();
            complete(&mut g, d);
            assert_eq!(g.mapping(0x101000).unwrap().flags.bits(), anon);
            // munmap(2) retires attributed memory like any other.
            let d = g.munmap(range(0x100000, 0x104000)).unwrap();
            complete(&mut g, d);
            assert!(nodes(&mut g).is_empty());
        }
    }

    #[test]
    fn reservation_mremap_carries_source_attributes() {
        let table = table();
        let mut g = admitted(&table, 0, 10);
        let rw = ReservationProtection::READ_WRITE;
        let carried = ReservationNodeFlags::LOCKED.union(ReservationNodeFlags::DONTDUMP);
        let flagged = ReservationNodeFlags::ANONYMOUS_PRIVATE
            .union(carried)
            .bits();
        let d = g.mmap(Placement::Fixed(0x100000), 0x2000, rw).unwrap();
        complete(&mut g, d);
        g.set_flags(
            range(0x100000, 0x102000),
            carried,
            ReservationNodeFlags::EMPTY,
        )
        .unwrap();
        // In-place growth extends the same VMA, attributes included.
        let d = g
            .mremap(range(0x100000, 0x102000), 0x3000, MoveTarget::InPlace)
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x100000);
        assert_eq!(nodes(&mut g), [(0x100000, 0x103000, 3, flagged)]);
        // A move carries them to the destination.
        let d = g
            .mremap(
                range(0x100000, 0x103000),
                0x3000,
                MoveTarget::Fixed(0x200000),
            )
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x200000);
        assert_eq!(nodes(&mut g), [(0x200000, 0x203000, 3, flagged)]);
        // MREMAP_DONTUNMAP: the source VMA stays mapped and the
        // destination is a second VMA with the source's attributes.
        let d = g
            .mremap(
                range(0x200000, 0x203000),
                0x3000,
                MoveTarget::KeepSource(Some(0x300000)),
            )
            .unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Prepare);
        assert_eq!(request.source, None);
        assert_eq!(complete(&mut g, d), 0x300000);
        assert_eq!(
            nodes(&mut g),
            [
                (0x200000, 0x203000, 3, flagged),
                (0x300000, 0x303000, 3, flagged)
            ]
        );
        let d = g
            .mremap(
                range(0x300000, 0x303000),
                0x3000,
                MoveTarget::KeepSource(None),
            )
            .unwrap();
        let placed = complete(&mut g, d);
        assert!(placed != 0x300000 && g.mapping(placed).is_some());
        // DONTUNMAP needs old_size == new_size and a disjoint destination.
        assert_eq!(
            g.mremap(
                range(0x200000, 0x203000),
                0x4000,
                MoveTarget::KeepSource(None)
            ),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            g.mremap(
                range(0x200000, 0x203000),
                0x3000,
                MoveTarget::KeepSource(Some(0x201000))
            ),
            Err(Refusal::Invalid)
        );
        // A grow-down stack stays host-owned.
        g.set_flags(
            range(0x200000, 0x201000),
            ReservationNodeFlags::GROWSDOWN,
            ReservationNodeFlags::EMPTY,
        )
        .unwrap();
        assert_eq!(
            g.mremap(range(0x200000, 0x201000), 0x1000, MoveTarget::MayMove),
            Err(Refusal::ForeignMapping)
        );
        assert!(g.pending().is_none());
    }

    #[test]
    fn reservation_mremap_growth_stops_at_the_next_mapping_of_any_owner() {
        // mremap(2): an in-place expansion fails "because other mappings
        // are in the way"; any owner's node is in the way, and a hole that
        // exactly fits is not.
        let table = table();
        let mut g = admitted(&table, 0, 11);
        let rw = ReservationProtection::READ_WRITE;
        let d = g.mmap(Placement::Fixed(0x100000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        g.insert_opaque(
            range(0x102000, 0x103000),
            ReservationProtection::from_bits(1).unwrap(),
            ReservationNodeFlags::PRIVATE,
        )
        .unwrap();
        assert_eq!(
            g.mremap(range(0x100000, 0x101000), 0x3000, MoveTarget::InPlace),
            Err(Refusal::Limit)
        );
        let d = g
            .mremap(range(0x100000, 0x101000), 0x3000, MoveTarget::MayMove)
            .unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Move);
        assert!(request.range.start() >= 0x103000);
        g.refuse(request).unwrap();
        // The one-page hole fits exactly: grow in place up to the obstacle.
        let d = g
            .mremap(range(0x100000, 0x101000), 0x2000, MoveTarget::InPlace)
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x100000);
        assert_eq!(
            g.mapping(0x101000).unwrap().range,
            range(0x100000, 0x102000)
        );
        assert!(!g.mapping(0x102000).unwrap().anonymous);
        // Growth past the end of the layout is blocked in place too: no
        // ForeignMapping forward for an anonymous source.
        let d = g.mmap(Placement::Fixed(0xfff000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        assert_eq!(
            g.mremap(range(0xfff000, 0x1000000), 0x2000, MoveTarget::InPlace),
            Err(Refusal::Limit)
        );
        let d = g
            .mremap(range(0xfff000, 0x1000000), 0x2000, MoveTarget::MayMove)
            .unwrap();
        let Decision::Work(request) = d else { panic!() };
        assert_eq!(request.operation, ReservationOperation::Move);
        g.refuse(request).unwrap();
    }

    #[test]
    fn owner_fork_keeps_file_identity_and_split_offsets() {
        use carrick_el1_abi::HostBackingIdentity;
        use core::num::NonZeroU64;
        let table = table();
        let a = ReservationMm::new(40).unwrap();
        let b = ReservationMm::new(41).unwrap();
        table.publish(0, a, layout()).unwrap();
        table.publish(1, b, layout()).unwrap();
        let source = HostBackingIdentity::new(
            NonZeroU64::new(17).unwrap(),
            NonZeroU64::new(3).unwrap(),
            0x8000,
        );
        let mut parent = table.lock(0, a).unwrap();
        parent
            .import_with_backing(
                range(0x100000, 0x104000),
                ReservationProtection::READ_WRITE,
                ReservationNodeFlags::PRIVATE,
                source,
            )
            .unwrap();
        parent.finish_import().unwrap();
        parent
            .set_flags(
                range(0x101000, 0x103000),
                ReservationNodeFlags::DONTFORK,
                ReservationNodeFlags::EMPTY,
            )
            .unwrap();
        assert_eq!(
            parent.mapping(0x101000).unwrap().host_backing,
            source.advance(0x1000)
        );
        assert_eq!(
            parent.mapping(0x103000).unwrap().host_backing,
            source.advance(0x3000)
        );
        let mut child = table.lock(1, b).unwrap();
        parent.clone_into(&mut child).unwrap();
        assert_eq!(child.mapping(0x100000).unwrap().host_backing, Some(source));
        assert!(child.mapping(0x101000).is_none());
        assert_eq!(
            child.mapping(0x103000).unwrap().host_backing,
            source.advance(0x3000)
        );
        assert_eq!(
            parent.mapping(0x101000).unwrap().host_backing,
            source.advance(0x1000)
        );
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

    #[test]
    fn reservation_incarnations_never_join_retired_memory() {
        let table = table();
        let mut g = admitted(&table, 0, 12);
        let rw = ReservationProtection::READ_WRITE;
        let inc = |g: &mut Reservations<'_>, va: u64| g.node(va).unwrap().1;
        let d = g.mmap(Placement::Fixed(0x100000), 0x2000, rw).unwrap();
        complete(&mut g, d);
        // Nothing retired yet: an adjacent mapping joins the incarnation
        // and the two coalesce into one node.
        let d = g.mmap(Placement::Fixed(0x102000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        let first = inc(&mut g, 0x100000);
        assert_eq!(inc(&mut g, 0x102000), first);
        assert_eq!(
            g.mapping(0x102000).unwrap().range,
            range(0x100000, 0x103000)
        );
        // A retire anywhere taints every incarnation minted so far.
        let d = g.mmap(Placement::Fixed(0x110000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        let d = g.munmap(range(0x110000, 0x111000)).unwrap();
        complete(&mut g, d);
        let d = g.mmap(Placement::Fixed(0x103000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        let fresh = inc(&mut g, 0x103000);
        assert_ne!(fresh, first);
        // One Linux mapping, two incarnations.
        let mut seen = std::vec::Vec::new();
        g.observe_mappings(&mut |m| seen.push(m.range)).unwrap();
        assert_eq!(seen, [range(0x100000, 0x104000)]);
        let mut nodes = std::vec::Vec::new();
        g.observe_nodes(range(0x100000, 0x104000), &mut |m, i| {
            nodes.push((m.range, i))
        })
        .unwrap();
        assert_eq!(
            nodes,
            [
                (range(0x100000, 0x103000), first),
                (range(0x103000, 0x104000), fresh)
            ]
        );
        // mprotect splits and rejoins keep the incarnation.
        let d = g
            .mprotect(range(0x101000, 0x102000), ReservationProtection::NONE)
            .unwrap();
        complete(&mut g, d);
        assert_eq!(inc(&mut g, 0x101000), first);
        assert_eq!(inc(&mut g, 0x102000), first);
        let d = g.mprotect(range(0x101000, 0x102000), rw).unwrap();
        complete(&mut g, d);
        assert_eq!(
            g.mapping(0x101000).unwrap().range,
            range(0x100000, 0x103000)
        );
        // A retired page recreated between live pages is a new incarnation.
        let d = g.munmap(range(0x101000, 0x102000)).unwrap();
        complete(&mut g, d);
        let d = g.mmap(Placement::Fixed(0x101000), 0x1000, rw).unwrap();
        complete(&mut g, d);
        let recreated = inc(&mut g, 0x101000);
        assert_ne!(recreated, first);
        assert_ne!(recreated, fresh);
        assert_eq!(inc(&mut g, 0x100000), first);
        assert_eq!(inc(&mut g, 0x102000), first);
        // mremap sees the Linux mapping, not the incarnations.
        let d = g
            .mremap(range(0x100000, 0x104000), 0x5000, MoveTarget::MayMove)
            .unwrap();
        assert_eq!(complete(&mut g, d), 0x100000);
        assert_eq!(g.mapping(0x104000).unwrap().protection, rw);
    }

    #[test]
    fn reservation_range_charges_and_high_water_are_logarithmic() {
        for count in [16u64, 512] {
            let table = table();
            let mm = ReservationMm::new(1).unwrap();
            table.publish(1, mm, layout()).unwrap();
            let mut g = table.lock(1, mm).unwrap();
            for i in 0..count {
                let start = 0x100000 + i * 0x2000;
                let prot = if i % 3 == 0 {
                    ReservationProtection::NONE
                } else {
                    ReservationProtection::READ_WRITE
                };
                let flags = if i % 5 == 0 {
                    ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::LOCKED)
                } else {
                    ReservationNodeFlags::ANONYMOUS_PRIVATE
                };
                g.import_with(range(start, start + 0x1000), prot, flags)
                    .unwrap();
            }
            g.finish_import().unwrap();
            let height = g.read(g.state().tree).height as usize;
            // Brute force over every node, then the one-descent answers.
            let query = range(0x100000 + 0x7000, 0x100000 + 0x13000);
            let mut expected = Charges::default();
            g.observe_nodes(range(0x100000, 0x1000000), &mut |m, _| {
                let bytes = m
                    .range
                    .end()
                    .min(query.end())
                    .saturating_sub(m.range.start().max(query.start()));
                expected.bytes += bytes;
                if m.flags.charges_data(m.protection) {
                    expected.data += bytes;
                }
                if m.flags.contains(ReservationNodeFlags::LOCKED) {
                    expected.locked += bytes;
                }
            })
            .unwrap();
            g.work = 0;
            assert_eq!(g.charges_within(query), expected);
            assert!(g.work <= 4 * (height + 1), "{} reads at {count}", g.work);
            g.work = 0;
            let last = g.last_mapping_within(range(0x100000, 0x1000000)).unwrap();
            assert_eq!(last.range.start(), 0x100000 + (count - 1) * 0x2000);
            assert!(g.work <= height + 1);
            g.work = 0;
            assert_eq!(g.charges().bytes, count * 0x1000);
            assert_eq!(g.work, 1);
        }
    }

    #[test]
    fn reservation_admission_secures_one_forwarding_request() {
        let table = table();
        let mut g = admitted(&table, 0, 13);
        assert_eq!(g.host_reserve(), HOST_RESERVE);
        let child_mm = ReservationMm::new(14).unwrap();
        table.publish(1, child_mm, layout()).unwrap();
        let mut child = table.lock(1, child_mm).unwrap();
        g.clone_into(&mut child).unwrap();
        assert_eq!(child.host_reserve(), HOST_RESERVE);
        g.retire().unwrap();
        child.retire().unwrap();
        let _reused_parent = admitted(&table, 0, 15);
        let _reused_child = admitted(&table, 1, 16);
        assert_eq!(table.allocated.load(Ordering::Relaxed), 2 * HOST_RESERVE);
    }

    #[test]
    fn reservation_failed_admission_returns_import_and_reserve_nodes() {
        let table = table();
        let mm = ReservationMm::new(13).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut g = table.lock(0, mm).unwrap();
        for page in 0..NODES {
            g.import_with(
                range(0x100000 + page as u64 * 8192, 0x101000 + page as u64 * 8192),
                ReservationProtection::READ_WRITE,
                ReservationNodeFlags::ANONYMOUS_PRIVATE,
            )
            .unwrap();
        }
        assert_eq!(g.finish_import(), Err(Refusal::MetadataRequired));
        assert!(!g.is_admitted());
        assert_eq!(g.host_reserve(), 0);
        g.abort_import().unwrap();
        let nodes: Vec<_> = (0..NODES)
            .map(|_| g.pool_node().expect("every imported node returned"))
            .collect();
        assert_eq!(g.pool_node(), Err(Refusal::MetadataRequired));
        for node in nodes {
            table.release(node, g.banks);
        }
    }

    #[test]
    fn reservation_host_reserve_covers_host_commits_at_exhaustion() {
        let table = table();
        let mut g = admitted(&table, 0, 13);
        g.secure_host_nodes(HOST_RESERVE).unwrap();
        assert_eq!(g.host_reserve(), HOST_RESERVE);
        let rw = ReservationProtection::READ_WRITE;
        let r = ReservationProtection::from_bits(1).unwrap();
        g.insert_opaque(range(0x200000, 0x204000), r, ReservationNodeFlags::PRIVATE)
            .unwrap();
        // Exhaust the shared pool with guest-venue mappings.
        let mut page = 0;
        loop {
            let prot = if page % 2 == 0 { rw } else { r };
            match g.mmap(Placement::Fixed(0x300000 + page * 0x2000), 0x1000, prot) {
                Ok(d) => {
                    complete(&mut g, d);
                    page += 1;
                }
                Err(Refusal::MetadataRequired) => break,
                Err(other) => panic!("{other:?}"),
            }
        }
        // Guest-venue frees never refill the host reserve.
        assert_eq!(g.host_reserve(), HOST_RESERVE);
        // A host commit that splits needs nodes the pool no longer has.
        g.retire_opaque(range(0x201000, 0x202000)).unwrap();
        assert_eq!(g.host_reserve(), HOST_RESERVE - 1);
        g.insert_opaque(range(0x201000, 0x202000), rw, ReservationNodeFlags::PRIVATE)
            .unwrap();
        assert_eq!(g.host_reserve(), HOST_RESERVE - 2);
        // Admission refuses what the reserve cannot cover, before any edit.
        assert_eq!(
            g.secure_host_nodes(HOST_RESERVE),
            Err(Refusal::MetadataRequired)
        );
        g.secure_host_nodes(0).unwrap();
        // The host's proposal can consume its admitted reserve even when
        // the guest shared pool has no node left.
        g.begin_host_proposal().unwrap();
        let decision = g.mmap(Placement::Fixed(0xe00000), 4096, rw).unwrap();
        complete(&mut g, decision);
        assert!(g.mapping(0xe00000).is_some());
        // Host retires refill the reserve first.
        g.retire_opaque(range(0x200000, 0x204000)).unwrap();
        assert_eq!(g.host_reserve(), HOST_RESERVE);
        g.secure_host_nodes(HOST_RESERVE).unwrap();
    }
}
