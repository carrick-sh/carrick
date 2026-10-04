//! Descriptor/OFD authority as shared records; no allocator or host dependencies.
//!
//! [`Core`] is plain `repr(C)` atomics with no pointers, so one instance can
//! live in memory shared by the host and EL1; both venues operate on it
//! through an [`Authority`] view that supplies descriptor-slot resolution
//! ([`SlotBacking`]) and a lock-wait policy ([`LockWait`]). Synchronization is
//! per table (a lock word in each [`TableRecord`]) plus lock-free OFD
//! reference/pin words and free lists; there is no whole-core lock. Threads
//! with CLONE_FILES use the same TableId; fork copies a table but shares its
//! OFDs. See README.md for lifecycle, locking and publication rules.
#![no_std]

pub use carrick_sched_core::{BoundedSpin, LockWait};
#[cfg(not(all(test, feature = "loom")))]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
#[cfg(all(test, feature = "loom"))]
use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

#[cfg(test)]
extern crate std;
#[cfg(all(test, not(feature = "loom")))]
mod tests;

#[cfg(all(test, feature = "loom"))]
mod loom_models;

#[cfg(not(all(test, feature = "loom")))]
static NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);
#[cfg(all(test, feature = "loom"))]
loom::lazy_static! {
    static ref NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);
}

/// Guest descriptor number, including invalid negative syscall arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fd(pub i32);
/// Opaque venue-owned backing resource. Never interpreted as a host fd here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingToken(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Offset(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Path,
}
/// Neutral flag representation. The personality translates architecture bits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusFlags {
    pub append: bool,
    pub nonblock: bool,
    pub asynchronous: bool,
    pub direct: bool,
    pub noatime: bool,
    pub dsync: bool,
    pub sync: bool,
    /// Additional immutable F_GETFL bits, interpreted only by the personality.
    pub immutable: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BadFd,
    InvalidArgument,
    TooManyFiles,
    /// Authority storage exhausted (not the process's RLIMIT_NOFILE).
    NoMemory,
    /// Every published open-file-description record is in use. The venue
    /// publishes more ([`Authority::publish_ofds`]) outside any lock and
    /// retries, or reports its zone-wide file limit (ENFILE). An internal
    /// storage request: never EMFILE, and never ENOMEM by itself.
    NeedsOfds,
    StaleTable,
    /// Supply at least this many descriptor slots and their bitmap, then retry.
    /// This is an internal storage request, never EMFILE.
    NeedsBacking {
        descriptors: usize,
    },
    /// The lock-wait policy gave up before any effect (EL1 forwards the
    /// syscall to the host). Never a guest errno.
    Contended,
    /// The venue could not resolve a table's backing extent. A venue bug;
    /// fail closed, never a guest errno.
    BadBacking,
    /// A pin that does not name a live pinned description (released twice,
    /// forged, or from another authority). A venue ownership bug.
    StalePin,
    /// A lock-free [`Authority::pin`] raced a close that freed and reused the
    /// description record: the pin it took holds the reuse, which the fd did
    /// not name. Its ownership moves to the caller (rebuild it with
    /// [`OfdPin::from_raw`]), who releases it through its normal unpin path
    /// (which may be that description's final release) and may retry.
    PinRaced(RawOfdPin),
}
/// Generation-checked identity; IDs from another Core are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableId {
    authority: u64,
    index: usize,
    generation: u64,
}
/// Plain-data form of a [`TableId`] for shared records (e.g. a task's
/// published file table). [`TableId::from_raw`] rebuilds the id; every use
/// still authenticates authority, index and generation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawTableId {
    pub authority: u64,
    pub index: u64,
    pub generation: u64,
}
impl TableId {
    pub const fn to_raw(self) -> RawTableId {
        RawTableId {
            authority: self.authority,
            index: self.index as u64,
            generation: self.generation,
        }
    }
    pub const fn from_raw(raw: RawTableId) -> Self {
        Self {
            authority: raw.authority,
            index: raw.index as usize,
            generation: raw.generation,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Description {
    pub backing: BackingToken,
    pub offset: Offset,
    pub access: AccessMode,
    pub flags: StatusFlags,
}
impl Description {
    pub const fn new(backing: BackingToken, access: AccessMode, flags: StatusFlags) -> Self {
        Self {
            backing,
            offset: Offset(0),
            access,
            flags,
        }
    }
}

/// Exact identity of one open file description incarnation. Copyable:
/// naming a description does not retain it (an [`OfdPin`] does).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfdKey {
    pub index: u32,
    pub generation: u64,
}

/// An owned retention of one open file description (a blocked or in-flight
/// syscall's lease). While any pin exists the description is not finalized,
/// even if every descriptor naming it is closed and the numbers reused.
/// Not `Clone`/`Copy`: exactly one owner releases it with
/// [`Authority::unpin`]. To keep it in a shared continuation record, move it
/// out with [`OfdPin::into_raw`] and back with [`OfdPin::from_raw`].
#[must_use = "a pin retains its description until unpin"]
#[derive(Debug, Eq, PartialEq)]
pub struct OfdPin {
    authority: u64,
    key: OfdKey,
}
/// Plain-data form of an [`OfdPin`] held in an owned continuation.
/// Converting either way transfers the one ownership; a copy of the raw
/// value is not a second pin.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawOfdPin {
    pub authority: u64,
    pub index: u64,
    pub generation: u64,
}
impl OfdPin {
    pub fn key(&self) -> OfdKey {
        self.key
    }
    pub fn into_raw(self) -> RawOfdPin {
        RawOfdPin {
            authority: self.authority,
            index: u64::from(self.key.index),
            generation: self.key.generation,
        }
    }
    /// Reclaim the ownership moved out by [`OfdPin::into_raw`].
    pub fn from_raw(raw: RawOfdPin) -> Self {
        Self {
            authority: raw.authority,
            key: OfdKey {
                index: raw.index.min(u64::from(u32::MAX)) as u32,
                generation: raw.generation,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    ofd: u32,
    cloexec: bool,
}
const SLOT_CLOEXEC: u64 = 1 << 63;
const SLOT_INDEX: u64 = u32::MAX as u64;
const fn encode_entry(entry: Option<Entry>) -> u64 {
    match entry {
        None => 0,
        Some(e) => (e.ofd as u64 + 1) | if e.cloexec { SLOT_CLOEXEC } else { 0 },
    }
}
const fn decode_entry(word: u64) -> Option<Entry> {
    let index = word & SLOT_INDEX;
    if index == 0 {
        None
    } else {
        Some(Entry {
            ofd: (index - 1) as u32,
            cloexec: word & SLOT_CLOEXEC != 0,
        })
    }
}

/// One descriptor slot in venue-provided (possibly shared) memory:
/// 0 = empty, otherwise OFD index + 1 with bit 63 = FD_CLOEXEC. Accessed only
/// under the owning table's lock.
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct DescriptorSlot(AtomicU64);

// Representation limit of the signed descriptor ABI, not a resource policy.
const MAX_DESCRIPTORS: usize = i32::MAX as usize + 1;
const MAX_LEVELS: usize = usize::BITS as usize / 6 + 1;

/// Number of u64 words needed for all levels of a 64-way free-slot bitmap.
/// A venue allocates these words along with `capacity` DescriptorSlots.
pub const fn bitmap_words(mut capacity: usize) -> usize {
    let mut words = 0;
    while capacity > 0 {
        capacity = capacity.div_ceil(64);
        words += capacity;
        if capacity == 1 {
            break;
        }
    }
    words
}

/// A venue-provisioned descriptor backing extent: an opaque token the venue
/// resolves to `capacity` [`DescriptorSlot`]s plus `bitmap_words(capacity)`
/// words. Stored in the table record, never as a pointer. The all-zero
/// extent is "no backing" and is never resolved.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Extent {
    pub token: u64,
    pub capacity: u64,
}
impl Extent {
    pub const EMPTY: Self = Self {
        token: 0,
        capacity: 0,
    };
}

/// How a venue turns an [`Extent`] into memory in its own address space
/// (host pointer or EL1 VA). Must return exactly `capacity` slots and at
/// least `bitmap_words(capacity)` words, or `None` (fails closed as
/// [`Error::BadBacking`]). Allocation of extents happens outside this
/// authority, never under a table lock.
///
/// Lifetime rule (lock-free lookups): an extent's memory must stay mapped,
/// and be accessed only as `DescriptorSlot`/`AtomicU64` words by every
/// party, for as long as the core lives, including after the extent is
/// retired (`grow_table`, `destroy_table`). A lookup may still read a
/// retired extent's words before `seq` rejects them, so the venue may reuse
/// that memory only as another extent (type-stable reclamation), never as
/// anything written non-atomically.
///
/// The venue also holds the open-file-description records: `ofd(index)`
/// resolves record `index` for every index below the core's published
/// count ([`Core::ofd_count`], grown by [`Authority::publish_ofds`]). The
/// core never asks for an unpublished index; `None` fails closed.
pub trait SlotBacking {
    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])>;
    fn ofd(&self, index: usize) -> Option<&OfdRecord>;
}

#[cfg(test)]
std::thread_local! {
    /// Descriptor-slot reads, for structural lookup budgets.
    static SLOT_READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static BITMAP_READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A view of one table's slots and free bitmap. Built per operation from the
/// resolved extent while the table's lock is held; never persisted.
pub struct TableStorage<'a> {
    entries: &'a [DescriptorSlot],
    bitmap: &'a [AtomicU64],
    offsets: [usize; MAX_LEVELS],
    sizes: [usize; MAX_LEVELS],
    levels: usize,
}
impl<'a> TableStorage<'a> {
    pub fn new(entries: &'a [DescriptorSlot], bitmap: &'a [AtomicU64]) -> Result<Self, Error> {
        if entries.len() > MAX_DESCRIPTORS || bitmap.len() < bitmap_words(entries.len()) {
            return Err(Error::InvalidArgument);
        }
        let mut result = Self::empty();
        let mut count = entries.len();
        let mut offset = 0;
        while count > 0 {
            count = count.div_ceil(64);
            result.offsets[result.levels] = offset;
            result.sizes[result.levels] = count;
            result.levels += 1;
            offset += count;
            if count == 1 {
                break;
            }
        }
        result.entries = entries;
        result.bitmap = bitmap;
        Ok(result)
    }
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }
    fn empty() -> Self {
        Self {
            entries: &[],
            bitmap: &[],
            offsets: [0; MAX_LEVELS],
            sizes: [0; MAX_LEVELS],
            levels: 0,
        }
    }
    fn get(&self, fd: usize) -> Option<Entry> {
        #[cfg(test)]
        SLOT_READS.with(|n| n.set(n.get() + 1));
        self.entries
            .get(fd)
            .and_then(|slot| decode_entry(slot.0.load(Ordering::Relaxed)))
    }
    fn set(&self, fd: usize, entry: Option<Entry>) {
        self.entries[fd]
            .0
            .store(encode_entry(entry), Ordering::Relaxed);
        self.mark_free(fd, entry.is_none());
    }
    fn clear(&self) {
        for slot in self.entries {
            slot.0.store(0, Ordering::Relaxed);
        }
        self.rebuild();
    }
    fn rebuild(&self) {
        for word in &self.bitmap[..bitmap_words(self.capacity())] {
            word.store(0, Ordering::Relaxed);
        }
        for (fd, slot) in self.entries.iter().enumerate() {
            if slot.0.load(Ordering::Relaxed) & SLOT_INDEX == 0 {
                self.bitmap[fd / 64].fetch_or(1 << (fd % 64), Ordering::Relaxed);
            }
        }
        for level in 1..self.levels {
            for word in 0..self.sizes[level - 1] {
                if self.bitmap[self.offsets[level - 1] + word].load(Ordering::Relaxed) != 0 {
                    self.bitmap[self.offsets[level] + word / 64]
                        .fetch_or(1 << (word % 64), Ordering::Relaxed);
                }
            }
        }
    }
    fn mark_free(&self, mut bit: usize, mut free: bool) {
        for level in 0..self.levels {
            let word = bit / 64;
            let cell = &self.bitmap[self.offsets[level] + word];
            let mask = 1u64 << (bit % 64);
            let value = if free {
                cell.load(Ordering::Relaxed) | mask
            } else {
                cell.load(Ordering::Relaxed) & !mask
            };
            cell.store(value, Ordering::Relaxed);
            free = value != 0;
            bit = word;
        }
    }
    // Search one partial word, ascend to a nonempty sibling and descend.
    // At most 2*levels-1 word reads, independent of occupancy or hole position.
    fn next_bit(&self, level: usize, min: usize, reads: &mut usize) -> Option<usize> {
        let word = min / 64;
        if level >= self.levels || word >= self.sizes[level] {
            return None;
        }
        *reads += 1;
        #[cfg(test)]
        BITMAP_READS.with(|n| n.set(n.get() + 1));
        let bits = self.bitmap[self.offsets[level] + word].load(Ordering::Relaxed)
            & (u64::MAX << (min % 64));
        if bits != 0 {
            return Some(word * 64 + bits.trailing_zeros() as usize);
        }
        let next = self.next_bit(level + 1, word + 1, reads)?;
        *reads += 1;
        #[cfg(test)]
        BITMAP_READS.with(|n| n.set(n.get() + 1));
        Some(
            next * 64
                + self.bitmap[self.offsets[level] + next]
                    .load(Ordering::Relaxed)
                    .trailing_zeros() as usize,
        )
    }
}
struct Table<'a> {
    storage: TableStorage<'a>,
    limit: usize,
}
impl Table<'_> {
    fn lowest(&self, min: usize) -> (Option<usize>, usize) {
        if min >= self.limit {
            return (None, 0);
        }
        let mut reads = 0;
        let fd = self
            .storage
            .next_bit(0, min, &mut reads)
            .filter(|fd| *fd < self.limit);
        (fd, reads)
    }
    fn allocate(&self, min: usize) -> Result<usize, Error> {
        if let Some(fd) = self.lowest(min).0 {
            return Ok(fd);
        }
        let next = min.max(self.storage.capacity());
        if next < self.limit {
            Err(Error::NeedsBacking {
                descriptors: next + 1,
            })
        } else {
            Err(Error::TooManyFiles)
        }
    }
    fn entry(&self, fd: Fd) -> Result<Entry, Error> {
        usize::try_from(fd.0)
            .ok()
            .and_then(|fd| self.storage.get(fd))
            .ok_or(Error::BadFd)
    }
}

const TABLE_FREE: u32 = 0;
const TABLE_LIVE: u32 = 1;
const FREE_INDEX: u64 = u32::MAX as u64;
const REF: u64 = 1 << 32;
const PIN: u64 = 1;

/// One table identity in shared memory. `lock` serializes every operation
/// that changes the table's slots; the other words are written only under
/// it. `seq` covers `state`, `generation`, the extent and multi-slot pair
/// publication (odd while a writer changes them): descriptor lookups ([`Authority::get`],
/// [`Authority::pin`]) take no lock, they read those words and the slot and
/// validate `seq`, so a lock holder stopped mid-section (a vCPU the host
/// took out of the guest) never stalls or refuses a lookup.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct TableRecord {
    lock: AtomicU32,
    state: AtomicU32,
    generation: AtomicU64,
    limit: AtomicU64,
    extent_token: AtomicU64,
    extent_capacity: AtomicU64,
    next_free: AtomicU64,
    seq: AtomicU64,
    _reserved: u64,
}
impl TableRecord {
    /// Under the table lock, before changing `state`, `generation` or the
    /// extent: lookups from here on retry.
    fn begin_write(&self) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq | 1, Ordering::Relaxed);
        fence(Ordering::Release);
    }
    /// Under the table lock, after the change: publish it.
    fn end_write(&self) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store((seq | 1) + 1, Ordering::Release);
    }
    /// A lookup that began at `seq` saw no concurrent writer.
    fn unchanged_since(&self, seq: u64) -> bool {
        fence(Ordering::Acquire);
        self.seq.load(Ordering::Relaxed) == seq
    }
}

/// One open file description in shared memory. `holds` packs descriptor
/// references (high 32 bits) and pins (low 32 bits): whoever moves it to
/// zero performs the one final release. `generation` advances when the
/// record is freed, so stale keys and pins never match a reuse.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct OfdRecord {
    generation: AtomicU64,
    holds: AtomicU64,
    backing: AtomicU64,
    offset: AtomicU64,
    mode: AtomicU64,
    immutable: AtomicU64,
    next_free: AtomicU64,
    _reserved: u64,
}

const MODE_ACCESS: u64 = 3;
const MODE_APPEND: u64 = 1 << 8;
const MODE_NONBLOCK: u64 = 1 << 9;
const MODE_ASYNC: u64 = 1 << 10;
const MODE_DIRECT: u64 = 1 << 11;
const MODE_NOATIME: u64 = 1 << 12;
const MODE_DSYNC: u64 = 1 << 13;
const MODE_SYNC: u64 = 1 << 14;
const MODE_MUTABLE: u64 = MODE_APPEND | MODE_NONBLOCK | MODE_ASYNC | MODE_DIRECT | MODE_NOATIME;

fn encode_mode(access: AccessMode, f: StatusFlags) -> u64 {
    let access = match access {
        AccessMode::ReadOnly => 0,
        AccessMode::WriteOnly => 1,
        AccessMode::ReadWrite => 2,
        AccessMode::Path => 3,
    };
    let bit = |set: bool, bit: u64| if set { bit } else { 0 };
    access
        | bit(f.append, MODE_APPEND)
        | bit(f.nonblock, MODE_NONBLOCK)
        | bit(f.asynchronous, MODE_ASYNC)
        | bit(f.direct, MODE_DIRECT)
        | bit(f.noatime, MODE_NOATIME)
        | bit(f.dsync, MODE_DSYNC)
        | bit(f.sync, MODE_SYNC)
}
fn decode_mode(mode: u64, immutable: u64) -> (AccessMode, StatusFlags) {
    let access = match mode & MODE_ACCESS {
        0 => AccessMode::ReadOnly,
        1 => AccessMode::WriteOnly,
        2 => AccessMode::ReadWrite,
        _ => AccessMode::Path,
    };
    let has = |bit: u64| mode & bit != 0;
    (
        access,
        StatusFlags {
            append: has(MODE_APPEND),
            nonblock: has(MODE_NONBLOCK),
            asynchronous: has(MODE_ASYNC),
            direct: has(MODE_DIRECT),
            noatime: has(MODE_NOATIME),
            dsync: has(MODE_DSYNC),
            sync: has(MODE_SYNC),
            immutable,
        },
    )
}

/// Venue-backed descriptor capacity and T table identities as one `repr(C)`
/// object of atomics. Open file descriptions live in venue memory
/// ([`SlotBacking::ofd`]) and grow elastically: the core records how many
/// the venue has published and keeps their free list. All-zero memory is a
/// valid *unpublished* core; exactly one initialization venue calls
/// [`Core::initialize`] (in shared memory: the host, before EL1 attaches).
/// Not Clone: copying the authority would duplicate backing ownership.
#[repr(C, align(64))]
pub struct Core<const T: usize> {
    identity: AtomicU64,
    free_tables: AtomicU64,
    free_ofds: AtomicU64,
    /// OFD records published by the venue ([`Authority::publish_ofds`]):
    /// indices below it resolve; it only grows.
    ofd_count: AtomicU64,
    _reserved: [u64; 4],
    tables: [TableRecord; T],
}

/// Layout facts a shared-memory venue folds into its ABI layout hash.
pub const LAYOUT_FACTS: [u64; 13] = [
    core::mem::size_of::<TableRecord>() as u64,
    core::mem::align_of::<TableRecord>() as u64,
    core::mem::size_of::<OfdRecord>() as u64,
    core::mem::align_of::<OfdRecord>() as u64,
    core::mem::size_of::<DescriptorSlot>() as u64,
    core::mem::offset_of!(TableRecord, extent_capacity) as u64,
    core::mem::offset_of!(OfdRecord, holds) as u64,
    core::mem::offset_of!(OfdRecord, mode) as u64,
    SLOT_CLOEXEC,
    MODE_MUTABLE,
    core::mem::offset_of!(Core<1>, ofd_count) as u64,
    core::mem::offset_of!(TableRecord, seq) as u64,
    core::mem::offset_of!(Core<1>, tables) as u64,
];

/// A tagged lock-free stack of free record indices, for venue record arrays
/// in shared memory: `head` holds the ABA tag (high 32 bits) and the top
/// index + 1 (low 32 bits, 0 = empty); each record's `link` holds the next
/// index + 1. Push and pop never block, so a final release can always free
/// its record, even from EL1.
pub mod free_list {
    use super::{AtomicU64, Ordering};
    const INDEX: u64 = u32::MAX as u64;

    /// Pop the top index; `link(i)` reads record `i`'s link (None: out of range).
    pub fn pop(head: &AtomicU64, link: impl Fn(usize) -> Option<u64>) -> Option<usize> {
        loop {
            let current = head.load(Ordering::Acquire);
            let top = current & INDEX;
            if top == 0 {
                return None;
            }
            let index = (top - 1) as usize;
            let successor = link(index)? & INDEX;
            let tag = (current >> 32).wrapping_add(1) << 32;
            if head
                .compare_exchange(
                    current,
                    tag | successor,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(index);
            }
        }
    }
    /// Push `index`, whose record link is `link`.
    pub fn push(head: &AtomicU64, index: usize, link: &AtomicU64) {
        loop {
            let current = head.load(Ordering::Acquire);
            link.store(current & INDEX, Ordering::Relaxed);
            let tag = (current >> 32).wrapping_add(1) << 32;
            if head
                .compare_exchange(
                    current,
                    tag | (index as u64 + 1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
        }
    }
}
use free_list::{pop, push};

impl<const T: usize> Core<T> {
    /// A published core for a single address space (host-only venues and
    /// tests), with a process-unique identity and no OFD records yet.
    pub fn new() -> Result<Self, Error> {
        let core = Self {
            identity: AtomicU64::new(0),
            free_tables: AtomicU64::new(0),
            free_ofds: AtomicU64::new(0),
            ofd_count: AtomicU64::new(0),
            _reserved: [0; 4],
            tables: core::array::from_fn(|_| TableRecord::default()),
        };
        let identity = NEXT_AUTHORITY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::NoMemory)?;
        core.initialize(identity)?;
        Ok(core)
    }

    /// Publish a zeroed core in place with a nonzero `identity` chosen by the
    /// one initialization venue (unique among authorities it serves). Links
    /// the table free list, then publishes the identity with Release; a core
    /// whose identity reads zero is unpublished and every operation fails
    /// closed. OFD records are published separately, as the venue grows
    /// ([`Authority::publish_ofds`]).
    pub fn initialize(&self, identity: u64) -> Result<(), Error> {
        if identity == 0
            || T >= FREE_INDEX as usize
            || T.checked_mul(MAX_DESCRIPTORS)
                .is_none_or(|n| n == usize::MAX)
            || self.identity.load(Ordering::Acquire) != 0
        {
            return Err(Error::InvalidArgument);
        }
        for i in (0..T).rev() {
            push(&self.free_tables, i, &self.tables[i].next_free);
        }
        self.identity.store(identity, Ordering::Release);
        Ok(())
    }

    pub fn identity(&self) -> u64 {
        self.identity.load(Ordering::Acquire)
    }

    /// OFD records the venue has published (indices `0..ofd_count`).
    pub fn ofd_count(&self) -> usize {
        self.ofd_count.load(Ordering::Acquire) as usize
    }

    /// Operate on this core with a venue's slot resolution and lock policy.
    pub fn bind<'a, B: SlotBacking, W: LockWait>(
        &'a self,
        backing: &'a B,
        wait: W,
    ) -> Authority<'a, B, W, T> {
        Authority {
            core: self,
            backing,
            wait,
        }
    }
}

/// A venue's view of a [`Core`]: every descriptor operation. Operations lock
/// exactly the tables they touch; OFD references, pins and free lists are
/// lock-free words. No operation allocates, sleeps or calls out except the
/// release callbacks documented per method.
pub struct Authority<'a, B: SlotBacking, W: LockWait, const T: usize> {
    core: &'a Core<T>,
    backing: &'a B,
    wait: W,
}

/// An authenticated slot-table mutation scope. Drop releases its one table
/// lock; no host types or storage references escape. Keep the scope strictly
/// around descriptor mutation, never user copy, I/O, service or suspension.
/// Each method commits wholly or refuses before publishing any slot.
#[must_use = "drop releases the table mutation lock"]
pub struct SlotTableTransaction<'view, 'core, B: SlotBacking, W: LockWait, const T: usize> {
    authority: &'view Authority<'core, B, W, T>,
    guard: Locked<'core>,
    table: Table<'core>,
    #[cfg(test)]
    after_first_publication: Option<fn(&Self)>,
}

impl<B: SlotBacking, W: LockWait, const T: usize> SlotTableTransaction<'_, '_, B, W, T> {
    /// Publish two prepared descriptions in the lowest free slots at or above
    /// `min` (reader then writer for pipe2). The pins remain caller-owned on
    /// both success and refusal. Provision backing and prepare user copy
    /// outside this scope; release the preparation pins after publication.
    /// Lock-free lookups cannot observe a half-published pair.
    pub fn install_pair(
        &mut self,
        min: Fd,
        pins: [&OfdPin; 2],
        cloexec: bool,
    ) -> Result<[Fd; 2], Error> {
        if min.0 < 0 {
            return Err(Error::InvalidArgument);
        }
        let c = self.authority;
        c.check_pin(pins[0])?;
        c.check_pin(pins[1])?;
        let first = self.table.allocate(min.0 as usize)?;
        // No bitmap/slot change during preparation: the next lowest hole is
        // strictly above the first, so two searches suffice without a scan.
        let second = self.table.allocate(first + 1)?;
        c.retain(pins[0].key.index, REF)?;
        if let Err(error) = c.retain(pins[1].key.index, REF) {
            // The preparation pin prevents this rollback being a final hold.
            c.drop_hold(pins[0].key.index, REF)?;
            return Err(error);
        }
        self.guard.record.begin_write();
        for (fd, pin) in [(first, pins[0]), (second, pins[1])] {
            self.table.storage.set(
                fd,
                Some(Entry {
                    ofd: pin.key.index,
                    cloexec,
                }),
            );
            #[cfg(test)]
            if fd == first
                && let Some(probe) = self.after_first_publication
            {
                probe(self);
            }
        }
        self.guard.record.end_write();
        Ok([Fd(first as i32), Fd(second as i32)])
    }
}

struct Locked<'a> {
    record: &'a TableRecord,
}
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.record.lock.store(0, Ordering::Release);
    }
}

impl<'a, B: SlotBacking, W: LockWait, const T: usize> Authority<'a, B, W, T> {
    /// Authenticate and lock one table for a typed mutation transaction.
    /// CLONE_FILES clients use the same TableId; no second table is created.
    pub fn transaction(
        &self,
        table: TableId,
    ) -> Result<SlotTableTransaction<'_, 'a, B, W, T>, Error> {
        let (guard, table) = self.lock(table)?;
        Ok(SlotTableTransaction {
            authority: self,
            guard,
            table,
            #[cfg(test)]
            after_first_publication: None,
        })
    }
    fn identity(&self) -> Result<u64, Error> {
        match self.core.identity.load(Ordering::Acquire) {
            0 => Err(Error::StaleTable),
            id => Ok(id),
        }
    }

    fn acquire(&self, record: &'a TableRecord) -> Result<Locked<'a>, Error> {
        let mut attempt: u32 = 0;
        loop {
            if record
                .lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(Locked { record });
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(Error::Contended);
            }
        }
    }

    fn storage(&self, extent: Extent) -> Result<TableStorage<'a>, Error> {
        if extent.capacity == 0 {
            return Ok(TableStorage::empty());
        }
        let (entries, bitmap) = self.backing.resolve(extent).ok_or(Error::BadBacking)?;
        if entries.len() as u64 != extent.capacity {
            return Err(Error::BadBacking);
        }
        TableStorage::new(entries, bitmap).map_err(|_| Error::BadBacking)
    }

    fn record_extent(record: &TableRecord) -> Extent {
        Extent {
            token: record.extent_token.load(Ordering::Relaxed),
            capacity: record.extent_capacity.load(Ordering::Relaxed),
        }
    }

    /// Lock `id`'s table and resolve its storage; authenticates authority,
    /// index, liveness and generation after the lock is held.
    fn lock(&self, id: TableId) -> Result<(Locked<'a>, Table<'a>), Error> {
        if id.authority != self.identity()? {
            return Err(Error::StaleTable);
        }
        let record = self.core.tables.get(id.index).ok_or(Error::StaleTable)?;
        let guard = self.acquire(record)?;
        if record.state.load(Ordering::Acquire) != TABLE_LIVE
            || record.generation.load(Ordering::Relaxed) != id.generation
        {
            return Err(Error::StaleTable);
        }
        let table = Table {
            storage: self.storage(Self::record_extent(record))?,
            limit: record.limit.load(Ordering::Relaxed) as usize,
        };
        Ok((guard, table))
    }

    /// A published OFD record. Indices come from slots this authority wrote,
    /// from checked pins or from its free list, so a failure is a venue bug
    /// (fail closed).
    fn ofd(&self, index: u32) -> Result<&'a OfdRecord, Error> {
        if u64::from(index) >= self.core.ofd_count.load(Ordering::Acquire) {
            return Err(Error::BadBacking);
        }
        self.backing.ofd(index as usize).ok_or(Error::BadBacking)
    }

    fn snapshot(&self, index: u32) -> Result<Description, Error> {
        let ofd = self.ofd(index)?;
        let (access, flags) = decode_mode(
            ofd.mode.load(Ordering::Acquire),
            ofd.immutable.load(Ordering::Relaxed),
        );
        Ok(Description {
            backing: BackingToken(ofd.backing.load(Ordering::Relaxed)),
            offset: Offset(ofd.offset.load(Ordering::Acquire)),
            access,
            flags,
        })
    }

    /// Publish `count` more OFD records: the venue has made records
    /// `ofd_count()..ofd_count() + count` resolvable, zero-filled and used by
    /// nothing else. The count is published (Release) before the records
    /// join the free list, so every index the list hands out resolves. The
    /// one growth venue serializes its calls; a concurrent publication
    /// refuses with `Contended` and changes nothing. O(count), outside any
    /// table lock.
    pub fn publish_ofds(&self, count: usize) -> Result<(), Error> {
        self.identity()?;
        let first = self.core.ofd_count.load(Ordering::Acquire);
        let end = first
            .checked_add(count as u64)
            .filter(|end| *end < FREE_INDEX)
            .ok_or(Error::InvalidArgument)?;
        if count == 0 {
            return Ok(());
        }
        for index in [first, end - 1] {
            let record = self.backing.ofd(index as usize).ok_or(Error::BadBacking)?;
            if record.holds.load(Ordering::Relaxed) != 0 {
                return Err(Error::BadBacking);
            }
        }
        self.core
            .ofd_count
            .compare_exchange(first, end, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Contended)?;
        for index in (first..end).rev() {
            let record = self.ofd(index as u32)?;
            push(&self.core.free_ofds, index as usize, &record.next_free);
        }
        Ok(())
    }

    fn alloc_ofd(&self, description: Description) -> Result<u32, Error> {
        let index = pop(&self.core.free_ofds, |i| {
            self.ofd(u32::try_from(i).ok()?)
                .ok()
                .map(|o| o.next_free.load(Ordering::Relaxed))
        })
        .ok_or(Error::NeedsOfds)?;
        let index = u32::try_from(index).map_err(|_| Error::BadBacking)?;
        let ofd = self.ofd(index)?;
        ofd.backing.store(description.backing.0, Ordering::Relaxed);
        ofd.offset.store(description.offset.0, Ordering::Relaxed);
        ofd.immutable
            .store(description.flags.immutable, Ordering::Relaxed);
        ofd.mode.store(
            encode_mode(description.access, description.flags),
            Ordering::Relaxed,
        );
        ofd.holds.store(REF, Ordering::Release);
        Ok(index)
    }

    fn free_ofd(&self, index: u32) -> Result<(), Error> {
        let ofd = self.ofd(index)?;
        // A generation that cannot advance retires the record (fail closed).
        if ofd.generation.fetch_add(1, Ordering::AcqRel) < u64::MAX - 1 {
            push(&self.core.free_ofds, index as usize, &ofd.next_free);
        }
        Ok(())
    }

    /// Add one descriptor reference or pin; refuses to resurrect a finalized
    /// description or overflow either half.
    fn retain(&self, index: u32, amount: u64) -> Result<(), Error> {
        let holds = &self.ofd(index)?.holds;
        let mut current = holds.load(Ordering::Relaxed);
        loop {
            let half = if amount == REF {
                current >> 32
            } else {
                current & FREE_INDEX
            };
            if current == 0 || half == FREE_INDEX {
                return Err(Error::NoMemory);
            }
            match holds.compare_exchange_weak(
                current,
                current + amount,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(seen) => current = seen,
            }
        }
    }

    /// [`Self::retain`] for a lookup that may race the final release:
    /// `Ok(false)` when the record was already finalized (nothing changed),
    /// `NoMemory` only when the live description's half is saturated.
    fn retain_unless_final(&self, index: u32, amount: u64) -> Result<bool, Error> {
        let holds = &self.ofd(index)?.holds;
        let mut current = holds.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return Ok(false);
            }
            let half = if amount == REF {
                current >> 32
            } else {
                current & FREE_INDEX
            };
            if half == FREE_INDEX {
                return Err(Error::NoMemory);
            }
            match holds.compare_exchange_weak(
                current,
                current + amount,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(true),
                Err(seen) => current = seen,
            }
        }
    }

    /// Drop one reference or pin; the caller that reaches zero receives the
    /// description and frees the record (exactly once).
    fn drop_hold(&self, index: u32, amount: u64) -> Result<Option<Description>, Error> {
        let holds = &self.ofd(index)?.holds;
        let mut current = holds.load(Ordering::Relaxed);
        loop {
            let half = if amount == REF {
                current >> 32
            } else {
                current & FREE_INDEX
            };
            if half == 0 {
                return Err(Error::StalePin);
            }
            match holds.compare_exchange_weak(
                current,
                current - amount,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        if current != amount {
            return Ok(None);
        }
        let released = self.snapshot(index)?;
        self.free_ofd(index)?;
        Ok(Some(released))
    }

    fn close_locked(&self, table: &Table<'a>, fd: Fd) -> Result<Option<Description>, Error> {
        let entry = table.entry(fd)?;
        table.storage.set(fd.0 as usize, None);
        self.drop_hold(entry.ofd, REF)
    }

    fn publish(&self, index: usize, limit: usize, storage: Extent) -> TableId {
        let record = &self.core.tables[index];
        let generation = record.generation.load(Ordering::Relaxed) + 1;
        record.begin_write();
        record.limit.store(limit as u64, Ordering::Relaxed);
        record.extent_token.store(storage.token, Ordering::Relaxed);
        record
            .extent_capacity
            .store(storage.capacity, Ordering::Relaxed);
        record.generation.store(generation, Ordering::Relaxed);
        record.state.store(TABLE_LIVE, Ordering::Release);
        record.end_write();
        TableId {
            authority: self.core.identity.load(Ordering::Relaxed),
            index,
            generation,
        }
    }

    fn pop_table(&self) -> Result<usize, Error> {
        let tables = &self.core.tables;
        pop(&self.core.free_tables, |i| {
            tables.get(i).map(|t| t.next_free.load(Ordering::Relaxed))
        })
        .ok_or(Error::NoMemory)
    }

    fn push_table(&self, index: usize) {
        let record = &self.core.tables[index];
        // Exhausted table IDs fail closed: the slot is never reused.
        if record.generation.load(Ordering::Relaxed) < u64::MAX {
            push(&self.core.free_tables, index, &record.next_free);
        }
    }

    /// Create an empty table over `storage`, consumed (swapped for
    /// [`Extent::EMPTY`]) only on success.
    pub fn create_table(&self, limit: usize, storage: &mut Extent) -> Result<TableId, Error> {
        self.identity()?;
        if limit > MAX_DESCRIPTORS {
            return Err(Error::InvalidArgument);
        }
        let view = self.storage(*storage)?;
        let index = self.pop_table()?;
        let guard = match self.acquire(&self.core.tables[index]) {
            Ok(guard) => guard,
            Err(e) => {
                self.push_table(index);
                return Err(e);
            }
        };
        view.clear();
        let id = self.publish(index, limit, core::mem::take(storage));
        drop(guard);
        Ok(id)
    }
    /// Changing the soft limit never closes existing descriptors above it.
    /// The venue validates RLIMIT_NOFILE against its hard limit and nr_open;
    /// neither soft nor hard limits are constrained by currently supplied backing.
    pub fn set_limit(&self, table: TableId, limit: usize) -> Result<(), Error> {
        if limit > MAX_DESCRIPTORS {
            return Err(Error::InvalidArgument);
        }
        let (guard, _) = self.lock(table)?;
        guard.record.limit.store(limit as u64, Ordering::Relaxed);
        Ok(())
    }
    /// Install a newly opened description. On error the caller still owns backing.
    pub fn open(
        &self,
        table: TableId,
        min: Fd,
        description: Description,
        cloexec: bool,
    ) -> Result<Fd, Error> {
        if min.0 < 0 {
            return Err(Error::InvalidArgument);
        }
        let (_guard, t) = self.lock(table)?;
        let fd = t.allocate(min.0 as usize)?;
        let ofd = self.alloc_ofd(description)?;
        t.storage.set(fd, Some(Entry { ofd, cloexec }));
        Ok(Fd(fd as i32))
    }
    /// O(1) read-only snapshot, taking no lock (see [`TableRecord`]); it
    /// retains nothing. `Contended` only while a writer keeps changing the
    /// table's extent or identity past the wait policy.
    pub fn get(&self, table: TableId, fd: Fd) -> Result<Description, Error> {
        let mut attempt: u32 = 0;
        loop {
            let (record, seq, storage) = self.read_table(table)?;
            let entry = Self::slot(&storage, fd);
            let snapshot = entry.map(|e| self.snapshot(e.ofd)).transpose();
            if Self::slot(&storage, fd) == entry && record.unchanged_since(seq) {
                return snapshot?.ok_or(Error::BadFd);
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(Error::Contended);
            }
        }
    }

    /// The lock-free view of `id`'s table: its record, the `seq` it was read
    /// at, and its slots. Every use validates with `unchanged_since(seq)`;
    /// a retired extent's bytes are never trusted past that check.
    fn read_table(&self, id: TableId) -> Result<(&'a TableRecord, u64, TableStorage<'a>), Error> {
        if id.authority != self.identity()? {
            return Err(Error::StaleTable);
        }
        let record = self.core.tables.get(id.index).ok_or(Error::StaleTable)?;
        let mut attempt: u32 = 0;
        loop {
            let seq = record.seq.load(Ordering::Acquire);
            if seq & 1 == 0 {
                let live = record.state.load(Ordering::Relaxed) == TABLE_LIVE
                    && record.generation.load(Ordering::Relaxed) == id.generation;
                let extent = Self::record_extent(record);
                if record.unchanged_since(seq) {
                    if !live {
                        return Err(Error::StaleTable);
                    }
                    return Ok((record, seq, self.storage(extent)?));
                }
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(Error::Contended);
            }
        }
    }

    fn slot(storage: &TableStorage<'_>, fd: Fd) -> Option<Entry> {
        usize::try_from(fd.0).ok().and_then(|fd| storage.get(fd))
    }
    /// Descriptor references to `fd`'s description (pins are not counted).
    pub fn refcount(&self, table: TableId, fd: Fd) -> Result<usize, Error> {
        let (_guard, t) = self.lock(table)?;
        let holds = self.ofd(t.entry(fd)?.ofd)?.holds.load(Ordering::Acquire);
        Ok((holds >> 32) as usize)
    }
    pub fn set_offset(&self, table: TableId, fd: Fd, offset: Offset) -> Result<(), Error> {
        let (_guard, t) = self.lock(table)?;
        let ofd = self.ofd(t.entry(fd)?.ofd)?;
        ofd.offset.store(offset.0, Ordering::Release);
        Ok(())
    }
    pub fn getfd(&self, table: TableId, fd: Fd) -> Result<bool, Error> {
        let (_guard, t) = self.lock(table)?;
        Ok(t.entry(fd)?.cloexec)
    }
    pub fn setfd(&self, table: TableId, fd: Fd, cloexec: bool) -> Result<(), Error> {
        let (_guard, t) = self.lock(table)?;
        let mut entry = t.entry(fd)?;
        entry.cloexec = cloexec;
        t.storage.set(fd.0 as usize, Some(entry));
        Ok(())
    }
    pub fn getfl(&self, table: TableId, fd: Fd) -> Result<(AccessMode, StatusFlags), Error> {
        let d = self.get(table, fd)?;
        Ok((d.access, d.flags))
    }
    /// Only Linux's five mutable status flags change. Venue authorizes append-only,
    /// NOATIME ownership, DIRECT support and asynchronous notification before commit.
    /// The flags word is shared by every table naming the description (fork,
    /// SCM_RIGHTS) and updated atomically.
    pub fn setfl(&self, table: TableId, fd: Fd, flags: StatusFlags) -> Result<(), Error> {
        let (_guard, t) = self.lock(table)?;
        let ofd = self.ofd(t.entry(fd)?.ofd)?;
        Self::set_ofd_flags(ofd, flags)
    }

    fn set_ofd_flags(ofd: &OfdRecord, flags: StatusFlags) -> Result<(), Error> {
        let requested = encode_mode(AccessMode::ReadOnly, flags) & MODE_MUTABLE;
        let mut current = ofd.mode.load(Ordering::Acquire);
        loop {
            if current & MODE_ACCESS == 3 {
                return Err(Error::BadFd);
            }
            let next = (current & !MODE_MUTABLE) | requested;
            match ofd
                .mode
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(seen) => current = seen,
            }
        }
    }
    pub fn dup(&self, table: TableId, old: Fd) -> Result<Fd, Error> {
        let (_guard, t) = self.lock(table)?;
        self.duplicate_min(&t, old, 0, false)
    }
    /// F_DUPFD and F_DUPFD_CLOEXEC. A minimum outside the soft limit is EINVAL.
    pub fn dupfd(&self, table: TableId, old: Fd, min: Fd, cloexec: bool) -> Result<Fd, Error> {
        let (_guard, t) = self.lock(table)?;
        t.entry(old)?;
        if min.0 < 0 || min.0 as usize >= t.limit {
            return Err(Error::InvalidArgument);
        }
        self.duplicate_min(&t, old, min.0 as usize, cloexec)
    }
    fn duplicate_min(
        &self,
        t: &Table<'a>,
        old: Fd,
        min: usize,
        cloexec: bool,
    ) -> Result<Fd, Error> {
        let entry = t.entry(old)?;
        let fd = t.allocate(min)?;
        self.retain(entry.ofd, REF)?;
        t.storage.set(
            fd,
            Some(Entry {
                ofd: entry.ofd,
                cloexec,
            }),
        );
        Ok(Fd(fd as i32))
    }
    /// Atomically replace new; return the displaced OFD only on its last ref.
    /// Same-fd dup2 succeeds even after the soft limit was lowered below old.
    pub fn dup2(&self, table: TableId, old: Fd, new: Fd) -> Result<Option<Description>, Error> {
        let (_guard, t) = self.lock(table)?;
        t.entry(old)?;
        if old == new {
            return Ok(None);
        }
        self.duplicate_exact(&t, old, new, false)
    }
    /// The personality rejects all raw flags except O_CLOEXEC before calling.
    pub fn dup3(
        &self,
        table: TableId,
        old: Fd,
        new: Fd,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        if old == new {
            return Err(Error::InvalidArgument);
        }
        let (_guard, t) = self.lock(table)?;
        self.duplicate_exact(&t, old, new, cloexec)
    }
    fn duplicate_exact(
        &self,
        t: &Table<'a>,
        old: Fd,
        new: Fd,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        let entry = t.entry(old)?;
        self.replace_exact(t, entry.ofd, new, cloexec)
    }

    fn replace_exact(
        &self,
        t: &Table<'a>,
        ofd: u32,
        new: Fd,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        if new.0 < 0 || new.0 as usize >= t.limit {
            return Err(Error::BadFd);
        }
        if new.0 as usize >= t.storage.capacity() {
            return Err(Error::NeedsBacking {
                descriptors: new.0 as usize + 1,
            });
        }
        // Retain first, so replacing an alias cannot temporarily finalize it.
        self.retain(ofd, REF)?;
        let released = match self.close_locked(t, new) {
            Ok(d) => d,
            Err(Error::BadFd) => None,
            Err(e) => return Err(e),
        };
        t.storage.set(new.0 as usize, Some(Entry { ofd, cloexec }));
        Ok(released)
    }
    /// Remove `fd`. Returns the description exactly when this removed its
    /// final hold: a pinned description is released by its last
    /// [`Authority::unpin`] instead.
    #[must_use = "the last-reference description owns backing resources to release"]
    pub fn close(&self, table: TableId, fd: Fd) -> Result<Option<Description>, Error> {
        let (_guard, t) = self.lock(table)?;
        self.close_locked(&t, fd)
    }
    /// Inclusive range, bounded by storage even for last=u32::MAX.
    /// CLOSE_RANGE_UNSHARE is fork + venue publication + this operation; it
    /// cannot be implemented by mutating a CLONE_FILES table in place.
    /// `release` runs under the table's lock and must not reenter it.
    pub fn close_range(
        &self,
        table: TableId,
        first: u32,
        last: u32,
        cloexec: bool,
        mut release: impl FnMut(Description),
    ) -> Result<(), Error> {
        if first > last {
            return Err(Error::InvalidArgument);
        }
        let (_guard, t) = self.lock(table)?;
        let end = (u64::from(last) + 1).min(t.storage.capacity() as u64) as usize;
        for fd in first as usize..end {
            let Some(mut entry) = t.storage.get(fd) else {
                continue;
            };
            if cloexec {
                entry.cloexec = true;
                t.storage.set(fd, Some(entry));
            } else if let Some(d) = self.close_locked(&t, Fd(fd as i32))? {
                release(d);
            }
        }
        Ok(())
    }
    /// CLOSE_RANGE_UNSHARE: prepare a private successor without changing the
    /// old CLONE_FILES table. The venue must atomically publish the returned ID
    /// for the calling task and retire its old ownership under the same lock.
    /// Invalid ranges and exhausted table storage leave the source untouched.
    pub fn unshare_close_range(
        &self,
        table: TableId,
        first: u32,
        last: u32,
        cloexec: bool,
        release: impl FnMut(Description),
        storage: &mut Extent,
    ) -> Result<TableId, Error> {
        if first > last {
            return Err(Error::InvalidArgument);
        }
        let successor = self.fork(table, storage)?;
        self.close_range(successor, first, last, cloexec, release)?;
        Ok(successor)
    }
    /// Replace backing without changing table identity, entries or OFD refs.
    /// `storage` receives the retired extent, reusable or reclaimable after
    /// this call. Failure changes neither input nor installed storage.
    pub fn grow_table(&self, table: TableId, storage: &mut Extent) -> Result<(), Error> {
        let (guard, t) = self.lock(table)?;
        if storage.capacity < t.storage.capacity() as u64 {
            return Err(Error::InvalidArgument);
        }
        let larger = self.storage(*storage)?;
        larger.clear();
        for (fd, slot) in t.storage.entries.iter().enumerate() {
            larger.entries[fd]
                .0
                .store(slot.0.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        larger.rebuild();
        let retired = Self::record_extent(guard.record);
        guard.record.begin_write();
        guard
            .record
            .extent_token
            .store(storage.token, Ordering::Relaxed);
        guard
            .record
            .extent_capacity
            .store(storage.capacity, Ordering::Relaxed);
        guard.record.end_write();
        *storage = retired;
        Ok(())
    }
    /// Copy descriptor flags/limit, retaining each OFD once per copied fd.
    /// Caller supplies backing at least as large as the parent's current backing.
    /// No partial retain or consumed storage on a capacity failure.
    pub fn fork(&self, parent: TableId, storage: &mut Extent) -> Result<TableId, Error> {
        let (_parent_guard, p) = self.lock(parent)?;
        let capacity = p.storage.capacity();
        if (storage.capacity as usize) < capacity {
            return Err(Error::NeedsBacking {
                descriptors: capacity,
            });
        }
        let child = self.storage(*storage)?;
        let index = self.pop_table()?;
        // The child is unpublished: only stale-ID holders can contend.
        let guard = match self.acquire(&self.core.tables[index]) {
            Ok(guard) => guard,
            Err(e) => {
                self.push_table(index);
                return Err(e);
            }
        };
        child.clear();
        for fd in 0..capacity {
            let Some(entry) = p.storage.get(fd) else {
                continue;
            };
            if let Err(e) = self.retain(entry.ofd, REF) {
                // Roll back every retain made so far; nothing was published.
                for undo in 0..fd {
                    if let Some(prior) = p.storage.get(undo) {
                        let _ = self.drop_hold(prior.ofd, REF);
                    }
                }
                drop(guard);
                self.push_table(index);
                return Err(e);
            }
            child.entries[fd]
                .0
                .store(encode_entry(Some(entry)), Ordering::Relaxed);
        }
        child.rebuild();
        let id = self.publish(index, p.limit, core::mem::take(storage));
        drop(guard);
        Ok(id)
    }
    /// Venue must unshare a CLONE_FILES table before exec; otherwise siblings
    /// would observe this sweep. Releases are delivered exactly once, under
    /// the table's lock.
    pub fn exec(&self, table: TableId, mut release: impl FnMut(Description)) -> Result<(), Error> {
        let (_guard, t) = self.lock(table)?;
        for fd in 0..t.storage.capacity() {
            if t.storage.get(fd).is_some_and(|e| e.cloexec)
                && let Some(d) = self.close_locked(&t, Fd(fd as i32))?
            {
                release(d);
            }
        }
        Ok(())
    }
    /// Call after the last CLONE_FILES owner exits (owner count is venue-owned).
    /// Returns the table's backing extent for the venue to reclaim.
    pub fn destroy_table(
        &self,
        table: TableId,
        mut release: impl FnMut(Description),
    ) -> Result<Extent, Error> {
        let (guard, t) = self.lock(table)?;
        for fd in 0..t.storage.capacity() {
            if t.storage.get(fd).is_some()
                && let Some(d) = self.close_locked(&t, Fd(fd as i32))?
            {
                release(d);
            }
        }
        let extent = Self::record_extent(guard.record);
        guard.record.begin_write();
        guard.record.extent_token.store(0, Ordering::Relaxed);
        guard.record.extent_capacity.store(0, Ordering::Relaxed);
        guard.record.state.store(TABLE_FREE, Ordering::Release);
        guard.record.end_write();
        drop(guard);
        self.push_table(table.index);
        Ok(extent)
    }

    /// Resolve `fd` and retain its exact description for an in-flight
    /// operation, taking no lock: read the slot, the named record's
    /// generation, the slot again (so that incarnation was the fd's), then
    /// add the pin and confirm the generation did not move (so the pin holds
    /// that incarnation, not a reuse). The pin linearizes at the second slot
    /// read, like a Linux `fget` racing `close`. Closing or reusing `fd`
    /// afterwards does not affect the pin; the description's final release
    /// waits for [`Authority::unpin`]. A pin that landed on a reused record
    /// is handed to the caller as [`Error::PinRaced`].
    pub fn pin(&self, table: TableId, fd: Fd) -> Result<(OfdPin, Description), Error> {
        let mut attempt: u32 = 0;
        loop {
            let (record, seq, storage) = self.read_table(table)?;
            let settled = |entry: Option<Entry>| {
                Self::slot(&storage, fd) == entry && record.unchanged_since(seq)
            };
            let entry = Self::slot(&storage, fd);
            let generation = match entry.map(|e| self.ofd(e.ofd)).transpose() {
                Ok(ofd) => ofd.map(|ofd| ofd.generation.load(Ordering::Acquire)),
                Err(error) if settled(entry) => return Err(error),
                Err(_) => None,
            };
            if settled(entry) {
                let (Some(entry), Some(generation)) = (entry, generation) else {
                    return Err(Error::BadFd);
                };
                match self.retain_unless_final(entry.ofd, PIN) {
                    Ok(true) => {
                        let ofd = self.ofd(entry.ofd)?;
                        if ofd.generation.load(Ordering::Acquire) == generation {
                            let pin = OfdPin {
                                authority: self.core.identity.load(Ordering::Relaxed),
                                key: OfdKey {
                                    index: entry.ofd,
                                    generation,
                                },
                            };
                            return Ok((pin, self.snapshot(entry.ofd)?));
                        }
                        // Freed and reused between the slot read and the pin.
                        return Err(Error::PinRaced(RawOfdPin {
                            authority: self.core.identity.load(Ordering::Relaxed),
                            index: u64::from(entry.ofd),
                            generation: ofd.generation.load(Ordering::Acquire),
                        }));
                    }
                    // Finalized since the slot read: the slot has moved on.
                    Ok(false) => {}
                    // Pins of a live description saturated: a real refusal.
                    Err(error) => return Err(error),
                }
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(Error::Contended);
            }
        }
    }

    fn check_pin(&self, pin: &OfdPin) -> Result<(), Error> {
        let ofd = self.ofd(pin.key.index).map_err(|_| Error::StalePin)?;
        if pin.authority != self.identity()?
            || ofd.generation.load(Ordering::Acquire) != pin.key.generation
            || ofd.holds.load(Ordering::Acquire) & FREE_INDEX == 0
        {
            return Err(Error::StalePin);
        }
        Ok(())
    }

    /// Current state of a pinned description (status flags may change while
    /// an operation is suspended, e.g. F_SETFL O_NONBLOCK from a sibling).
    pub fn pinned(&self, pin: &OfdPin) -> Result<Description, Error> {
        self.check_pin(pin)?;
        self.snapshot(pin.key.index)
    }

    /// Admit a description before installing a numeric descriptor. The pin
    /// owns its backing until installation or rollback; no scratch fd table
    /// or second description is needed for host admission and SCM_RIGHTS.
    pub fn create_pinned(&self, description: Description) -> Result<OfdPin, Error> {
        let authority = self.identity()?;
        let index = self.alloc_ofd(description)?;
        let ofd = self.ofd(index)?;
        // Newly allocated and unpublished: exchange the initial descriptor
        // hold for the caller's pin before exposing the OFD identity.
        ofd.holds.store(PIN, Ordering::Release);
        Ok(OfdPin {
            authority,
            key: OfdKey {
                index,
                generation: ofd.generation.load(Ordering::Acquire),
            },
        })
    }

    /// Install the SAME pinned description at an empty exact descriptor slot.
    /// Refuse occupied slots without replacement or mutation. The caller owns
    /// the target-table admission (including any external fd reservation).
    pub fn install_pin(
        &self,
        table: TableId,
        target: Fd,
        pin: &OfdPin,
        cloexec: bool,
    ) -> Result<(), Error> {
        self.check_pin(pin)?;
        let (_guard, t) = self.lock(table)?;
        if target.0 < 0 || target.0 as usize >= t.limit {
            return Err(Error::BadFd);
        }
        if target.0 as usize >= t.storage.capacity() {
            return Err(Error::NeedsBacking {
                descriptors: target.0 as usize + 1,
            });
        }
        if t.storage.get(target.0 as usize).is_some() {
            return Err(Error::TooManyFiles);
        }
        self.retain(pin.key.index, REF)?;
        t.storage.set(
            target.0 as usize,
            Some(Entry {
                ofd: pin.key.index,
                cloexec,
            }),
        );
        Ok(())
    }

    /// Atomically install a pinned description, replacing any target slot.
    /// Uses the same replacement transaction as dup2/dup3; no intermediate
    /// absent slot is visible. A displaced description is returned only on
    /// its final hold and must be released outside the table lock.
    #[must_use = "the displaced last-hold description owns backing resources"]
    pub fn replace_pin(
        &self,
        table: TableId,
        target: Fd,
        pin: &OfdPin,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        self.check_pin(pin)?;
        let (_guard, t) = self.lock(table)?;
        self.replace_exact(&t, pin.key.index, target, cloexec)
    }

    /// F_SETFL-class mutation through an owned description, independent of
    /// numeric fd reuse. Uses the same immutable/mutable mask as `setfl`.
    pub fn set_pinned_flags(&self, pin: &OfdPin, flags: StatusFlags) -> Result<(), Error> {
        self.check_pin(pin)?;
        Self::set_ofd_flags(self.ofd(pin.key.index)?, flags)
    }

    /// Release a pin. Returns the description exactly when this was its final
    /// hold (every descriptor was closed meanwhile); the caller then releases
    /// the backing, as after a final close. A stale pin changes nothing.
    #[must_use = "the last-hold description owns backing resources to release"]
    pub fn unpin(&self, pin: OfdPin) -> Result<Option<Description>, Error> {
        self.check_pin(&pin)?;
        self.drop_hold(pin.key.index, PIN)
    }

    /// Descriptor references and pins of a pinned description.
    pub fn holds(&self, pin: &OfdPin) -> Result<(usize, usize), Error> {
        self.check_pin(pin)?;
        let holds = self.ofd(pin.key.index)?.holds.load(Ordering::Acquire);
        Ok(((holds >> 32) as usize, (holds & FREE_INDEX) as usize))
    }

    #[cfg(all(test, not(feature = "loom")))]
    fn probe_lowest(&self, table: TableId, min: usize) -> (Option<usize>, usize, usize) {
        let Ok((_guard, t)) = self.lock(table) else {
            return (None, usize::MAX, 0);
        };
        let (found, reads) = t.lowest(min);
        (found, reads, t.storage.levels)
    }
}
