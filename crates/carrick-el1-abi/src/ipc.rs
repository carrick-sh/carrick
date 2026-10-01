//! Shared IPC records for checkpoint 3: the descriptor authority, pipe and
//! eventfd objects that the host and EL1 both operate on, in place.
//!
//! # ABI (v4: elastic stores)
//!
//! One directory mapping plus one byte *pool* hold every record. Both are
//! plain `repr(C)` memory with no pointers, `Arc`, `Mutex` or trait objects;
//! every cross-reference is a typed index + generation or a pool offset.
//! The directory mapping ([`IPC_DIRECTORY_BYTES`]) starts with the fixed
//! [`IpcDirectory`] and reserves, at fixed offsets, the elastic stores: the
//! object records ([`IPC_MAX_OBJECTS`]), the open-file-description records
//! ([`IPC_MAX_OFDS`]) and the leaf words of the owed-host-wake index. The
//! reservation is address space only: a store grows by *publishing* one
//! segment at a time (the growth venue, the host, links the new zeroed
//! records into the free list after publishing the count with Release), so
//! memory is committed in proportion to the records ever used, and both
//! venues resolve an index only below the published count. The ceilings are
//! the zone-wide file table's limit (ENFILE), not an allocation policy.
//!
//! - **Descriptors** — [`IpcFdCore`] (`carrick_fd_core::Core`): tables, open
//!   file descriptions (OFDs), descriptor-local CLOEXEC, shared status flags,
//!   reference and pin counts. A table's slots/bitmap live in a pool
//!   [`carrick_fd_core::Extent`] whose token is the pool offset.
//! - **Descriptions → objects** — an OFD's `BackingToken` encodes an
//!   [`IpcBacking`]: a pipe endpoint, an eventfd, or an opaque
//!   [`HostResourceToken`] for every description that stays host-backed.
//! - **Objects** — [`IpcObjectRecord`]: lock word, kind, generation, the
//!   readiness sequences, host-subscriber accounting, and the object state
//!   (`carrick_pipe_core::PipeRecord` or `EventFd`). A pipe's ring bytes and
//!   page metadata live in a pool [`IpcPipeStorage`] extent, attached at the
//!   pipe's first write (Linux allocates pipe pages on demand): until then
//!   the pipe is *unbacked* and costs only its record.
//! - **Continuations** — [`IpcOperation`]: the plain-data record an owned
//!   suspended operation keeps outside any stack, in an [`IpcOperationSlot`]
//!   named by the owned [`IpcOpToken`] `(index, generation)` that the
//!   scheduler stores with the parked thread.
//! - **Wait identity** — an object's wait queue is named by its
//!   [`IpcObjectHandle`] `(index, generation)` plus the lane
//!   (`pipe::WaitFor::{Readable, Writable}`); distinct from any futex key.
//!
//! Handles ([`IpcObjectHandle`], `TableId`, `OfdPin`) carry generations;
//! freeing an object, OFD or table advances its generation, so a stale handle
//! never resolves a reused slot, and an exhausted generation retires the slot.
//!
//! # Publication ordering
//!
//! 1. The initialization venue (the host) zeroes the directory and pool,
//!    calls [`IpcRegion::initialize`]: the fd core publishes its identity,
//!    the object free list is linked, header facts are written, and only then
//!    `state = READY` is stored with Release.
//! 2. Every other attach ([`IpcRegion::attach`], EL1 or another host
//!    thread) loads `state` with Acquire and authenticates magic, layout
//!    hash and pool length before touching anything else.
//! 3. An object is published by writing its state and storage, then its
//!    `kind` with Release; it is used only under its lock after checking
//!    kind and generation. Freeing stores `FREE` and advances the generation
//!    under the lock before the index returns to the free list.
//! 4. Readiness: every state change that wakes readers/writers advances
//!    `read_seq`/`write_seq` with Release *under the object lock*, before the
//!    lock is released; waiters sample them with Acquire (check → enroll →
//!    recheck). Wakes and host notifications happen after unlock.
//!
//! # Locks
//!
//! One lock word per fd table (inside the fd core) and one per object; an
//! object's lock word names its holder ([`IpcLockHolder`]). Descriptor
//! lookups and pins take no table lock (they validate the table's sequence
//! count), so a description is pinned before any object work; then one
//! object lock. EL1 waits for an EL1 holder (its section never waits on
//! another vCPU, and one a host kick stops mid-section is resumed to
//! completion on its vCPU), so another vCPU's transfer never turns this one
//! into a host round trip. A host holder may itself wait for this vCPU to
//! stop, so EL1 waits for it only a bounded while and then refuses with
//! `Contended` before effects; the host waits for any holder. No lock is held across I/O, a WFI, a context switch or a host wait,
//! and nothing allocates under a lock: pool storage is provisioned by the
//! host before it takes any lock. A write to an unbacked pipe refuses with
//! `pipe::Error::Storage` before any effect; EL1 then forwards the call and
//! the host provides the ring ([`IpcObjectGuard::provide_pipe_storage`]).
//!
//! Zone epoll objects ([`epoll`]) add one rule: a member (pipe or eventfd)
//! lock is taken before an epoll lock (`EPOLL_CTL_ADD`/`MOD`/`DEL`, a final
//! release detaching items), never the reverse; a member publication takes
//! no epoll lock at all (it pushes on the epoll's lock-free ready stack);
//! and a harvest holds the epoll lock or one member lock, never both.
//!
//! Guest page size for pipe accounting is [`IPC_PIPE_PAGE_SIZE`] (Linux
//! aarch64 4 KiB pages, `carrick_abi::LINUX_PAGE_SIZE`).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use carrick_fd_core::BoundedSpin;
use carrick_fd_core::free_list::{pop, push};
pub use carrick_fd_core::{
    self as fd, BackingToken, DescriptorSlot, Extent, LockWait, OfdPin, OfdRecord, RawOfdPin,
    RawTableId, SlotBacking, bitmap_words,
};
pub use carrick_pipe_core::{
    self as pipe, End, EventFd, EventMode, Page, Pipe, PipeRecord, WakeSet, WriteProgress,
};

/// Descriptor tables (distinct `CLONE_FILES` groups) in the shared authority.
/// Exhaustion is not guest-visible: the host keeps serving a table it could
/// not publish.
pub const IPC_FD_TABLES: usize = 256;
/// Zone-wide ceiling on open file descriptions: the elastic OFD store's
/// reservation, and the zone's file-table limit (ENFILE, `fs.file-max`).
pub const IPC_MAX_OFDS: usize = 1 << 20;
/// OFD records published per growth step.
pub const IPC_OFD_SEGMENT: usize = 2048;
/// Suspended-operation records ([`IpcOperation`] behind an [`IpcOpToken`]).
/// Exhaustion refuses before effects (`NoOperations`: EL1 forwards).
pub const IPC_OPERATIONS: usize = 1024;
/// Zone-wide ceiling on pipe and eventfd objects: the elastic object store's
/// reservation (ENFILE beyond it).
pub const IPC_MAX_OBJECTS: usize = 1 << 18;
/// Object records published per growth step.
pub const IPC_OBJECT_SEGMENT: usize = 1024;
/// Default-capacity rings the host keeps provisioned in the shared ring
/// stock, so a pipe's first write takes its ring in either venue without a
/// host exit. The stock is refilled by the host (one ring per pipe it
/// creates, and at its own first writes), never by EL1.
pub const IPC_RING_STOCK: usize = 512;
/// Ring bytes of a stock ring: the default pipe capacity (sixteen pages).
pub const IPC_STOCK_RING_BYTES: u64 = (pipe::DEFAULT_PIPE_PAGES * IPC_PIPE_PAGE_SIZE) as u64;
/// Guest page size used for pipe capacity and ring pages.
pub const IPC_PIPE_PAGE_SIZE: usize = 4096;
/// Alignment of every pool extent (a pipe ring starts on a guest page).
pub const IPC_POOL_ALIGN: u64 = IPC_PIPE_PAGE_SIZE as u64;
/// Region magic: "CRKIPC" + ABI version 5 (elastic object and description
/// stores, three-level host wake index, zone epoll records).
pub const IPC_MAGIC: u64 = u64::from_le_bytes(*b"CRKIPC\x00\x05");
const IPC_READY: u64 = 1;
/// Leaf words of the owed-host-wake index: one bit per object.
const HOST_WAKE_LEAF_WORDS: usize = IPC_MAX_OBJECTS / 64;
/// Middle words: one bit per leaf word.
const HOST_WAKE_MID_WORDS: usize = HOST_WAKE_LEAF_WORDS / 64;
const _: () = assert!(
    HOST_WAKE_MID_WORDS <= 64,
    "one summary word covers the middle level"
);
const _: () = assert!(IPC_MAX_OBJECTS.is_multiple_of(IPC_OBJECT_SEGMENT));
const _: () = assert!(IPC_MAX_OFDS.is_multiple_of(IPC_OFD_SEGMENT));
const _: () = assert!(IPC_MAX_OFDS < u32::MAX as usize);

/// The descriptor authority shared by host and EL1.
pub type IpcFdCore = fd::Core<IPC_FD_TABLES>;
/// The descriptor authority bound to this region and a lock policy.
pub type IpcFdAuthority<'a, W> = fd::Authority<'a, IpcRegion<'a>, W, IPC_FD_TABLES>;

// ---------------------------------------------------------------- handles

/// Exact incarnation of one IPC object. Copyable identity; it retains
/// nothing (a description pin retains the object through its endpoint).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IpcObjectHandle {
    index: u32,
    generation: u32,
}
impl IpcObjectHandle {
    pub const fn index(self) -> u32 {
        self.index
    }
    pub const fn generation(self) -> u32 {
        self.generation
    }
    /// Plain-data form for shared records.
    pub const fn to_raw(self) -> RawIpcObject {
        RawIpcObject {
            index: self.index,
            generation: self.generation,
        }
    }
    /// Rebuild from a shared record; every use still checks the generation.
    pub const fn from_raw(raw: RawIpcObject) -> Self {
        Self {
            index: raw.index,
            generation: raw.generation,
        }
    }
}

/// The shared queue identity for one readiness direction of an IPC incarnation.
pub fn object_wait_key(
    object: IpcObjectHandle,
    direction: pipe::WaitFor,
) -> Option<carrick_sched_core::object_wait::ObjectWaitKey> {
    let lane = u32::from(direction == pipe::WaitFor::Writable);
    let index = object.index().checked_mul(2)?.checked_add(1 + lane)?;
    carrick_sched_core::object_wait::ObjectWaitKey::new(index, u64::from(object.generation()) + 1)
}

/// The object index and readiness direction whose waits queue `queue`
/// holds (the inverse of [`object_wait_key`]'s index), for a census.
pub fn object_of_wait_queue(queue: u32) -> Option<(u32, pipe::WaitFor)> {
    let slot = queue.checked_sub(1)?;
    let lane = if slot % 2 == 0 {
        pipe::WaitFor::Readable
    } else {
        pipe::WaitFor::Writable
    };
    Some((slot / 2, lane))
}

/// For a wedge post-mortem: every object queue a live zone record waits on,
/// with its object's incarnation and readiness. Read-only; each object lock
/// is taken only if it is free within a few spins, never waited for.
pub fn write_ipc_wait_census(
    zone: &carrick_sched_core::ZoneTables,
    region: &IpcRegion<'_>,
    out: &mut impl core::fmt::Write,
) -> core::fmt::Result {
    // Zone queues name only objects below ZONE_RECORDS / 2 (two lanes each).
    const QUEUED_OBJECTS: usize = carrick_sched_core::ZONE_RECORDS / 2;
    let mut seen = [0u64; QUEUED_OBJECTS.div_ceil(64)];
    for id in 1..carrick_sched_core::ZONE_RECORDS as u32 {
        let Some(record) = carrick_sched_core::RecordId::from_raw(id) else {
            continue;
        };
        let rec = zone.record(record);
        if rec.claim() == carrick_sched_core::Claim::Free {
            continue;
        }
        let Some(wait) = rec.object_wait_census() else {
            continue;
        };
        let Some((object, lane)) = object_of_wait_queue(wait.queue) else {
            continue;
        };
        let o = object as usize;
        if o >= QUEUED_OBJECTS || seen[o / 64] & (1 << (o % 64)) != 0 {
            continue;
        }
        seen[o / 64] |= 1 << (o % 64);
        write!(out, "ipc object {object} (queue {} {lane:?}): ", wait.queue)?;
        region.write_object_census(object, out)?;
    }
    Ok(())
}

/// Plain-data [`IpcObjectHandle`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawIpcObject {
    pub index: u32,
    pub generation: u32,
}

/// Opaque identity of a host-backed resource (a description that is not a
/// migrated IPC object). Interpreted only by the host venue; never a host fd
/// number EL1 could act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostResourceToken(u64);
impl HostResourceToken {
    /// Largest encodable token.
    pub const MAX: u64 = (1 << TAG_SHIFT) - 1;
    pub const fn new(token: u64) -> Option<Self> {
        if token == 0 || token > Self::MAX {
            None
        } else {
            Some(Self(token))
        }
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What an open file description is backed by, encoded in its fd-core
/// `BackingToken`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcBacking {
    Host(HostResourceToken),
    Pipe {
        object: IpcObjectHandle,
        end: End,
    },
    EventFd {
        object: IpcObjectHandle,
    },
    /// An epoll instance whose interest list lives in the shared record
    /// ([`epoll`]).
    Epoll {
        object: IpcObjectHandle,
    },
}

const TAG_SHIFT: u32 = 61;
const TAG_HOST: u64 = 1;
const TAG_PIPE: u64 = 2;
const TAG_EVENTFD: u64 = 3;
const TAG_EPOLL: u64 = 4;
const END_WRITER: u64 = 1 << 60;
const INDEX_SHIFT: u32 = 32;
const INDEX_BITS: u64 = (1 << 28) - 1;

impl IpcBacking {
    /// Bits 63..61 tag (1 host, 2 pipe, 3 eventfd, 4 epoll); host: bits
    /// 60..0 token;
    /// object: bit 60 pipe writer end, bits 59..32 index, 31..0 generation.
    pub const fn encode(self) -> BackingToken {
        BackingToken(match self {
            Self::Host(token) => (TAG_HOST << TAG_SHIFT) | token.0,
            Self::Pipe { object, end } => {
                let end = match end {
                    End::Reader => 0,
                    End::Writer => END_WRITER,
                };
                (TAG_PIPE << TAG_SHIFT) | end | object_bits(object)
            }
            Self::EventFd { object } => (TAG_EVENTFD << TAG_SHIFT) | object_bits(object),
            Self::Epoll { object } => (TAG_EPOLL << TAG_SHIFT) | object_bits(object),
        })
    }
    /// `None` for any token this ABI never encodes (fails closed).
    pub const fn decode(token: BackingToken) -> Option<Self> {
        let raw = token.0;
        let object = IpcObjectHandle {
            index: ((raw >> INDEX_SHIFT) & INDEX_BITS) as u32,
            generation: raw as u32,
        };
        match raw >> TAG_SHIFT {
            TAG_HOST => match HostResourceToken::new(raw & HostResourceToken::MAX) {
                Some(t) => Some(Self::Host(t)),
                None => None,
            },
            TAG_PIPE => Some(Self::Pipe {
                object,
                end: if raw & END_WRITER != 0 {
                    End::Writer
                } else {
                    End::Reader
                },
            }),
            TAG_EVENTFD if raw & END_WRITER == 0 => Some(Self::EventFd { object }),
            TAG_EPOLL if raw & END_WRITER == 0 => Some(Self::Epoll { object }),
            _ => None,
        }
    }
}
const fn object_bits(object: IpcObjectHandle) -> u64 {
    ((object.index as u64 & INDEX_BITS) << INDEX_SHIFT) | object.generation as u64
}
const _: () = assert!(IPC_MAX_OBJECTS as u64 <= INDEX_BITS);

// ---------------------------------------------------------------- records

/// Object kinds stored in [`IpcObjectRecord`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcObjectKind {
    Pipe,
    EventFd,
    Epoll,
}
const KIND_FREE: u32 = 0;
const KIND_PIPE: u32 = 1;
const KIND_EVENTFD: u32 = 2;
const KIND_EPOLL: u32 = 3;

/// A pipe's pool storage: `ring_bytes` of ring (guest-page multiple) followed
/// by `pages` [`Page`] metadata entries, starting at pool `offset`
/// ([`IPC_POOL_ALIGN`]-aligned). Provisioned by the host outside any lock;
/// a free object keeps its storage for reuse.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpcPipeStorage {
    pub offset: u64,
    pub ring_bytes: u64,
    pub pages: u64,
}
impl IpcPipeStorage {
    /// Pool bytes this storage occupies.
    pub const fn footprint(&self) -> u64 {
        self.ring_bytes + self.pages * core::mem::size_of::<Page>() as u64
    }
    /// Storage able to hold a pipe of `capacity` bytes.
    pub const fn fits(&self, capacity: usize) -> bool {
        self.ring_bytes >= capacity as u64
            && self.pages >= (capacity / IPC_PIPE_PAGE_SIZE) as u64
            && self.ring_bytes > 0
    }
}

/// The object's state; which part is meaningful follows `kind`.
#[repr(C)]
#[derive(Debug)]
pub struct IpcObjectState {
    pub pipe: PipeRecord,
    pub eventfd: EventFd,
    pub epoll: epoll::EpollState,
}

/// One pipe or eventfd, shared by host and EL1. Every field is written only
/// under `lock`, except the readiness sequences and subscriber count, which
/// are also read lock-free (Acquire).
#[repr(C, align(64))]
pub struct IpcObjectRecord {
    lock: AtomicU32,
    kind: AtomicU32,
    /// Incarnation, u32-valued; advances when the object is freed.
    generation: AtomicU64,
    /// Advanced (Release, under the lock) whenever readers must recheck.
    read_seq: AtomicU64,
    /// Advanced (Release, under the lock) whenever writers must recheck.
    write_seq: AtomicU64,
    /// Host readiness subscribers (poll/epoll/blocked host waits). Zero
    /// means no host notification is owed for any change.
    host_subscribers: AtomicU32,
    /// Set by a change made while host subscribers existed; the host clears
    /// it when it delivers the notification.
    host_wake_owed: AtomicU32,
    next_free: AtomicU64,
    storage_offset: AtomicU64,
    storage_ring_bytes: AtomicU64,
    storage_pages: AtomicU64,
    /// Kind-dependent epoll link ([`epoll`]): for a pipe or eventfd, the
    /// first zone epoll item watching it (item number, 0 none; written
    /// under this object's lock); for an epoll, its lock-free ready stack
    /// (pushed by member publishers holding only the member's lock,
    /// drained whole under this epoll's lock).
    epoll_link: AtomicU64,
    state: UnsafeCell<IpcObjectState>,
}
// SAFETY: `state` is accessed only through an `IpcObjectGuard`, which holds
// the record's lock; every other field is atomic.
unsafe impl Sync for IpcObjectRecord {}

/// Region header: authenticated by every attach.
#[repr(C, align(64))]
pub struct IpcHeader {
    magic: AtomicU64,
    layout_hash: AtomicU64,
    state: AtomicU64,
    pool_len: AtomicU64,
    _reserved: [u64; 4],
}

/// The fixed head of the directory mapping, as one zero-initializable
/// `repr(C)` object. The elastic stores follow it in the same mapping at
/// [`IPC_OBJECTS_OFFSET`], [`IPC_OFDS_OFFSET`] and [`IPC_WAKE_LEAVES_OFFSET`];
/// the byte pool is separate memory (see [`IpcRegion`]).
#[repr(C, align(4096))]
pub struct IpcDirectory {
    header: IpcHeader,
    free_objects: AtomicU64,
    /// Owed host wakes a host boundary found with no live delivery target
    /// for their object's incarnation, and so left owed and indexed rather
    /// than consumed. Must stay zero: nonzero names a host subscriber whose
    /// wake target was never registered or was dropped while it waited.
    owed_host_wakes_without_target: AtomicU64,
    /// Object records published ([`IpcRegion::grow_objects`]); only grows,
    /// always a multiple of [`IPC_OBJECT_SEGMENT`].
    object_count: AtomicU64,
    _reserved: [u64; 5],
    fd: IpcFdCore,
    free_operations: AtomicU64,
    /// Ring stock: two tagged lock-free stacks over `ring_stock` slots, the
    /// provisioned rings and the empty slots.
    ring_stock_full: AtomicU64,
    ring_stock_empty: AtomicU64,
    _reserved_ops: [u64; 5],
    ring_stock: [RingStockSlot; IPC_RING_STOCK],
    operations: [IpcOperationSlot; IPC_OPERATIONS],
    /// Three-level pending index (summary → middle → leaf words, the
    /// leaves in the elastic area). Publishers set the leaf bit first and
    /// the summary bit last; a host boundary takes one bounded snapshot,
    /// visiting only pending words, never live objects.
    host_wake_summary: AtomicU64,
    host_wake_mid: [AtomicU64; HOST_WAKE_MID_WORDS],
    /// Free zone epoll items ([`epoll`]), a tagged lock-free stack over
    /// the item array at [`IPC_EPOLL_ITEMS_OFFSET`].
    free_epoll_items: AtomicU64,
    _reserved_epoll: [u64; 7],
}

const fn page_round(n: usize) -> usize {
    n.next_multiple_of(IPC_PIPE_PAGE_SIZE)
}
/// Offset, in the directory mapping, of the object store's reservation.
pub const IPC_OBJECTS_OFFSET: usize = page_round(core::mem::size_of::<IpcDirectory>());
/// Offset of the OFD store's reservation.
pub const IPC_OFDS_OFFSET: usize =
    page_round(IPC_OBJECTS_OFFSET + IPC_MAX_OBJECTS * core::mem::size_of::<IpcObjectRecord>());
/// Offset of the owed-host-wake index's leaf words.
pub const IPC_WAKE_LEAVES_OFFSET: usize =
    page_round(IPC_OFDS_OFFSET + IPC_MAX_OFDS * core::mem::size_of::<OfdRecord>());
/// Offset of the zone epoll item array ([`epoll::IpcEpollItem`]).
pub const IPC_EPOLL_ITEMS_OFFSET: usize =
    page_round(IPC_WAKE_LEAVES_OFFSET + HOST_WAKE_LEAF_WORDS * core::mem::size_of::<AtomicU64>());
/// Length of the directory mapping: fixed head plus every store's
/// reservation, a multiple of 16 KiB (the host's stage-2 granule).
pub const IPC_DIRECTORY_BYTES: usize = (IPC_EPOLL_ITEMS_OFFSET
    + epoll::IPC_EPOLL_ITEMS * core::mem::size_of::<epoll::IpcEpollItem>())
.next_multiple_of(0x4000);
const _: () =
    assert!(IPC_EPOLL_ITEMS_OFFSET.is_multiple_of(core::mem::align_of::<epoll::IpcEpollItem>()));
const _: () = assert!(IPC_OBJECTS_OFFSET.is_multiple_of(core::mem::align_of::<IpcObjectRecord>()));
// The elastic stores' reservations follow the head, in order, without overlap.
const _: () = assert!(IPC_OBJECTS_OFFSET >= core::mem::size_of::<IpcDirectory>());
const _: () = assert!(
    IPC_OFDS_OFFSET
        >= IPC_OBJECTS_OFFSET + IPC_MAX_OBJECTS * core::mem::size_of::<IpcObjectRecord>()
);
const _: () = assert!(
    IPC_WAKE_LEAVES_OFFSET >= IPC_OFDS_OFFSET + IPC_MAX_OFDS * core::mem::size_of::<OfdRecord>()
);
const _: () = assert!(IPC_OFDS_OFFSET.is_multiple_of(core::mem::align_of::<OfdRecord>()));

/// Layout facts of this ABI; see [`IPC_LAYOUT_HASH`].
const LAYOUT_FACTS: &[u64] = &[
    IPC_MAGIC,
    IPC_FD_TABLES as u64,
    IPC_MAX_OFDS as u64,
    IPC_OFD_SEGMENT as u64,
    IPC_MAX_OBJECTS as u64,
    IPC_OBJECT_SEGMENT as u64,
    IPC_OBJECTS_OFFSET as u64,
    IPC_OFDS_OFFSET as u64,
    IPC_WAKE_LEAVES_OFFSET as u64,
    IPC_DIRECTORY_BYTES as u64,
    core::mem::offset_of!(IpcDirectory, object_count) as u64,
    IPC_PIPE_PAGE_SIZE as u64,
    IPC_POOL_ALIGN,
    core::mem::size_of::<usize>() as u64,
    core::mem::size_of::<IpcDirectory>() as u64,
    core::mem::align_of::<IpcDirectory>() as u64,
    core::mem::offset_of!(IpcDirectory, owed_host_wakes_without_target) as u64,
    core::mem::offset_of!(IpcDirectory, fd) as u64,
    core::mem::size_of::<IpcFdCore>() as u64,
    core::mem::size_of::<IpcObjectRecord>() as u64,
    core::mem::offset_of!(IpcObjectRecord, generation) as u64,
    core::mem::offset_of!(IpcObjectRecord, read_seq) as u64,
    core::mem::offset_of!(IpcObjectRecord, write_seq) as u64,
    core::mem::offset_of!(IpcObjectRecord, host_subscribers) as u64,
    core::mem::offset_of!(IpcObjectRecord, storage_offset) as u64,
    core::mem::offset_of!(IpcObjectRecord, state) as u64,
    core::mem::size_of::<IpcObjectState>() as u64,
    core::mem::size_of::<PipeRecord>() as u64,
    core::mem::size_of::<EventFd>() as u64,
    core::mem::size_of::<Page>() as u64,
    core::mem::size_of::<IpcPipeStorage>() as u64,
    core::mem::size_of::<IpcOperation>() as u64,
    core::mem::offset_of!(IpcOperation, pin) as u64,
    core::mem::offset_of!(IpcOperation, progress) as u64,
    core::mem::offset_of!(IpcOperation, park_seq) as u64,
    core::mem::offset_of!(IpcOperation, value) as u64,
    core::mem::offset_of!(IpcOperation, orig_x0) as u64,
    core::mem::offset_of!(IpcOperation, handback) as u64,
    core::mem::offset_of!(IpcOperation, result) as u64,
    IPC_HANDBACK_NR,
    core::mem::size_of::<RawOfdPin>() as u64,
    core::mem::size_of::<RawTableId>() as u64,
    core::mem::size_of::<DescriptorSlot>() as u64,
    TAG_SHIFT as u64,
    END_WRITER,
    INDEX_BITS,
    IPC_OPERATIONS as u64,
    core::mem::size_of::<IpcOperationSlot>() as u64,
    core::mem::offset_of!(IpcDirectory, operations) as u64,
    core::mem::offset_of!(IpcDirectory, host_wake_summary) as u64,
    core::mem::offset_of!(IpcDirectory, host_wake_mid) as u64,
    HOST_WAKE_MID_WORDS as u64,
    HOST_WAKE_LEAF_WORDS as u64,
    core::mem::offset_of!(IpcOperationSlot, op) as u64,
    IPC_RING_STOCK as u64,
    IPC_POOL_AREAS,
    IPC_STOCK_RING_BYTES,
    core::mem::size_of::<RingStockSlot>() as u64,
    core::mem::offset_of!(IpcDirectory, ring_stock) as u64,
    core::mem::offset_of!(IpcObjectRecord, epoll_link) as u64,
    core::mem::size_of::<epoll::EpollState>() as u64,
    core::mem::offset_of!(IpcObjectState, epoll) as u64,
    core::mem::offset_of!(IpcDirectory, free_epoll_items) as u64,
    IPC_EPOLL_ITEMS_OFFSET as u64,
    epoll::IPC_EPOLL_ITEMS as u64,
    core::mem::size_of::<epoll::IpcEpollItem>() as u64,
    TAG_EPOLL,
    KIND_EPOLL as u64,
];

/// FNV-1a over `LAYOUT_FACTS` and the fd core's layout facts. Written into
/// the header by the initializing venue; an attach compiled with a different
/// layout fails closed.
pub const IPC_LAYOUT_HASH: u64 = {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    let n = LAYOUT_FACTS.len() + fd::LAYOUT_FACTS.len();
    while i < n {
        let mut word = if i < LAYOUT_FACTS.len() {
            LAYOUT_FACTS[i]
        } else {
            fd::LAYOUT_FACTS[i - LAYOUT_FACTS.len()]
        };
        let mut b = 0;
        while b < 8 {
            hash ^= word & 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            word >>= 8;
            b += 1;
        }
        i += 1;
    }
    hash
};

// ------------------------------------------------------------ continuation

/// Kind of a suspended IPC operation.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcOpKind {
    None = 0,
    PipeRead = 1,
    PipeWrite = 2,
    EventFdRead = 3,
    EventFdWrite = 4,
}

/// Exact task key of the operation's owner (venue-defined, generation-bearing).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct IpcTaskKey(pub u64);
/// Exact address-space key whose user memory the buffer names.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct IpcMmKey(pub u64);
/// Guest user virtual address of the operation's buffer (in `mm`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct IpcUserVa(pub u64);

/// The owned, stack-independent state of one suspended pipe/eventfd
/// operation (proposed for the read/write adapter and runtime integration).
/// It owns `pin` (moved in with [`OfdPin::into_raw`]); exactly one
/// completion owner moves it out again and unpins. `progress.written` is the
/// bytes already transferred: a resumed operation continues from it and a
/// signal after progress returns it (never replays bytes). `park_seq` is the
/// object's read/write sequence sampled before parking. The copier reloads
/// `mm` before touching `buf`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcOperation {
    pub kind: IpcOpKind,
    pub nonblock: u32,
    pub pin: RawOfdPin,
    pub object: RawIpcObject,
    pub task: IpcTaskKey,
    pub mm: IpcMmKey,
    pub buf: IpcUserVa,
    pub progress: WriteProgress,
    pub park_seq: u64,
    /// An eventfd write's counter value, copied from `buf` before the
    /// operation could block: a resumed write adds this value, never a
    /// re-read of user memory (eventfd(2)). Unused by other kinds.
    pub value: IpcEventValue,
    /// The call's original `x0` and syscall number: a handback frame
    /// carries the token in `x0` and [`IPC_HANDBACK_NR`] in `x8`, and the
    /// host restores both (every other register is untouched).
    pub orig_x0: u64,
    pub nr: u32,
    /// What the host must do with a handed-back operation.
    pub handback: IpcHandback,
    /// The completed result for [`IpcHandback::Sigpipe`].
    pub result: i64,
}

/// Private call number of an EL1 handback frame (`x0` = the packed raw
/// [`IpcOpToken`]); next to `SYS_CARRICK_EL1_CONTROL`.
pub const IPC_HANDBACK_NR: u64 = 0xCA88_0002;

/// What the host does with an operation EL1 handed back.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcHandback {
    /// Not handed back.
    None = 0,
    /// Continue the owned operation from its recorded progress (never
    /// replaying it from the numeric fd).
    Continue = 1,
    /// The operation completed with `result` after progress but its peer
    /// closed: finish it and deliver SIGPIPE with the result.
    Sigpipe = 2,
    /// The operation never took effect: finish (unpin) it and run the
    /// original call again on the host path.
    Restart = 3,
}

impl RawIpcOpToken {
    /// The one-register form a handback frame carries.
    pub const fn pack(self) -> u64 {
        self.index as u64 | ((self.generation as u64) << 32)
    }
    pub const fn unpack(word: u64) -> Self {
        Self {
            index: word as u32,
            generation: (word >> 32) as u32,
        }
    }
}

/// The 8-byte value of one eventfd write.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpcEventValue(pub u64);
impl IpcOperation {
    pub const EMPTY: Self = Self {
        kind: IpcOpKind::None,
        nonblock: 0,
        pin: RawOfdPin {
            authority: 0,
            index: 0,
            generation: 0,
        },
        object: RawIpcObject {
            index: 0,
            generation: 0,
        },
        task: IpcTaskKey(0),
        mm: IpcMmKey(0),
        buf: IpcUserVa(0),
        progress: WriteProgress { len: 0, written: 0 },
        park_seq: 0,
        value: IpcEventValue(0),
        orig_x0: 0,
        nr: 0,
        handback: IpcHandback::None,
        result: 0,
    };
}

/// Owned handle of one suspended operation's record: the opaque
/// `(index, generation)` the scheduler keeps in the parked thread's record
/// across park, wake and control claims. Exactly one owner: not
/// `Clone`/`Copy`; [`IpcOpToken::into_raw`]/[`IpcOpToken::from_raw`] move
/// that ownership into and out of a shared record (a copied raw value is
/// not a second owner). The owner alone reads and updates the record, so
/// the pinned description, buffer authority and byte progress behind the
/// token have one completion owner; [`IpcRegion::finish_operation`]
/// returns them and retires the token.
#[must_use = "an operation record stays allocated until finish_operation"]
#[derive(Debug, Eq, PartialEq)]
pub struct IpcOpToken {
    index: u32,
    generation: u32,
}
/// Plain-data [`IpcOpToken`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawIpcOpToken {
    pub index: u32,
    pub generation: u32,
}
impl IpcOpToken {
    pub fn into_raw(self) -> RawIpcOpToken {
        RawIpcOpToken {
            index: self.index,
            generation: self.generation,
        }
    }
    /// Reclaim the ownership moved out by [`IpcOpToken::into_raw`].
    pub fn from_raw(raw: RawIpcOpToken) -> Self {
        Self {
            index: raw.index,
            generation: raw.generation,
        }
    }
}

/// One operation record slot. `op` is touched only by the token's owner;
/// `live`/`generation` authenticate tokens (a finished record advances its
/// generation, retiring the slot when exhausted).
#[repr(C)]
pub struct IpcOperationSlot {
    generation: AtomicU32,
    live: AtomicU32,
    next_free: AtomicU64,
    op: UnsafeCell<IpcOperation>,
}
/// One provisioned ring waiting in the stock (pool extent of a default
/// capacity ring). Written only by the party that popped the slot from the
/// empty stack, read only by the party that popped it from the full stack.
#[repr(C)]
#[derive(Default)]
struct RingStockSlot {
    next_free: AtomicU64,
    offset: AtomicU64,
    ring_bytes: AtomicU64,
    pages: AtomicU64,
}

// SAFETY: `op` is accessed only by the single owner of the slot's live
// token; ownership moves between vCPUs/host through the scheduler's claim
// CAS (Acquire/Release), which orders the accesses.
unsafe impl Sync for IpcOperationSlot {}

// ---------------------------------------------------------------- errors

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// The lock policy gave up before any effect (EL1 forwards).
    Contended,
    /// The handle names a freed or reused object.
    Stale,
    /// The handle names an object of another kind.
    WrongKind,
    /// Every published object record is in use: the host grows the store
    /// ([`IpcRegion::grow_objects`]) and retries. Never an errno by itself.
    NoObjects,
    /// A store is at its zone-wide ceiling ([`IPC_MAX_OBJECTS`] objects or
    /// [`IPC_MAX_OFDS`] descriptions): the zone's file table is full (ENFILE).
    ZoneLimit,
    /// Every operation record is in use (refused before effects).
    NoOperations,
    /// A pool extent is out of bounds or misaligned (venue bug; fail closed).
    BadStorage,
    /// The region is unpublished or its header does not match this ABI.
    BadRegion,
    /// A record violates its invariants (venue bug; fail closed).
    Corrupt,
    /// A pipe/eventfd rule refused the operation.
    Object(pipe::Error),
    /// The descriptor authority refused the operation.
    Fd(fd::Error),
}

// ---------------------------------------------------------------- region

/// A venue's view of the shared IPC memory: the directory mapping plus the
/// byte pool, each at this venue's own address (host mapping or EL1 VA).
/// Offsets in records are directory- or pool-relative, so both venues
/// resolve the same records.
#[derive(Clone, Copy)]
pub struct IpcRegion<'a> {
    dir: &'a IpcDirectory,
    /// The whole directory mapping ([`IPC_DIRECTORY_BYTES`]): the head `dir`
    /// and the elastic stores after it.
    base: *mut u8,
    pool: *mut u8,
    pool_len: u64,
    /// Who this view's object locks name as their holder.
    holder: IpcLockHolder,
    _pool: PhantomData<&'a UnsafeCell<[u8]>>,
}

/// Who holds an object lock, as its lock word records it (0 = free).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcLockHolder {
    /// A host thread (every host view).
    Host,
    /// EL1 on the vCPU of this mailbox slot.
    El1 { slot: u32 },
}
const LOCK_FREE: u32 = 0;
const LOCK_HOST: u32 = u32::MAX;
impl IpcLockHolder {
    const fn word(self) -> u32 {
        match self {
            Self::Host => LOCK_HOST,
            Self::El1 { slot } => slot.saturating_add(1),
        }
    }
    const fn from_word(word: u32) -> Option<Self> {
        match word {
            LOCK_FREE => None,
            LOCK_HOST => Some(Self::Host),
            n => Some(Self::El1 { slot: n - 1 }),
        }
    }
}
// SAFETY: the pool is shared memory whose bytes are accessed only under the
// owning table/object lock, through slices bounded by authenticated extents.
unsafe impl Send for IpcRegion<'_> {}
unsafe impl Sync for IpcRegion<'_> {}

impl<'a> IpcRegion<'a> {
    /// Host views of the same registered directory and pool mapping. Reject
    /// mismatched owners before consuming an operation or releasing a host token.
    pub fn same_mapping(&self, other: &IpcRegion<'_>) -> bool {
        core::ptr::eq(self.dir, other.dir)
            && self.base == other.base
            && self.pool == other.pool
            && self.pool_len == other.pool_len
    }

    fn checked(dir: *mut IpcDirectory, dir_len: usize, pool: *mut u8) -> Result<(), IpcError> {
        if dir.is_null()
            || !(dir as usize).is_multiple_of(core::mem::align_of::<IpcDirectory>())
            || dir_len < IPC_DIRECTORY_BYTES
            || pool.is_null()
            || !(pool as usize).is_multiple_of(IPC_POOL_ALIGN as usize)
        {
            return Err(IpcError::BadRegion);
        }
        Ok(())
    }

    /// Publish a new region (the one initialization venue, once), with the
    /// first segment of each elastic store.
    ///
    /// # Safety
    /// `dir` points to zeroed memory of `dir_len` (at least
    /// [`IPC_DIRECTORY_BYTES`]) bytes and `pool` to `pool_len` bytes, both
    /// valid and shared for `'a`, used for nothing else. The reservation may
    /// be committed lazily: only published segments are ever touched.
    pub unsafe fn initialize(
        dir: *mut IpcDirectory,
        dir_len: usize,
        pool: *mut u8,
        pool_len: usize,
        identity: u64,
    ) -> Result<Self, IpcError> {
        Self::checked(dir, dir_len, pool)?;
        // SAFETY: caller contract; all-zero is a valid IpcDirectory.
        let d: &'a IpcDirectory = unsafe { &*dir };
        if d.header.state.load(Ordering::Acquire) != 0 {
            return Err(IpcError::BadRegion);
        }
        d.fd.initialize(identity).map_err(IpcError::Fd)?;
        let region = Self {
            dir: d,
            base: dir.cast(),
            pool,
            pool_len: pool_len as u64,
            holder: IpcLockHolder::Host,
            _pool: PhantomData,
        };
        region.grow_ofds()?;
        region.grow_objects()?;
        for i in (0..IPC_RING_STOCK).rev() {
            push(&d.ring_stock_empty, i, &d.ring_stock[i].next_free);
        }
        for i in (0..IPC_OPERATIONS).rev() {
            push(&d.free_operations, i, &d.operations[i].next_free);
        }
        for i in (0..epoll::IPC_EPOLL_ITEMS).rev() {
            let item = region.epoll_item_at(i).ok_or(IpcError::Corrupt)?;
            push(&d.free_epoll_items, i, &item.next_free);
        }
        d.header.magic.store(IPC_MAGIC, Ordering::Relaxed);
        d.header
            .layout_hash
            .store(IPC_LAYOUT_HASH, Ordering::Relaxed);
        d.header.pool_len.store(pool_len as u64, Ordering::Relaxed);
        d.header.state.store(IPC_READY, Ordering::Release);
        Ok(region)
    }

    /// Attach to a published region, authenticating magic, layout hash,
    /// readiness and pool length.
    ///
    /// # Safety
    /// `dir` (`dir_len` bytes) and `pool` map the same shared memory the
    /// initializing venue published (at this venue's addresses), valid for
    /// `'a`.
    pub unsafe fn attach(
        dir: *mut IpcDirectory,
        dir_len: usize,
        pool: *mut u8,
        pool_len: usize,
    ) -> Result<Self, IpcError> {
        Self::checked(dir, dir_len, pool)?;
        // SAFETY: caller contract.
        let d: &'a IpcDirectory = unsafe { &*dir };
        let h = &d.header;
        if h.state.load(Ordering::Acquire) != IPC_READY
            || h.magic.load(Ordering::Relaxed) != IPC_MAGIC
            || h.layout_hash.load(Ordering::Relaxed) != IPC_LAYOUT_HASH
            || h.pool_len.load(Ordering::Relaxed) != pool_len as u64
            || d.fd.identity() == 0
        {
            return Err(IpcError::BadRegion);
        }
        Ok(Self {
            dir: d,
            base: dir.cast(),
            pool,
            pool_len: pool_len as u64,
            holder: IpcLockHolder::Host,
            _pool: PhantomData,
        })
    }

    /// This view as EL1 on the vCPU of mailbox `slot` uses it: its object
    /// locks name that slot as their holder.
    pub fn for_el1_slot(self, slot: u32) -> Self {
        Self {
            holder: IpcLockHolder::El1 { slot },
            ..self
        }
    }

    /// Who holds `object`'s lock right now (`None`: free), for a caller
    /// that gave up waiting for it.
    pub fn lock_holder(&self, object: IpcObjectHandle) -> Option<IpcLockHolder> {
        self.record(object.index)
            .and_then(|r| IpcLockHolder::from_word(r.lock.load(Ordering::Acquire)))
    }

    /// The shared descriptor authority, with this venue's lock policy.
    pub fn fd<W: LockWait>(&'a self, wait: W) -> IpcFdAuthority<'a, W> {
        self.dir.fd.bind(self, wait)
    }

    /// Pool bytes `[offset, offset+len)`, authenticated against the pool.
    fn pool_range(
        &self,
        area: core::ops::Range<u64>,
        offset: u64,
        len: u64,
        align: u64,
    ) -> Option<*mut u8> {
        let end = offset.checked_add(len)?;
        if !offset.is_multiple_of(align) || offset < area.start || end > area.end {
            return None;
        }
        // SAFETY: in bounds of the pool mapping.
        Some(unsafe { self.pool.add(offset as usize) })
    }

    /// Pipe-ring bytes `[offset, offset+len)`, inside the ring area.
    fn ring_range(&self, offset: u64, len: u64) -> Option<*mut u8> {
        self.pool_range(ipc_ring_area(self.pool_len), offset, len, IPC_POOL_ALIGN)
    }

    /// Descriptor-extent words `[offset, offset+len)`, inside the
    /// descriptor area.
    fn descriptor_range(&self, offset: u64, len: u64) -> Option<*mut u8> {
        self.pool_range(ipc_descriptor_area(self.pool_len), offset, len, 64)
    }

    /// A published object record; `None` past the published count.
    fn record(&self, index: u32) -> Option<&'a IpcObjectRecord> {
        if u64::from(index) >= self.dir.object_count.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the mapping spans IPC_DIRECTORY_BYTES (checked at attach)
        // and index < object_count <= IPC_MAX_OBJECTS; all-zero is a valid
        // record, accessed through atomics and the object lock.
        Some(unsafe {
            &*self
                .base
                .add(IPC_OBJECTS_OFFSET)
                .cast::<IpcObjectRecord>()
                .add(index as usize)
        })
    }

    /// Leaf word `word` of the owed-host-wake index.
    fn wake_leaf(&self, word: usize) -> Option<&'a AtomicU64> {
        (word < HOST_WAKE_LEAF_WORDS).then(|| {
            // SAFETY: in bounds of the leaf reservation of the mapping.
            unsafe {
                &*self
                    .base
                    .add(IPC_WAKE_LEAVES_OFFSET)
                    .cast::<AtomicU64>()
                    .add(word)
            }
        })
    }

    /// Host: whether the ring stock has an empty slot to refill.
    pub fn ring_stock_has_room(&self) -> bool {
        self.dir.ring_stock_empty.load(Ordering::Acquire) & u64::from(u32::MAX) != 0
    }

    /// Host: put a provisioned default-capacity ring (an extent it owns
    /// exclusively, outside any lock) into the stock. Lock-free, O(1).
    /// A full stock or a ring of another size hands the extent back.
    pub fn stock_ring(&self, ring: IpcPipeStorage) -> Result<(), IpcPipeStorage> {
        if ring.ring_bytes != IPC_STOCK_RING_BYTES
            || !ring.fits(IPC_STOCK_RING_BYTES as usize)
            || self.ring_range(ring.offset, ring.footprint()).is_none()
        {
            return Err(ring);
        }
        let slots = &self.dir.ring_stock;
        let Some(index) = pop(&self.dir.ring_stock_empty, |i| {
            slots.get(i).map(|s| s.next_free.load(Ordering::Relaxed))
        }) else {
            return Err(ring);
        };
        let slot = &slots[index];
        slot.offset.store(ring.offset, Ordering::Relaxed);
        slot.ring_bytes.store(ring.ring_bytes, Ordering::Relaxed);
        slot.pages.store(ring.pages, Ordering::Relaxed);
        push(&self.dir.ring_stock_full, index, &slot.next_free);
        Ok(())
    }

    /// Take one stocked ring (either venue; lock-free, no allocation, so it
    /// may run under an object lock).
    fn take_stock_ring(&self) -> Option<IpcPipeStorage> {
        let slots = &self.dir.ring_stock;
        let index = pop(&self.dir.ring_stock_full, |i| {
            slots.get(i).map(|s| s.next_free.load(Ordering::Relaxed))
        })?;
        let slot = &slots[index];
        let ring = IpcPipeStorage {
            offset: slot.offset.load(Ordering::Relaxed),
            ring_bytes: slot.ring_bytes.load(Ordering::Relaxed),
            pages: slot.pages.load(Ordering::Relaxed),
        };
        push(&self.dir.ring_stock_empty, index, &slot.next_free);
        Some(ring)
    }

    /// Published object records ([`IpcRegion::grow_objects`]).
    pub fn object_count(&self) -> usize {
        self.dir.object_count.load(Ordering::Acquire) as usize
    }

    /// Published open-file-description records ([`IpcRegion::grow_ofds`]).
    pub fn ofd_count(&self) -> usize {
        self.dir.fd.ofd_count()
    }

    /// Publish the next [`IPC_OBJECT_SEGMENT`] object records: the count is
    /// published (Release) before the zeroed records join the free list, so
    /// every popped index resolves in both venues. Growth venue (the host)
    /// only, outside any lock; a concurrent growth refuses (`Contended`).
    /// Returns the records added: O(segment) work, once per segment.
    pub fn grow_objects(&self) -> Result<usize, IpcError> {
        let first = self.dir.object_count.load(Ordering::Acquire);
        if first >= IPC_MAX_OBJECTS as u64 {
            return Err(IpcError::ZoneLimit);
        }
        let end = first + IPC_OBJECT_SEGMENT as u64;
        self.dir
            .object_count
            .compare_exchange(first, end, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| IpcError::Contended)?;
        for index in (first..end).rev() {
            let record = self.record(index as u32).ok_or(IpcError::Corrupt)?;
            push(&self.dir.free_objects, index as usize, &record.next_free);
        }
        Ok(IPC_OBJECT_SEGMENT)
    }

    /// Publish the next [`IPC_OFD_SEGMENT`] open-file-description records
    /// (see [`fd::Authority::publish_ofds`]). Growth venue only. Returns the
    /// records added.
    pub fn grow_ofds(&self) -> Result<usize, IpcError> {
        let first = self.ofd_count();
        if first >= IPC_MAX_OFDS {
            return Err(IpcError::ZoneLimit);
        }
        let count = IPC_OFD_SEGMENT.min(IPC_MAX_OFDS - first);
        self.dir
            .fd
            .bind(self, BoundedSpin(0))
            .publish_ofds(count)
            .map_err(IpcError::Fd)?;
        Ok(count)
    }

    /// For a wedge post-mortem: the owed-host-wake index as a host boundary
    /// would take it, then one census line for every live object a host
    /// party subscribes to (a host-blocked reader or writer, poll, epoll) or
    /// is owed a wake on. A host-side waiter is invisible to the zone census
    /// (it holds no zone record); this is where it shows. An owed wake that
    /// is still indexed while every slot waits in the guest was published
    /// and never delivered; a readable object with subscribers and nothing
    /// owed was delivered and its waiter never ran. Read-only: each object
    /// lock is taken only when free within a few spins.
    pub fn write_host_wake_census(&self, out: &mut impl core::fmt::Write) -> core::fmt::Result {
        write!(
            out,
            "ipc host-wake index: owed_without_target={} summary={:#x}",
            self.owed_host_wakes_without_target(),
            self.dir.host_wake_summary.load(Ordering::Acquire)
        )?;
        for (word, bits) in self.dir.host_wake_mid.iter().enumerate() {
            let bits = bits.load(Ordering::Acquire);
            if bits != 0 {
                write!(out, " mid{word}={bits:#x}")?;
            }
        }
        writeln!(out)?;
        for index in 0..self.object_count() {
            let Some(record) = self.record(index as u32) else {
                break;
            };
            if record.kind.load(Ordering::Acquire) == KIND_FREE {
                continue;
            }
            let indexed = self
                .wake_leaf(index / 64)
                .is_some_and(|w| w.load(Ordering::Acquire) & (1 << (index % 64)) != 0);
            if record.host_subscribers.load(Ordering::Acquire) == 0
                && record.host_wake_owed.load(Ordering::Acquire) == 0
                && !indexed
            {
                continue;
            }
            write!(out, "ipc object {index} (host, indexed={indexed}): ")?;
            self.write_object_census(index as u32, out)?;
        }
        Ok(())
    }

    /// One census line for the object at `index`, whatever its incarnation:
    /// kind, generation, readiness sequences, host subscribers and owed
    /// wake, and (only when its lock is free within a few spins) its pipe
    /// bytes and endpoint counts or eventfd counter. Never waits on a holder.
    pub fn write_object_census(
        &self,
        index: u32,
        out: &mut impl core::fmt::Write,
    ) -> core::fmt::Result {
        let Some(record) = self.record(index) else {
            return writeln!(out, "no such object");
        };
        let kind = record.kind.load(Ordering::Acquire);
        let generation = record.generation.load(Ordering::Acquire);
        write!(
            out,
            "kind={} generation={generation} read_seq={} write_seq={} host_subscribers={} host_wake_owed={}",
            match kind {
                KIND_PIPE => "pipe",
                KIND_EVENTFD => "eventfd",
                KIND_EPOLL => "epoll",
                KIND_FREE => "free",
                _ => "?",
            },
            record.read_seq.load(Ordering::Acquire),
            record.write_seq.load(Ordering::Acquire),
            record.host_subscribers.load(Ordering::Acquire),
            record.host_wake_owed.load(Ordering::Acquire),
        )?;
        let mut locked = false;
        for _ in 0..64 {
            if record
                .lock
                .compare_exchange(
                    LOCK_FREE,
                    self.holder.word(),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                locked = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !locked {
            return writeln!(out, " state=<locked>");
        }
        let mut guard = IpcObjectGuard {
            region: *self,
            record,
            handle: IpcObjectHandle {
                index,
                generation: generation as u32,
            },
        };
        match guard.kind() {
            Some(IpcObjectKind::Pipe) => match guard.pipe() {
                Ok(p) => writeln!(
                    out,
                    " unread={} capacity={} readers={} writers={}",
                    p.unread_bytes(),
                    p.capacity(),
                    p.references(End::Reader),
                    p.references(End::Writer),
                ),
                Err(e) => writeln!(out, " pipe={e:?}"),
            },
            Some(IpcObjectKind::EventFd) => match guard.eventfd() {
                Ok(e) => writeln!(out, " counter={} mode={:?}", e.value(), e.mode()),
                Err(e) => writeln!(out, " eventfd={e:?}"),
            },
            Some(IpcObjectKind::Epoll) => match guard.epoll_census() {
                Some((zone, host, dead, ready)) => writeln!(
                    out,
                    " zone_items={zone} host_items={host} dead={dead} ready_head={ready}"
                ),
                None => writeln!(out, " epoll=?"),
            },
            None => writeln!(out),
        }
    }

    /// Lock `object` for exclusive use. Authenticates kind and generation
    /// after the lock is held.
    pub fn lock<W: LockWait>(
        &self,
        object: IpcObjectHandle,
        wait: &W,
    ) -> Result<IpcObjectGuard<'a>, IpcError> {
        let record = self.record(object.index).ok_or(IpcError::Stale)?;
        let mut attempt: u32 = 0;
        while record
            .lock
            .compare_exchange_weak(
                LOCK_FREE,
                self.holder.word(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            attempt = attempt.saturating_add(1);
            if !wait.wait(attempt) {
                return Err(IpcError::Contended);
            }
        }
        let guard = IpcObjectGuard {
            region: *self,
            record,
            handle: object,
        };
        let kind = record.kind.load(Ordering::Acquire);
        if kind == KIND_FREE
            || record.generation.load(Ordering::Relaxed) != object.generation as u64
        {
            return Err(IpcError::Stale);
        }
        Ok(guard)
    }

    /// Lock-free sample of an object's readiness sequences (for waiters'
    /// check → enroll → recheck). Fails if the handle is stale.
    pub fn observe(&self, object: IpcObjectHandle) -> Result<IpcSeqs, IpcError> {
        let record = self.record(object.index).ok_or(IpcError::Stale)?;
        let seqs = IpcSeqs {
            read: record.read_seq.load(Ordering::Acquire),
            write: record.write_seq.load(Ordering::Acquire),
        };
        if record.kind.load(Ordering::Acquire) == KIND_FREE
            || record.generation.load(Ordering::Acquire) != object.generation as u64
        {
            return Err(IpcError::Stale);
        }
        Ok(seqs)
    }

    fn pop_object(&self) -> Result<(u32, &'a IpcObjectRecord), IpcError> {
        let index = pop(&self.dir.free_objects, |i| {
            self.record(u32::try_from(i).ok()?)
                .map(|o| o.next_free.load(Ordering::Relaxed))
        })
        .ok_or(IpcError::NoObjects)?;
        let index = u32::try_from(index).map_err(|_| IpcError::Corrupt)?;
        Ok((index, self.record(index).ok_or(IpcError::Corrupt)?))
    }

    fn lock_fresh<W: LockWait>(
        &self,
        index: u32,
        record: &'a IpcObjectRecord,
        wait: &W,
    ) -> Result<IpcObjectGuard<'a>, IpcError> {
        let mut attempt: u32 = 0;
        while record
            .lock
            .compare_exchange_weak(
                LOCK_FREE,
                self.holder.word(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            attempt = attempt.saturating_add(1);
            if !wait.wait(attempt) {
                push(&self.dir.free_objects, index as usize, &record.next_free);
                return Err(IpcError::Contended);
            }
        }
        Ok(IpcObjectGuard {
            region: *self,
            record,
            handle: IpcObjectHandle {
                index,
                generation: record.generation.load(Ordering::Relaxed) as u32,
            },
        })
    }

    /// Create a pipe of `capacity` bytes (rounded like F_SETPIPE_SZ) with one
    /// reader and one writer reference. No pool storage is needed: a free
    /// record's retained storage is reused when it fits, otherwise the pipe
    /// starts *unbacked* (its ring is provided at the first write) and the
    /// record's too-small storage is detached into `retired` for the host to
    /// reclaim. `retired` must be `None` on entry. Host venue only.
    pub fn create_pipe<W: LockWait>(
        &self,
        capacity: usize,
        retired: &mut Option<IpcPipeStorage>,
        wait: &W,
    ) -> Result<IpcObjectHandle, IpcError> {
        if retired.is_some() {
            return Err(IpcError::BadStorage);
        }
        let capacity =
            Pipe::rounded_capacity(IPC_PIPE_PAGE_SIZE, capacity).map_err(IpcError::Object)?;
        let (index, record) = self.pop_object()?;
        let mut guard = self.lock_fresh(index, record, wait)?;
        let existing = guard.storage();
        let initialized = if existing.fits(capacity) {
            guard.pipe_parts().and_then(|(state, bytes, slots)| {
                Pipe::init(&mut state.pipe, bytes, slots, IPC_PIPE_PAGE_SIZE, capacity)
                    .map(|_| ())
                    .map_err(IpcError::Object)
            })
        } else {
            PipeRecord::unbacked(IPC_PIPE_PAGE_SIZE, capacity)
                .map_err(IpcError::Object)
                .and_then(|fresh| {
                    guard.set_storage(IpcPipeStorage::default())?;
                    // SAFETY: the object lock is held and the record is
                    // unpublished.
                    unsafe { (*record.state.get()).pipe = fresh };
                    Ok(())
                })
        };
        if let Err(e) = initialized {
            let _ = guard.set_storage(existing);
            drop(guard);
            push(&self.dir.free_objects, index as usize, &record.next_free);
            return Err(e);
        }
        if guard.storage() != existing {
            *retired = Some(existing);
        }
        Ok(guard.publish_kind(KIND_PIPE))
    }

    /// Create an eventfd counter object.
    pub fn create_eventfd<W: LockWait>(
        &self,
        initial: u32,
        mode: EventMode,
        wait: &W,
    ) -> Result<IpcObjectHandle, IpcError> {
        let (index, record) = self.pop_object()?;
        let guard = self.lock_fresh(index, record, wait)?;
        // SAFETY: the object lock is held and the record is unpublished.
        unsafe { (*record.state.get()).eventfd = EventFd::new(initial, mode) };
        Ok(guard.publish_kind(KIND_EVENTFD))
    }

    /// Release the backing of a description whose final hold just went
    /// away (from `close`, `dup2/3`, range/exec/destroy, or `unpin`). A pipe
    /// endpoint drops its reference (waking the peer); the object is freed
    /// when no endpoint remains, an eventfd immediately. A host-backed
    /// description is returned for the host venue to release. On
    /// `Contended` nothing changed: an EL1 caller hands the release to the
    /// host rather than retrying.
    pub fn release_backing<W: LockWait>(
        &self,
        backing: BackingToken,
        wait: &W,
    ) -> Result<IpcReleased, IpcError> {
        match IpcBacking::decode(backing).ok_or(IpcError::Corrupt)? {
            IpcBacking::Host(token) => Ok(IpcReleased::Host(token)),
            IpcBacking::Pipe { object, end } => {
                let mut guard = self.lock(object, wait)?;
                let other = match end {
                    End::Reader => End::Writer,
                    End::Writer => End::Reader,
                };
                let last = {
                    let pipe = guard.pipe()?;
                    pipe.references(end) == 1 && pipe.references(other) == 0
                };
                if last {
                    // Before any effect: a refused detach changes nothing.
                    guard.detach_all_member_items(wait)?;
                }
                let mut pipe = guard.pipe()?;
                let step = pipe.release(end);
                step.result.map_err(IpcError::Object)?;
                let gone = pipe.references(End::Reader) == 0 && pipe.references(End::Writer) == 0;
                let wake = guard.publish(step.wake);
                if gone {
                    guard.free();
                }
                Ok(IpcReleased::Object { wake, freed: gone })
            }
            IpcBacking::EventFd { object } => {
                let mut guard = self.lock(object, wait)?;
                guard.eventfd()?;
                guard.detach_all_member_items(wait)?;
                let wake = guard.publish(WakeSet::default());
                guard.free();
                Ok(IpcReleased::Object { wake, freed: true })
            }
            IpcBacking::Epoll { object } => {
                self.epoll_destroy(object, wait)?;
                Ok(IpcReleased::Epoll)
            }
        }
    }

    /// Register a host readiness subscriber (poll/epoll/host blocking wait)
    /// on `object`. While any exist, changes set the owed-wake flag.
    pub fn subscribe_host<W: LockWait>(
        &self,
        object: IpcObjectHandle,
        wait: &W,
    ) -> Result<(), IpcError> {
        let guard = self.lock(object, wait)?;
        guard.record.host_subscribers.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    pub fn unsubscribe_host<W: LockWait>(
        &self,
        object: IpcObjectHandle,
        wait: &W,
    ) -> Result<(), IpcError> {
        let guard = self.lock(object, wait)?;
        let subs = &guard.record.host_subscribers;
        if subs.load(Ordering::Relaxed) == 0 {
            return Err(IpcError::Corrupt);
        }
        if subs.fetch_sub(1, Ordering::AcqRel) == 1 {
            guard.record.host_wake_owed.store(0, Ordering::Release);
        }
        Ok(())
    }

    /// Take a bounded batch of pending object identities. Each returned handle
    /// is only a candidate: the host must authenticate its incarnation and
    /// consume its owed flag under the object lock before notifying anyone.
    /// Work is proportional to pending words and bits, not the live population.
    /// A concurrent publication either joins this batch or remains indexed for
    /// the next boundary; repeated publications of one object coalesce.
    pub fn drain_host_wake_candidates(&self, mut deliver: impl FnMut(IpcObjectHandle)) -> usize {
        let mut summary = self.dir.host_wake_summary.swap(0, Ordering::AcqRel);
        let mut visited = 0;
        while summary != 0 {
            let mid = summary.trailing_zeros() as usize;
            summary &= summary - 1;
            let Some(mid_word) = self.dir.host_wake_mid.get(mid) else {
                continue;
            };
            let mut leaves = mid_word.swap(0, Ordering::AcqRel);
            while leaves != 0 {
                let leaf = mid * 64 + leaves.trailing_zeros() as usize;
                leaves &= leaves - 1;
                let Some(leaf_word) = self.wake_leaf(leaf) else {
                    continue;
                };
                let mut pending = leaf_word.swap(0, Ordering::AcqRel);
                while pending != 0 {
                    let index = leaf * 64 + pending.trailing_zeros() as usize;
                    pending &= pending - 1;
                    if let Some(record) = self.record(index as u32) {
                        visited += 1;
                        deliver(IpcObjectHandle {
                            index: index as u32,
                            generation: record.generation.load(Ordering::Acquire) as u32,
                        });
                    }
                }
            }
        }
        visited
    }

    /// Set object `index`'s bits in the owed-wake index: leaf bit, then
    /// middle bit, then summary bit, so a boundary that sees the summary
    /// finds the object. O(1): three words, whatever the live population.
    /// Needs no object lock (an epoll publication indexes the epoll while
    /// holding only its member's lock).
    fn index_host_wake(&self, index: u32) {
        let index = index as usize;
        let leaf = index / 64;
        let Some(leaf_word) = self.wake_leaf(leaf) else {
            return;
        };
        leaf_word.fetch_or(1u64 << (index % 64), Ordering::Release);
        let mid = leaf / 64;
        self.dir.host_wake_mid[mid].fetch_or(1u64 << (leaf % 64), Ordering::Release);
        self.dir
            .host_wake_summary
            .fetch_or(1u64 << mid, Ordering::Release);
    }

    /// Owed host wakes a boundary found with no live delivery target (see
    /// [`IpcObjectGuard::retain_undeliverable_host_wake`]). Must stay zero.
    pub fn owed_host_wakes_without_target(&self) -> u64 {
        self.dir
            .owed_host_wakes_without_target
            .load(Ordering::Relaxed)
    }

    /// Host: take (and clear) the owed-wake flag of `object`.
    pub fn take_host_wake(&self, object: IpcObjectHandle) -> bool {
        self.record(object.index).is_some_and(|r| {
            r.generation.load(Ordering::Acquire) == object.generation as u64
                && r.host_wake_owed.swap(0, Ordering::AcqRel) != 0
        })
    }
}

impl<'a> IpcRegion<'a> {
    fn op_slot(&self, token: &IpcOpToken) -> Result<&'a IpcOperationSlot, IpcError> {
        let slot = self
            .dir
            .operations
            .get(token.index as usize)
            .ok_or(IpcError::Stale)?;
        if slot.live.load(Ordering::Acquire) == 0
            || slot.generation.load(Ordering::Acquire) != token.generation
        {
            return Err(IpcError::Stale);
        }
        Ok(slot)
    }

    /// Record a suspended operation (moving its pin into `op`) and return
    /// the owned token the scheduler keeps with the parked thread. Lock-free.
    pub fn begin_operation(&self, op: IpcOperation) -> Result<IpcOpToken, IpcError> {
        let ops = &self.dir.operations;
        let index = pop(&self.dir.free_operations, |i| {
            ops.get(i).map(|o| o.next_free.load(Ordering::Relaxed))
        })
        .ok_or(IpcError::NoOperations)?;
        let slot = &ops[index];
        // SAFETY: the slot was just popped from the free list: no token
        // names it, so this caller is its only accessor.
        unsafe { *slot.op.get() = op };
        slot.live.store(1, Ordering::Release);
        Ok(IpcOpToken {
            index: index as u32,
            generation: slot.generation.load(Ordering::Relaxed),
        })
    }

    /// The owner's view of its operation record.
    pub fn operation(&self, token: &IpcOpToken) -> Result<IpcOperation, IpcError> {
        let slot = self.op_slot(token)?;
        // SAFETY: the token's owner is the slot's only accessor.
        Ok(unsafe { *slot.op.get() })
    }

    /// Store the owner's progress (e.g. bytes transferred before re-parking).
    pub fn update_operation(&self, token: &IpcOpToken, op: IpcOperation) -> Result<(), IpcError> {
        let slot = self.op_slot(token)?;
        // SAFETY: the token's owner is the slot's only accessor.
        unsafe { *slot.op.get() = op };
        Ok(())
    }

    /// Complete the operation: return its record (the caller then unpins
    /// `op.pin` exactly once) and retire the token.
    pub fn finish_operation(&self, token: IpcOpToken) -> Result<IpcOperation, IpcError> {
        let slot = self.op_slot(&token)?;
        // SAFETY: the token's owner is the slot's only accessor.
        let op = unsafe { *slot.op.get() };
        slot.live.store(0, Ordering::Relaxed);
        let next = token.generation.wrapping_add(1);
        slot.generation.store(next, Ordering::Release);
        if next != u32::MAX {
            push(
                &self.dir.free_operations,
                token.index as usize,
                &slot.next_free,
            );
        }
        Ok(op)
    }
}

impl SlotBacking for IpcRegion<'_> {
    fn ofd(&self, index: usize) -> Option<&OfdRecord> {
        (index < IPC_MAX_OFDS).then(|| {
            // SAFETY: in bounds of the OFD reservation of the mapping; the
            // fd core resolves only published (initialized) indices, and
            // all-zero is a valid record of atomics.
            unsafe {
                &*self
                    .base
                    .add(IPC_OFDS_OFFSET)
                    .cast::<OfdRecord>()
                    .add(index)
            }
        })
    }

    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        let capacity = usize::try_from(extent.capacity).ok()?;
        let words = bitmap_words(capacity);
        let slot_bytes = (capacity as u64).checked_mul(8)?;
        let total = slot_bytes.checked_add((words as u64).checked_mul(8)?)?;
        let base = self.descriptor_range(extent.token, total)?;
        // SAFETY: an authenticated, 64-byte aligned range of the pool's
        // descriptor area. That area is type-stable: every word in it is
        // only ever accessed as an `AtomicU64` (slots, bitmaps), by every
        // venue, for the pool mapping's whole lifetime, whichever extent
        // currently owns it. So a lock-free lookup that resolved an extent
        // retired and reused meanwhile only makes atomic loads of atomics
        // that are written atomically, and rejects what it read via the
        // table's `seq`.
        unsafe {
            Some((
                core::slice::from_raw_parts(base as *const DescriptorSlot, capacity),
                core::slice::from_raw_parts(
                    base.add(slot_bytes as usize) as *const AtomicU64,
                    words,
                ),
            ))
        }
    }
}

/// The pool's pipe-ring area: its lower half. Ring bytes are plain memory
/// (copied under the object lock); they never overlap the descriptor area.
pub const fn ipc_ring_area(pool_len: u64) -> core::ops::Range<u64> {
    0..pool_len / IPC_POOL_AREAS
}

/// The pool's descriptor-extent area: its upper half. It is type-stable:
/// its words are only ever descriptor slots and free-slot bitmap words,
/// accessed as `AtomicU64` by every venue, so a retired extent's memory can
/// be reused for another extent while a lock-free lookup still reads it.
pub const fn ipc_descriptor_area(pool_len: u64) -> core::ops::Range<u64> {
    pool_len / IPC_POOL_AREAS..pool_len
}

/// The pool is split into this many equal areas (rings, then descriptors).
pub const IPC_POOL_AREAS: u64 = 2;

/// Pool bytes a descriptor extent of `capacity` slots occupies.
pub const fn descriptor_extent_bytes(capacity: usize) -> u64 {
    (capacity as u64 + bitmap_words(capacity) as u64) * 8
}

/// An object's readiness sequences.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpcSeqs {
    pub read: u64,
    pub write: u64,
}

/// What a state change owes, delivered by the caller after unlocking:
/// guest waiters on the advanced side(s), and a host notification when
/// `host_owed` (only if host subscribers exist).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcWake {
    pub object: IpcObjectHandle,
    pub readers: bool,
    pub writers: bool,
    pub seqs: IpcSeqs,
    pub host_owed: bool,
    /// Zone epolls this change queued items on: their `Readable` waiters
    /// are notified like the object's own.
    pub epolls: epoll::EpollWakes,
}

/// Result of releasing a description's backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcReleased {
    /// The host venue releases this host resource.
    Host(HostResourceToken),
    /// An object endpoint was released; `freed` if the object is gone.
    Object { wake: IpcWake, freed: bool },
    /// An epoll instance was destroyed with its zone items (it has no
    /// waiters: each one holds a pin on it).
    Epoll,
}

/// A held object lock. Dropping it releases the lock.
pub struct IpcObjectGuard<'a> {
    region: IpcRegion<'a>,
    record: &'a IpcObjectRecord,
    handle: IpcObjectHandle,
}
impl Drop for IpcObjectGuard<'_> {
    fn drop(&mut self) {
        self.record.lock.store(LOCK_FREE, Ordering::Release);
    }
}

impl<'a> IpcObjectGuard<'a> {
    pub fn handle(&self) -> IpcObjectHandle {
        self.handle
    }
    pub fn kind(&self) -> Option<IpcObjectKind> {
        match self.record.kind.load(Ordering::Relaxed) {
            KIND_PIPE => Some(IpcObjectKind::Pipe),
            KIND_EVENTFD => Some(IpcObjectKind::EventFd),
            KIND_EPOLL => Some(IpcObjectKind::Epoll),
            _ => None,
        }
    }
    pub fn seqs(&self) -> IpcSeqs {
        IpcSeqs {
            read: self.record.read_seq.load(Ordering::Relaxed),
            write: self.record.write_seq.load(Ordering::Relaxed),
        }
    }
    pub fn host_subscribers(&self) -> u32 {
        self.record.host_subscribers.load(Ordering::Relaxed)
    }
    fn storage(&self) -> IpcPipeStorage {
        IpcPipeStorage {
            offset: self.record.storage_offset.load(Ordering::Relaxed),
            ring_bytes: self.record.storage_ring_bytes.load(Ordering::Relaxed),
            pages: self.record.storage_pages.load(Ordering::Relaxed),
        }
    }
    fn set_storage(&mut self, s: IpcPipeStorage) -> Result<(), IpcError> {
        if s != IpcPipeStorage::default()
            && self.region.ring_range(s.offset, s.footprint()).is_none()
        {
            return Err(IpcError::BadStorage);
        }
        self.record
            .storage_offset
            .store(s.offset, Ordering::Relaxed);
        self.record
            .storage_ring_bytes
            .store(s.ring_bytes, Ordering::Relaxed);
        self.record.storage_pages.store(s.pages, Ordering::Relaxed);
        Ok(())
    }
    #[allow(clippy::type_complexity)]
    fn pipe_parts(&mut self) -> Result<(&mut IpcObjectState, &mut [u8], &mut [Page]), IpcError> {
        let s = self.storage();
        if s == IpcPipeStorage::default() {
            // Unbacked: the record alone (its ring comes at the first write).
            // SAFETY: the object lock is held (exclusive state access).
            return Ok((unsafe { &mut *self.record.state.get() }, &mut [], &mut []));
        }
        let base = self
            .region
            .ring_range(s.offset, s.footprint())
            .filter(|_| s.ring_bytes != 0)
            .ok_or(IpcError::BadStorage)?;
        // SAFETY: the object lock is held (exclusive state access); the
        // storage range is authenticated in bounds and owned by this object
        // (the host allocator never hands one range to two objects); the
        // metadata follows the ring at a 4-byte-aligned offset.
        unsafe {
            let bytes = core::slice::from_raw_parts_mut(base, s.ring_bytes as usize);
            let slots = core::slice::from_raw_parts_mut(
                base.add(s.ring_bytes as usize) as *mut Page,
                s.pages as usize,
            );
            Ok((&mut *self.record.state.get(), bytes, slots))
        }
    }
    /// The pipe, as a view over its shared record and storage.
    pub fn pipe(&mut self) -> Result<Pipe<'_, &mut PipeRecord>, IpcError> {
        if self.kind() != Some(IpcObjectKind::Pipe) {
            return Err(IpcError::WrongKind);
        }
        let (state, bytes, slots) = self.pipe_parts()?;
        Pipe::attach(&mut state.pipe, bytes, slots).map_err(|_| IpcError::Corrupt)
    }

    /// Either venue, under this lock: give an unbacked pipe a ring from the
    /// host-provisioned stock, so its first write needs no host exit.
    /// `true` when the pipe has its ring (already, or now); `false` when the
    /// stock is empty, the pipe has no reader (the write is EPIPE) or its
    /// capacity exceeds a stock ring (the host sizes it). No allocation.
    pub fn provide_ring_from_stock(&mut self) -> Result<bool, IpcError> {
        let pipe = self.pipe()?;
        if pipe.is_backed() {
            return Ok(true);
        }
        // EPIPE is decided before any ring is spent; a pipe resized past the
        // default capacity is sized by the host.
        if pipe.references(End::Reader) == 0 || pipe.capacity() as u64 > IPC_STOCK_RING_BYTES {
            return Ok(false);
        }
        let Some(mut ring) = self.region.take_stock_ring() else {
            return Ok(false);
        };
        match self.provide_pipe_storage(&mut ring) {
            Ok(installed) => Ok(installed),
            Err(error) => {
                // Unreachable for a stocked ring; never lose the extent.
                if self.region.stock_ring(ring).is_err() {
                    return Err(IpcError::Corrupt);
                }
                Err(error)
            }
        }
    }

    /// Host, under this lock: give an unbacked pipe its ring. `storage` is an
    /// independently owned pool extent the host provisioned before locking,
    /// holding at least the pipe's current capacity. Returns `true` when it
    /// was installed (`storage` becomes the empty extent); `false` when the
    /// pipe already has its ring (another writer provided it) and `storage`
    /// stays the caller's to reclaim. `pipe::Error::Storage` when `storage`
    /// is smaller than the capacity (F_SETPIPE_SZ grew it meanwhile).
    pub fn provide_pipe_storage(&mut self, storage: &mut IpcPipeStorage) -> Result<bool, IpcError> {
        if self.pipe()?.is_backed() {
            return Ok(false);
        }
        self.replace_pipe_storage(storage)?;
        Ok(true)
    }

    /// Replace a live pipe's storage with an independently owned pool extent.
    /// The host provisions it before locking; on success `replacement` receives
    /// the old extent for reclamation after unlocking. The capacity is unchanged
    /// until the caller authorizes it through `Pipe::set_capacity`.
    /// No record layout changes and no allocation occurs here.
    pub fn replace_pipe_storage(
        &mut self,
        replacement: &mut IpcPipeStorage,
    ) -> Result<(), IpcError> {
        if self.kind() != Some(IpcObjectKind::Pipe) {
            return Err(IpcError::WrongKind);
        }
        let old = self.storage();
        let new = *replacement;
        let footprint = new
            .pages
            .checked_mul(core::mem::size_of::<Page>() as u64)
            .and_then(|n| new.ring_bytes.checked_add(n))
            .ok_or(IpcError::BadStorage)?;
        let end = new
            .offset
            .checked_add(footprint)
            .ok_or(IpcError::BadStorage)?;
        let old_end = old
            .offset
            .checked_add(old.footprint())
            .ok_or(IpcError::Corrupt)?;
        if new.ring_bytes == 0
            || !new.ring_bytes.is_multiple_of(IPC_PIPE_PAGE_SIZE as u64)
            || (new.offset < old_end && old.offset < end)
        {
            return Err(IpcError::BadStorage);
        }
        let base = self
            .region
            .ring_range(new.offset, footprint)
            .ok_or(IpcError::BadStorage)?;
        // SAFETY: checked pool bounds, page alignment and disjointness from
        // this object's live extent. As for creation, the host allocator owns
        // the supplied extent exclusively and never assigns it to two objects.
        let (new_bytes, new_slots) = unsafe {
            (
                core::slice::from_raw_parts_mut(base, new.ring_bytes as usize),
                core::slice::from_raw_parts_mut(
                    base.add(new.ring_bytes as usize).cast::<Page>(),
                    new.pages as usize,
                ),
            )
        };
        self.pipe()?
            .replace_storage(new_bytes, new_slots)
            .map_err(IpcError::Object)?;
        // Already authenticated above. Publish only after the complete copy.
        self.set_storage(new)?;
        *replacement = old;
        Ok(())
    }
    /// The eventfd counter, in place.
    pub fn eventfd(&mut self) -> Result<&mut EventFd, IpcError> {
        if self.kind() != Some(IpcObjectKind::EventFd) {
            return Err(IpcError::WrongKind);
        }
        // SAFETY: the object lock is held.
        Ok(unsafe { &mut (*self.record.state.get()).eventfd })
    }
    /// Publish a state change: advance the sequences named by `wake`
    /// (Release, under this lock) and owe the host a notification if it has
    /// subscribers. Deliver the returned [`IpcWake`] after dropping the guard.
    pub fn publish(&mut self, wake: WakeSet) -> IpcWake {
        let r = self.record;
        if wake.readers {
            r.read_seq.fetch_add(1, Ordering::Release);
        }
        if wake.writers {
            r.write_seq.fetch_add(1, Ordering::Release);
        }
        let changed = wake.readers || wake.writers;
        let mut host_owed = changed && r.host_subscribers.load(Ordering::Relaxed) != 0;
        if host_owed {
            r.host_wake_owed.store(1, Ordering::Release);
            self.index_host_wake();
        }
        // Zone epoll items watching this member: queued on their epolls
        // under this lock alone (see `epoll`). An epoll owes the host a
        // wake only when it has a host-side waiter.
        let mut epolls = epoll::EpollWakes::EMPTY;
        if changed
            && r.epoll_link.load(Ordering::Relaxed) != 0
            && self.kind() != Some(IpcObjectKind::Epoll)
        {
            let (queued, epoll_host_owed) = self.publish_to_epolls(wake);
            epolls = queued;
            host_owed |= epoll_host_owed;
        }
        IpcWake {
            object: self.handle,
            readers: wake.readers,
            writers: wake.writers,
            seqs: self.seqs(),
            host_owed,
            epolls,
        }
    }
    /// Set this object's bits in the owed-wake index: leaf bit, then middle
    /// bit, then summary bit, so a boundary that sees the summary finds the
    /// object. O(1): three words, whatever the live population.
    fn index_host_wake(&self) {
        self.region.index_host_wake(self.handle.index);
    }

    /// Host, under this lock: consume the owed host wake, for delivery to a
    /// target the caller already holds alive.
    pub fn take_host_wake(&mut self) -> bool {
        self.record.host_wake_owed.swap(0, Ordering::AcqRel) != 0
    }

    /// Host, under this lock, with no live delivery target for this
    /// incarnation: never consume the owed wake. Keep it owed and put it
    /// back in the index (a boundary drained it) for the boundary after a
    /// target exists, and count the refusal. False: nothing was owed.
    pub fn retain_undeliverable_host_wake(&mut self) -> bool {
        if self.record.host_wake_owed.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.index_host_wake();
        self.region
            .dir
            .owed_host_wakes_without_target
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn publish_kind(self, kind: u32) -> IpcObjectHandle {
        self.record.host_subscribers.store(0, Ordering::Relaxed);
        self.record.host_wake_owed.store(0, Ordering::Relaxed);
        self.record.kind.store(kind, Ordering::Release);
        self.handle
    }
    /// Free the object under its lock: advance the generation (retiring the
    /// slot when exhausted) and return the index to the free list. Storage
    /// stays attached for reuse. Consumes the guard.
    fn free(self) {
        let r = self.record;
        r.kind.store(KIND_FREE, Ordering::Release);
        let next = r.generation.load(Ordering::Relaxed) + 1;
        r.generation.store(next, Ordering::Release);
        let index = self.handle.index as usize;
        let dir = self.region.dir;
        drop(self);
        if next < u64::from(u32::MAX) {
            push(&dir.free_objects, index, &r.next_free);
        }
    }
}

pub mod epoll;

#[cfg(test)]
mod tests;
