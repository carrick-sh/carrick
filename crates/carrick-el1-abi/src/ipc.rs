//! Shared IPC records for checkpoint 3: the descriptor authority, pipe and
//! eventfd objects that the host and EL1 both operate on, in place.
//!
//! # Frozen ABI (v1)
//!
//! One [`IpcDirectory`] plus one byte *pool* hold every record. Both are plain
//! `repr(C)` memory with no pointers, `Arc`, `Mutex` or trait objects; every
//! cross-reference is a typed index + generation or a pool offset:
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
//!   page metadata live in a pool [`IpcPipeStorage`] extent.
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
//! One lock word per fd table (inside the fd core) and one per object. Order:
//! a brief table lock to pin a description (released before any object
//! work), then one object lock. The `LockWait` policy is the venue's: EL1
//! spins a bounded while and forwards on `Contended` before effects; the host
//! waits. No lock is held across I/O, a WFI, a context switch or a host wait,
//! and nothing allocates under a lock: pool storage is provisioned by the
//! host before it takes any lock ([`IpcError::NeedsStorage`] asks for it).
//!
//! Guest page size for pipe accounting is [`IPC_PIPE_PAGE_SIZE`] (Linux
//! aarch64 4 KiB pages, `carrick_abi::LINUX_PAGE_SIZE`).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use carrick_fd_core::free_list::{pop, push};
pub use carrick_fd_core::{
    self as fd, BackingToken, DescriptorSlot, Extent, LockWait, OfdPin, RawOfdPin, RawTableId,
    SlotBacking, bitmap_words,
};
pub use carrick_pipe_core::{
    self as pipe, End, EventFd, EventMode, Page, Pipe, PipeRecord, WakeSet, WriteProgress,
};

/// Descriptor tables (distinct `CLONE_FILES` groups) in the shared authority.
pub const IPC_FD_TABLES: usize = 256;
/// Open file descriptions in the shared authority.
pub const IPC_OFDS: usize = 2048;
/// Suspended-operation records ([`IpcOperation`] behind an [`IpcOpToken`]).
/// Exhaustion refuses before effects (`NoOperations`: EL1 forwards).
pub const IPC_OPERATIONS: usize = 1024;
/// Pipe and eventfd objects.
pub const IPC_OBJECTS: usize = 1024;
/// Guest page size used for pipe capacity and ring pages.
pub const IPC_PIPE_PAGE_SIZE: usize = 4096;
/// Alignment of every pool extent (a pipe ring starts on a guest page).
pub const IPC_POOL_ALIGN: u64 = IPC_PIPE_PAGE_SIZE as u64;
/// Region magic: "CRKIPC" + ABI version 2 (v2: `IpcOperation::value`).
pub const IPC_MAGIC: u64 = u64::from_le_bytes(*b"CRKIPC\x00\x02");
const IPC_READY: u64 = 1;

/// The descriptor authority shared by host and EL1.
pub type IpcFdCore = fd::Core<IPC_FD_TABLES, IPC_OFDS>;
/// The descriptor authority bound to this region and a lock policy.
pub type IpcFdAuthority<'a, W> = fd::Authority<'a, IpcRegion<'a>, W, IPC_FD_TABLES, IPC_OFDS>;

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
    Pipe { object: IpcObjectHandle, end: End },
    EventFd { object: IpcObjectHandle },
}

const TAG_SHIFT: u32 = 61;
const TAG_HOST: u64 = 1;
const TAG_PIPE: u64 = 2;
const TAG_EVENTFD: u64 = 3;
const END_WRITER: u64 = 1 << 60;
const INDEX_SHIFT: u32 = 32;
const INDEX_BITS: u64 = (1 << 28) - 1;

impl IpcBacking {
    /// Bits 63..61 tag (1 host, 2 pipe, 3 eventfd); host: bits 60..0 token;
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
            _ => None,
        }
    }
}
const fn object_bits(object: IpcObjectHandle) -> u64 {
    ((object.index as u64 & INDEX_BITS) << INDEX_SHIFT) | object.generation as u64
}
const _: () = assert!(IPC_OBJECTS as u64 <= INDEX_BITS);

// ---------------------------------------------------------------- records

/// Object kinds stored in [`IpcObjectRecord`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcObjectKind {
    Pipe,
    EventFd,
}
const KIND_FREE: u32 = 0;
const KIND_PIPE: u32 = 1;
const KIND_EVENTFD: u32 = 2;

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

/// The object's state; which half is meaningful follows `kind`.
#[repr(C)]
#[derive(Debug)]
pub struct IpcObjectState {
    pub pipe: PipeRecord,
    pub eventfd: EventFd,
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
    _reserved: u64,
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

/// Every IPC record, as one zero-initializable `repr(C)` object. The byte
/// pool is separate memory (see [`IpcRegion`]).
#[repr(C, align(4096))]
pub struct IpcDirectory {
    header: IpcHeader,
    free_objects: AtomicU64,
    _reserved: [u64; 7],
    fd: IpcFdCore,
    objects: [IpcObjectRecord; IPC_OBJECTS],
    free_operations: AtomicU64,
    _reserved_ops: [u64; 7],
    operations: [IpcOperationSlot; IPC_OPERATIONS],
}

/// Layout facts of this ABI; see [`IPC_LAYOUT_HASH`].
const LAYOUT_FACTS: &[u64] = &[
    IPC_MAGIC,
    IPC_FD_TABLES as u64,
    IPC_OFDS as u64,
    IPC_OBJECTS as u64,
    IPC_PIPE_PAGE_SIZE as u64,
    IPC_POOL_ALIGN,
    core::mem::size_of::<usize>() as u64,
    core::mem::size_of::<IpcDirectory>() as u64,
    core::mem::align_of::<IpcDirectory>() as u64,
    core::mem::offset_of!(IpcDirectory, fd) as u64,
    core::mem::offset_of!(IpcDirectory, objects) as u64,
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
    core::mem::offset_of!(IpcOperationSlot, op) as u64,
];

/// FNV-1a over [`LAYOUT_FACTS`] and the fd core's layout facts. Written into
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
    /// Every object record is in use.
    NoObjects,
    /// Every operation record is in use (refused before effects).
    NoOperations,
    /// The host must provision pipe storage of at least this size (outside
    /// any lock) and retry; never a guest errno by itself.
    NeedsStorage { ring_bytes: u64, pages: u64 },
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

/// A venue's view of the shared IPC memory: the directory plus the byte
/// pool, each at this venue's own address (host mapping or EL1 VA). Offsets
/// in records are pool-relative, so both venues resolve the same records.
#[derive(Clone, Copy)]
pub struct IpcRegion<'a> {
    dir: &'a IpcDirectory,
    pool: *mut u8,
    pool_len: u64,
    _pool: PhantomData<&'a UnsafeCell<[u8]>>,
}
// SAFETY: the pool is shared memory whose bytes are accessed only under the
// owning table/object lock, through slices bounded by authenticated extents.
unsafe impl Send for IpcRegion<'_> {}
unsafe impl Sync for IpcRegion<'_> {}

impl<'a> IpcRegion<'a> {
    fn checked(dir: *mut IpcDirectory, pool: *mut u8) -> Result<(), IpcError> {
        if dir.is_null()
            || !(dir as usize).is_multiple_of(core::mem::align_of::<IpcDirectory>())
            || pool.is_null()
            || !(pool as usize).is_multiple_of(IPC_POOL_ALIGN as usize)
        {
            return Err(IpcError::BadRegion);
        }
        Ok(())
    }

    /// Publish a new region (the one initialization venue, once).
    ///
    /// # Safety
    /// `dir` points to zeroed memory of `size_of::<IpcDirectory>()` bytes and
    /// `pool` to `pool_len` bytes, both valid and shared for `'a`, used for
    /// nothing else.
    pub unsafe fn initialize(
        dir: *mut IpcDirectory,
        pool: *mut u8,
        pool_len: usize,
        identity: u64,
    ) -> Result<Self, IpcError> {
        Self::checked(dir, pool)?;
        // SAFETY: caller contract; all-zero is a valid IpcDirectory.
        let d: &'a IpcDirectory = unsafe { &*dir };
        if d.header.state.load(Ordering::Acquire) != 0 {
            return Err(IpcError::BadRegion);
        }
        d.fd.initialize(identity).map_err(IpcError::Fd)?;
        for i in (0..IPC_OBJECTS).rev() {
            push(&d.free_objects, i, &d.objects[i].next_free);
        }
        for i in (0..IPC_OPERATIONS).rev() {
            push(&d.free_operations, i, &d.operations[i].next_free);
        }
        d.header.magic.store(IPC_MAGIC, Ordering::Relaxed);
        d.header
            .layout_hash
            .store(IPC_LAYOUT_HASH, Ordering::Relaxed);
        d.header.pool_len.store(pool_len as u64, Ordering::Relaxed);
        d.header.state.store(IPC_READY, Ordering::Release);
        Ok(Self {
            dir: d,
            pool,
            pool_len: pool_len as u64,
            _pool: PhantomData,
        })
    }

    /// Attach to a published region, authenticating magic, layout hash,
    /// readiness and pool length.
    ///
    /// # Safety
    /// `dir`/`pool` map the same shared memory the initializing venue
    /// published (at this venue's addresses), valid for `'a`.
    pub unsafe fn attach(
        dir: *mut IpcDirectory,
        pool: *mut u8,
        pool_len: usize,
    ) -> Result<Self, IpcError> {
        Self::checked(dir, pool)?;
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
            pool,
            pool_len: pool_len as u64,
            _pool: PhantomData,
        })
    }

    /// The shared descriptor authority, with this venue's lock policy.
    pub fn fd<W: LockWait>(&'a self, wait: W) -> IpcFdAuthority<'a, W> {
        self.dir.fd.bind(self, wait)
    }

    /// Pool bytes `[offset, offset+len)`, authenticated against the pool.
    fn pool_range(&self, offset: u64, len: u64, align: u64) -> Option<*mut u8> {
        let end = offset.checked_add(len)?;
        if !offset.is_multiple_of(align) || end > self.pool_len {
            return None;
        }
        // SAFETY: in bounds of the pool mapping.
        Some(unsafe { self.pool.add(offset as usize) })
    }

    fn record(&self, index: u32) -> Option<&'a IpcObjectRecord> {
        self.dir.objects.get(index as usize)
    }

    /// Lock `object` for exclusive use. Authenticates kind and generation
    /// after the lock is held.
    pub fn lock<W: LockWait>(
        &self,
        object: IpcObjectHandle,
        wait: &W,
    ) -> Result<IpcObjectGuard<'a>, IpcError> {
        let record = self.record(object.index).ok_or(IpcError::Stale)?;
        let mut attempt = 0;
        while record
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            attempt += 1;
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
        let objects = &self.dir.objects;
        let index = pop(&self.dir.free_objects, |i| {
            objects.get(i).map(|o| o.next_free.load(Ordering::Relaxed))
        })
        .ok_or(IpcError::NoObjects)?;
        Ok((index as u32, &objects[index]))
    }

    fn lock_fresh<W: LockWait>(
        &self,
        index: u32,
        record: &'a IpcObjectRecord,
        wait: &W,
    ) -> Result<IpcObjectGuard<'a>, IpcError> {
        let mut attempt = 0;
        while record
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            attempt += 1;
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
    /// reader and one writer reference. A free record keeps its storage: if
    /// that storage is too small, `storage` must supply adequate storage
    /// (consumed; the record's old storage is handed back in its place for
    /// the host to reclaim). Otherwise `NeedsStorage` asks for it, with no
    /// state changed. Host venue only (it provisions pool storage).
    pub fn create_pipe<W: LockWait>(
        &self,
        capacity: usize,
        storage: &mut Option<IpcPipeStorage>,
        wait: &W,
    ) -> Result<IpcObjectHandle, IpcError> {
        let capacity =
            Pipe::rounded_capacity(IPC_PIPE_PAGE_SIZE, capacity).map_err(IpcError::Object)?;
        let (index, record) = self.pop_object()?;
        let mut guard = self.lock_fresh(index, record, wait)?;
        let existing = guard.storage();
        let chosen = if existing.fits(capacity) {
            existing
        } else {
            match *storage {
                Some(s) if s.fits(capacity) => s,
                _ => {
                    drop(guard);
                    push(&self.dir.free_objects, index as usize, &record.next_free);
                    return Err(IpcError::NeedsStorage {
                        ring_bytes: capacity as u64,
                        pages: (capacity / IPC_PIPE_PAGE_SIZE) as u64,
                    });
                }
            }
        };
        if let Err(e) = guard.set_storage(chosen).and_then(|()| {
            let (state, bytes, slots) = guard.pipe_parts()?;
            Pipe::init(&mut state.pipe, bytes, slots, IPC_PIPE_PAGE_SIZE, capacity)
                .map(|_| ())
                .map_err(IpcError::Object)
        }) {
            let _ = guard.set_storage(existing);
            drop(guard);
            push(&self.dir.free_objects, index as usize, &record.next_free);
            return Err(e);
        }
        if chosen != existing {
            *storage = (existing != IpcPipeStorage::default()).then_some(existing);
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
                let wake = guard.publish(WakeSet::default());
                guard.free();
                Ok(IpcReleased::Object { wake, freed: true })
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
        subs.fetch_sub(1, Ordering::AcqRel);
        Ok(())
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
    fn resolve(&self, extent: Extent) -> Option<(&[DescriptorSlot], &[AtomicU64])> {
        let capacity = usize::try_from(extent.capacity).ok()?;
        let words = bitmap_words(capacity);
        let slot_bytes = (capacity as u64).checked_mul(8)?;
        let total = slot_bytes.checked_add((words as u64).checked_mul(8)?)?;
        let base = self.pool_range(extent.token, total, 64)?;
        // SAFETY: authenticated in-bounds, 64-byte aligned pool range of
        // atomics; the fd core accesses it only under the table's lock.
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
}

/// Result of releasing a description's backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcReleased {
    /// The host venue releases this host resource.
    Host(HostResourceToken),
    /// An object endpoint was released; `freed` if the object is gone.
    Object { wake: IpcWake, freed: bool },
}

/// A held object lock. Dropping it releases the lock.
pub struct IpcObjectGuard<'a> {
    region: IpcRegion<'a>,
    record: &'a IpcObjectRecord,
    handle: IpcObjectHandle,
}
impl Drop for IpcObjectGuard<'_> {
    fn drop(&mut self) {
        self.record.lock.store(0, Ordering::Release);
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
            && self
                .region
                .pool_range(s.offset, s.footprint(), IPC_POOL_ALIGN)
                .is_none()
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
        let base = self
            .region
            .pool_range(s.offset, s.footprint(), IPC_POOL_ALIGN)
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
        let host_owed = changed && r.host_subscribers.load(Ordering::Relaxed) != 0;
        if host_owed {
            r.host_wake_owed.store(1, Ordering::Release);
        }
        IpcWake {
            object: self.handle,
            readers: wake.readers,
            writers: wake.writers,
            seqs: self.seqs(),
            host_owed,
        }
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

#[cfg(test)]
mod tests;
