//! The in-zone [`FileService`] over VFS-admitted delegated records.
//!
//! A pin is one owned ring reference in the admitted record's [`OpenLifetime`],
//! named by a table-issued key: slot index, slot generation and the carrier pin
//! table's 24-bit nonce. One [`ZonePinTable`] is constructed per carrier and
//! borrowed across [`ZoneFileService`] calls; allocator state (`table_nonce`,
//! `free`, `high_water`, `live`) is persisted in the caller-owned [`ZonePinSlot`]
//! storage so dropping and rebuilding the service or table wrapper over the
//! same slice recovers every live pin without consuming a new nonce or
//! overwriting a live slot. A replayed, retired or foreign key is refused
//! before any record or byte is touched, so it can never consume a live peer's
//! reference. Positional I/O runs under the inode lock through the shared
//! [`super::file`] core (including watch-mark lock and event admission) and
//! never moves the record's cursor. The last release queues the record's
//! indexed terminal handoff in the service's region through
//! [`carrick_el1_abi::queue_open_release`] once and nudges the host drain
//! through the venue; it performs no storage and never waits.
//!
//! Path open and work the zone cannot complete resident (a demoted record,
//! a contended inode or watch lock, bytes beyond the resident slot) belong to
//! F4's counted host crossing and owned continuation; until then they are
//! refused with `Unsupported` rather than served by a second implementation.
//!
//! [`OpenLifetime`]: carrick_el1_abi::OpenLifetime
use super::file::{self, FileDataEvent, FileError, StoreAt, TryInstanceLock};
use super::file_notification::FileAccess;
use carrick_core::file::{
    FileAttributes, FileKind, FileOperation, FilePin, FilePinKey, FileRoot, FileService, IoError,
    NamePath, OpenOutcome, OpenRequest, WriteAt,
};
use carrick_el1_abi::{
    AdmittedOpenReference, DELEGATED_FILE_MAX_SIZE, DELEGATED_FLAG_APPEND, DELEGATED_FLAG_READABLE,
    DELEGATED_FLAG_WRITABLE, DelegatedFile, DelegatedInotify, DelegatedOpenFile, EL1_CACHE_OFFSET,
    EL1_INOTIFY_TABLE_OFFSET, EL1_OBJECT_TABLE_OFFSET, EL1_OPEN_FILE_TABLE_OFFSET, EL1_ZONE_OFFSET,
    MAX_DELEGATED_FILES, MAX_DELEGATED_INOTIFY, MAX_ZONE_OPEN_FILES, OpenReferenceKey,
    OpenReferenceWork, OpenRelease, SlotId, ZoneTables, queue_open_release,
};
use core::sync::atomic::{AtomicU32, Ordering};

const INDEX_BITS: u32 = 16;
const GENERATION_BITS: u32 = 24;
const GENERATION_MAX: u32 = (1 << GENERATION_BITS) - 1;
const NONCE_MAX: u32 = (1 << (64 - INDEX_BITS - GENERATION_BITS)) - 1;

/// Carrier pin tables never share a nonce; one nonce is minted per fresh
/// [`ZonePinSlot`] storage slice, and saturates at [`NONCE_MAX`] (refusing
/// further fresh table allocations rather than wrapping).
static NEXT_NONCE: AtomicU32 = AtomicU32::new(1);

/// The venue that wakes the host drain of indexed terminal handoffs.
pub trait ZoneFileVenue {
    /// One record became terminal and its handoff is queued in the region.
    /// Must not perform storage or wait.
    fn terminal_queued(&self, key: OpenReferenceKey);

    /// Observe one open-record lookup and any [`OpenReferenceWork`] CAS
    /// attempts on its [`OpenLifetime`]. Default no-op in production.
    fn observe_record(&self, _handle: u32, _work: OpenReferenceWork) {}
}

/// The delegated tables of one retained supervisor region.
#[derive(Clone, Copy)]
pub struct ZoneFileTables<'a> {
    region: usize,
    open: &'a [DelegatedOpenFile],
    objects: &'a [DelegatedFile],
    watches: &'a [DelegatedInotify],
    zone: &'a ZoneTables,
}
impl<'a> ZoneFileTables<'a> {
    /// # Safety
    /// `region` is the aligned base of a supervisor region that stays mapped,
    /// and is never retired, for `'a`.
    pub unsafe fn at_region(region: usize) -> Self {
        // SAFETY: the caller retains the region; offsets and capacities are
        // the shared ABI layout.
        unsafe {
            Self {
                region,
                open: core::slice::from_raw_parts(
                    (region + EL1_OPEN_FILE_TABLE_OFFSET as usize) as *const DelegatedOpenFile,
                    MAX_ZONE_OPEN_FILES,
                ),
                objects: core::slice::from_raw_parts(
                    (region + EL1_OBJECT_TABLE_OFFSET as usize) as *const DelegatedFile,
                    MAX_DELEGATED_FILES,
                ),
                watches: core::slice::from_raw_parts(
                    (region + EL1_INOTIFY_TABLE_OFFSET as usize) as *const DelegatedInotify,
                    MAX_DELEGATED_INOTIFY,
                ),
                zone: &*((region + EL1_ZONE_OFFSET as usize) as *const ZoneTables),
            }
        }
    }
    fn cache(&self, inode_handle: u32) -> *mut u8 {
        (self.region
            + EL1_CACHE_OFFSET as usize
            + (inode_handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8
    }
}

/// One pin slot inside [`ZonePinSlots`] / [`ZonePinSlice`].
///
/// Non-`Copy`, non-`Clone`, with no per-slot constructor or [`Default`]
/// implementation, and never exposed by mutable reference outside this module,
/// so callers cannot individually reset or overwrite a live slot:
///
/// ```compile_fail
/// use carrick_el1::substrate::zone_file_service::*;
/// let mut slots = ZonePinSlot::new_storage::<2>();
/// let _ = core::mem::take(&mut slots);
/// ```
///
/// ```compile_fail
/// use carrick_el1::substrate::zone_file_service::*;
/// let mut slots = ZonePinSlot::new_storage::<2>();
/// slots[0] = ZonePinSlot::new_storage::<1>()[0];
/// ```
///
/// Slot 0 also persists the table's allocator state (`table_nonce`,
/// `table_free`, `table_high_water`, `table_live`) so dropping and rebuilding
/// [`ZonePinTable`] over the same storage recovers all live pins without
/// orphaning ring references.
#[derive(Debug)]
pub struct ZonePinSlot {
    generation: u32,
    live: bool,
    open: OpenReferenceKey,
    next_free: u32,
    table_nonce: u32,
    table_free: u32,
    table_high_water: u32,
    table_live: u32,
}
impl ZonePinSlot {
    const VACANT: Self = Self {
        generation: 1,
        live: false,
        open: OpenReferenceKey {
            handle: 0,
            incarnation: 0,
        },
        next_free: u32::MAX,
        table_nonce: 0,
        table_free: u32::MAX,
        table_high_water: 0,
        table_live: 0,
    };

    /// Construct fresh, uninitialized pin-table storage of `N` vacant slots.
    pub const fn new_storage<const N: usize>() -> ZonePinSlots<N> {
        ZonePinSlots::new()
    }
}

/// Unsized slice view of caller-owned [`ZonePinSlot`] storage. Does not
/// implement [`core::ops::IndexMut`] or expose `&mut ZonePinSlot`, preventing
/// callers from resetting or swapping individual slots while pins are live.
#[repr(transparent)]
#[derive(Debug)]
pub struct ZonePinSlice([ZonePinSlot]);
impl ZonePinSlice {
    pub const fn len(&self) -> usize {
        self.0.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Caller-owned array of `N` pin slots; the service never allocates.
/// Intentionally omits [`Default`] so `core::mem::take` cannot reset live
/// storage without going through [`ZonePinTable::close`].
#[repr(transparent)]
#[derive(Debug)]
pub struct ZonePinSlots<const N: usize>([ZonePinSlot; N]);
impl<const N: usize> ZonePinSlots<N> {
    /// Construct fresh, uninitialized pin-table storage of `N` vacant slots.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self([ZonePinSlot::VACANT; N])
    }
    pub const fn as_slice(&self) -> &ZonePinSlice {
        // SAFETY: `ZonePinSlice` is `#[repr(transparent)]` over `[ZonePinSlot]`.
        unsafe { &*(&self.0 as *const [ZonePinSlot] as *const ZonePinSlice) }
    }
    pub const fn as_slice_mut(&mut self) -> &mut ZonePinSlice {
        // SAFETY: `ZonePinSlice` is `#[repr(transparent)]` over `[ZonePinSlot]`.
        unsafe { &mut *(&mut self.0 as *mut [ZonePinSlot] as *mut ZonePinSlice) }
    }
}
impl<const N: usize> core::ops::Deref for ZonePinSlots<N> {
    type Target = ZonePinSlice;
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl<const N: usize> core::ops::DerefMut for ZonePinSlots<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

/// Backing storage for [`ZonePinTable`], allowing tests to wrap [`ZonePinSlots`]
/// in a counting storage adapter without exposing `&mut ZonePinSlot`.
pub trait ZonePinStorage {
    fn pin_slice(&self) -> &ZonePinSlice;
    fn pin_slice_mut(&mut self) -> &mut ZonePinSlice;
    /// Observe one slot probe at `index` during allocation or key resolution.
    /// Default no-op in production.
    fn observe_slot(&self, _index: usize) {}
}
impl ZonePinStorage for ZonePinSlice {
    fn pin_slice(&self) -> &ZonePinSlice {
        self
    }
    fn pin_slice_mut(&mut self) -> &mut ZonePinSlice {
        self
    }
}
impl<const N: usize> ZonePinStorage for ZonePinSlots<N> {
    fn pin_slice(&self) -> &ZonePinSlice {
        self.as_slice()
    }
    fn pin_slice_mut(&mut self) -> &mut ZonePinSlice {
        self.as_slice_mut()
    }
}

/// Carrier-owned pin table view over caller-supplied [`ZonePinStorage`].
/// Allocator state (`nonce`, `free`, `high_water`, `live`) lives in the slot
/// storage itself, so dropping and rebuilding [`ZonePinTable`] over the same
/// slice recovers every live pin and its allocator state. If a corrupted slice
/// has live pins without an initialized header nonce, construction refuses
/// `Stale`.
pub struct ZonePinTable<'a, S: ZonePinStorage + ?Sized = ZonePinSlice> {
    slots: &'a mut S,
}
impl<'a, S: ZonePinStorage + ?Sized> ZonePinTable<'a, S> {
    pub fn new(storage: &'a mut S) -> Result<Self, IoError> {
        let slots = &mut storage.pin_slice_mut().0;
        if slots.len() > 1 << INDEX_BITS {
            return Err(IoError::CapacityExhausted);
        }
        let Some(first) = slots.first() else {
            return Ok(Self { slots: storage });
        };
        if first.table_nonce != 0 {
            if first.table_nonce > NONCE_MAX
                || first.table_high_water as usize > slots.len()
                || (first.table_free != u32::MAX && first.table_free as usize >= slots.len())
            {
                return Err(IoError::Stale);
            }
            return Ok(Self { slots: storage });
        }
        if slots
            .iter()
            .any(|slot| slot.live || slot.generation == 0 || slot.generation > GENERATION_MAX)
        {
            return Err(IoError::Stale);
        }
        let nonce = NEXT_NONCE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n <= NONCE_MAX).then_some(n + 1)
            })
            .map_err(|_| IoError::CapacityExhausted)?;
        let first = &mut slots[0];
        first.table_nonce = nonce;
        first.table_free = u32::MAX;
        first.table_high_water = 0;
        first.table_live = 0;
        Ok(Self { slots: storage })
    }
    pub fn live_pins(&self) -> u32 {
        self.slots.pin_slice().0.first().map_or(0, |s| s.table_live)
    }
    /// Close the pin table and reset its backing storage to fresh vacant slots.
    /// Refuses with [`IoError::Stale`] while any pin remains live so an active
    /// ring reference can never be orphaned.
    pub fn close(self) -> Result<(), IoError> {
        if self.live_pins() != 0 {
            return Err(IoError::Stale);
        }
        for slot in &mut self.slots.pin_slice_mut().0 {
            *slot = ZonePinSlot::VACANT;
        }
        Ok(())
    }
    fn nonce(&self) -> u32 {
        self.slots
            .pin_slice()
            .0
            .first()
            .map_or(0, |s| s.table_nonce)
    }
    fn probe_slot(&self, index: usize) -> Option<&ZonePinSlot> {
        self.slots.observe_slot(index);
        self.slots.pin_slice().0.get(index)
    }
    fn raw_slots_mut(&mut self) -> &mut [ZonePinSlot] {
        &mut self.slots.pin_slice_mut().0
    }
}

/// Measured work of the last operation: CAS attempts on the record's lifetime
/// word, constant-time slot and record touches, and bytes moved between the
/// caller's buffer and the resident cache.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZoneFileWork {
    pub cas_attempts: u64,
    pub records_visited: u64,
    pub slots_visited: u64,
    pub bytes_moved: usize,
}

pub struct ZoneFileService<'a, 's, V: ZoneFileVenue, S: ZonePinStorage + ?Sized = ZonePinSlice> {
    tables: ZoneFileTables<'a>,
    slot: SlotId,
    venue: &'a V,
    pins: &'a mut ZonePinTable<'s, S>,
    work: ZoneFileWork,
}

struct Pinned {
    index: usize,
    open: OpenReferenceKey,
}

impl<'a, 's, V: ZoneFileVenue, S: ZonePinStorage + ?Sized> ZoneFileService<'a, 's, V, S> {
    /// `slot` is the execution slot whose wake a released inode lock targets.
    /// Borrows the carrier's [`ZonePinTable`] without resetting allocator state
    /// or consuming a new nonce.
    pub fn new(
        tables: ZoneFileTables<'a>,
        slot: SlotId,
        venue: &'a V,
        pins: &'a mut ZonePinTable<'s, S>,
    ) -> Self {
        Self {
            tables,
            slot,
            venue,
            pins,
            work: ZoneFileWork::default(),
        }
    }

    pub fn last_work(&self) -> ZoneFileWork {
        self.work
    }

    /// Pin one admitted record: retain one ring reference in its lifetime.
    /// Requires the admission-issued [`AdmittedOpenReference`] witness.
    /// A retired or reused record refuses `Stale`; exhausted pin storage
    /// refuses without retaining anything.
    pub fn pin_admitted(&mut self, open: AdmittedOpenReference) -> Result<FilePin, IoError> {
        self.work = ZoneFileWork::default();
        let open = open.key();
        let record = self.record(open.handle).ok_or(IoError::Stale)?;
        let index = self.allocate()?;
        let mut cas = 0;
        let retained = record
            .lifetime
            .retain_observed(open.incarnation, |w: OpenReferenceWork| {
                cas = w.cas_attempts
            });
        self.work.cas_attempts = cas;
        self.venue
            .observe_record(open.handle, OpenReferenceWork { cas_attempts: cas });
        if !retained {
            self.vacate(index);
            return Err(IoError::Stale);
        }
        let nonce = self.pins.nonce();
        let slots = self.pins.raw_slots_mut();
        slots[0].table_live += 1;
        let pin = &mut slots[index];
        pin.live = true;
        pin.open = open;
        Ok(FilePin::from_backend(FilePinKey::from_backend(
            (u64::from(nonce) << (INDEX_BITS + GENERATION_BITS))
                | (u64::from(pin.generation) << INDEX_BITS)
                | index as u64,
        )))
    }

    fn record(&mut self, handle: u32) -> Option<&'a DelegatedOpenFile> {
        self.work.records_visited += 1;
        self.tables.open.get(handle.checked_sub(1)? as usize)
    }

    fn allocate(&mut self) -> Result<usize, IoError> {
        self.work.slots_visited += 1;
        let Some(first) = self.pins.slots.pin_slice().0.first() else {
            return Err(IoError::CapacityExhausted);
        };
        let free = first.table_free;
        let high_water = first.table_high_water as usize;
        if free != u32::MAX {
            let Some(pin) = self.pins.probe_slot(free as usize) else {
                return Err(IoError::Stale);
            };
            if pin.live {
                return Err(IoError::Stale);
            }
            let next_free = pin.next_free;
            self.pins.raw_slots_mut()[0].table_free = next_free;
            return Ok(free as usize);
        }
        let Some(pin) = self.pins.probe_slot(high_water) else {
            return Err(IoError::CapacityExhausted);
        };
        if pin.live {
            return Err(IoError::Stale);
        }
        self.pins.raw_slots_mut()[0].table_high_water += 1;
        Ok(high_water)
    }

    /// Retire the slot's key; an exhausted generation retires the slot.
    fn vacate(&mut self, index: usize) {
        let slots = self.pins.raw_slots_mut();
        let free = slots[0].table_free;
        let was_live = slots[index].live;
        let exhausted = {
            let pin = &mut slots[index];
            pin.live = false;
            if pin.generation == GENERATION_MAX {
                true
            } else {
                pin.generation += 1;
                pin.next_free = free;
                false
            }
        };
        if was_live {
            slots[0].table_live -= 1;
        }
        if !exhausted {
            slots[0].table_free = index as u32;
        }
    }

    /// Authenticate a key against this table before any record access.
    fn resolve(&mut self, pin: &FilePin) -> Result<Pinned, IoError> {
        self.work.slots_visited += 1;
        let key = pin.key().backend_value();
        let index = (key & ((1 << INDEX_BITS) - 1)) as usize;
        let generation = ((key >> INDEX_BITS) & u64::from(GENERATION_MAX)) as u32;
        let nonce = (key >> (INDEX_BITS + GENERATION_BITS)) as u32;
        let table_nonce = self.pins.nonce();
        match self.pins.probe_slot(index) {
            Some(slot) if nonce == table_nonce && slot.live && slot.generation == generation => {
                Ok(Pinned {
                    index,
                    open: slot.open,
                })
            }
            _ => Err(IoError::Stale),
        }
    }

    /// Run `op` on the pinned record and its inode under the inode lock and
    /// any matching watch-mark locks.
    fn locked<T>(
        &mut self,
        pin: &FilePin,
        event: FileDataEvent,
        moved: impl FnOnce(&T) -> bool,
        op: impl FnOnce(&file::ZoneFile<'a>, *mut u8) -> Result<T, IoError>,
    ) -> Result<T, IoError> {
        self.work = ZoneFileWork::default();
        let pinned = self.resolve(pin)?;
        let open = self.record(pinned.open.handle).ok_or(IoError::Stale)?;
        self.venue
            .observe_record(pinned.open.handle, OpenReferenceWork { cas_attempts: 0 });
        if open.generation.load(Ordering::Acquire) != pinned.open.incarnation {
            return Err(IoError::Stale);
        }
        let inode_handle = open.inode_handle.load(Ordering::Acquire);
        let inode = inode_handle
            .checked_sub(1)
            .and_then(|index| self.tables.objects.get(index as usize))
            .ok_or(IoError::Unsupported)?;
        let guard = FileAccess::notified(self.tables.zone, self.slot)
            .lock(inode, inode_handle)
            .ok_or(IoError::Unsupported)?;
        let result = if open.generation.load(Ordering::Acquire) != pinned.open.incarnation {
            Err(IoError::Stale)
        } else if open.inode_handle.load(Ordering::Acquire) == inode_handle
            && open.is_bound_to(inode)
        {
            file::with_data_marks(
                inode,
                self.tables.watches,
                event,
                &TryInstanceLock,
                IoError::Unsupported,
                moved,
                || {
                    op(
                        &file::ZoneFile { inode, open },
                        self.tables.cache(inode_handle),
                    )
                },
            )
        } else {
            Err(IoError::Unsupported)
        };
        drop(guard);
        result
    }
}

fn io_error(error: FileError) -> IoError {
    match error {
        FileError::AccessDenied => IoError::AccessDenied,
        FileError::OffsetOverflow | FileError::InvalidOffset => IoError::TooLarge,
        FileError::Forward => IoError::Unsupported,
    }
}

impl<V: ZoneFileVenue, S: ZonePinStorage + ?Sized> FileService for ZoneFileService<'_, '_, V, S> {
    /// Name lookup and admission are F4's counted host crossing.
    fn open(&mut self, _: &FileRoot, _: NamePath, _: OpenRequest) -> FileOperation<OpenOutcome> {
        Err(IoError::Unsupported).into()
    }

    fn read_at(&mut self, pin: &FilePin, offset: u64, dst: &mut [u8]) -> FileOperation<usize> {
        let result = self.locked(
            pin,
            FileDataEvent::Access,
            |&moved| moved > 0,
            |zf, cache| {
                if zf.open.flags.load(Ordering::Acquire) & DELEGATED_FLAG_READABLE == 0 {
                    return Err(IoError::AccessDenied);
                }
                // SAFETY: the inode is locked and revalidated; `cache` is its slot.
                let src = unsafe { file::resident_at(zf.inode, cache, offset, dst.len()) };
                dst[..src.len()].copy_from_slice(src);
                Ok(src.len())
            },
        );
        if let Ok(moved) = result {
            self.work.bytes_moved = moved;
        }
        result.into()
    }

    fn write_at(&mut self, pin: &FilePin, at: WriteAt, src: &[u8]) -> FileOperation<usize> {
        let result = self.locked(
            pin,
            FileDataEvent::Modify,
            |&moved| moved > 0,
            |zf, cache| {
                let flags = zf.open.flags.load(Ordering::Acquire);
                if flags & DELEGATED_FLAG_WRITABLE == 0 {
                    return Err(IoError::AccessDenied);
                }
                let at = match at {
                    WriteAt::Offset(_) if flags & DELEGATED_FLAG_APPEND != 0 => {
                        return Err(IoError::AccessDenied);
                    }
                    WriteAt::Offset(offset) => StoreAt::Offset(offset),
                    WriteAt::End => StoreAt::End,
                };
                // SAFETY: the inode is locked and revalidated; `cache` is its slot.
                unsafe {
                    file::store_with(zf.inode, cache, at, src.len(), |dst| {
                        dst.copy_from_slice(src);
                        true
                    })
                }
                .map_err(io_error)?;
                Ok(src.len())
            },
        );
        if let Ok(moved) = result {
            self.work.bytes_moved = moved;
        }
        result.into()
    }

    fn attributes(&mut self, pin: &FilePin) -> FileOperation<FileAttributes> {
        self.locked(
            pin,
            FileDataEvent::None,
            |_| false,
            |zf, _| {
                Ok(FileAttributes {
                    kind: FileKind::File,
                    len: zf.inode.size.load(Ordering::Acquire),
                    read_only: zf.open.flags.load(Ordering::Acquire) & DELEGATED_FLAG_WRITABLE == 0,
                })
            },
        )
        .into()
    }

    /// Consume exactly the pin's reference. The last one queues the record's
    /// terminal handoff once in the service's region through
    /// [`queue_open_release`]; recall and writeback run on the host drain.
    fn release(&mut self, pin: FilePin) -> FileOperation<()> {
        self.work = ZoneFileWork::default();
        let pinned = match self.resolve(&pin) {
            Ok(pinned) => pinned,
            Err(error) => return Err(error).into(),
        };
        self.vacate(pinned.index);
        let Some(record) = self.record(pinned.open.handle) else {
            return Err(IoError::Stale).into();
        };
        let mut cas = 0;
        let release = record
            .lifetime
            .release_observed(pinned.open.incarnation, |w| cas = w.cas_attempts);
        self.work.cas_attempts = cas;
        self.venue
            .observe_record(pinned.open.handle, OpenReferenceWork { cas_attempts: cas });
        match release {
            OpenRelease::Live => Ok(()).into(),
            OpenRelease::Terminal => {
                queue_open_release(self.tables.region, pinned.open);
                self.venue.terminal_queued(pinned.open);
                Ok(()).into()
            }
            OpenRelease::Stale => Err(IoError::Stale).into(),
        }
    }
}
