//! The in-zone [`FileService`] over VFS-admitted delegated records.
//!
//! A pin is one owned ring reference in the admitted record's [`OpenLifetime`],
//! named by a table-issued key: slot index, slot generation and the carrier pin
//! table's 24-bit nonce. One [`ZonePinTable`] is constructed per carrier and
//! borrowed across [`ZoneFileService`] calls, so per-call service construction
//! never consumes a nonce and dropping/rebuilding the service wrapper over the
//! same table preserves every live pin. A replayed, retired or foreign key is
//! refused before any record or byte is touched, so it can never consume a live
//! peer's reference. Positional I/O runs under the inode lock through the
//! shared [`super::file`] core (including watch-mark lock and event admission)
//! and never moves the record's cursor. The last release queues the record's
//! indexed terminal handoff through [`carrick_el1_abi::queue_open_release`]
//! once and nudges the host drain through the venue; it performs no storage and
//! never waits.
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

/// Carrier pin tables never share a nonce; one nonce is minted per carrier
/// [`ZonePinTable`], not per [`ZoneFileService`] call.
static NEXT_NONCE: AtomicU32 = AtomicU32::new(1);

/// The venue that wakes the host drain of indexed terminal handoffs.
pub trait ZoneFileVenue {
    /// One record became terminal and its handoff is queued in the region.
    /// Must not perform storage or wait.
    fn terminal_queued(&self, key: OpenReferenceKey);
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

/// Caller-owned pin slot storage; the service never allocates.
#[derive(Clone, Copy, Debug)]
pub struct ZonePinSlot {
    generation: u32,
    live: bool,
    open: OpenReferenceKey,
    next_free: u32,
}
impl ZonePinSlot {
    pub const VACANT: Self = Self {
        generation: 1,
        live: false,
        open: OpenReferenceKey {
            handle: 0,
            incarnation: 0,
        },
        next_free: u32::MAX,
    };
}

/// Carrier-owned pin table and allocator state (`nonce`, `free`, `high_water`,
/// `live`). Constructed once per carrier and borrowed by [`ZoneFileService`]
/// across calls so dropping and rebuilding the service preserves live pins and
/// never overwrites a live slot. Reinitializing a slice that still holds any
/// live pin is refused.
pub struct ZonePinTable<'a> {
    slots: &'a mut [ZonePinSlot],
    nonce: u32,
    free: u32,
    high_water: u32,
    live: u32,
}
impl<'a> ZonePinTable<'a> {
    pub fn new(slots: &'a mut [ZonePinSlot]) -> Result<Self, IoError> {
        if slots.len() > 1 << INDEX_BITS || slots.iter().any(|slot| slot.live) {
            return Err(IoError::CapacityExhausted);
        }
        let nonce = NEXT_NONCE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n <= NONCE_MAX).then_some(n + 1)
            })
            .map_err(|_| IoError::CapacityExhausted)?;
        Ok(Self {
            slots,
            nonce,
            free: u32::MAX,
            high_water: 0,
            live: 0,
        })
    }
    pub fn live_pins(&self) -> u32 {
        self.live
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

pub struct ZoneFileService<'a, 's, V: ZoneFileVenue> {
    tables: ZoneFileTables<'a>,
    slot: SlotId,
    venue: &'a V,
    pins: &'a mut ZonePinTable<'s>,
    work: ZoneFileWork,
}

struct Pinned {
    index: usize,
    open: OpenReferenceKey,
}

impl<'a, 's, V: ZoneFileVenue> ZoneFileService<'a, 's, V> {
    /// `slot` is the execution slot whose wake a released inode lock targets.
    /// Borrows the carrier's [`ZonePinTable`] without resetting allocator state
    /// or consuming a new nonce.
    pub fn new(
        tables: ZoneFileTables<'a>,
        slot: SlotId,
        venue: &'a V,
        pins: &'a mut ZonePinTable<'s>,
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
        if !retained {
            self.vacate(index);
            return Err(IoError::Stale);
        }
        let nonce = self.pins.nonce;
        let pin = &mut self.pins.slots[index];
        pin.live = true;
        pin.open = open;
        self.pins.live += 1;
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
        if let Some(pin) = self.pins.slots.get(self.pins.free as usize) {
            if pin.live {
                return Err(IoError::CapacityExhausted);
            }
            let index = self.pins.free as usize;
            self.pins.free = pin.next_free;
            return Ok(index);
        }
        let index = self.pins.high_water as usize;
        let Some(pin) = self.pins.slots.get(index) else {
            return Err(IoError::CapacityExhausted);
        };
        if pin.live {
            return Err(IoError::CapacityExhausted);
        }
        self.pins.high_water += 1;
        Ok(index)
    }

    /// Retire the slot's key; an exhausted generation retires the slot.
    fn vacate(&mut self, index: usize) {
        let pin = &mut self.pins.slots[index];
        if pin.live {
            pin.live = false;
            self.pins.live -= 1;
        }
        if pin.generation == GENERATION_MAX {
            return;
        }
        pin.generation += 1;
        pin.next_free = self.pins.free;
        self.pins.free = index as u32;
    }

    /// Authenticate a key against this table before any record access.
    fn resolve(&mut self, pin: &FilePin) -> Result<Pinned, IoError> {
        self.work.slots_visited += 1;
        let key = pin.key().backend_value();
        let index = (key & ((1 << INDEX_BITS) - 1)) as usize;
        let generation = ((key >> INDEX_BITS) & u64::from(GENERATION_MAX)) as u32;
        let nonce = (key >> (INDEX_BITS + GENERATION_BITS)) as u32;
        match self.pins.slots.get(index) {
            Some(slot)
                if nonce == self.pins.nonce && slot.live && slot.generation == generation =>
            {
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

impl<V: ZoneFileVenue> FileService for ZoneFileService<'_, '_, V> {
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
    /// terminal handoff once through [`queue_open_release`]; recall and
    /// writeback run on the host drain.
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
        match release {
            OpenRelease::Live => Ok(()).into(),
            OpenRelease::Terminal => {
                queue_open_release(pinned.open);
                self.venue.terminal_queued(pinned.open);
                Ok(()).into()
            }
            OpenRelease::Stale => Err(IoError::Stale).into(),
        }
    }
}
