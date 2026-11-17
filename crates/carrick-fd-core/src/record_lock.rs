//! Advisory file locks as shared records: fcntl(2) record locks, open file
//! description (OFD) locks and flock(2), for every venue that serves them.
//!
//! One [`LockTable`] holds every lock of a zone. A record names its file by
//! [`FileIdentity`] (device and inode, so two descriptions of one file
//! conflict) and its owner by [`LockOwner`]:
//!
//! - an fcntl(2) record lock (`F_SETLK`) belongs to the caller's descriptor
//!   table. Linux keys these locks on the files table, so threads and
//!   `CLONE_FILES` siblings share them; a close of ANY descriptor naming the
//!   file through that table releases them ([`LockTable::release_file`]), and
//!   so does the table's retirement at exit ([`LockTable::release_owner`]);
//! - an OFD lock (`F_OFD_SETLK`) and a flock(2) lock belong to one open file
//!   description, released when its last reference closes.
//!
//! The table is plain atomics with no lock of its own: the venue serializes
//! every operation under its own exclusion, and after any operation that
//! reports a release it notifies the waiters it parked on that exclusion.
//! Liveness of an owner is the descriptor authority's answer
//! ([`LockOwners`]): a record whose owner died without its release hook (a
//! table retired with its process) never blocks anyone, and [`LockTable::reap`]
//! drops it.
//!
//! The live records are kept dense at the front of the record array, so an
//! operation costs the number of locks held, not the table's capacity.

#[cfg(not(all(test, feature = "loom")))]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(all(test, feature = "loom"))]
use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::{OfdKey, TableId};

/// Device number of a locked file, as the file's venue reports it in
/// `stat`. Linux and Darwin `dev_t` values are 32 bits wide.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileDevice(u32);
impl FileDevice {
    pub const fn new(device: u32) -> Self {
        Self(device)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Inode number of a locked file. Zero names no file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileInode(core::num::NonZeroU64);
impl FileInode {
    pub const fn new(inode: u64) -> Option<Self> {
        match core::num::NonZeroU64::new(inode) {
            Some(inode) => Some(Self(inode)),
            None => None,
        }
    }
    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// The file a lock names: two open file descriptions of one file share it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    pub device: FileDevice,
    pub inode: FileInode,
}

/// One open file description's [`FileIdentity`], in a store parallel to the
/// description records. The authority clears it when it allocates the
/// description; the venue that opened the file stamps it while it alone
/// pins the new description, before any descriptor names it. A reader holds
/// a pin, so it never races the clear of a reuse. An inode of zero is
/// unstamped.
#[repr(C)]
#[derive(Debug, Default)]
pub struct OfdIdentityRecord {
    device: AtomicU32,
    inode_low: AtomicU32,
    inode_high: AtomicU32,
}
impl OfdIdentityRecord {
    pub(crate) fn clear(&self) {
        self.inode_low.store(0, Ordering::Relaxed);
        self.inode_high.store(0, Ordering::Relaxed);
        self.device.store(0, Ordering::Release);
    }
    pub(crate) fn stamp(&self, identity: FileIdentity) {
        let inode = identity.inode.raw();
        self.device.store(identity.device.raw(), Ordering::Relaxed);
        self.inode_high
            .store((inode >> 32) as u32, Ordering::Relaxed);
        self.inode_low.store(inode as u32, Ordering::Release);
    }
    pub(crate) fn identity(&self) -> Option<FileIdentity> {
        let low = self.inode_low.load(Ordering::Acquire);
        let inode = (u64::from(self.inode_high.load(Ordering::Relaxed)) << 32) | u64::from(low);
        Some(FileIdentity {
            device: FileDevice(self.device.load(Ordering::Relaxed)),
            inode: FileInode::new(inode)?,
        })
    }
}

/// Who holds a lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockOwner {
    /// A descriptor table: fcntl(2) record locks.
    Table { index: u32, generation: u64 },
    /// One open file description: OFD locks and flock(2).
    Description(OfdKey),
}
impl LockOwner {
    pub const fn table(table: TableId) -> Self {
        Self::Table {
            index: table.index as u32,
            generation: table.generation,
        }
    }
    pub const fn description(key: OfdKey) -> Self {
        Self::Description(key)
    }
}

/// Lock families that never conflict with each other: fcntl(2) record and
/// OFD locks share one family, flock(2) locks are the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockClass {
    Record,
    Flock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockKind {
    Read,
    Write,
}

/// Byte range `[start, end)`; [`LockRange::END_OF_FILE`] extends a lock to
/// the end of any file (Linux's largest offset plus one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockRange {
    start: u64,
    end: u64,
}

/// Why a POSIX `l_start`/`l_len` pair names no range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeError {
    /// Negative start, or an empty or wrapped interval (EINVAL).
    Invalid,
}

impl LockRange {
    pub const END_OF_FILE: u64 = i64::MAX as u64 + 1;
    /// A whole file, as flock(2) locks it.
    pub const WHOLE_FILE: Self = Self {
        start: 0,
        end: Self::END_OF_FILE,
    };

    /// fcntl(2): bytes `start .. start + len`, or for a negative `len`
    /// `start + len .. start`; a zero `len` extends to the end of any file.
    /// `origin` is the `l_whence` base already resolved to an offset.
    pub fn from_posix(origin: u64, start: i64, len: i64) -> Result<Self, RangeError> {
        let anchor = i128::from(origin) + i128::from(start);
        let end_of_file = i128::from(Self::END_OF_FILE);
        let (first, last) = match len {
            0 => (anchor, end_of_file),
            len if len > 0 => (anchor, anchor + i128::from(len)),
            len => (anchor + i128::from(len), anchor),
        };
        if first < 0 || last <= first || last > end_of_file {
            return Err(RangeError::Invalid);
        }
        Ok(Self {
            start: first as u64,
            end: last as u64,
        })
    }
    pub const fn start(self) -> u64 {
        self.start
    }
    /// One past the last byte; [`Self::END_OF_FILE`] for a lock to EOF.
    pub const fn end(self) -> u64 {
        self.end
    }
    /// fcntl(2) `l_len` for this range: 0 for a lock to the end of file.
    pub const fn posix_len(self) -> i64 {
        if self.end == Self::END_OF_FILE {
            0
        } else {
            (self.end - self.start) as i64
        }
    }
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
    const fn touches(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
    /// What remains of `self` once `removed` is cut out: the part before it
    /// and the part after it.
    pub const fn carve(self, removed: Self) -> [Option<Self>; 2] {
        if !self.overlaps(removed) {
            return [Some(self), None];
        }
        let before = if self.start < removed.start {
            Some(Self {
                start: self.start,
                end: removed.start,
            })
        } else {
            None
        };
        let after = if removed.end < self.end {
            Some(Self {
                start: removed.end,
                end: self.end,
            })
        } else {
            None
        };
        [before, after]
    }
}

/// The namespace PID of the process that took a record lock, which
/// `F_GETLK` reports in `l_pid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockPid(u32);
impl LockPid {
    pub const fn new(pid: u32) -> Self {
        Self(pid)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// One lock, held or requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lock {
    pub file: FileIdentity,
    pub owner: LockOwner,
    pub class: LockClass,
    pub kind: LockKind,
    pub range: LockRange,
    pub pid: LockPid,
}
impl Lock {
    fn blocks(&self, other: &Lock) -> bool {
        self.file == other.file
            && self.class == other.class
            && self.owner != other.owner
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Write || other.kind == LockKind::Write)
    }
    fn same_holding(&self, file: FileIdentity, owner: LockOwner, class: LockClass) -> bool {
        self.file == file && self.owner == owner && self.class == class
    }
}

/// The descriptor authority's view of which owners still exist.
pub trait LockOwners {
    fn live(&self, owner: LockOwner) -> bool;
}

/// Why a lock was not taken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetRefusal {
    /// A live lock of another owner blocks it.
    Conflict(Lock),
    /// The table has no record for it (ENOLCK).
    Full,
}

/// The outcome of [`LockTable::set`]. `released` reports a lock this call
/// gave up (a downgrade, a replaced range, or flock's conversion, which drops
/// the old lock before it takes the new one): waiters must rerun even when
/// the new lock was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "a released lock owes its waiters a notification"]
pub struct SetOutcome {
    pub taken: Result<(), SetRefusal>,
    pub released: bool,
}

/// Header of a [`LockTable`]: how many records are live.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct LockTableHeader {
    count: AtomicU64,
    _reserved: [u64; 7],
}

const TAG_LIVE: u64 = 1;
const TAG_FLOCK: u64 = 1 << 1;
const TAG_WRITE: u64 = 1 << 2;
const TAG_DESCRIPTION: u64 = 1 << 3;

/// One lock in shared memory, written only under the venue's exclusion.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct LockRecord {
    tag: AtomicU64,
    device: AtomicU64,
    inode: AtomicU64,
    owner_index: AtomicU64,
    owner_generation: AtomicU64,
    start: AtomicU64,
    end: AtomicU64,
    pid: AtomicU64,
}

impl LockRecord {
    fn load(&self) -> Option<Lock> {
        let tag = self.tag.load(Ordering::Relaxed);
        if tag & TAG_LIVE == 0 {
            return None;
        }
        let index = self.owner_index.load(Ordering::Relaxed);
        let generation = self.owner_generation.load(Ordering::Relaxed);
        Some(Lock {
            file: FileIdentity {
                device: FileDevice(self.device.load(Ordering::Relaxed) as u32),
                inode: FileInode::new(self.inode.load(Ordering::Relaxed))?,
            },
            owner: if tag & TAG_DESCRIPTION != 0 {
                LockOwner::Description(OfdKey {
                    index: index as u32,
                    generation,
                })
            } else {
                LockOwner::Table {
                    index: index as u32,
                    generation,
                }
            },
            class: if tag & TAG_FLOCK != 0 {
                LockClass::Flock
            } else {
                LockClass::Record
            },
            kind: if tag & TAG_WRITE != 0 {
                LockKind::Write
            } else {
                LockKind::Read
            },
            range: LockRange {
                start: self.start.load(Ordering::Relaxed),
                end: self.end.load(Ordering::Relaxed),
            },
            pid: LockPid(self.pid.load(Ordering::Relaxed) as u32),
        })
    }

    fn store(&self, lock: Lock) {
        let (description, index, generation) = match lock.owner {
            LockOwner::Table { index, generation } => (0, index, generation),
            LockOwner::Description(key) => (TAG_DESCRIPTION, key.index, key.generation),
        };
        let tag = TAG_LIVE
            | description
            | if lock.class == LockClass::Flock {
                TAG_FLOCK
            } else {
                0
            }
            | if lock.kind == LockKind::Write {
                TAG_WRITE
            } else {
                0
            };
        self.device
            .store(u64::from(lock.file.device.raw()), Ordering::Relaxed);
        self.inode.store(lock.file.inode.raw(), Ordering::Relaxed);
        self.owner_index.store(u64::from(index), Ordering::Relaxed);
        self.owner_generation.store(generation, Ordering::Relaxed);
        self.start.store(lock.range.start, Ordering::Relaxed);
        self.end.store(lock.range.end, Ordering::Relaxed);
        self.pid.store(u64::from(lock.pid.raw()), Ordering::Relaxed);
        self.tag.store(tag, Ordering::Relaxed);
    }

    fn clear(&self) {
        self.tag.store(0, Ordering::Relaxed);
    }
}

/// Every lock of a zone, over shared records. Each method is one operation
/// the venue must serialize under its exclusion (see the module docs).
#[derive(Clone, Copy)]
pub struct LockTable<'a> {
    header: &'a LockTableHeader,
    records: &'a [LockRecord],
}

impl<'a> LockTable<'a> {
    pub fn new(header: &'a LockTableHeader, records: &'a [LockRecord]) -> Self {
        Self { header, records }
    }

    /// Live records (dead owners' included until [`Self::reap`]).
    pub fn len(&self) -> usize {
        (self.header.count.load(Ordering::Relaxed) as usize).min(self.records.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, index: usize) -> Option<Lock> {
        self.records.get(index)?.load()
    }

    fn locks(&self) -> impl Iterator<Item = (usize, Lock)> + '_ {
        (0..self.len()).filter_map(|index| Some((index, self.get(index)?)))
    }

    fn push(&self, lock: Lock) -> bool {
        let len = self.len();
        let Some(record) = self.records.get(len) else {
            return false;
        };
        record.store(lock);
        self.header.count.store(len as u64 + 1, Ordering::Relaxed);
        true
    }

    /// Drop record `index`, moving the last live record into its place.
    fn remove(&self, index: usize) {
        let len = self.len();
        if index >= len {
            return;
        }
        let last = len - 1;
        if index != last
            && let Some(moved) = self.get(last)
        {
            self.records[index].store(moved);
        }
        self.records[last].clear();
        self.header.count.store(last as u64, Ordering::Relaxed);
    }

    /// Drop every record matching `doomed`; whether any was dropped.
    fn remove_where(&self, mut doomed: impl FnMut(&Lock) -> bool) -> bool {
        let mut removed = false;
        let mut index = 0;
        while index < self.len() {
            match self.get(index) {
                Some(lock) if !doomed(&lock) => index += 1,
                // A moved-in record is examined at the same index next.
                _ => {
                    self.remove(index);
                    removed = true;
                }
            }
        }
        removed
    }

    /// Drop the records of owners that no longer exist.
    pub fn reap(&self, owners: &impl LockOwners) -> bool {
        self.remove_where(|lock| !owners.live(lock.owner))
    }

    /// The live lock that blocks `request`, lowest start first (`F_GETLK`).
    pub fn conflict(&self, request: &Lock, owners: &impl LockOwners) -> Option<Lock> {
        self.locks()
            .map(|(_, lock)| lock)
            .filter(|lock| lock.blocks(request) && owners.live(lock.owner))
            .min_by_key(|lock| lock.range.start)
    }

    /// Records `[before, after]` of the owner's `class` locks on `file`
    /// inside `range` would leave, beyond those it removes.
    fn carve_growth(
        &self,
        file: FileIdentity,
        owner: LockOwner,
        class: LockClass,
        range: LockRange,
    ) -> usize {
        self.locks()
            .filter(|(_, lock)| lock.same_holding(file, owner, class) && lock.range.overlaps(range))
            .map(|(_, lock)| lock.range.carve(range).iter().flatten().count())
            .sum::<usize>()
            .saturating_sub(
                self.locks()
                    .filter(|(_, lock)| {
                        lock.same_holding(file, owner, class) && lock.range.overlaps(range)
                    })
                    .count(),
            )
    }

    /// Cut `range` out of the owner's `class` locks on `file`. The caller
    /// checked capacity with [`Self::carve_growth`].
    fn carve(
        &self,
        file: FileIdentity,
        owner: LockOwner,
        class: LockClass,
        range: LockRange,
    ) -> bool {
        let mut carved = false;
        let mut index = 0;
        while index < self.len() {
            let Some(lock) = self.get(index) else {
                self.remove(index);
                continue;
            };
            if !lock.same_holding(file, owner, class) || !lock.range.overlaps(range) {
                index += 1;
                continue;
            }
            carved = true;
            self.remove(index);
            for piece in lock.range.carve(range).into_iter().flatten() {
                // Appended past `index`: examined again, but no longer
                // overlapping `range`, so kept.
                let _ = self.push(Lock {
                    range: piece,
                    ..lock
                });
            }
        }
        carved
    }

    /// Take `request`, replacing whatever its owner held on that part of
    /// the file (`F_SETLK`, `F_OFD_SETLK`, flock(2)). A record lock merges
    /// with the owner's adjacent locks of the same kind.
    pub fn set(&self, request: Lock, owners: &impl LockOwners) -> SetOutcome {
        let mut released = false;
        if request.class == LockClass::Flock {
            // flock(2): a conversion drops the old lock first, then takes
            // the new one as a fresh request.
            released = self.remove_where(|lock| {
                lock.same_holding(request.file, request.owner, LockClass::Flock)
                    && lock.kind != request.kind
            });
            let held = self
                .locks()
                .any(|(_, lock)| lock.same_holding(request.file, request.owner, LockClass::Flock));
            if held {
                return SetOutcome {
                    taken: Ok(()),
                    released,
                };
            }
        }
        if let Some(blocker) = self.conflict(&request, owners) {
            return SetOutcome {
                taken: Err(SetRefusal::Conflict(blocker)),
                released,
            };
        }
        // Capacity before any effect: the carve's split and the new record.
        let growth = self.carve_growth(request.file, request.owner, request.class, request.range);
        if self.len() + growth + 1 > self.records.len() {
            // A dead owner's records may be all that fills the table.
            if !self.reap(owners) || self.len() + growth + 1 > self.records.len() {
                return SetOutcome {
                    taken: Err(SetRefusal::Full),
                    released,
                };
            }
        }
        // Replacing any part of an owned lock gives up what it covered,
        // unless the same kind is retaken over it: waiters may now proceed.
        released |= self.locks().any(|(_, lock)| {
            lock.same_holding(request.file, request.owner, request.class)
                && lock.range.overlaps(request.range)
                && lock.kind != request.kind
        });
        self.carve(request.file, request.owner, request.class, request.range);
        let mut merged = request;
        if request.class == LockClass::Record {
            let _ = self.remove_where(|lock| {
                let adjacent = lock.same_holding(request.file, request.owner, LockClass::Record)
                    && lock.kind == request.kind
                    && lock.range.touches(merged.range);
                if adjacent {
                    merged.range = LockRange {
                        start: merged.range.start.min(lock.range.start),
                        end: merged.range.end.max(lock.range.end),
                    };
                }
                adjacent
            });
        }
        let pushed = self.push(merged);
        debug_assert!(pushed, "capacity was checked before any effect");
        SetOutcome {
            taken: Ok(()),
            released,
        }
    }

    /// Give up the owner's `class` locks on `range` of `file` (`F_UNLCK`,
    /// `LOCK_UN`). `Err(Full)` when splitting a lock needs a record the table
    /// does not have; nothing changed then.
    pub fn unlock(
        &self,
        file: FileIdentity,
        owner: LockOwner,
        class: LockClass,
        range: LockRange,
    ) -> Result<bool, SetRefusal> {
        if self.len() + self.carve_growth(file, owner, class, range) > self.records.len() {
            return Err(SetRefusal::Full);
        }
        Ok(self.carve(file, owner, class, range))
    }

    /// Whether `owner` holds any lock of `class`.
    pub fn holds(&self, owner: LockOwner, class: LockClass) -> bool {
        self.locks()
            .any(|(_, lock)| lock.owner == owner && lock.class == class)
    }

    /// A close of any descriptor naming `file` through `owner` (a table):
    /// its record locks on `file` are released (fcntl(2)).
    pub fn release_file(&self, file: FileIdentity, owner: LockOwner) -> bool {
        self.remove_where(|lock| lock.same_holding(file, owner, LockClass::Record))
    }

    /// Every lock `owner` holds, at its table's retirement or its
    /// description's final close.
    pub fn release_owner(&self, owner: LockOwner) -> bool {
        self.remove_where(|lock| lock.owner == owner)
    }
}

/// Layout facts of the shared lock records, folded into the venue's ABI hash.
pub const LAYOUT_FACTS: [u64; 8] = [
    core::mem::size_of::<OfdIdentityRecord>() as u64,
    core::mem::size_of::<LockTableHeader>() as u64,
    core::mem::size_of::<LockRecord>() as u64,
    core::mem::align_of::<LockRecord>() as u64,
    core::mem::offset_of!(LockRecord, owner_generation) as u64,
    core::mem::offset_of!(LockRecord, pid) as u64,
    TAG_DESCRIPTION | TAG_WRITE | TAG_FLOCK | TAG_LIVE,
    LockRange::END_OF_FILE,
];

#[cfg(all(test, not(feature = "loom")))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tests::{Spin, core_with, storage};
    use crate::{AccessMode, BackingToken, Description, Fd, StatusFlags};
    use std::boxed::Box;
    use std::vec::Vec;

    fn table(records: usize) -> LockTable<'static> {
        let header = Box::leak(Box::new(LockTableHeader::default()));
        let records = Box::leak(
            (0..records)
                .map(|_| LockRecord::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        LockTable::new(header, records)
    }

    /// Every owner exists unless listed as dead.
    struct Owners(Vec<LockOwner>);
    impl LockOwners for Owners {
        fn live(&self, owner: LockOwner) -> bool {
            !self.0.contains(&owner)
        }
    }
    const LIVE: Owners = Owners(Vec::new());

    const FILE: FileIdentity = FileIdentity {
        device: FileDevice(7),
        inode: match FileInode::new(42) {
            Some(inode) => inode,
            None => panic!(),
        },
    };
    const OTHER_FILE: FileIdentity = FileIdentity {
        device: FileDevice(7),
        inode: match FileInode::new(43) {
            Some(inode) => inode,
            None => panic!(),
        },
    };
    const A: LockOwner = LockOwner::Table {
        index: 1,
        generation: 1,
    };
    const B: LockOwner = LockOwner::Table {
        index: 2,
        generation: 1,
    };

    fn range(start: u64, end: u64) -> LockRange {
        LockRange { start, end }
    }

    fn record(owner: LockOwner, kind: LockKind, range: LockRange) -> Lock {
        Lock {
            file: FILE,
            owner,
            class: LockClass::Record,
            kind,
            range,
            pid: LockPid(match owner {
                LockOwner::Table { index, .. } => 100 + index,
                LockOwner::Description(_) => 0,
            }),
        }
    }

    fn held(table: &LockTable<'_>, owner: LockOwner) -> Vec<(LockKind, u64, u64)> {
        let mut held: Vec<_> = table
            .locks()
            .map(|(_, lock)| lock)
            .filter(|lock| lock.owner == owner)
            .map(|lock| (lock.kind, lock.range.start, lock.range.end))
            .collect();
        held.sort_unstable_by_key(|&(_, start, _)| start);
        held
    }

    /// fcntl(2): another table's write lock refuses F_SETLK, F_GETLK reports
    /// it with its holder's PID, and a close through its table releases it.
    #[test]
    fn two_tables_contend_for_one_record_lock_until_a_close_releases_it() {
        let t = table(8);
        let whole = range(0, LockRange::END_OF_FILE);
        assert_eq!(
            t.set(record(A, LockKind::Write, whole), &LIVE).taken,
            Ok(())
        );
        let request = record(B, LockKind::Write, range(10, 20));
        let blocker = record(A, LockKind::Write, whole);
        assert_eq!(
            t.set(request, &LIVE).taken,
            Err(SetRefusal::Conflict(blocker))
        );
        assert_eq!(t.conflict(&request, &LIVE), Some(blocker));
        assert_eq!(t.conflict(&request, &LIVE).unwrap().pid, LockPid(101));
        // Another file and a read-shared request of the holder never conflict.
        assert_eq!(
            t.conflict(
                &Lock {
                    file: OTHER_FILE,
                    ..request
                },
                &LIVE
            ),
            None
        );
        assert!(t.release_file(FILE, A));
        assert_eq!(t.set(request, &LIVE).taken, Ok(()));
        assert!(!t.release_file(FILE, A), "nothing left to release");
    }

    #[test]
    fn readers_share_and_a_writer_waits_for_every_reader() {
        let t = table(8);
        let all = range(0, 100);
        assert_eq!(t.set(record(A, LockKind::Read, all), &LIVE).taken, Ok(()));
        assert_eq!(t.set(record(B, LockKind::Read, all), &LIVE).taken, Ok(()));
        let c = LockOwner::Table {
            index: 3,
            generation: 1,
        };
        assert!(t.set(record(c, LockKind::Write, all), &LIVE).taken.is_err());
        assert!(t.release_owner(A));
        assert!(t.set(record(c, LockKind::Write, all), &LIVE).taken.is_err());
        assert!(t.release_owner(B));
        assert_eq!(t.set(record(c, LockKind::Write, all), &LIVE).taken, Ok(()));
    }

    /// An unlock in the middle splits a lock; retaking the hole merges the
    /// pieces back, and a downgrade reports a release to the waiters.
    #[test]
    fn unlock_splits_and_a_retake_merges_the_owners_ranges() {
        let t = table(8);
        assert_eq!(
            t.set(record(A, LockKind::Write, range(0, 10)), &LIVE).taken,
            Ok(())
        );
        assert_eq!(t.unlock(FILE, A, LockClass::Record, range(3, 5)), Ok(true));
        assert_eq!(
            held(&t, A),
            [(LockKind::Write, 0, 3), (LockKind::Write, 5, 10)]
        );
        let retake = t.set(record(A, LockKind::Write, range(3, 5)), &LIVE);
        assert_eq!((retake.taken, retake.released), (Ok(()), false));
        assert_eq!(held(&t, A), [(LockKind::Write, 0, 10)]);
        let downgrade = t.set(record(A, LockKind::Read, range(2, 4)), &LIVE);
        assert_eq!((downgrade.taken, downgrade.released), (Ok(()), true));
        assert_eq!(
            held(&t, A),
            [
                (LockKind::Write, 0, 2),
                (LockKind::Read, 2, 4),
                (LockKind::Write, 4, 10)
            ]
        );
        // The downgraded bytes now admit another reader, not a writer.
        assert_eq!(
            t.set(record(B, LockKind::Read, range(2, 4)), &LIVE).taken,
            Ok(())
        );
        assert!(
            t.set(record(B, LockKind::Write, range(2, 3)), &LIVE)
                .taken
                .is_err()
        );
    }

    /// ENOLCK refuses before any effect, including the split an unlock needs.
    #[test]
    fn a_full_table_refuses_before_any_effect() {
        let t = table(2);
        assert_eq!(
            t.set(record(A, LockKind::Write, range(0, 10)), &LIVE).taken,
            Ok(())
        );
        // A split needs a second record and the new lock a third.
        assert_eq!(
            t.set(record(A, LockKind::Read, range(3, 5)), &LIVE).taken,
            Err(SetRefusal::Full)
        );
        assert_eq!(held(&t, A), [(LockKind::Write, 0, 10)]);
        assert_eq!(t.unlock(FILE, A, LockClass::Record, range(3, 5)), Ok(true));
        assert_eq!(
            t.unlock(FILE, A, LockClass::Record, range(6, 7)),
            Err(SetRefusal::Full)
        );
        assert_eq!(
            held(&t, A),
            [(LockKind::Write, 0, 3), (LockKind::Write, 5, 10)]
        );
    }

    /// An OFD lock conflicts with every other owner, a table included, and
    /// never with flock(2) locks, which are a separate family.
    #[test]
    fn ofd_and_flock_locks_keep_their_owners_and_families_apart() {
        let t = table(8);
        let ofd = LockOwner::Description(OfdKey {
            index: 5,
            generation: 2,
        });
        let other = LockOwner::Description(OfdKey {
            index: 6,
            generation: 2,
        });
        let whole = LockRange::WHOLE_FILE;
        assert_eq!(
            t.set(record(ofd, LockKind::Write, whole), &LIVE).taken,
            Ok(())
        );
        assert!(
            t.set(record(A, LockKind::Read, whole), &LIVE)
                .taken
                .is_err()
        );
        let flock = |owner, kind| Lock {
            class: LockClass::Flock,
            ..record(owner, kind, whole)
        };
        assert_eq!(t.set(flock(other, LockKind::Write), &LIVE).taken, Ok(()));
        assert!(t.set(flock(ofd, LockKind::Read), &LIVE).taken.is_err());
        // Shared flocks coexist; a conversion drops the old lock first.
        assert!(t.release_owner(other));
        assert_eq!(t.set(flock(ofd, LockKind::Read), &LIVE).taken, Ok(()));
        assert_eq!(t.set(flock(other, LockKind::Read), &LIVE).taken, Ok(()));
        let converted = t.set(flock(ofd, LockKind::Write), &LIVE);
        assert!(converted.released, "the shared lock was dropped");
        assert!(matches!(converted.taken, Err(SetRefusal::Conflict(_))));
        assert_eq!(t.unlock(FILE, other, LockClass::Flock, whole), Ok(true));
        assert_eq!(t.set(flock(ofd, LockKind::Write), &LIVE).taken, Ok(()));
        // The record lock survived every flock change.
        assert!(
            t.set(record(A, LockKind::Read, whole), &LIVE)
                .taken
                .is_err()
        );
    }

    /// A lock whose owner died without its release hook never blocks, and
    /// reaping drops it.
    #[test]
    fn a_dead_owners_locks_block_nobody() {
        let t = table(8);
        let whole = LockRange::WHOLE_FILE;
        assert_eq!(
            t.set(record(A, LockKind::Write, whole), &LIVE).taken,
            Ok(())
        );
        let dead = Owners(Vec::from([A]));
        let request = record(B, LockKind::Write, whole);
        assert_eq!(t.conflict(&request, &dead), None);
        assert_eq!(t.set(request, &dead).taken, Ok(()));
        assert!(t.reap(&dead));
        assert_eq!(t.len(), 1);
        assert_eq!(held(&t, B), [(LockKind::Write, 0, LockRange::END_OF_FILE)]);
    }

    #[test]
    fn posix_ranges_follow_fcntl() {
        assert_eq!(LockRange::from_posix(0, 0, 0), Ok(LockRange::WHOLE_FILE));
        assert_eq!(LockRange::from_posix(0, 10, 5), Ok(range(10, 15)));
        assert_eq!(LockRange::from_posix(0, 10, -5), Ok(range(5, 10)));
        assert_eq!(LockRange::from_posix(100, -10, 5), Ok(range(90, 95)));
        assert_eq!(LockRange::from_posix(0, -1, 0), Err(RangeError::Invalid));
        assert_eq!(LockRange::from_posix(0, 3, -5), Err(RangeError::Invalid));
        assert_eq!(
            LockRange::from_posix(0, i64::MAX, 2),
            Err(RangeError::Invalid)
        );
        assert_eq!(LockRange::from_posix(0, 7, 0).unwrap().posix_len(), 0);
        assert_eq!(range(3, 8).posix_len(), 5);
    }

    /// A description opened with an identity names its file to a pin and to
    /// its descriptors; a reuse of the record starts unstamped, and the
    /// final deferred close names the exact description it ended.
    #[test]
    fn identities_follow_the_description_incarnation() {
        let (core, arena) = core_with::<2>(4);
        let c = core.bind(arena, Spin);
        let t = c.create_table(16, &mut storage(8)).unwrap();
        let host = Description::new(
            BackingToken(100),
            AccessMode::ReadWrite,
            StatusFlags::default(),
        );
        let fd = c
            .open_identified(t, Fd(0), host, Some(FILE), false)
            .unwrap();
        assert_eq!(c.file_identity(t, fd), Ok(Some(FILE)));
        let (pin, _) = c.pin(t, fd).unwrap();
        let key = pin.key();
        assert_eq!(c.pinned_identity(&pin), Ok(Some(FILE)));
        assert!(c.lock_owner_live(LockOwner::Description(key)));
        assert!(c.lock_owner_live(LockOwner::table(t)));
        assert_eq!(c.unpin(pin), Ok(None));
        assert_eq!(
            c.close_filtered(t, fd, |_| false),
            Ok(crate::DeferredRelease::Deferred(key))
        );
        assert!(!c.lock_owner_live(LockOwner::Description(key)));
        assert!(c.take_retired_ofd().unwrap().is_some());
        let reused = c.open(t, Fd(0), host, false).unwrap();
        assert_eq!(c.file_identity(t, reused), Ok(None));
        assert_eq!(c.file_identity(t, Fd(5)), Err(crate::Error::BadFd));
        c.destroy_table(t, |_| {}).unwrap();
        assert!(!c.lock_owner_live(LockOwner::table(t)));
    }
}
