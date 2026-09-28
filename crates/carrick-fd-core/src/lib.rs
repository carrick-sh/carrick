//! Venue-backed descriptor/OFD authority; no allocator or host dependencies.
//!
//! A venue provides exclusive access to this authority across table and OFD
//! mutations. Threads with CLONE_FILES use the same TableId; fork copies a
//! table but shares its OFDs. See README.md for lifecycle and locking rules.
#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
static NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);

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
    StaleTable,
    /// Supply at least this many descriptor slots and their bitmap, then retry.
    /// This is an internal storage request, never EMFILE.
    NeedsBacking {
        descriptors: usize,
    },
}
/// Generation-checked identity; IDs from another Core are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableId {
    authority: u64,
    index: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OfdId(usize);
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
#[derive(Clone, Copy)]
struct Ofd {
    description: Description,
    refs: usize,
}
#[derive(Clone, Copy)]
struct Entry {
    ofd: OfdId,
    cloexec: bool,
}
/// Caller-owned descriptor slot; only the authority can change its contents.
#[derive(Clone, Copy, Default)]
pub struct DescriptorSlot(Option<Entry>);

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

/// Borrowed backing, not a wire ABI. Storage can live in host or guest memory.
/// Growth swaps in larger venue-provided slices and returns old backing through
/// the same value. The core never allocates or retains pointers to retired slices.
pub struct TableStorage<'a> {
    entries: &'a mut [DescriptorSlot],
    bitmap: &'a mut [u64],
    offsets: [usize; MAX_LEVELS],
    sizes: [usize; MAX_LEVELS],
    levels: usize,
}
impl<'a> TableStorage<'a> {
    pub fn new(entries: &'a mut [DescriptorSlot], bitmap: &'a mut [u64]) -> Result<Self, Error> {
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
        result.clear();
        Ok(result)
    }
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }
    /// Recover retired backing for reuse by the venue's storage allocator.
    pub fn into_parts(self) -> (&'a mut [DescriptorSlot], &'a mut [u64]) {
        (self.entries, self.bitmap)
    }
    fn empty() -> Self {
        Self {
            entries: &mut [],
            bitmap: &mut [],
            offsets: [0; MAX_LEVELS],
            sizes: [0; MAX_LEVELS],
            levels: 0,
        }
    }
    fn clear(&mut self) {
        self.entries.fill(DescriptorSlot(None));
        self.rebuild();
    }
    fn rebuild(&mut self) {
        self.bitmap.fill(0);
        for (fd, entry) in self.entries.iter().enumerate() {
            if entry.0.is_none() {
                self.bitmap[fd / 64] |= 1 << (fd % 64);
            }
        }
        for level in 1..self.levels {
            for word in 0..self.sizes[level - 1] {
                if self.bitmap[self.offsets[level - 1] + word] != 0 {
                    self.bitmap[self.offsets[level] + word / 64] |= 1 << (word % 64);
                }
            }
        }
    }
    fn mark_free(&mut self, mut bit: usize, mut free: bool) {
        for level in 0..self.levels {
            let word = bit / 64;
            let value = &mut self.bitmap[self.offsets[level] + word];
            let mask = 1u64 << (bit % 64);
            if free {
                *value |= mask;
            } else {
                *value &= !mask;
            }
            free = *value != 0;
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
        let bits = self.bitmap[self.offsets[level] + word] & (u64::MAX << (min % 64));
        if bits != 0 {
            return Some(word * 64 + bits.trailing_zeros() as usize);
        }
        let next = self.next_bit(level + 1, word + 1, reads)?;
        *reads += 1;
        Some(next * 64 + self.bitmap[self.offsets[level] + next].trailing_zeros() as usize)
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
}
struct TableSlot<'a> {
    generation: u64,
    table: Option<Table<'a>>,
}
#[derive(Clone, Copy)]
struct OfdSlot {
    ofd: Option<Ofd>,
    next: Option<usize>,
}

/// Venue-backed descriptor capacity, T table identities and O shared OFDs.
/// All operations are allocation-free, including fork. Not Clone: copying the
/// authority would duplicate backing-resource ownership without retaining it.
/// Use close/destroy_table to collect releases before dropping the authority.
pub struct Core<'a, const T: usize, const O: usize> {
    identity: u64,
    tables: [TableSlot<'a>; T],
    ofds: [OfdSlot; O],
    free_ofd: Option<usize>,
}
impl<'a, const T: usize, const O: usize> Core<'a, T, O> {
    pub fn new() -> Result<Self, Error> {
        if T.checked_mul(MAX_DESCRIPTORS)
            .is_none_or(|n| n == usize::MAX)
        {
            return Err(Error::InvalidArgument);
        }
        let identity = NEXT_AUTHORITY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            identity,
            tables: [const {
                TableSlot {
                    generation: 0,
                    table: None,
                }
            }; T],
            ofds: core::array::from_fn(|i| OfdSlot {
                ofd: None,
                next: (i + 1 < O).then_some(i + 1),
            }),
            free_ofd: (O != 0).then_some(0),
        })
    }
    fn table(&self, id: TableId) -> Result<&Table<'a>, Error> {
        self.tables
            .get(id.index)
            .filter(|s| s.generation == id.generation && id.authority == self.identity)
            .and_then(|s| s.table.as_ref())
            .ok_or(Error::StaleTable)
    }
    fn table_mut(&mut self, id: TableId) -> Result<&mut Table<'a>, Error> {
        self.tables
            .get_mut(id.index)
            .filter(|s| s.generation == id.generation && id.authority == self.identity)
            .and_then(|s| s.table.as_mut())
            .ok_or(Error::StaleTable)
    }
    fn entry(&self, table: TableId, fd: Fd) -> Result<Entry, Error> {
        self.table(table)?
            .storage
            .entries
            .get(fd.0 as usize)
            .and_then(|slot| slot.0)
            .ok_or(Error::BadFd)
    }
    fn ofd(&self, entry: Entry) -> &Ofd {
        // IDs never escape the authority and occupied entries retain their OFD.
        match &self.ofds[entry.ofd.0].ofd {
            Some(ofd) => ofd,
            None => unreachable!(),
        }
    }
    fn ofd_mut(&mut self, entry: Entry) -> &mut Ofd {
        match &mut self.ofds[entry.ofd.0].ofd {
            Some(ofd) => ofd,
            None => unreachable!(),
        }
    }
    fn install(&mut self, table: TableId, fd: usize, entry: Entry) -> Result<(), Error> {
        let table = self.table_mut(table)?;
        table.storage.entries[fd].0 = Some(entry);
        table.storage.mark_free(fd, false);
        Ok(())
    }
    pub fn create_table(
        &mut self,
        limit: usize,
        storage: &mut TableStorage<'a>,
    ) -> Result<TableId, Error> {
        if limit > MAX_DESCRIPTORS {
            return Err(Error::InvalidArgument);
        }
        let index = self
            .tables
            .iter()
            .position(|s| s.table.is_none() && s.generation != u64::MAX)
            .ok_or(Error::NoMemory)?;
        let slot = &mut self.tables[index];
        slot.generation += 1;
        storage.clear();
        slot.table = Some(Table {
            storage: core::mem::replace(storage, TableStorage::empty()),
            limit,
        });
        Ok(TableId {
            authority: self.identity,
            index,
            generation: slot.generation,
        })
    }
    /// Changing the soft limit never closes existing descriptors above it.
    /// The venue validates RLIMIT_NOFILE against its hard limit and nr_open;
    /// neither soft nor hard limits are constrained by currently supplied backing.
    pub fn set_limit(&mut self, table: TableId, limit: usize) -> Result<(), Error> {
        if limit > MAX_DESCRIPTORS {
            return Err(Error::InvalidArgument);
        }
        self.table_mut(table)?.limit = limit;
        Ok(())
    }
    /// Install a newly opened description. On error the caller still owns backing.
    pub fn open(
        &mut self,
        table: TableId,
        min: Fd,
        description: Description,
        cloexec: bool,
    ) -> Result<Fd, Error> {
        if min.0 < 0 {
            return Err(Error::InvalidArgument);
        }
        let fd = self.table(table)?.allocate(min.0 as usize)?;
        let index = self.free_ofd.ok_or(Error::NoMemory)?;
        self.free_ofd = self.ofds[index].next;
        self.ofds[index].ofd = Some(Ofd {
            description,
            refs: 1,
        });
        self.install(
            table,
            fd,
            Entry {
                ofd: OfdId(index),
                cloexec,
            },
        )?;
        Ok(Fd(fd as i32))
    }
    /// O(1) read-only snapshot; it does not retain the backing beyond the lock.
    pub fn get(&self, table: TableId, fd: Fd) -> Result<Description, Error> {
        Ok(self.ofd(self.entry(table, fd)?).description)
    }
    pub fn refcount(&self, table: TableId, fd: Fd) -> Result<usize, Error> {
        Ok(self.ofd(self.entry(table, fd)?).refs)
    }
    pub fn set_offset(&mut self, table: TableId, fd: Fd, offset: Offset) -> Result<(), Error> {
        let entry = self.entry(table, fd)?;
        self.ofd_mut(entry).description.offset = offset;
        Ok(())
    }
    pub fn getfd(&self, table: TableId, fd: Fd) -> Result<bool, Error> {
        Ok(self.entry(table, fd)?.cloexec)
    }
    pub fn setfd(&mut self, table: TableId, fd: Fd, cloexec: bool) -> Result<(), Error> {
        let mut entry = self.entry(table, fd)?;
        entry.cloexec = cloexec;
        self.install(table, fd.0 as usize, entry)
    }
    pub fn getfl(&self, table: TableId, fd: Fd) -> Result<(AccessMode, StatusFlags), Error> {
        let d = self.get(table, fd)?;
        Ok((d.access, d.flags))
    }
    /// Only Linux's five mutable status flags change. Venue authorizes append-only,
    /// NOATIME ownership, DIRECT support and asynchronous notification before commit.
    pub fn setfl(&mut self, table: TableId, fd: Fd, flags: StatusFlags) -> Result<(), Error> {
        let entry = self.entry(table, fd)?;
        let d = &mut self.ofd_mut(entry).description;
        if d.access == AccessMode::Path {
            return Err(Error::BadFd);
        }
        d.flags = StatusFlags {
            dsync: d.flags.dsync,
            sync: d.flags.sync,
            immutable: d.flags.immutable,
            ..flags
        };
        Ok(())
    }
    pub fn dup(&mut self, table: TableId, old: Fd) -> Result<Fd, Error> {
        self.duplicate_min(table, old, 0, false)
    }
    /// F_DUPFD and F_DUPFD_CLOEXEC. A minimum outside the soft limit is EINVAL.
    pub fn dupfd(&mut self, table: TableId, old: Fd, min: Fd, cloexec: bool) -> Result<Fd, Error> {
        self.entry(table, old)?;
        if min.0 < 0 || min.0 as usize >= self.table(table)?.limit {
            return Err(Error::InvalidArgument);
        }
        self.duplicate_min(table, old, min.0 as usize, cloexec)
    }
    fn duplicate_min(
        &mut self,
        table: TableId,
        old: Fd,
        min: usize,
        cloexec: bool,
    ) -> Result<Fd, Error> {
        let mut entry = self.entry(table, old)?;
        let fd = self.table(table)?.allocate(min)?;
        entry.cloexec = cloexec;
        self.ofd_mut(entry).refs += 1;
        self.install(table, fd, entry)?;
        Ok(Fd(fd as i32))
    }
    /// Atomically replace new; return the displaced OFD only on its last ref.
    /// Same-fd dup2 succeeds even after the soft limit was lowered below old.
    pub fn dup2(&mut self, table: TableId, old: Fd, new: Fd) -> Result<Option<Description>, Error> {
        self.entry(table, old)?;
        if old == new {
            return Ok(None);
        }
        self.duplicate_exact(table, old, new, false)
    }
    /// The personality rejects all raw flags except O_CLOEXEC before calling.
    pub fn dup3(
        &mut self,
        table: TableId,
        old: Fd,
        new: Fd,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        if old == new {
            return Err(Error::InvalidArgument);
        }
        self.duplicate_exact(table, old, new, cloexec)
    }
    fn duplicate_exact(
        &mut self,
        table: TableId,
        old: Fd,
        new: Fd,
        cloexec: bool,
    ) -> Result<Option<Description>, Error> {
        let mut entry = self.entry(table, old)?;
        if new.0 < 0 || new.0 as usize >= self.table(table)?.limit {
            return Err(Error::BadFd);
        }
        if new.0 as usize >= self.table(table)?.storage.capacity() {
            return Err(Error::NeedsBacking {
                descriptors: new.0 as usize + 1,
            });
        }
        // Retain first, so replacing an alias cannot temporarily finalize it.
        self.ofd_mut(entry).refs += 1;
        let released = match self.close(table, new) {
            Ok(d) => d,
            Err(Error::BadFd) => None,
            Err(e) => return Err(e),
        };
        entry.cloexec = cloexec;
        self.install(table, new.0 as usize, entry)?;
        Ok(released)
    }
    #[must_use = "the last-reference description owns backing resources to release"]
    pub fn close(&mut self, table: TableId, fd: Fd) -> Result<Option<Description>, Error> {
        let entry = self.entry(table, fd)?;
        let t = self.table_mut(table)?;
        t.storage.entries[fd.0 as usize].0 = None;
        t.storage.mark_free(fd.0 as usize, true);
        let ofd = self.ofd_mut(entry);
        ofd.refs -= 1;
        if ofd.refs != 0 {
            return Ok(None);
        }
        let released = ofd.description;
        self.ofds[entry.ofd.0] = OfdSlot {
            ofd: None,
            next: self.free_ofd,
        };
        self.free_ofd = Some(entry.ofd.0);
        Ok(Some(released))
    }
    /// Inclusive range, bounded by storage even for last=u32::MAX.
    /// CLOSE_RANGE_UNSHARE is fork + venue publication + this operation; it
    /// cannot be implemented by mutating a CLONE_FILES table in place.
    pub fn close_range(
        &mut self,
        table: TableId,
        first: u32,
        last: u32,
        cloexec: bool,
        mut release: impl FnMut(Description),
    ) -> Result<(), Error> {
        if first > last {
            return Err(Error::InvalidArgument);
        }
        self.table(table)?;
        let end = (u64::from(last) + 1).min(self.table(table)?.storage.capacity() as u64) as usize;
        for fd in first as usize..end {
            if self.table(table)?.storage.entries[fd].0.is_none() {
                continue;
            }
            if cloexec {
                self.setfd(table, Fd(fd as i32), true)?;
            } else if let Some(d) = self.close(table, Fd(fd as i32))? {
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
        &mut self,
        table: TableId,
        first: u32,
        last: u32,
        cloexec: bool,
        release: impl FnMut(Description),
        storage: &mut TableStorage<'a>,
    ) -> Result<TableId, Error> {
        if first > last {
            return Err(Error::InvalidArgument);
        }
        let successor = self.fork(table, storage)?;
        self.close_range(successor, first, last, cloexec, release)?;
        Ok(successor)
    }
    /// Replace backing without changing table identity, entries or OFD refs.
    /// The caller receives the old slices in storage, reusable or reclaimable
    /// after this call. Failure changes neither input nor installed storage.
    pub fn grow_table(
        &mut self,
        table: TableId,
        storage: &mut TableStorage<'a>,
    ) -> Result<(), Error> {
        let t = self.table_mut(table)?;
        if storage.capacity() < t.storage.capacity() {
            return Err(Error::InvalidArgument);
        }
        storage.clear();
        storage.entries[..t.storage.capacity()].copy_from_slice(t.storage.entries);
        storage.rebuild();
        core::mem::swap(&mut t.storage, storage);
        storage.clear();
        Ok(())
    }
    /// Copy descriptor flags/limit, retaining each OFD once per copied fd.
    /// Caller supplies backing at least as large as the parent's current backing.
    /// No partial retain or consumed storage on a capacity failure.
    pub fn fork(
        &mut self,
        parent: TableId,
        storage: &mut TableStorage<'a>,
    ) -> Result<TableId, Error> {
        let p = self.table(parent)?;
        let capacity = p.storage.capacity();
        if storage.capacity() < capacity {
            return Err(Error::NeedsBacking {
                descriptors: capacity,
            });
        }
        let child = self.create_table(p.limit, storage)?;
        for fd in 0..capacity {
            if let Some(entry) = self.table(parent)?.storage.entries[fd].0 {
                self.ofd_mut(entry).refs += 1;
                self.table_mut(child)?.storage.entries[fd].0 = Some(entry);
            }
        }
        self.table_mut(child)?.storage.rebuild();
        Ok(child)
    }
    /// Venue must unshare a CLONE_FILES table before exec; otherwise siblings
    /// would observe this sweep. Releases are delivered exactly once.
    pub fn exec(
        &mut self,
        table: TableId,
        mut release: impl FnMut(Description),
    ) -> Result<(), Error> {
        self.table(table)?;
        for fd in 0..self.table(table)?.storage.capacity() {
            if self.table(table)?.storage.entries[fd]
                .0
                .is_some_and(|e| e.cloexec)
                && let Some(d) = self.close(table, Fd(fd as i32))?
            {
                release(d);
            }
        }
        Ok(())
    }
    /// Call after the last CLONE_FILES owner exits (owner count is venue-owned).
    pub fn destroy_table(
        &mut self,
        table: TableId,
        release: impl FnMut(Description),
    ) -> Result<TableStorage<'a>, Error> {
        self.close_range(table, 0, u32::MAX, false, release)?;
        match self.tables[table.index].table.take() {
            Some(t) => Ok(t.storage),
            None => unreachable!(),
        }
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
