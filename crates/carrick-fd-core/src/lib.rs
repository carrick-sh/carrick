//! Fixed-storage descriptor/OFD authority; no allocator or host dependencies.
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
#[derive(Clone, Copy)]
struct Table<const F: usize> {
    entries: [Option<Entry>; F],
    free: [u64; 64],
    summary: u64,
    limit: usize,
}
impl<const F: usize> Table<F> {
    fn new(limit: usize) -> Self {
        let mut table = Self {
            entries: [None; F],
            free: [0; 64],
            summary: 0,
            limit,
        };
        for fd in 0..F {
            table.mark_free(fd, true);
        }
        table
    }
    fn mark_free(&mut self, fd: usize, free: bool) {
        let word = fd / 64;
        let mask = 1u64 << (fd % 64);
        if free {
            self.free[word] |= mask;
        } else {
            self.free[word] &= !mask;
        }
        if self.free[word] == 0 {
            self.summary &= !(1u64 << word);
        } else {
            self.summary |= 1u64 << word;
        }
    }
    // At most two leaf-word reads and one summary-word read, at all occupancies.
    fn lowest(&self, min: usize) -> (Option<usize>, usize) {
        if min >= self.limit {
            return (None, 0);
        }
        let word = min / 64;
        let candidates = self.free[word] & (u64::MAX << (min % 64));
        if candidates != 0 {
            let fd = word * 64 + candidates.trailing_zeros() as usize;
            return ((fd < self.limit).then_some(fd), 1);
        }
        let later = if word == 63 {
            0
        } else {
            self.summary & (u64::MAX << (word + 1))
        };
        if later == 0 {
            return (None, 2);
        }
        let next = later.trailing_zeros() as usize;
        let fd = next * 64 + self.free[next].trailing_zeros() as usize;
        ((fd < self.limit).then_some(fd), 3)
    }
}
#[derive(Clone, Copy)]
struct TableSlot<const F: usize> {
    generation: u64,
    table: Option<Table<F>>,
}
#[derive(Clone, Copy)]
struct OfdSlot {
    ofd: Option<Ofd>,
    next: Option<usize>,
}

/// Fixed capacity: T tables, F descriptors/table (1..=4096), O shared OFDs.
/// All operations are allocation-free, including fork. Not Clone: copying the
/// authority would duplicate backing-resource ownership without retaining it.
/// Use close/destroy_table to collect releases before dropping the authority.
pub struct Core<const T: usize, const F: usize, const O: usize> {
    identity: u64,
    tables: [TableSlot<F>; T],
    ofds: [OfdSlot; O],
    free_ofd: Option<usize>,
}
impl<const T: usize, const F: usize, const O: usize> Core<T, F, O> {
    pub fn new() -> Result<Self, Error> {
        if F == 0 || F > 4096 || T.checked_mul(F).is_none_or(|n| n == usize::MAX) {
            return Err(Error::InvalidArgument);
        }
        let identity = NEXT_AUTHORITY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            identity,
            tables: [TableSlot {
                generation: 0,
                table: None,
            }; T],
            ofds: core::array::from_fn(|i| OfdSlot {
                ofd: None,
                next: (i + 1 < O).then_some(i + 1),
            }),
            free_ofd: (O != 0).then_some(0),
        })
    }
    fn table(&self, id: TableId) -> Result<&Table<F>, Error> {
        self.tables
            .get(id.index)
            .filter(|s| s.generation == id.generation && id.authority == self.identity)
            .and_then(|s| s.table.as_ref())
            .ok_or(Error::StaleTable)
    }
    fn table_mut(&mut self, id: TableId) -> Result<&mut Table<F>, Error> {
        self.tables
            .get_mut(id.index)
            .filter(|s| s.generation == id.generation && id.authority == self.identity)
            .and_then(|s| s.table.as_mut())
            .ok_or(Error::StaleTable)
    }
    fn entry(&self, table: TableId, fd: Fd) -> Result<Entry, Error> {
        self.table(table)?
            .entries
            .get(fd.0 as usize)
            .copied()
            .flatten()
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
        table.entries[fd] = Some(entry);
        table.mark_free(fd, false);
        Ok(())
    }
    pub fn create_table(&mut self, limit: usize) -> Result<TableId, Error> {
        if limit > F {
            return Err(Error::InvalidArgument);
        }
        let index = self
            .tables
            .iter()
            .position(|s| s.table.is_none() && s.generation != u64::MAX)
            .ok_or(Error::NoMemory)?;
        let slot = &mut self.tables[index];
        slot.generation += 1;
        slot.table = Some(Table::new(limit));
        Ok(TableId {
            authority: self.identity,
            index,
            generation: slot.generation,
        })
    }
    /// Changing the soft limit never closes existing descriptors above it.
    /// The venue must constrain its advertised hard limit to F.
    pub fn set_limit(&mut self, table: TableId, limit: usize) -> Result<(), Error> {
        if limit > F {
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
        let fd = self
            .table(table)?
            .lowest(min.0 as usize)
            .0
            .ok_or(Error::TooManyFiles)?;
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
        let fd = self
            .table(table)?
            .lowest(min)
            .0
            .ok_or(Error::TooManyFiles)?;
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
        t.entries[fd.0 as usize] = None;
        t.mark_free(fd.0 as usize, true);
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
        let end = (last as usize).min(F - 1);
        for fd in first as usize..=end {
            if self.table(table)?.entries[fd].is_none() {
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
    ) -> Result<TableId, Error> {
        if first > last {
            return Err(Error::InvalidArgument);
        }
        let successor = self.fork(table)?;
        self.close_range(successor, first, last, cloexec, release)?;
        Ok(successor)
    }
    /// Copy descriptor flags/limit; retain each shared OFD once per copied fd.
    /// O(T + F), allocation-free. No partial retain when table storage is full.
    pub fn fork(&mut self, parent: TableId) -> Result<TableId, Error> {
        let copy = *self.table(parent)?;
        let child = self.create_table(copy.limit)?;
        for entry in copy.entries.iter().flatten() {
            self.ofd_mut(*entry).refs += 1;
        }
        *self.table_mut(child)? = copy;
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
        for fd in 0..F {
            if self.table(table)?.entries[fd].is_some_and(|e| e.cloexec)
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
    ) -> Result<(), Error> {
        self.close_range(table, 0, u32::MAX, false, release)?;
        self.tables[table.index].table = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
