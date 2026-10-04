//! Allocation-free pipe and event counter substrate. See README.md for the
//! semantic contract and the venue's synchronization/continuation obligations.
//!
//! One algorithm, two storage shapes: a [`Pipe`] either owns its
//! [`PipeRecord`] (host-only venues and tests) or is a *view* over a record
//! the venue placed in shared memory (`Pipe<'_, &mut PipeRecord>`, built by
//! [`Pipe::attach`] while the venue holds the object's lock). Every
//! algorithm below is written once, against the record.
#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

use core::borrow::BorrowMut;

pub const PIPE_BUF: usize = 4096;
pub const DEFAULT_PIPE_PAGES: usize = 16;
pub const EVENTFD_MAX: u64 = u64::MAX - 1;
/// Largest supported page size: page offsets/lengths are 32-bit in [`Page`].
pub const MAX_PAGE_SIZE: usize = 1 << 30;

/// The venue maps this to a wait queue belonging to this exact object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitFor {
    Readable,
    Writable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Map to EAGAIN for nonblocking descriptions, otherwise enroll and park.
    WouldBlock(WaitFor),
    /// Map to EPIPE and generate SIGPIPE (also after partial blocking progress).
    BrokenPipe,
    Invalid,
    Busy,
    Permission,
    /// The venue must provide more backing, without changing existing state.
    Storage,
    Refcount,
    /// The venue's copy callback transferred no byte (a user-copy fault).
    /// Nothing was consumed or published; map to EFAULT.
    Fault,
    /// A shared record violates the pipe's invariants. A venue bug (both
    /// venues are trusted kernel code); fail closed, never a guest errno.
    Corrupt,
    /// Readiness revision cannot advance. Retire this object incarnation;
    /// never wrap and mistake a new publication for an old observation.
    RevisionExhausted,
    /// This view did not bind the object's venue-owned revision storage.
    RevisionUnavailable,
}

/// Wake all matching object waiters, including readiness subscribers. These
/// are notifications to recheck, not grants to consume bytes. Enroll/recheck
/// under the same venue lock used to mutate the object, to avoid lost wakes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeSet {
    pub readers: bool,
    pub writers: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step<T> {
    pub result: Result<T, Error>,
    pub wake: WakeSet,
}
impl<T> Step<T> {
    /// Signal policy stays with the personality. True requests its SIGPIPE
    /// decision, including a blocking writer that already delivered a prefix.
    /// No signal is raised by the substrate.
    pub const fn broken_pipe_signal(&self) -> bool {
        matches!(self.result, Err(Error::BrokenPipe))
    }
    fn quiet(result: Result<T, Error>) -> Self {
        Self {
            result,
            wake: WakeSet::default(),
        }
    }
    fn changed(value: T, readers: bool, writers: bool) -> Self {
        Self {
            result: Ok(value),
            wake: WakeSet { readers, writers },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub hup: bool,
    pub err: bool,
}

/// Non-wrapping revision scoped to one pipe object incarnation. The venue
/// must also authenticate that incarnation when retaining a wait observation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessRevision(u64);

mod revision_storage {
    pub trait Sealed {}
    impl Sealed for super::NoRevision {}
    impl Sealed for &mut super::ReadinessRevision {}
}

/// A pipe view's revision storage, sealed to an unbound view or an exclusive
/// borrow of the venue-owned word. Neither shape changes the PipeRecord ABI.
pub trait RevisionStorage: revision_storage::Sealed {
    fn revision(&self) -> Option<&ReadinessRevision>;
    fn revision_mut(&mut self) -> Option<&mut ReadinessRevision>;
}

/// Existing venues without readiness revision storage. A snapshot on this
/// shape refuses, so it cannot supply misleading enrollment evidence.
pub struct NoRevision;
impl RevisionStorage for NoRevision {
    fn revision(&self) -> Option<&ReadinessRevision> {
        None
    }
    fn revision_mut(&mut self) -> Option<&mut ReadinessRevision> {
        None
    }
}
impl RevisionStorage for &mut ReadinessRevision {
    fn revision(&self) -> Option<&ReadinessRevision> {
        Some(self)
    }
    fn revision_mut(&mut self) -> Option<&mut ReadinessRevision> {
        Some(self)
    }
}

/// Probe under the object lock AFTER enrollment. Changed revision means an
/// intervening publication requires a recheck, even if the readiness bits
/// returned to their earlier values; it is never permission to consume data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    pub readiness: Readiness,
    pub revision: ReadinessRevision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Reader,
    Writer,
}

/// Caller-provided page metadata; contents are private to the pipe.
/// `repr(C)` so it can live in shared memory next to the ring bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Page {
    offset: u32,
    len: u32,
}

/// The pipe's complete mutable state apart from its byte ring and page
/// metadata: plain data with a fixed `repr(C)` layout and no pointers, so a
/// venue can keep it in memory shared by host and EL1 and attach a view to
/// it under the object's lock. All-zero is "not initialized"
/// ([`Pipe::attach`] rejects it).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeRecord {
    pub page_size: u64,
    pub capacity_pages: u64,
    pub head: u64,
    pub used: u64,
    pub unread: u64,
    pub readers: u64,
    pub writers: u64,
}

/// Ordinary byte-stream pipe (no packet mode, splice or gifted pages).
/// All methods require exclusive venue ownership. Backing can be host or guest
/// memory; the borrowed slices are never persisted — only the record is.
pub struct Pipe<'a, R: BorrowMut<PipeRecord> = PipeRecord, V: RevisionStorage = NoRevision> {
    state: R,
    bytes: &'a mut [u8],
    slots: &'a mut [Page],
    revision: V,
    #[cfg(test)]
    work: Work,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadAction {
    CopyAndConsume,
    Peek,
    Consume,
}

#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct Work {
    copied: usize,
    visits: usize,
}

fn validate_page_size(page_size: usize) -> Result<(), Error> {
    if !(PIPE_BUF..=MAX_PAGE_SIZE).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(Error::Invalid);
    }
    Ok(())
}

impl PipeRecord {
    /// A fresh pipe record: one reader and one writer reference, empty ring.
    /// Fails exactly as [`Pipe::with_capacity`] does.
    pub fn new(
        bytes_len: usize,
        slots_len: usize,
        page_size: usize,
        requested: usize,
    ) -> Result<Self, Error> {
        let capacity = Pipe::rounded_capacity(page_size, requested)?;
        let pages = capacity / page_size;
        if capacity > bytes_len || pages > slots_len {
            return Err(Error::Storage);
        }
        Ok(Self::fresh(page_size, pages))
    }

    /// A fresh pipe record with no ring storage yet (Linux allocates pipe
    /// pages on demand): one reader and one writer reference, empty, with
    /// the rounded `requested` capacity. Everything but a write works on it
    /// ([`Pipe::attach`] accepts it with empty storage); the first write
    /// refuses with [`Error::Storage`] before any effect, so the venue can
    /// provide storage ([`Pipe::replace_storage`]) and retry.
    pub fn unbacked(page_size: usize, requested: usize) -> Result<Self, Error> {
        let capacity = Pipe::rounded_capacity(page_size, requested)?;
        Ok(Self::fresh(page_size, capacity / page_size))
    }

    const fn fresh(page_size: usize, pages: usize) -> Self {
        Self {
            page_size: page_size as u64,
            capacity_pages: pages as u64,
            head: 0,
            used: 0,
            unread: 0,
            readers: 1,
            writers: 1,
        }
    }
}

impl<'a> Pipe<'a, PipeRecord> {
    /// Default capacity is sixteen guest pages, independent of host page size.
    pub fn new(
        bytes: &'a mut [u8],
        slots: &'a mut [Page],
        page_size: usize,
    ) -> Result<Self, Error> {
        let capacity = page_size
            .checked_mul(DEFAULT_PIPE_PAGES)
            .ok_or(Error::Invalid)?;
        Self::with_capacity(bytes, slots, page_size, capacity)
    }

    /// Initial capacity may reflect the venue's per-user quota. The byte and
    /// metadata reserves can exceed it, permitting allocation-free resizing.
    pub fn with_capacity(
        bytes: &'a mut [u8],
        slots: &'a mut [Page],
        page_size: usize,
        requested: usize,
    ) -> Result<Self, Error> {
        let state = PipeRecord::new(bytes.len(), slots.len(), page_size, requested)?;
        slots.fill(Page::default());
        Ok(Self {
            state,
            bytes,
            slots,
            revision: NoRevision,
            #[cfg(test)]
            work: Work::default(),
        })
    }

    pub fn rounded_capacity(page_size: usize, requested: usize) -> Result<usize, Error> {
        validate_page_size(page_size)?;
        requested
            .max(page_size)
            .checked_next_power_of_two()
            .filter(|n| *n <= i32::MAX as usize)
            .ok_or(Error::Invalid)
    }
}

impl<'a> Pipe<'a, &'a mut PipeRecord> {
    /// Format a shared record for new storage: the same initial state as
    /// [`Pipe::with_capacity`], written into the venue's record.
    pub fn init(
        record: &'a mut PipeRecord,
        bytes: &'a mut [u8],
        slots: &'a mut [Page],
        page_size: usize,
        requested: usize,
    ) -> Result<Self, Error> {
        *record = PipeRecord::new(bytes.len(), slots.len(), page_size, requested)?;
        slots.fill(Page::default());
        Ok(Self {
            state: record,
            bytes,
            slots,
            revision: NoRevision,
            #[cfg(test)]
            work: Work::default(),
        })
    }

    /// View an existing shared record over its storage. The caller holds the
    /// object's lock for the view's lifetime. O(1) invariant checks reject a
    /// record that does not describe this storage (fail closed: `Corrupt`);
    /// per-page metadata is checked where it is used. Empty `bytes` and
    /// `slots` attach an *unbacked* pipe ([`PipeRecord::unbacked`]), which
    /// must hold no page.
    pub fn attach(
        record: &'a mut PipeRecord,
        bytes: &'a mut [u8],
        slots: &'a mut [Page],
    ) -> Result<Self, Error> {
        let r = *record;
        let page_size = usize::try_from(r.page_size).map_err(|_| Error::Corrupt)?;
        validate_page_size(page_size).map_err(|_| Error::Corrupt)?;
        let pages = usize::try_from(r.capacity_pages).map_err(|_| Error::Corrupt)?;
        let unbacked = bytes.is_empty() && slots.is_empty();
        let fits = pages
            .checked_mul(page_size)
            .is_some_and(|n| (unbacked || n <= bytes.len()) && n <= i32::MAX as usize);
        if pages == 0
            || !fits
            || (!unbacked && pages > slots.len())
            || (unbacked && (r.used != 0 || r.unread != 0))
            || r.head >= r.capacity_pages
            || r.used > r.capacity_pages
            || r.unread > r.used.saturating_mul(r.page_size)
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            state: record,
            bytes,
            slots,
            revision: NoRevision,
            #[cfg(test)]
            work: Work::default(),
        })
    }
}

impl<'a, R: BorrowMut<PipeRecord>> Pipe<'a, R> {
    /// Bind the same object-scoped revision word on every view, under the
    /// same lock as its PipeRecord and waiter enrollment. Storage is supplied
    /// by the venue; this does not grow the shared PipeRecord ABI. Never reset
    /// the revision while that object incarnation or its waiters survive.
    pub fn with_revision(
        self,
        revision: &mut ReadinessRevision,
    ) -> Pipe<'a, R, &mut ReadinessRevision> {
        Pipe {
            state: self.state,
            bytes: self.bytes,
            slots: self.slots,
            revision,
            #[cfg(test)]
            work: self.work,
        }
    }
}

impl<R: BorrowMut<PipeRecord>, V: RevisionStorage> Pipe<'_, R, V> {
    fn revision_available(&self) -> bool {
        self.revision.revision().is_none_or(|r| r.0 != u64::MAX)
    }

    fn advance_revision(&mut self) {
        // Every mutating caller checks availability before effects/callbacks.
        if let Some(revision) = self.revision.revision_mut() {
            revision.0 += 1;
        }
    }
    fn st(&self) -> &PipeRecord {
        self.state.borrow()
    }

    pub fn page_size(&self) -> usize {
        self.st().page_size as usize
    }
    pub fn capacity(&self) -> usize {
        (self.st().capacity_pages * self.st().page_size) as usize
    }
    /// FIONREAD returns this same count on BOTH ends, including after closure.
    pub fn unread_bytes(&self) -> usize {
        self.st().unread as usize
    }
    pub fn references(&self, end: End) -> usize {
        match end {
            End::Reader => self.st().readers as usize,
            End::Writer => self.st().writers as usize,
        }
    }
    /// Whether ring storage for the current capacity is attached. An
    /// unbacked pipe holds no byte; its first write needs storage.
    pub fn is_backed(&self) -> bool {
        self.bytes.len() >= self.capacity() && self.slots.len() >= self.st().capacity_pages as usize
    }

    /// Move live storage to a separately provisioned extent. The caller holds
    /// the object lock and publishes the replacement only after success. The
    /// logical capacity, page offsets, byte order and endpoint counts survive;
    /// `set_capacity` separately applies the venue's authorized growth limit.
    /// Failure leaves the old storage and shared record unchanged. The new
    /// extent can be discarded; it is never installed on refusal.
    pub fn replace_storage<'b>(
        mut self,
        bytes: &'b mut [u8],
        slots: &'b mut [Page],
    ) -> Result<Pipe<'b, R, V>, Error> {
        let state = *self.st();
        let page_size = self.page_size();
        let pages = state.capacity_pages as usize;
        if bytes.len() < self.capacity() || slots.len() < pages {
            return Err(Error::Storage);
        }
        // Authenticate every live page before changing even destination bytes.
        for ordinal in 0..state.used as usize {
            let page = self.slots[(state.head as usize + ordinal) % pages];
            if page.len == 0 || u64::from(page.offset) + u64::from(page.len) > state.page_size {
                return Err(Error::Corrupt);
            }
        }
        slots.fill(Page::default());
        for (ordinal, slot) in slots.iter_mut().enumerate().take(state.used as usize) {
            let old = (state.head as usize + ordinal) % pages;
            let page = self.slots[old];
            let offset = page.offset as usize;
            let len = page.len as usize;
            let source = old * page_size + offset;
            let dest = ordinal * page_size + offset;
            bytes[dest..dest + len].copy_from_slice(&self.bytes[source..source + len]);
            *slot = page;
            #[cfg(test)]
            {
                self.work.copied += len;
                self.work.visits += 1;
            }
        }
        self.state.borrow_mut().head = 0;
        Ok(Pipe {
            state: self.state,
            bytes,
            slots,
            revision: self.revision,
            #[cfg(test)]
            work: self.work,
        })
    }

    /// Retain an existing live endpoint (including a suspended syscall lease).
    /// A closed endpoint cannot be resurrected. Dup/fork of a description may
    /// instead share a venue lease and release this count only on final close.
    pub fn retain(&mut self, end: End) -> Result<(), Error> {
        let s = self.state.borrow_mut();
        let count = match end {
            End::Reader => &mut s.readers,
            End::Writer => &mut s.writers,
        };
        if *count == 0 {
            return Err(Error::Refcount);
        }
        *count = count.checked_add(1).ok_or(Error::Refcount)?;
        Ok(())
    }

    pub fn release(&mut self, end: End) -> Step<()> {
        if self.references(end) == 1 && !self.revision_available() {
            return Step::quiet(Err(Error::RevisionExhausted));
        }
        let s = self.state.borrow_mut();
        let count = match end {
            End::Reader => &mut s.readers,
            End::Writer => &mut s.writers,
        };
        if *count == 0 {
            return Step::quiet(Err(Error::Refcount));
        }
        *count -= 1;
        let final_close = *count == 0;
        if final_close {
            self.advance_revision();
        }
        Step::changed(
            (),
            end == End::Writer && final_close,
            end == End::Reader && final_close,
        )
    }

    /// The venue supplies its authorized growth ceiling (including privilege
    /// and per-user accounting). Shrinking is allowed even above a new ceiling.
    /// Failed resize leaves bytes, ordering, capacity and readiness unchanged.
    pub fn set_capacity(&mut self, requested: usize, growth_limit: usize) -> Step<usize> {
        let page_size = self.page_size();
        let capacity = match Pipe::rounded_capacity(page_size, requested) {
            Ok(n) => n,
            Err(e) => return Step::quiet(Err(e)),
        };
        if capacity > self.capacity() && capacity > growth_limit {
            return Step::quiet(Err(Error::Permission));
        }
        let pages = capacity / page_size;
        if (pages as u64) < self.st().used {
            return Step::quiet(Err(Error::Busy));
        }
        let old_pages = self.st().capacity_pages as usize;
        if self.bytes.is_empty() && self.slots.is_empty() {
            // Unbacked: no byte to move; storage is sized at the first write.
            if pages == old_pages {
                return Step::quiet(Ok(capacity));
            }
            if !self.revision_available() {
                return Step::quiet(Err(Error::RevisionExhausted));
            }
            let s = self.state.borrow_mut();
            s.head = 0;
            s.capacity_pages = pages as u64;
            self.advance_revision();
            return Step::changed(capacity, false, pages > old_pages);
        }
        if capacity > self.bytes.len() || pages > self.slots.len() {
            return Step::quiet(Err(Error::Storage));
        }
        if pages == old_pages {
            return Step::quiet(Ok(capacity));
        }
        if !self.revision_available() {
            return Step::quiet(Err(Error::RevisionExhausted));
        }
        let old = self.capacity();
        let head = self.st().head as usize;
        self.bytes[..old].rotate_left(head * page_size);
        self.slots[..old_pages].rotate_left(head);
        let s = self.state.borrow_mut();
        s.head = 0;
        s.capacity_pages = pages as u64;
        self.advance_revision();
        Step::changed(capacity, false, pages > old_pages)
    }

    pub fn readiness(&self, end: End) -> Readiness {
        let s = self.st();
        match end {
            End::Reader => Readiness {
                readable: s.unread != 0,
                hup: s.writers == 0,
                ..Readiness::default()
            },
            // A full ring can accept a tail merge but is not POLLOUT-ready.
            End::Writer => Readiness {
                writable: s.used < s.capacity_pages,
                err: s.readers == 0,
                ..Readiness::default()
            },
        }
    }

    pub fn readiness_snapshot(&self, end: End) -> Result<ReadinessSnapshot, Error> {
        Ok(ReadinessSnapshot {
            readiness: self.readiness(end),
            revision: *self.revision.revision().ok_or(Error::RevisionUnavailable)?,
        })
    }

    pub fn try_read(&mut self, dst: &mut [u8]) -> Step<usize> {
        let mut at = 0;
        self.read_with(dst.len(), |chunk| {
            dst[at..at + chunk.len()].copy_from_slice(chunk);
            at += chunk.len();
            chunk.len()
        })
    }

    /// Staged read: hand at most `max` queued bytes to `copy` in ring order,
    /// one contiguous chunk at a time. `copy` returns how many bytes of the
    /// chunk it delivered (e.g. a guarded user copy stopping at a fault);
    /// only delivered bytes are consumed, and a short return ends the read.
    /// The delivered prefix is the result; if nothing was delivered the
    /// result is [`Error::Fault`] and the pipe is unchanged. EOF and
    /// `WouldBlock` are decided before `copy` runs.
    pub fn read_with(&mut self, max: usize, copy: impl FnMut(&[u8]) -> usize) -> Step<usize> {
        self.read_action(max, copy, ReadAction::CopyAndConsume)
    }

    /// Copy without consuming. The caller retains the object lock through a
    /// following `consume`, committing only the prefix accepted by a splice
    /// destination. A tee omits that commit entirely.
    pub fn peek_with(
        &mut self,
        max: usize,
        copy: impl FnMut(&[u8]) -> usize,
    ) -> Result<usize, Error> {
        self.read_action(max, copy, ReadAction::Peek).result
    }

    /// Commit an already delivered prefix under the same exclusive ownership
    /// as `peek_with`. No bytes are copied or allocated by this operation.
    pub fn consume(&mut self, count: usize) -> Step<usize> {
        if count > self.unread_bytes() {
            return Step::quiet(Err(Error::Invalid));
        }
        self.read_action(count, |chunk| chunk.len(), ReadAction::Consume)
    }

    fn read_action(
        &mut self,
        max: usize,
        mut copy: impl FnMut(&[u8]) -> usize,
        action: ReadAction,
    ) -> Step<usize> {
        if max == 0 {
            return Step::quiet(Ok(0));
        }
        let s = *self.st();
        if s.unread == 0 {
            return Step::quiet(if s.writers == 0 {
                Ok(0)
            } else {
                Err(Error::WouldBlock(WaitFor::Readable))
            });
        }
        if action != ReadAction::Peek && !self.revision_available() {
            return Step::quiet(Err(Error::RevisionExhausted));
        }
        let page_size = s.page_size as usize;
        let pages = s.capacity_pages as usize;
        let total = max.min(s.unread as usize);
        let mut head = s.head as usize;
        let mut used = s.used;
        let mut done = 0;
        while done < total {
            let page = self.slots[head];
            let (offset, len) = (page.offset as usize, page.len as usize);
            if len == 0 || offset + len > page_size {
                return Step::quiet(Err(Error::Corrupt));
            }
            let n = len.min(total - done);
            let start = head * page_size + offset;
            let delivered = copy(&self.bytes[start..start + n]).min(n);
            #[cfg(test)]
            {
                if action != ReadAction::Consume {
                    self.work.copied += delivered;
                }
                self.work.visits += 1;
            }
            done += delivered;
            let mut slot = self.slots[head];
            slot.offset += delivered as u32;
            slot.len -= delivered as u32;
            if action != ReadAction::Peek {
                self.slots[head] = slot;
            }
            if slot.len == 0 {
                head = (head + 1) % pages;
                used -= 1;
            }
            if delivered < n {
                break;
            }
        }
        if action != ReadAction::Peek {
            let s = self.state.borrow_mut();
            s.head = head as u64;
            s.used = used;
            s.unread -= done as u64;
        }
        if done == 0 {
            Step::quiet(Err(Error::Fault))
        } else {
            if action != ReadAction::Peek {
                self.advance_revision();
            }
            Step::changed(done, false, action != ReadAction::Peek)
        }
    }

    pub fn try_write(&mut self, src: &[u8]) -> Step<usize> {
        self.write_with(src.len(), |at, dst| {
            dst.copy_from_slice(&src[at..at + dst.len()]);
            dst.len()
        })
    }

    /// Staged write of `len` bytes: the ring reserves destination chunks in
    /// order and `fill(source_offset, chunk)` supplies them, returning how
    /// many bytes it filled (short = a user-copy fault). Only filled bytes
    /// are published. Space and atomicity are decided before any fill: a
    /// write of at most one page either merges wholly into the tail page or
    /// takes one free page, never a prefix. An empty fill publishes nothing
    /// and yields [`Error::Fault`].
    pub fn write_with(
        &mut self,
        len: usize,
        mut fill: impl FnMut(usize, &mut [u8]) -> usize,
    ) -> Step<usize> {
        if len == 0 {
            return Step::quiet(Ok(0));
        }
        let s = *self.st();
        if s.readers == 0 {
            return Step::quiet(Err(Error::BrokenPipe));
        }
        if !self.is_backed() {
            // Before any effect: the venue provides storage and retries.
            return Step::quiet(Err(Error::Storage));
        }
        if !self.revision_available() {
            return Step::quiet(Err(Error::RevisionExhausted));
        }
        let page_size = s.page_size as usize;
        let pages = s.capacity_pages as usize;
        let mut used = s.used as usize;
        let mut done = 0;
        let mut faulted = false;
        // Merge only the remainder, so subsequent slots contain whole pages.
        // A small write either merges completely or needs one free page.
        let remainder = len % page_size;
        if used != 0 && remainder != 0 {
            let tail = (s.head as usize + used - 1) % pages;
            let page = self.slots[tail];
            let end = page.offset as usize + page.len as usize;
            if end + remainder <= page_size {
                let start = tail * page_size + end;
                let n = fill(0, &mut self.bytes[start..start + remainder]).min(remainder);
                self.slots[tail].len += n as u32;
                done = n;
                faulted = n < remainder;
                #[cfg(test)]
                {
                    self.work.copied += n;
                    self.work.visits += 1;
                }
            }
        }
        while !faulted && done < len && used < pages {
            let tail = (s.head as usize + used) % pages;
            let n = page_size.min(len - done);
            let start = tail * page_size;
            let filled = fill(done, &mut self.bytes[start..start + n]).min(n);
            #[cfg(test)]
            {
                self.work.copied += filled;
                self.work.visits += 1;
            }
            if filled == 0 {
                faulted = true;
                break;
            }
            self.slots[tail] = Page {
                offset: 0,
                len: filled as u32,
            };
            used += 1;
            done += filled;
            faulted = filled < n;
        }
        let st = self.state.borrow_mut();
        st.used = used as u64;
        st.unread += done as u64;
        if done != 0 {
            self.advance_revision();
            Step::changed(done, true, false)
        } else if faulted {
            Step::quiet(Err(Error::Fault))
        } else {
            Step::quiet(Err(Error::WouldBlock(WaitFor::Writable)))
        }
    }

    /// Resume a suspended write recorded in `progress`: the same algorithm
    /// as [`Pipe::write_with`] over the unwritten suffix. `fill` receives
    /// offsets into the ORIGINAL source, so a resumed write never restarts
    /// at offset zero.
    pub fn write_progress(
        &mut self,
        progress: &mut WriteProgress,
        mut fill: impl FnMut(usize, &mut [u8]) -> usize,
    ) -> Step<usize> {
        let base = progress.written as usize;
        let step = self.write_with(progress.remaining(), |at, dst| fill(base + at, dst));
        if let Ok(n) = step.result {
            progress.written += n as u64;
        }
        step
    }
}

/// The byte progress of one blocking write, as plain data a venue keeps in
/// an owned continuation outside any stack (`repr(C)`, no pointers). The
/// venue also retains the writer endpoint (a description pin) and the
/// source's authority (task, address space, buffer) until completion.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteProgress {
    pub len: u64,
    pub written: u64,
}
impl WriteProgress {
    pub const fn new(len: u64) -> Self {
        Self { len, written: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.len.saturating_sub(self.written) as usize
    }
    pub fn is_complete(&self) -> bool {
        self.written >= self.len
    }
}

/// Retains the byte offset across blocking large-write suspension. The venue
/// must also retain the writer endpoint and original input lifetime. A short
/// step is progress, not syscall completion. On BrokenPipe after progress,
/// return the accumulated count AND deliver SIGPIPE; on interruption after
/// progress, return the count. Never restart the operation at offset zero.
pub struct WriteCursor<'a> {
    source: &'a [u8],
    progress: WriteProgress,
}
impl<'a> WriteCursor<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            progress: WriteProgress::new(source.len() as u64),
        }
    }
    pub fn written(&self) -> usize {
        self.progress.written as usize
    }
    pub fn is_complete(&self) -> bool {
        self.progress.is_complete()
    }
    pub fn advance<R: BorrowMut<PipeRecord>, V: RevisionStorage>(
        &mut self,
        pipe: &mut Pipe<'_, R, V>,
    ) -> Step<usize> {
        let source = self.source;
        pipe.write_progress(&mut self.progress, |at, dst| {
            dst.copy_from_slice(&source[at..at + dst.len()]);
            dst.len()
        })
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventMode {
    Counter = 0,
    Semaphore = 1,
}

/// User-write eventfd counter. KAIO kernel overflow is outside this interface.
/// Wire size/endianness, flags, fd lifetime and O_NONBLOCK are venue concerns.
/// `repr(C)` plain data: a venue may keep it in shared memory and operate on
/// it in place under the object's lock (all-zero is a zero counter).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventFd {
    value: u64,
    mode: EventMode,
    _reserved: u32,
}
impl EventFd {
    pub fn new(initial: u32, mode: EventMode) -> Self {
        Self {
            value: u64::from(initial),
            mode,
            _reserved: 0,
        }
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn mode(&self) -> EventMode {
        self.mode
    }
    pub fn readiness(&self) -> Readiness {
        Readiness {
            readable: self.value != 0,
            writable: self.value < EVENTFD_MAX,
            ..Readiness::default()
        }
    }
    pub fn try_read(&mut self) -> Step<u64> {
        self.read_with(|_| true)
    }
    /// Staged read: `deliver` copies the value out (e.g. a guarded user
    /// copy); the counter is consumed only if it returns true. On false the
    /// counter is unchanged and the result is [`Error::Fault`].
    pub fn read_with(&mut self, deliver: impl FnOnce(u64) -> bool) -> Step<u64> {
        if self.value == 0 {
            return Step::quiet(Err(Error::WouldBlock(WaitFor::Readable)));
        }
        let value = match self.mode {
            EventMode::Counter => self.value,
            EventMode::Semaphore => 1,
        };
        if !deliver(value) {
            return Step::quiet(Err(Error::Fault));
        }
        self.value -= value;
        Step::changed(value, false, true)
    }
    pub fn try_write(&mut self, value: u64) -> Step<()> {
        if value == u64::MAX {
            return Step::quiet(Err(Error::Invalid));
        }
        if value > EVENTFD_MAX - self.value {
            return Step::quiet(Err(Error::WouldBlock(WaitFor::Writable)));
        }
        self.value += value;
        Step::changed((), self.value != 0, false)
    }
}
