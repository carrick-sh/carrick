//! Allocation-free pipe and event counter substrate. See README.md for the
//! semantic contract and the venue's synchronization/continuation obligations.
#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub const PIPE_BUF: usize = 4096;
pub const DEFAULT_PIPE_PAGES: usize = 16;
pub const EVENTFD_MAX: u64 = u64::MAX - 1;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Reader,
    Writer,
}

/// Caller-provided page metadata; contents are private to the pipe.
#[derive(Clone, Copy, Debug, Default)]
pub struct Page {
    offset: usize,
    len: usize,
}

/// Ordinary byte-stream pipe (no packet mode, splice or gifted pages).
/// All methods require exclusive venue ownership. Backing can be host or guest
/// memory; no pointer here is a guest address or a wire/shared-memory ABI.
pub struct Pipe<'a> {
    bytes: &'a mut [u8],
    slots: &'a mut [Page],
    page_size: usize,
    capacity_pages: usize,
    head: usize,
    used: usize,
    unread: usize,
    readers: usize,
    writers: usize,
    #[cfg(test)]
    work: Work,
}

#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct Work {
    copied: usize,
    visits: usize,
}

impl<'a> Pipe<'a> {
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
        let capacity = Self::rounded_capacity(page_size, requested)?;
        let pages = capacity / page_size;
        if capacity > bytes.len() || pages > slots.len() {
            return Err(Error::Storage);
        }
        slots.fill(Page::default());
        Ok(Self {
            bytes,
            slots,
            page_size,
            capacity_pages: pages,
            head: 0,
            used: 0,
            unread: 0,
            readers: 1,
            writers: 1,
            #[cfg(test)]
            work: Work::default(),
        })
    }

    pub fn rounded_capacity(page_size: usize, requested: usize) -> Result<usize, Error> {
        if page_size < PIPE_BUF || !page_size.is_power_of_two() {
            return Err(Error::Invalid);
        }
        requested
            .max(page_size)
            .checked_next_power_of_two()
            .filter(|n| *n <= i32::MAX as usize)
            .ok_or(Error::Invalid)
    }

    pub fn capacity(&self) -> usize {
        self.capacity_pages * self.page_size
    }
    /// FIONREAD returns this same count on BOTH ends, including after closure.
    pub fn unread_bytes(&self) -> usize {
        self.unread
    }
    pub fn references(&self, end: End) -> usize {
        match end {
            End::Reader => self.readers,
            End::Writer => self.writers,
        }
    }

    /// Retain an existing live endpoint (including a suspended syscall lease).
    /// A closed endpoint cannot be resurrected. Dup/fork of a description may
    /// instead share a venue lease and release this count only on final close.
    pub fn retain(&mut self, end: End) -> Result<(), Error> {
        let count = match end {
            End::Reader => &mut self.readers,
            End::Writer => &mut self.writers,
        };
        if *count == 0 {
            return Err(Error::Refcount);
        }
        *count = count.checked_add(1).ok_or(Error::Refcount)?;
        Ok(())
    }

    pub fn release(&mut self, end: End) -> Step<()> {
        let count = match end {
            End::Reader => &mut self.readers,
            End::Writer => &mut self.writers,
        };
        if *count == 0 {
            return Step::quiet(Err(Error::Refcount));
        }
        *count -= 1;
        Step::changed(
            (),
            end == End::Writer && *count == 0,
            end == End::Reader && *count == 0,
        )
    }

    /// The venue supplies its authorized growth ceiling (including privilege
    /// and per-user accounting). Shrinking is allowed even above a new ceiling.
    /// Failed resize leaves bytes, ordering, capacity and readiness unchanged.
    pub fn set_capacity(&mut self, requested: usize, growth_limit: usize) -> Step<usize> {
        let capacity = match Self::rounded_capacity(self.page_size, requested) {
            Ok(n) => n,
            Err(e) => return Step::quiet(Err(e)),
        };
        if capacity > self.capacity() && capacity > growth_limit {
            return Step::quiet(Err(Error::Permission));
        }
        let pages = capacity / self.page_size;
        if pages < self.used {
            return Step::quiet(Err(Error::Busy));
        }
        if capacity > self.bytes.len() || pages > self.slots.len() {
            return Step::quiet(Err(Error::Storage));
        }
        if pages == self.capacity_pages {
            return Step::quiet(Ok(capacity));
        }
        let old = self.capacity();
        self.bytes[..old].rotate_left(self.head * self.page_size);
        self.slots[..self.capacity_pages].rotate_left(self.head);
        self.head = 0;
        let grew = pages > self.capacity_pages;
        self.capacity_pages = pages;
        Step::changed(capacity, false, grew)
    }

    pub fn readiness(&self, end: End) -> Readiness {
        match end {
            End::Reader => Readiness {
                readable: self.unread != 0,
                hup: self.writers == 0,
                ..Readiness::default()
            },
            // A full ring can accept a tail merge but is not POLLOUT-ready.
            End::Writer => Readiness {
                writable: self.used < self.capacity_pages,
                err: self.readers == 0,
                ..Readiness::default()
            },
        }
    }

    pub fn try_read(&mut self, dst: &mut [u8]) -> Step<usize> {
        if dst.is_empty() {
            return Step::quiet(Ok(0));
        }
        if self.unread == 0 {
            return Step::quiet(if self.writers == 0 {
                Ok(0)
            } else {
                Err(Error::WouldBlock(WaitFor::Readable))
            });
        }
        let total = dst.len().min(self.unread);
        let mut done = 0;
        while done < total {
            let page = &mut self.slots[self.head];
            let n = page.len.min(total - done);
            let start = self.head * self.page_size + page.offset;
            dst[done..done + n].copy_from_slice(&self.bytes[start..start + n]);
            #[cfg(test)]
            {
                self.work.copied += n;
                self.work.visits += 1;
            }
            done += n;
            page.offset += n;
            page.len -= n;
            if page.len == 0 {
                self.head = (self.head + 1) % self.capacity_pages;
                self.used -= 1;
            }
        }
        self.unread -= done;
        Step::changed(done, false, true)
    }

    pub fn try_write(&mut self, src: &[u8]) -> Step<usize> {
        if src.is_empty() {
            return Step::quiet(Ok(0));
        }
        if self.readers == 0 {
            return Step::quiet(Err(Error::BrokenPipe));
        }
        let mut done = 0;
        // Merge only the remainder, so subsequent slots contain whole pages.
        // A small write either merges completely or needs one free page.
        let remainder = src.len() % self.page_size;
        if self.used != 0 && remainder != 0 {
            let tail = (self.head + self.used - 1) % self.capacity_pages;
            let page = &mut self.slots[tail];
            if page.offset + page.len + remainder <= self.page_size {
                let start = tail * self.page_size + page.offset + page.len;
                self.bytes[start..start + remainder].copy_from_slice(&src[..remainder]);
                page.len += remainder;
                done = remainder;
                #[cfg(test)]
                {
                    self.work.copied += remainder;
                    self.work.visits += 1;
                }
            }
        }
        while done < src.len() && self.used < self.capacity_pages {
            let tail = (self.head + self.used) % self.capacity_pages;
            let n = self.page_size.min(src.len() - done);
            let start = tail * self.page_size;
            self.bytes[start..start + n].copy_from_slice(&src[done..done + n]);
            self.slots[tail] = Page { offset: 0, len: n };
            self.used += 1;
            done += n;
            #[cfg(test)]
            {
                self.work.copied += n;
                self.work.visits += 1;
            }
        }
        self.unread += done;
        if done == 0 {
            Step::quiet(Err(Error::WouldBlock(WaitFor::Writable)))
        } else {
            Step::changed(done, true, false)
        }
    }
}

/// Retains the byte offset across blocking large-write suspension. The venue
/// must also retain the writer endpoint and original input lifetime. A short
/// step is progress, not syscall completion. On BrokenPipe after progress,
/// return the accumulated count AND deliver SIGPIPE; on interruption after
/// progress, return the count. Never restart the operation at offset zero.
pub struct WriteCursor<'a> {
    source: &'a [u8],
    written: usize,
}
impl<'a> WriteCursor<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self { source, written: 0 }
    }
    pub fn written(&self) -> usize {
        self.written
    }
    pub fn is_complete(&self) -> bool {
        self.written == self.source.len()
    }
    pub fn advance(&mut self, pipe: &mut Pipe<'_>) -> Step<usize> {
        let step = pipe.try_write(&self.source[self.written..]);
        if let Ok(n) = step.result {
            self.written += n;
        }
        step
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventMode {
    Counter,
    Semaphore,
}

/// User-write eventfd counter. KAIO kernel overflow is outside this interface.
/// Wire size/endianness, flags, fd lifetime and O_NONBLOCK are venue concerns.
pub struct EventFd {
    value: u64,
    mode: EventMode,
}
impl EventFd {
    pub fn new(initial: u32, mode: EventMode) -> Self {
        Self {
            value: u64::from(initial),
            mode,
        }
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn readiness(&self) -> Readiness {
        Readiness {
            readable: self.value != 0,
            writable: self.value < EVENTFD_MAX,
            ..Readiness::default()
        }
    }
    pub fn try_read(&mut self) -> Step<u64> {
        if self.value == 0 {
            return Step::quiet(Err(Error::WouldBlock(WaitFor::Readable)));
        }
        let value = match self.mode {
            EventMode::Counter => self.value,
            EventMode::Semaphore => 1,
        };
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
