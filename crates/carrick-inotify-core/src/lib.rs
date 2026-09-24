//! Shared core inotify logic: watch descriptor allocation, event queue ring,
//! and coalescing rules shared between the host model and the EL1 in-guest kernel.

#![no_std]

/// Wire size of Linux `struct inotify_event` header (16 bytes).
pub const INOTIFY_EVENT_HEADER_SIZE: usize = 16;
pub const LINUX_IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const LINUX_IN_MODIFY: u32 = 0x0000_0002;
pub const LINUX_IN_IGNORED: u32 = 0x0000_8000;
pub const LINUX_IN_ONLYDIR: u32 = 0x0100_0000;
pub const LINUX_IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const LINUX_IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const LINUX_IN_MASK_CREATE: u32 = 0x1000_0000;
pub const LINUX_IN_MASK_ADD: u32 = 0x2000_0000;
pub const LINUX_IN_ONESHOT: u32 = 0x8000_0000;
/// Linux errno representation in inotify core.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Debug)]
pub struct LinuxErrno(pub i32);

impl From<i32> for LinuxErrno {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

pub const LINUX_EINVAL: LinuxErrno = LinuxErrno(22);
pub const LINUX_ENOSPC: LinuxErrno = LinuxErrno(28);

/// Linux `struct inotify_event` wire header.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinuxInotifyEventHeader {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub len: u32,
}

/// Maximum queued records before synthesizing an `IN_Q_OVERFLOW` event.
/// Matches Linux's `/proc/sys/fs/inotify/max_queued_events` default (16384).
pub const INOTIFY_MAX_QUEUED_EVENTS: usize = 16384;

/// Capacity of the fixed ring buffer: max events plus one slot for overflow marker.
pub const INOTIFY_RING_CAPACITY: usize = INOTIFY_MAX_QUEUED_EVENTS + 1;

/// Result of pushing an event into the inotify queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Record was successfully queued. `was_empty` indicates if the queue was previously empty.
    Appended { was_empty: bool },
    /// Record was coalesced with the preceding event and dropped.
    Coalesced,
    /// Queue reached capacity; single `IN_Q_OVERFLOW` record was appended.
    Overflowed { was_empty: bool },
    /// Queue has already overflowed; subsequent records are dropped until drained.
    DroppedOverflow,
}

/// Check if two successive events should coalesce per inotify(7).
///
/// "If successive output inotify events produced on the inotify file descriptor
/// are identical (same wd, mask, cookie, and name), then they are coalesced into
/// a single event if the older event has not yet been read."
#[inline]
pub fn should_coalesce(
    last_wd: i32,
    last_mask: u32,
    last_cookie: u32,
    new_wd: i32,
    new_mask: u32,
    new_cookie: u32,
) -> bool {
    last_wd == new_wd && last_mask == new_mask && last_cookie == new_cookie
}

/// Allocate a watch descriptor monotonically, wrapping at `i32::MAX`.
///
/// Pending events retain their wd; descriptors are never reset while the instance lives.
pub fn alloc_wd<F>(next_wd: &mut i32, live_count: usize, is_in_use: F) -> Result<i32, LinuxErrno>
where
    F: Fn(i32) -> bool,
{
    if live_count >= i32::MAX as usize {
        return Err(LINUX_ENOSPC);
    }
    for _ in 0..=live_count {
        let wd = *next_wd;
        *next_wd = if wd == i32::MAX { 1 } else { wd + 1 };
        if wd > 0 && !is_in_use(wd) {
            return Ok(wd);
        }
    }
    Err(LINUX_ENOSPC)
}

/// Ring buffer of inotify event headers enforcing coalescing, overflow, and byte tracking.
#[repr(C)]
#[derive(Debug)]
pub struct InotifyRingCore<const CAP: usize> {
    pub head: usize,
    pub count: usize,
    pub queued_bytes: usize,
    pub overflowed: bool,
    pub events: [LinuxInotifyEventHeader; CAP],
}

impl<const CAP: usize> InotifyRingCore<CAP> {
    pub const fn new() -> Self {
        Self {
            head: 0,
            count: 0,
            queued_bytes: 0,
            overflowed: false,
            events: [const {
                LinuxInotifyEventHeader {
                    wd: 0,
                    mask: 0,
                    cookie: 0,
                    len: 0,
                }
            }; CAP],
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    #[inline]
    pub fn peek_tail(&self) -> Option<LinuxInotifyEventHeader> {
        if self.count == 0 {
            None
        } else {
            let tail_idx = (self.head + self.count - 1) % CAP;
            Some(self.events[tail_idx])
        }
    }

    /// Push an event header with inotify coalescing and queue overflow enforcement.
    pub fn push(&mut self, wd: i32, mask: u32, cookie: u32) -> PushResult {
        if self.overflowed {
            return PushResult::DroppedOverflow;
        }

        if let Some(tail) = self.peek_tail() {
            let tail_wd = tail.wd;
            let tail_mask = tail.mask;
            let tail_cookie = tail.cookie;
            if should_coalesce(tail_wd, tail_mask, tail_cookie, wd, mask, cookie) {
                return PushResult::Coalesced;
            }
        }

        let was_empty = self.count == 0;

        if self.count >= INOTIFY_MAX_QUEUED_EVENTS || self.count >= CAP {
            self.overflowed = true;
            let overflow_hdr = LinuxInotifyEventHeader {
                wd: -1,
                mask: LINUX_IN_Q_OVERFLOW,
                cookie: 0,
                len: 0,
            };
            let idx = (self.head + self.count) % CAP;
            self.events[idx] = overflow_hdr;
            self.count += 1;
            self.queued_bytes += INOTIFY_EVENT_HEADER_SIZE;
            return PushResult::Overflowed { was_empty };
        }

        let idx = (self.head + self.count) % CAP;
        self.events[idx] = LinuxInotifyEventHeader {
            wd,
            mask,
            cookie,
            len: 0,
        };
        self.count += 1;
        self.queued_bytes += INOTIFY_EVENT_HEADER_SIZE;
        PushResult::Appended { was_empty }
    }

    /// Pop a single event header from the front of the queue.
    pub fn pop(&mut self) -> Option<LinuxInotifyEventHeader> {
        if self.count == 0 {
            return None;
        }
        let hdr = self.events[self.head];
        self.head = (self.head + 1) % CAP;
        self.count -= 1;
        self.queued_bytes = self.queued_bytes.saturating_sub(INOTIFY_EVENT_HEADER_SIZE);
        if hdr.mask & LINUX_IN_Q_OVERFLOW != 0 {
            self.overflowed = false;
        }
        Some(hdr)
    }

    /// Drain queued events into a destination byte slice up to `dest.len()`.
    ///
    /// If `dest.len()` is smaller than a single record (16 bytes) and records are queued,
    /// returns `Err(LINUX_EINVAL)`.
    pub fn drain_into(&mut self, dest: &mut [u8]) -> Result<usize, LinuxErrno> {
        if self.count == 0 {
            return Ok(0);
        }
        if dest.len() < INOTIFY_EVENT_HEADER_SIZE {
            return Err(LINUX_EINVAL);
        }

        let mut written = 0;
        while self.count > 0 && written + INOTIFY_EVENT_HEADER_SIZE <= dest.len() {
            let hdr = self.events[self.head];
            self.head = (self.head + 1) % CAP;
            self.count -= 1;
            self.queued_bytes = self.queued_bytes.saturating_sub(INOTIFY_EVENT_HEADER_SIZE);
            if hdr.mask & LINUX_IN_Q_OVERFLOW != 0 {
                self.overflowed = false;
            }

            let slice = &mut dest[written..written + INOTIFY_EVENT_HEADER_SIZE];
            slice[0..4].copy_from_slice(&hdr.wd.to_ne_bytes());
            slice[4..8].copy_from_slice(&hdr.mask.to_ne_bytes());
            slice[8..12].copy_from_slice(&hdr.cookie.to_ne_bytes());
            slice[12..16].copy_from_slice(&hdr.len.to_ne_bytes());
            written += INOTIFY_EVENT_HEADER_SIZE;
        }

        Ok(written)
    }
}

impl<const CAP: usize> Default for InotifyRingCore<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Encoded size of one `inotify_event` record: the 16-byte header plus the
/// NUL-terminated name padded to a 4-byte boundary (`len` includes padding).
pub const fn encoded_record_len(name_len: Option<usize>) -> usize {
    match name_len {
        None => INOTIFY_EVENT_HEADER_SIZE,
        Some(n) => INOTIFY_EVENT_HEADER_SIZE + ((n + 1 + 3) & !3),
    }
}

/// Outcome of [`InotifyEventQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePush {
    /// Appended; `was_empty` reports a readiness transition.
    Appended { was_empty: bool },
    /// Identical to the tail record (inotify(7) coalescing): dropped.
    Coalesced,
    /// The queue reached its event limit: one `IN_Q_OVERFLOW` record was
    /// appended and later records are dropped until the queue drains.
    Overflowed { was_empty: bool },
    /// Dropped because the queue has already overflowed.
    Dropped,
    /// The byte buffer cannot hold this record. The caller must preserve
    /// FIFO order some other way (the host keeps an ordered spill); the queue
    /// is unchanged.
    NoSpace,
}

/// The one inotify event queue, shared by the in-guest instance and the host.
///
/// Records are stored contiguously in exactly the wire format `read(2)`
/// returns, so a read is a copy of a prefix. Semantics match the
/// oracle-verified host model: byte-identical tail coalescing, an event-count
/// bound of [`INOTIFY_MAX_QUEUED_EVENTS`] with a single overflow marker, a
/// latch that lifts only when the queue fully drains, and whole-record reads
/// (EINVAL when the first record does not fit).
#[repr(C)]
#[derive(Debug)]
pub struct InotifyEventQueue<const BYTES: usize> {
    used: usize,
    count: usize,
    tail: usize,
    overflowed: bool,
    buf: [u8; BYTES],
}

impl<const BYTES: usize> InotifyEventQueue<BYTES> {
    pub const fn new() -> Self {
        Self {
            used: 0,
            count: 0,
            tail: 0,
            overflowed: false,
            buf: [0; BYTES],
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of queued records.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Bytes a `read(2)` could return right now (FIONREAD).
    #[inline]
    pub fn queued_bytes(&self) -> usize {
        self.used
    }

    #[inline]
    pub fn has_overflowed(&self) -> bool {
        self.overflowed
    }

    fn write_record(&mut self, at: usize, wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) {
        let len = encoded_record_len(name.map(<[u8]>::len));
        let name_field = (len - INOTIFY_EVENT_HEADER_SIZE) as u32;
        self.buf[at..at + 4].copy_from_slice(&wd.to_ne_bytes());
        self.buf[at + 4..at + 8].copy_from_slice(&mask.to_ne_bytes());
        self.buf[at + 8..at + 12].copy_from_slice(&cookie.to_ne_bytes());
        self.buf[at + 12..at + 16].copy_from_slice(&name_field.to_ne_bytes());
        if let Some(name) = name {
            let start = at + INOTIFY_EVENT_HEADER_SIZE;
            self.buf[start..start + name.len()].copy_from_slice(name);
            for byte in &mut self.buf[start + name.len()..at + len] {
                *byte = 0;
            }
        }
    }

    fn tail_equals(&self, wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) -> bool {
        if self.count == 0 {
            return false;
        }
        let len = encoded_record_len(name.map(<[u8]>::len));
        if self.used - self.tail != len {
            return false;
        }
        let t = self.tail;
        let field = |o: usize| {
            [
                self.buf[t + o],
                self.buf[t + o + 1],
                self.buf[t + o + 2],
                self.buf[t + o + 3],
            ]
        };
        if i32::from_ne_bytes(field(0)) != wd
            || u32::from_ne_bytes(field(4)) != mask
            || u32::from_ne_bytes(field(8)) != cookie
        {
            return false;
        }
        match name {
            None => true,
            Some(name) => {
                let start = t + INOTIFY_EVENT_HEADER_SIZE;
                self.buf[start..start + name.len()] == *name
                    && self.buf[start + name.len()..t + len]
                        .iter()
                        .all(|b| *b == 0)
            }
        }
    }

    /// Queue one event (see [`QueuePush`]).
    pub fn push(&mut self, wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) -> QueuePush {
        if self.overflowed {
            return QueuePush::Dropped;
        }
        if self.tail_equals(wd, mask, cookie, name) {
            return QueuePush::Coalesced;
        }
        let was_empty = self.count == 0;
        if self.count >= INOTIFY_MAX_QUEUED_EVENTS {
            if self.used + INOTIFY_EVENT_HEADER_SIZE > BYTES {
                return QueuePush::NoSpace;
            }
            let at = self.used;
            self.write_record(at, -1, LINUX_IN_Q_OVERFLOW, 0, None);
            self.tail = at;
            self.used += INOTIFY_EVENT_HEADER_SIZE;
            self.count += 1;
            self.overflowed = true;
            return QueuePush::Overflowed { was_empty };
        }
        let len = encoded_record_len(name.map(<[u8]>::len));
        if self.used + len > BYTES {
            return QueuePush::NoSpace;
        }
        let at = self.used;
        self.write_record(at, wd, mask, cookie, name);
        self.tail = at;
        self.used += len;
        self.count += 1;
        QueuePush::Appended { was_empty }
    }

    fn record_len_at(&self, at: usize) -> usize {
        let name_field = u32::from_ne_bytes([
            self.buf[at + 12],
            self.buf[at + 13],
            self.buf[at + 14],
            self.buf[at + 15],
        ]);
        INOTIFY_EVENT_HEADER_SIZE + name_field as usize
    }

    /// Move whole records into `dest`, oldest first, stopping before the first
    /// that does not fit. `Err(EINVAL)` when records are queued and even the
    /// first does not fit.
    pub fn drain_into(&mut self, dest: &mut [u8]) -> Result<usize, LinuxErrno> {
        if self.count == 0 {
            return Ok(0);
        }
        if self.record_len_at(0) > dest.len() {
            return Err(LINUX_EINVAL);
        }
        let mut taken = 0;
        let mut records = 0;
        while taken < self.used {
            let len = self.record_len_at(taken);
            if taken + len > dest.len() {
                break;
            }
            taken += len;
            records += 1;
        }
        dest[..taken].copy_from_slice(&self.buf[..taken]);
        self.buf.copy_within(taken..self.used, 0);
        self.used -= taken;
        self.count -= records;
        self.tail = self.tail.saturating_sub(taken);
        if self.count == 0 {
            self.tail = 0;
            self.overflowed = false;
        }
        Ok(taken)
    }
}

impl<const BYTES: usize> Default for InotifyEventQueue<BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod queue_tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    type Q = InotifyEventQueue<4096>;

    fn records(bytes: &[u8]) -> Vec<(i32, u32, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let f = |o: usize| {
                [
                    bytes[at + o],
                    bytes[at + o + 1],
                    bytes[at + o + 2],
                    bytes[at + o + 3],
                ]
            };
            let len = u32::from_ne_bytes(f(12)) as usize;
            let name = bytes[at + 16..at + 16 + len].to_vec();
            out.push((
                i32::from_ne_bytes(f(0)),
                u32::from_ne_bytes(f(4)),
                u32::from_ne_bytes(f(8)),
                name,
            ));
            at += 16 + len;
        }
        out
    }

    #[test]
    fn names_are_nul_terminated_and_padded_to_four_bytes() {
        let mut q = Q::new();
        assert_eq!(
            q.push(1, 0x100, 0, Some(b"abc")),
            QueuePush::Appended { was_empty: true }
        );
        assert_eq!(q.queued_bytes(), 16 + 4);
        assert_eq!(
            q.push(1, 0x100, 0, Some(b"abcd")),
            QueuePush::Appended { was_empty: false }
        );
        assert_eq!(q.queued_bytes(), 16 + 4 + 16 + 8);
        let mut out = [0u8; 64];
        let n = q.drain_into(&mut out).unwrap();
        let recs = records(&out[..n]);
        assert_eq!(recs[0].3, b"abc\0".to_vec());
        assert_eq!(recs[1].3, b"abcd\0\0\0\0".to_vec());
    }

    #[test]
    fn identical_tail_coalesces_distinct_names_do_not() {
        let mut q = Q::new();
        q.push(1, 2, 0, None);
        assert_eq!(q.push(1, 2, 0, None), QueuePush::Coalesced);
        assert_eq!(
            q.push(2, 2, 0, None),
            QueuePush::Appended { was_empty: false }
        );
        q.push(1, 0x100, 0, Some(b"x"));
        assert_eq!(q.push(1, 0x100, 0, Some(b"x")), QueuePush::Coalesced);
        assert_eq!(
            q.push(1, 0x100, 0, Some(b"y")),
            QueuePush::Appended { was_empty: false }
        );
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn read_takes_whole_records_and_rejects_a_buffer_smaller_than_the_first() {
        let mut q = Q::new();
        q.push(1, 0x100, 0, Some(b"name"));
        q.push(2, 2, 0, None);
        let mut small = [0u8; 16];
        assert_eq!(q.drain_into(&mut small), Err(LINUX_EINVAL));
        let mut one = [0u8; 30];
        assert_eq!(q.drain_into(&mut one), Ok(24));
        assert_eq!(q.len(), 1);
        assert_eq!(q.queued_bytes(), 16);
        // After compaction the remaining record is still intact and coalesces.
        assert_eq!(q.push(2, 2, 0, None), QueuePush::Coalesced);
    }

    #[test]
    fn overflow_appends_one_marker_and_lifts_only_when_drained() {
        let mut q: InotifyEventQueue<{ (INOTIFY_MAX_QUEUED_EVENTS + 1) * 16 }> =
            InotifyEventQueue::new();
        for i in 0..INOTIFY_MAX_QUEUED_EVENTS as i32 {
            assert!(matches!(
                q.push(i + 1, 2, 0, None),
                QueuePush::Appended { .. }
            ));
        }
        assert_eq!(
            q.push(-5, 2, 0, None),
            QueuePush::Overflowed { was_empty: false }
        );
        assert_eq!(q.push(-6, 2, 0, None), QueuePush::Dropped);
        let mut part = vec![0u8; 16 * 10];
        q.drain_into(&mut part).unwrap();
        assert_eq!(
            q.push(-7, 2, 0, None),
            QueuePush::Dropped,
            "latch holds until drained"
        );
        let mut all = vec![0u8; 16 * (INOTIFY_MAX_QUEUED_EVENTS + 1)];
        let n = q.drain_into(&mut all).unwrap();
        let last = records(&all[..n]).pop().unwrap();
        assert_eq!((last.0, last.1), (-1, LINUX_IN_Q_OVERFLOW));
        assert!(matches!(
            q.push(1, 2, 0, None),
            QueuePush::Appended { was_empty: true }
        ));
    }

    #[test]
    fn a_record_that_does_not_fit_reports_no_space_and_changes_nothing() {
        let mut q: InotifyEventQueue<40> = InotifyEventQueue::new();
        assert!(matches!(q.push(1, 2, 0, None), QueuePush::Appended { .. }));
        assert_eq!(q.push(1, 0x100, 0, Some(&[b'n'; 30])), QueuePush::NoSpace);
        assert_eq!((q.len(), q.queued_bytes()), (1, 16));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonic_wd_allocation() {
        let mut next_wd = 1;
        let mut live = [false; 200];

        // Allocate 128 wds with interleaved remove
        for i in 1..=128 {
            let wd = alloc_wd(&mut next_wd, 0, |w| live[w as usize]).unwrap();
            assert_eq!(wd, i);
            live[wd as usize] = true;
            // Simulate remove-watch:
            live[wd as usize] = false;
        }
        // next_wd must NOT reset to 1 after removing watches
        assert_eq!(next_wd, 129);
    }

    #[test]
    fn test_in_ignored_never_coalesces_across_distinct_wds() {
        let mut ring = InotifyRingCore::<1024>::new();

        // 128 distinct wds being removed:
        for wd in 1..=128 {
            let res = ring.push(wd, LINUX_IN_IGNORED, 0);
            assert!(matches!(res, PushResult::Appended { .. }));
        }
        assert_eq!(ring.len(), 128);
        assert_eq!(ring.queued_bytes(), 128 * 16);
    }

    #[test]
    fn test_identical_consecutive_in_modify_coalesces() {
        let mut ring = InotifyRingCore::<1024>::new();

        let res1 = ring.push(1, LINUX_IN_MODIFY, 0);
        assert!(matches!(res1, PushResult::Appended { was_empty: true }));

        // Identical write to same wd: must coalesce!
        let res2 = ring.push(1, LINUX_IN_MODIFY, 0);
        assert_eq!(res2, PushResult::Coalesced);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.queued_bytes(), 16);

        // Different wd: does not coalesce
        let res3 = ring.push(2, LINUX_IN_MODIFY, 0);
        assert!(matches!(res3, PushResult::Appended { was_empty: false }));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.queued_bytes(), 32);
    }

    #[test]
    fn test_overflow_at_host_limit_emits_one_overflow_event() {
        let mut ring = InotifyRingCore::<INOTIFY_RING_CAPACITY>::new();

        for i in 0..INOTIFY_MAX_QUEUED_EVENTS {
            let res = ring.push(i as i32 + 1, LINUX_IN_MODIFY, 0);
            assert!(matches!(res, PushResult::Appended { .. }));
        }
        assert_eq!(ring.len(), INOTIFY_MAX_QUEUED_EVENTS);

        // Next event triggers overflow
        let res_overflow = ring.push(99999, LINUX_IN_MODIFY, 0);
        assert!(matches!(res_overflow, PushResult::Overflowed { .. }));
        assert_eq!(ring.len(), INOTIFY_MAX_QUEUED_EVENTS + 1);

        // Subsequent events are dropped
        let res_drop = ring.push(99999, LINUX_IN_MODIFY, 0);
        assert_eq!(res_drop, PushResult::DroppedOverflow);
        assert_eq!(ring.len(), INOTIFY_MAX_QUEUED_EVENTS + 1);

        // Verify last event is IN_Q_OVERFLOW
        let tail = ring.peek_tail().unwrap();
        let wd = tail.wd;
        let mask = tail.mask;
        assert_eq!(wd, -1);
        assert_eq!(mask, LINUX_IN_Q_OVERFLOW);
    }

    #[test]
    fn test_ring_drain_byte_exact_roundtrip() {
        let mut ring = InotifyRingCore::<1024>::new();
        ring.push(1, LINUX_IN_MODIFY, 0);
        ring.push(1, LINUX_IN_IGNORED, 0);

        let mut buf = [0u8; 64];
        let bytes = ring.drain_into(&mut buf).unwrap();
        assert_eq!(bytes, 32);
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.queued_bytes(), 0);

        let wd0 = i32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let mask0 = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(wd0, 1);
        assert_eq!(mask0, LINUX_IN_MODIFY);

        let wd1 = i32::from_ne_bytes(buf[16..20].try_into().unwrap());
        let mask1 = u32::from_ne_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(wd1, 1);
        assert_eq!(mask1, LINUX_IN_IGNORED);
    }
}
