//! Kernel-owned bounded syslog service (`syslog(2)` / `klogctl(3)`).
//!
//! # Execution Architecture & Ownership
//!
//! Under HVPatch every Linux process is a thread of ONE VM carrier, so syslog
//! log storage and reader state belong to [`crate::kernel::Kernel`], never a
//! host-process static, a per-task ring, or a stale dispatcher copy:
//!
//! - The **log store** is bounded by capacity (default 64 KiB), storing records
//!   with monotonic sequence numbers. Oldest records are dropped when the ring
//!   wraps, advancing `oldest_seq`. Records exceeding capacity are truncated/bounded.
//! - The **consuming read cursor** (`read_seq`, `read_offset`) tracks the unread
//!   position of the kernel log reader. If records wrap past `read_seq`, the
//!   cursor advances to `oldest_seq` without corruption.
//! - The **clear marker** (`clear_seq`) isolates `READ_ALL` from previously
//!   cleared records without altering the independent consuming `read_seq` cursor.
//! - `READ_ALL` (`SYSLOG_ACTION_READ_ALL`) selects the newest complete records
//!   that fit within the user-supplied buffer limit, matching Linux printk semantics.
//! - **Blocking reads** use Carrick's continuation / wait-set primitives: when
//!   an empty ring is read via action 2 (`SYSLOG_ACTION_READ`), the handler
//!   yields a [`crate::dispatch::DispatchOutcome::WaitOnFds`] outcome with the
//!   service's host readiness pipe. Readiness token synchronization is maintained
//!   under state mutex to prevent lost-wake or spurious-drain races.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_abi::{LINUX_EINVAL, LinuxErrno};
use parking_lot::Mutex;

use crate::dispatch::fd_table::{HostFdRef, make_readiness_pipe};
use crate::kernel::wait_set::WaitQueue;

pub const DEFAULT_LOG_BUF_LEN: usize = 65536; // 64 KiB
pub const DEFAULT_CONSOLE_LOGLEVEL: u32 = 7;
pub const MINIMUM_CONSOLE_LOGLEVEL: u32 = 1;
pub const MAXIMUM_CONSOLE_LOGLEVEL: u32 = 8;

static NEXT_SYSLOG_SERVICE_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// A single log record stored in the kernel syslog ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogRecord {
    pub seq: u64,
    pub facility: u8,
    pub level: u8,
    pub timestamp_ns: u64,
    pub formatted: Vec<u8>,
}

impl SyslogRecord {
    /// Creates a record with formatted representation bounded by `capacity`.
    ///
    /// If the raw payload already has a `<N>` prefix (where `N` is 0..999), that prefix is
    /// preserved. Otherwise, a `<level & 7>` prefix is prepended. A trailing newline `\n`
    /// is guaranteed. If `capacity` is too small to contain even the minimal formatted prefix
    /// and newline (i.e. `capacity < prefix.len() + 1`), returns `None`.
    pub fn create_bounded(
        seq: u64,
        level: u8,
        facility: u8,
        timestamp_ns: u64,
        raw_payload: &[u8],
        capacity: usize,
    ) -> Option<Self> {
        if capacity == 0 {
            return None;
        }

        // Determine if raw_payload already has a valid <N> prefix
        let (prefix, body) = if raw_payload.starts_with(b"<")
            && let Some(pos) = raw_payload.iter().position(|&b| b == b'>')
            && (2..=4).contains(&pos)
            && raw_payload[1..pos].iter().all(|b| b.is_ascii_digit())
        {
            (&raw_payload[..=pos], &raw_payload[pos + 1..])
        } else {
            (b"" as &[u8], raw_payload)
        };

        let gen_prefix;
        let prefix_bytes: &[u8] = if prefix.is_empty() {
            gen_prefix = format!("<{}>", level & 7).into_bytes();
            &gen_prefix
        } else {
            prefix
        };

        let body = if body.ends_with(b"\n") {
            &body[..body.len() - 1]
        } else {
            body
        };

        let min_required = prefix_bytes.len() + 1; // prefix + '\n'
        if capacity < min_required {
            return None;
        }

        let max_body_len = capacity - min_required;
        let truncated_body = &body[..body.len().min(max_body_len)];

        let mut formatted = Vec::with_capacity(prefix_bytes.len() + truncated_body.len() + 1);
        formatted.extend_from_slice(prefix_bytes);
        formatted.extend_from_slice(truncated_body);
        formatted.push(b'\n');

        debug_assert!(formatted.len() <= capacity);

        Some(Self {
            seq,
            facility,
            level,
            timestamp_ns,
            formatted,
        })
    }

    pub fn formatted_len(&self) -> usize {
        self.formatted.len()
    }

    pub fn formatted_bytes(&self) -> &[u8] {
        &self.formatted
    }
}

/// Internal protected state of the syslog service.
#[derive(Debug)]
struct SyslogState {
    records: VecDeque<SyslogRecord>,
    capacity: usize,
    total_bytes: usize,
    next_seq: u64,
    oldest_seq: u64,
    head_seq: u64,
    clear_seq: u64,
    read_seq: u64,
    read_offset: usize,
    console_loglevel: u32,
    saved_console_loglevel: Option<u32>,
    console_enabled: bool,
    append_count: u64,
    read_count: u64,
    drain_count: u64,
    is_ready: bool,
}

impl SyslogState {
    fn new(capacity: usize) -> Self {
        Self {
            records: VecDeque::new(),
            capacity,
            total_bytes: 0,
            next_seq: 1,
            oldest_seq: 1,
            head_seq: 1,
            clear_seq: 1,
            read_seq: 1,
            read_offset: 0,
            console_loglevel: DEFAULT_CONSOLE_LOGLEVEL,
            saved_console_loglevel: None,
            console_enabled: true,
            append_count: 0,
            read_count: 0,
            drain_count: 0,
            is_ready: false,
        }
    }

    fn has_unread_locked(&self) -> bool {
        let start_seq = self.read_seq.max(self.oldest_seq);
        for record in self.records.iter().filter(|r| r.seq >= start_seq) {
            if record.seq == self.read_seq {
                if self.read_offset < record.formatted_len() {
                    return true;
                }
            } else {
                return true;
            }
        }
        false
    }

    fn append_locked(
        &mut self,
        level: u8,
        facility: u8,
        timestamp_ns: u64,
        payload: Vec<u8>,
        owner_id: u32,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.head_seq = self.next_seq;
        self.append_count = self.append_count.saturating_add(1);

        let Some(record) = SyslogRecord::create_bounded(
            seq,
            level,
            facility,
            timestamp_ns,
            &payload,
            self.capacity,
        ) else {
            return seq;
        };

        let record_len = record.formatted_len();
        debug_assert!(record_len <= self.capacity);

        // Enforce capacity bounds: evict oldest records until there is space
        while self.total_bytes + record_len > self.capacity && !self.records.is_empty() {
            if let Some(popped) = self.records.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(popped.formatted_len());
            }
        }

        self.records.push_back(record);
        self.total_bytes = self.total_bytes.saturating_add(record_len);

        self.oldest_seq = self.records.front().map_or(seq, |r| r.seq);
        if self.read_seq < self.oldest_seq {
            self.read_seq = self.oldest_seq;
            self.read_offset = 0;
        }
        if self.clear_seq < self.oldest_seq {
            self.clear_seq = self.oldest_seq;
        }

        crate::event_ring::rec_syslog_record(owner_id, seq, record_len, self.total_bytes);
        crate::event_ring::rec_syslog_state(
            owner_id,
            self.read_seq,
            self.clear_seq,
            self.size_unread_locked(),
        );

        seq
    }

    fn read_consuming_locked(&mut self, max_len: usize) -> Option<Vec<u8>> {
        let start_seq = self.read_seq.max(self.oldest_seq);
        if self.read_seq < start_seq {
            self.read_seq = start_seq;
            self.read_offset = 0;
        }

        let first_idx = self.records.iter().position(|r| r.seq >= self.read_seq)?;
        let mut out = Vec::new();

        for record in self.records.iter().skip(first_idx) {
            if out.len() >= max_len {
                break;
            }
            let formatted = record.formatted_bytes();
            let slice = if record.seq == self.read_seq {
                if self.read_offset >= formatted.len() {
                    self.read_seq = record.seq.saturating_add(1);
                    self.read_offset = 0;
                    continue;
                }
                &formatted[self.read_offset..]
            } else {
                formatted
            };

            let remaining_budget = max_len - out.len();
            if slice.len() <= remaining_budget {
                out.extend_from_slice(slice);
                self.read_seq = record.seq.saturating_add(1);
                self.read_offset = 0;
            } else {
                out.extend_from_slice(&slice[..remaining_budget]);
                if record.seq == self.read_seq {
                    self.read_offset += remaining_budget;
                } else {
                    self.read_seq = record.seq;
                    self.read_offset = remaining_budget;
                }
                break;
            }
        }

        if !out.is_empty() {
            self.read_count = self.read_count.saturating_add(1);
            Some(out)
        } else {
            None
        }
    }

    /// Linux printk find_first_fitting_seq + syslog_print_all:
    /// Returns newest complete records from clear_seq to head that fit within max_len.
    fn read_all_locked(&self, max_len: usize) -> Vec<u8> {
        let start_seq = self.oldest_seq.max(self.clear_seq);
        let eligible: Vec<&SyslogRecord> =
            self.records.iter().filter(|r| r.seq >= start_seq).collect();

        if eligible.is_empty() || max_len == 0 {
            return Vec::new();
        }

        // Find the first record sequence such that all subsequent complete records fit in max_len
        let mut total_fitting = 0;
        let mut start_idx = eligible.len();
        for (i, record) in eligible.iter().enumerate().rev() {
            let len = record.formatted_len();
            if total_fitting + len <= max_len {
                total_fitting += len;
                start_idx = i;
            } else {
                break;
            }
        }

        if start_idx >= eligible.len() {
            return Vec::new();
        }

        let mut out = Vec::with_capacity(total_fitting);
        for record in &eligible[start_idx..] {
            out.extend_from_slice(record.formatted_bytes());
        }
        out
    }

    fn clear_locked(&mut self, owner_id: u32) {
        // syslog_clear in Linux only sets clear_seq = head_seq. It does NOT alter read_seq.
        self.clear_seq = self.head_seq;
        self.drain_count = self.drain_count.saturating_add(1);
        crate::event_ring::rec_syslog_state(
            owner_id,
            self.read_seq,
            self.clear_seq,
            self.size_unread_locked(),
        );
    }

    fn size_unread_locked(&self) -> usize {
        let start_seq = self.read_seq.max(self.oldest_seq);
        let mut total = 0;
        for record in self.records.iter().filter(|r| r.seq >= start_seq) {
            let len = record.formatted_len();
            if record.seq == self.read_seq && self.read_offset > 0 {
                total += len.saturating_sub(self.read_offset);
            } else {
                total += len;
            }
        }
        total
    }
}

/// Snapshot of the Syslog service state for diagnostics, LLDB inspection, and testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogSnapshot {
    pub capacity: usize,
    pub total_bytes: usize,
    pub record_count: usize,
    pub head_seq: u64,
    pub oldest_seq: u64,
    pub clear_seq: u64,
    pub read_seq: u64,
    pub read_offset: usize,
    pub append_count: u64,
    pub read_count: u64,
    pub wake_count: u64,
    pub drain_count: u64,
    pub console_loglevel: u32,
    pub saved_console_loglevel: u32,
    pub console_enabled: bool,
}

/// Kernel-wide syslog service.
#[derive(Debug)]
pub struct SyslogService {
    id: u32,
    state: Mutex<SyslogState>,
    wait_queue: Arc<WaitQueue>,
    pipe: Mutex<Option<(HostFdRef, HostFdRef)>>,
    wake_count: AtomicU64,
}

impl Default for SyslogService {
    fn default() -> Self {
        Self::new()
    }
}

impl SyslogService {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_LOG_BUF_LEN)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let pipe_pair = make_readiness_pipe();
        let id = NEXT_SYSLOG_SERVICE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            state: Mutex::new(SyslogState::new(capacity)),
            wait_queue: Arc::new(WaitQueue::new()),
            pipe: Mutex::new(pipe_pair),
            wake_count: AtomicU64::new(0),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn wait_queue(&self) -> &Arc<WaitQueue> {
        &self.wait_queue
    }

    /// Read poll fd for `WaitOnFds` integration.
    pub(crate) fn read_poll_fd(&self) -> Option<HostFdRef> {
        let mut pipe_guard = self.pipe.lock();
        if pipe_guard.is_none() {
            *pipe_guard = make_readiness_pipe();
        }
        pipe_guard.as_ref().map(|(r, _)| r.clone())
    }

    fn write_poll_fd(&self) -> Option<HostFdRef> {
        let mut pipe_guard = self.pipe.lock();
        if pipe_guard.is_none() {
            *pipe_guard = make_readiness_pipe();
        }
        pipe_guard.as_ref().map(|(_, w)| w.clone())
    }

    /// Append a message into the kernel log store.
    pub fn append(&self, level: u8, facility: u8, timestamp_ns: u64, payload: Vec<u8>) -> u64 {
        let (seq, should_wake, poll_fd) = {
            let mut state = self.state.lock();
            let seq = state.append_locked(level, facility, timestamp_ns, payload, self.id);
            let has_unread = state.has_unread_locked();
            let mut should_wake = false;
            let mut poll_fd = -1;
            if has_unread {
                should_wake = true;
                if !state.is_ready {
                    if let Some(w) = self.write_poll_fd() {
                        poll_fd = w.raw();
                        let byte = 1u8;
                        loop {
                            let rc = unsafe {
                                libc::write(w.raw(), &byte as *const _ as *const libc::c_void, 1)
                            };
                            if rc > 0 {
                                state.is_ready = true;
                                break;
                            } else if rc < 0 {
                                let err = std::io::Error::last_os_error();
                                if err.raw_os_error() == Some(libc::EINTR) {
                                    continue;
                                } else if err.raw_os_error() == Some(libc::EAGAIN)
                                    || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                                {
                                    // Pipe buffer is full: readiness byte is already pending.
                                    state.is_ready = true;
                                    break;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            (seq, should_wake, poll_fd)
        };

        if should_wake {
            let wake = self.wake_count.fetch_add(1, Ordering::Relaxed) + 1;
            crate::event_ring::rec_syslog_wake(self.id, 1, wake, poll_fd);
            self.wait_queue.wake_all();
        }
        seq
    }

    /// Consuming read from the log (action 2). Returns `None` if buffer is empty
    /// relative to this read cursor.
    pub fn read_consuming(&self, max_len: usize) -> Option<Vec<u8>> {
        let mut state = self.state.lock();
        let data = state.read_consuming_locked(max_len);
        let has_unread = state.has_unread_locked();

        if !has_unread && state.is_ready {
            self.drain_read_pipe_locked();
            state.is_ready = false;
        }
        crate::event_ring::rec_syslog_state(
            self.id,
            state.read_seq,
            state.clear_seq,
            state.size_unread_locked(),
        );
        data
    }

    /// Read all remaining messages (action 3). Does not advance read cursor.
    pub fn read_all(&self, max_len: usize) -> Vec<u8> {
        let state = self.state.lock();
        state.read_all_locked(max_len)
    }

    /// Read all messages and clear the buffer (action 4).
    pub fn read_clear(&self, max_len: usize) -> Vec<u8> {
        let mut state = self.state.lock();
        let data = state.read_all_locked(max_len);
        state.clear_locked(self.id);
        data
    }

    /// Clear the ring buffer (action 5).
    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.clear_locked(self.id);
    }

    /// Disable logging to console (action 6).
    pub fn console_off(&self) {
        let mut state = self.state.lock();
        if state.saved_console_loglevel.is_none() {
            state.saved_console_loglevel = Some(state.console_loglevel);
        }
        state.console_loglevel = MINIMUM_CONSOLE_LOGLEVEL;
        state.console_enabled = false;
    }

    /// Enable logging to console (action 7).
    pub fn console_on(&self) {
        let mut state = self.state.lock();
        if let Some(saved) = state.saved_console_loglevel.take() {
            state.console_loglevel = saved;
        }
        state.console_enabled = true;
    }

    /// Set console loglevel (action 8). Valid levels are 1..=8.
    pub fn set_console_level(&self, level: u32) -> Result<(), LinuxErrno> {
        if !(MINIMUM_CONSOLE_LOGLEVEL..=MAXIMUM_CONSOLE_LOGLEVEL).contains(&level) {
            return Err(LINUX_EINVAL);
        }
        let mut state = self.state.lock();
        state.console_loglevel = level;
        state.saved_console_loglevel = None;
        state.console_enabled = level > MINIMUM_CONSOLE_LOGLEVEL;
        Ok(())
    }

    /// Number of unread bytes in the buffer for consuming read (action 9).
    pub fn size_unread(&self) -> usize {
        let state = self.state.lock();
        state.size_unread_locked()
    }

    /// Buffer capacity in bytes (action 10).
    pub fn size_buffer(&self) -> usize {
        let state = self.state.lock();
        state.capacity
    }

    /// Capture snapshot of internal state.
    pub fn snapshot(&self) -> SyslogSnapshot {
        let state = self.state.lock();
        SyslogSnapshot {
            capacity: state.capacity,
            total_bytes: state.total_bytes,
            record_count: state.records.len(),
            head_seq: state.head_seq,
            oldest_seq: state.oldest_seq,
            clear_seq: state.clear_seq,
            read_seq: state.read_seq,
            read_offset: state.read_offset,
            append_count: state.append_count,
            read_count: state.read_count,
            wake_count: self.wake_count.load(Ordering::Relaxed),
            drain_count: state.drain_count,
            console_loglevel: state.console_loglevel,
            saved_console_loglevel: state
                .saved_console_loglevel
                .unwrap_or(DEFAULT_CONSOLE_LOGLEVEL),
            console_enabled: state.console_enabled,
        }
    }

    fn drain_read_pipe_locked(&self) {
        if let Some(r) = self.read_poll_fd() {
            let mut buf = [0u8; 64];
            loop {
                let rc = unsafe {
                    libc::read(r.raw(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if rc > 0 {
                    continue;
                } else if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                }
                break;
            }
            crate::event_ring::rec_syslog_wake(
                self.id,
                2,
                self.wake_count.load(Ordering::Relaxed),
                r.raw(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    #[test]
    fn syslog_empty_ring_behavior() {
        let service = SyslogService::new();
        assert_eq!(service.size_unread(), 0);
        assert_eq!(service.read_consuming(512), None);
        assert_eq!(service.read_all(512), Vec::<u8>::new());
    }

    #[test]
    fn syslog_append_and_read_consuming() {
        let service = SyslogService::new();
        let seq = service.append(6, 0, 1000, b"boot complete\n".to_vec());
        assert_eq!(seq, 1);
        assert_eq!(service.size_unread(), b"<6>boot complete\n".len());

        let read1 = service.read_consuming(1024).expect("read should succeed");
        assert_eq!(read1, b"<6>boot complete\n");
        assert_eq!(service.size_unread(), 0);
        assert_eq!(service.read_consuming(1024), None);
    }

    #[test]
    fn syslog_partial_consuming_read() {
        let service = SyslogService::new();
        service.append(6, 0, 1000, b"first line\n".to_vec());
        service.append(4, 0, 2000, b"second line\n".to_vec());

        // Read only 5 bytes of the first message
        let chunk1 = service.read_consuming(5).expect("chunk1");
        assert_eq!(chunk1, b"<6>fi");

        // Read next 20 bytes: should finish first message and part/all of second
        let chunk2 = service.read_consuming(20).expect("chunk2");
        assert_eq!(chunk2, b"rst line\n<4>second l");

        // Read remainder
        let chunk3 = service.read_consuming(1024).expect("chunk3");
        assert_eq!(chunk3, b"ine\n");
        assert_eq!(service.read_consuming(1024), None);
    }

    #[test]
    fn syslog_read_all_does_not_advance_consuming_cursor() {
        let service = SyslogService::new();
        service.append(6, 0, 1000, b"hello\n".to_vec());

        let all1 = service.read_all(512);
        assert_eq!(all1, b"<6>hello\n");
        assert_eq!(service.size_unread(), b"<6>hello\n".len());

        let consuming = service.read_consuming(512).expect("consuming read");
        assert_eq!(consuming, b"<6>hello\n");
        assert_eq!(service.size_unread(), 0);
    }

    #[test]
    fn syslog_read_clear_and_clear() {
        let service = SyslogService::new();
        service.append(6, 0, 1000, b"msg 1\n".to_vec());

        let all = service.read_clear(512);
        assert_eq!(all, b"<6>msg 1\n");
        assert_eq!(service.read_all(512), Vec::<u8>::new());

        // Consuming read is independent and still reads msg 1
        let consuming = service.read_consuming(512).expect("consuming read");
        assert_eq!(consuming, b"<6>msg 1\n");

        service.append(6, 0, 2000, b"msg 2\n".to_vec());
        service.clear();
        assert_eq!(service.read_all(512), Vec::<u8>::new());
    }

    #[test]
    fn syslog_buffer_wrapping_and_cursor_advancement() {
        // Small buffer: 40 bytes capacity
        let service = SyslogService::with_capacity(40);
        service.append(6, 0, 1000, b"msg A\n".to_vec()); // 9 bytes ("<6>msg A\n")
        service.append(6, 0, 2000, b"msg B\n".to_vec()); // 9 bytes
        service.append(6, 0, 3000, b"msg C\n".to_vec()); // 9 bytes
        service.append(6, 0, 4000, b"msg D\n".to_vec()); // 9 bytes (total 36)

        // Adding msg E (9 bytes) pushes total to 45 > 40, evicting msg A
        service.append(6, 0, 5000, b"msg E\n".to_vec());

        let snapshot = service.snapshot();
        assert_eq!(snapshot.oldest_seq, 2);
        assert_eq!(snapshot.read_seq, 2);

        let data = service.read_all(512);
        assert_eq!(data, b"<6>msg B\n<6>msg C\n<6>msg D\n<6>msg E\n");
    }

    #[test]
    fn syslog_console_level_controls() {
        let service = SyslogService::new();
        assert_eq!(
            service.snapshot().console_loglevel,
            DEFAULT_CONSOLE_LOGLEVEL
        );

        assert!(service.set_console_level(0).is_err());
        assert!(service.set_console_level(9).is_err());
        assert!(service.set_console_level(4).is_ok());
        assert_eq!(service.snapshot().console_loglevel, 4);

        service.console_off();
        assert_eq!(
            service.snapshot().console_loglevel,
            MINIMUM_CONSOLE_LOGLEVEL
        );

        service.console_on();
        assert_eq!(service.snapshot().console_loglevel, 4);
    }

    #[test]
    fn syslog_multithreaded_append_read_race() {
        let service = Arc::new(SyslogService::new());
        let read_bytes = Arc::new(AtomicUsize::new(0));

        let writer_service = Arc::clone(&service);
        let writer = thread::spawn(move || {
            for i in 0..50 {
                writer_service.append(6, 0, i as u64, format!("message {}\n", i).into_bytes());
                thread::yield_now();
            }
        });

        let reader_service = Arc::clone(&service);
        let reader_bytes = Arc::clone(&read_bytes);
        let reader = thread::spawn(move || {
            let mut drained = 0;
            while drained < 50 {
                if let Some(bytes) = reader_service.read_consuming(128) {
                    let count = bytes.iter().filter(|&&b| b == b'\n').count();
                    drained += count;
                    reader_bytes.fetch_add(bytes.len(), Ordering::Relaxed);
                }
                thread::yield_now();
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();

        let snap = service.snapshot();
        assert_eq!(snap.append_count, 50);
    }
}

#[cfg(test)]
mod controller_regressions {
    use super::*;

    #[test]
    fn syslog_oversized_record_respects_capacity_controller() {
        let service = SyslogService::with_capacity(32);
        service.append(6, 0, 0, vec![b'x'; 4096]);
        let snapshot = service.snapshot();
        assert!(
            snapshot.total_bytes <= snapshot.capacity,
            "bounded ring exceeded capacity: {snapshot:?}"
        );
    }

    #[test]
    fn syslog_console_off_on_restores_default_controller() {
        let service = SyslogService::new();
        let initial = service.snapshot().console_loglevel;
        service.console_off();
        service.console_on();
        assert_eq!(service.snapshot().console_loglevel, initial);
    }

    #[test]
    fn syslog_independent_clear_and_consuming_cursors() {
        let service = SyslogService::new();
        service.append(6, 0, 100, b"line 1\n".to_vec());
        service.append(6, 0, 200, b"line 2\n".to_vec());

        // Clear log (action 5) advances clear_seq to 3, but read_seq remains 1
        service.clear();
        let snapshot = service.snapshot();
        assert_eq!(snapshot.clear_seq, 3);
        assert_eq!(snapshot.read_seq, 1);
        assert_eq!(service.read_all(512), Vec::<u8>::new());

        // Consuming read (action 2) still reads from read_seq (1)
        let consumed = service.read_consuming(512).expect("consuming read");
        assert_eq!(consumed, b"<6>line 1\n<6>line 2\n");
    }

    #[test]
    fn syslog_read_all_fits_newest_complete_records() {
        let service = SyslogService::new();
        service.append(6, 0, 100, b"alpha\n".to_vec()); // "<6>alpha\n" = 9 bytes
        service.append(6, 0, 200, b"beta\n".to_vec()); // "<6>beta\n"  = 8 bytes
        service.append(6, 0, 300, b"gamma\n".to_vec()); // "<6>gamma\n" = 9 bytes

        // If buffer max_len is 17 bytes, it fits "<6>beta\n" (8) + "<6>gamma\n" (9) = 17 bytes.
        // It must NOT return partial "<6>alpha\n" or oldest records.
        let read = service.read_all(17);
        assert_eq!(read, b"<6>beta\n<6>gamma\n");
    }
}

#[cfg(test)]
mod capacity_edge_controller {
    use super::*;
    #[test]
    fn syslog_oversized_newline_record_respects_capacity_controller() {
        let service = SyslogService::with_capacity(32);
        let mut payload = vec![b'x'; 4095];
        payload.push(b'\n');
        service.append(6, 0, 0, payload);
        let snapshot = service.snapshot();
        assert!(
            snapshot.total_bytes <= snapshot.capacity,
            "newline truncation exceeded capacity: {snapshot:?}"
        );
    }
}

#[cfg(test)]
mod formatted_capacity_matrix_controller {
    use super::*;
    #[test]
    fn formatted_capacity_matrix_controller() {
        for capacity in 0..=40 {
            for payload in [
                b"<6>long record\n".as_slice(),
                b"<123>long record".as_slice(),
                b"plain record\n".as_slice(),
            ] {
                let service = SyslogService::with_capacity(capacity);
                service.append(6, 0, 0, payload.to_vec());
                let snapshot = service.snapshot();
                assert!(
                    snapshot.total_bytes <= capacity,
                    "capacity={capacity} payload={payload:?} snapshot={snapshot:?}"
                );
            }
        }
    }
}
