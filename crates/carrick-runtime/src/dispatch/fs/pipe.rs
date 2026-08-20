use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use carrick_abi::*;
use carrick_guest_mem::GuestMemory;
use parking_lot::{Condvar, Mutex};

use super::DispatchOutcome;

pub(crate) const DEFAULT_PIPE_CAPACITY: usize = 65536; // 64 KiB = 16 Linux pages
pub(crate) const MAX_PIPE_CAPACITY: usize = 1048576; // 1 MiB (/proc/sys/fs/pipe-max-size)
pub(crate) const PIPE_BUF: usize = 4096;

static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_pipe_id() -> u64 {
    NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipeState {
    pub(crate) buffer: VecDeque<u8>,
    pub(crate) capacity: usize,
    pub(crate) readers: usize,
    pub(crate) writers: usize,
    pub(crate) pipe_id: u64,
}

#[derive(Debug)]
pub(crate) struct PipeInner {
    pub(crate) state: Mutex<PipeState>,
    pub(crate) changed: Condvar,
    pub(crate) capacity_cell: Arc<AtomicI64>,
}

pub(crate) type PipeRef = Arc<PipeInner>;

impl PipeInner {
    pub(crate) fn new(pipe_id: u64, capacity: usize) -> Self {
        let capacity = capacity.clamp(PIPE_BUF, MAX_PIPE_CAPACITY);
        Self {
            state: Mutex::new(PipeState {
                buffer: VecDeque::with_capacity(capacity.min(65536)),
                capacity,
                readers: 1,
                writers: 1,
                pipe_id,
            }),
            changed: Condvar::new(),
            capacity_cell: Arc::new(AtomicI64::new(capacity as i64)),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn pipe_id(&self) -> u64 {
        self.state.lock().pipe_id
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.state.lock().buffer.len()
    }

    pub(crate) fn set_capacity(&self, new_capacity: usize) -> Result<usize, LinuxErrno> {
        let mut state = self.state.lock();
        if state.buffer.len() > new_capacity {
            return Err(LINUX_EBUSY);
        }
        state.capacity = new_capacity;
        self.capacity_cell
            .store(new_capacity as i64, Ordering::Release);
        drop(state);
        self.changed.notify_all();
        Ok(new_capacity)
    }

    #[allow(dead_code)]
    pub(crate) fn get_capacity(&self) -> usize {
        self.state.lock().capacity
    }
}

pub(crate) fn read_pipe<M: GuestMemory>(
    memory: &mut M,
    address: u64,
    length: usize,
    pipe: &PipeRef,
    status_flags: u64,
    tid: crate::thread::ThreadId,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let mut state = pipe.state.lock();
    loop {
        if !state.buffer.is_empty() {
            let read_len = state.buffer.len().min(length);
            let bytes: Vec<u8> = state.buffer.drain(..read_len).collect();
            drop(state);
            pipe.changed.notify_all();
            if memory.write_bytes(address, &bytes).is_err() {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
            return DispatchOutcome::Returned {
                value: read_len as i64,
            };
        }
        if state.writers == 0 {
            // EOF: all writers closed and buffer empty
            return DispatchOutcome::Returned { value: 0 };
        }
        if nonblocking {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        if crate::host_signal::has_unblocked_pending_for(tid.raw(), carrick_abi::SigBlockMask::NONE)
        {
            return DispatchOutcome::errno(LINUX_EINTR);
        }
        pipe.changed.wait_for(&mut state, Duration::from_millis(10));
    }
}

#[allow(dead_code)]
pub(crate) fn read_pipe_bytes(
    buf: &mut [u8],
    pipe: &PipeRef,
    status_flags: u64,
    tid: crate::thread::ThreadId,
) -> Result<usize, LinuxErrno> {
    if buf.is_empty() {
        return Ok(0);
    }
    let length = buf.len();
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let mut state = pipe.state.lock();
    loop {
        if !state.buffer.is_empty() {
            let read_len = state.buffer.len().min(length);
            for (dest, src) in buf[..read_len]
                .iter_mut()
                .zip(state.buffer.drain(..read_len))
            {
                *dest = src;
            }
            drop(state);
            pipe.changed.notify_all();
            return Ok(read_len);
        }
        if state.writers == 0 {
            // EOF
            return Ok(0);
        }
        if nonblocking {
            return Err(LINUX_EAGAIN);
        }
        if crate::host_signal::has_unblocked_pending_for(tid.raw(), carrick_abi::SigBlockMask::NONE)
        {
            return Err(LINUX_EINTR);
        }
        pipe.changed.wait_for(&mut state, Duration::from_millis(10));
    }
}

pub(crate) fn take_pipe_bytes(
    pipe: &PipeRef,
    length: usize,
    status_flags: u64,
) -> Result<Vec<u8>, LinuxErrno> {
    let mut state = pipe.state.lock();
    if state.buffer.is_empty() {
        if state.writers == 0 {
            return Ok(Vec::new());
        }
        if status_flags & LINUX_O_NONBLOCK != 0 {
            return Err(LINUX_EAGAIN);
        }
        return Ok(Vec::new());
    }

    let read_len = state.buffer.len().min(length);
    let bytes = state.buffer.drain(..read_len).collect();
    drop(state);
    pipe.changed.notify_all();
    Ok(bytes)
}

pub(crate) fn restore_pipe_bytes(pipe: &PipeRef, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut state = pipe.state.lock();
    for byte in bytes.iter().rev() {
        state.buffer.push_front(*byte);
    }
    drop(state);
    pipe.changed.notify_all();
}

pub(crate) fn write_pipe(
    bytes: &[u8],
    pipe: &PipeRef,
    status_flags: u64,
    tid: crate::thread::ThreadId,
) -> DispatchOutcome {
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let length = bytes.len();

    let mut state = pipe.state.lock();
    if state.readers == 0 {
        return DispatchOutcome::errno(LINUX_EPIPE);
    }
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }

    let mut written = 0;
    while written < length {
        if state.readers == 0 {
            if written > 0 {
                return DispatchOutcome::Returned {
                    value: written as i64,
                };
            }
            return DispatchOutcome::errno(LINUX_EPIPE);
        }

        let capacity = state.capacity;
        let available = capacity.saturating_sub(state.buffer.len());

        // For writes <= PIPE_BUF (4096), write must be atomic: all or wait.
        let needed = if length <= PIPE_BUF { length } else { 1 };

        if available >= needed {
            let chunk_len = (length - written).min(available);
            state.buffer.extend(&bytes[written..written + chunk_len]);
            written += chunk_len;
            drop(state);
            pipe.changed.notify_all();
            if written == length || nonblocking {
                return DispatchOutcome::Returned {
                    value: written as i64,
                };
            }
            state = pipe.state.lock();
        } else {
            if written > 0 {
                return DispatchOutcome::Returned {
                    value: written as i64,
                };
            }
            if nonblocking {
                return DispatchOutcome::errno(LINUX_EAGAIN);
            }
            if crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            ) {
                return DispatchOutcome::errno(LINUX_EINTR);
            }
            pipe.changed.wait_for(&mut state, Duration::from_millis(10));
        }
    }

    DispatchOutcome::Returned {
        value: written as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_pipe_basic_read_write() {
        let pipe = Arc::new(PipeInner::new(1, 65536));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        let data = b"hello, in-memory pipe!";
        let out = write_pipe(data, &pipe, 0, tid);
        assert_eq!(
            out,
            DispatchOutcome::Returned {
                value: data.len() as i64
            }
        );

        let mut buf = vec![0u8; data.len()];
        let read_n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(read_n, data.len());
        assert_eq!(&buf[..], data);
    }

    #[test]
    fn in_memory_pipe_capacity_and_resize() {
        let pipe = Arc::new(PipeInner::new(2, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        assert_eq!(pipe.get_capacity(), 4096);
        assert_eq!(pipe.set_capacity(8192), Ok(8192));
        assert_eq!(pipe.get_capacity(), 8192);

        // Fill 5000 bytes
        let data = vec![0x42u8; 5000];
        let out = write_pipe(&data, &pipe, 0, tid);
        assert_eq!(out, DispatchOutcome::Returned { value: 5000 });

        // Shrinking below buffered bytes must return EBUSY
        assert_eq!(pipe.set_capacity(4096), Err(LINUX_EBUSY));

        // Growing capacity succeeds
        assert_eq!(pipe.set_capacity(16384), Ok(16384));
    }

    #[test]
    fn in_memory_pipe_broken_pipe_and_eof() {
        let pipe = Arc::new(PipeInner::new(3, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Close all readers
        pipe.state.lock().readers = 0;
        let out = write_pipe(b"test", &pipe, 0, tid);
        assert_eq!(out, DispatchOutcome::errno(LINUX_EPIPE));

        // Restore reader, close all writers
        pipe.state.lock().readers = 1;
        pipe.state.lock().writers = 0;
        let mut buf = [0u8; 10];
        let n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(n, 0); // EOF
    }

    #[test]
    fn in_memory_pipe_nonblocking_eagain() {
        let pipe = Arc::new(PipeInner::new(4, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Read from empty nonblocking pipe -> EAGAIN
        let mut buf = [0u8; 10];
        assert_eq!(
            read_pipe_bytes(&mut buf, &pipe, LINUX_O_NONBLOCK, tid),
            Err(LINUX_EAGAIN)
        );

        // Fill pipe to capacity
        let data = vec![0xaa; 4096];
        assert_eq!(
            write_pipe(&data, &pipe, LINUX_O_NONBLOCK, tid),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Write to full nonblocking pipe -> EAGAIN
        assert_eq!(
            write_pipe(b"more", &pipe, LINUX_O_NONBLOCK, tid),
            DispatchOutcome::errno(LINUX_EAGAIN)
        );
    }
}
