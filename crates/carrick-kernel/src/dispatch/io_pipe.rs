//! Host-backed pipe and socket I/O helpers.
//!
//! Owns non-blocking I/O dispatch to host file descriptors, including
//! readiness handoff (WaitOnFds), partial write buffering, and archive
//! write forensics.

use std::collections::HashMap;
use std::sync::Arc;

use carrick_abi::{LINUX_EAGAIN, LINUX_EFAULT, LINUX_EINTR, LinuxErrno};
use carrick_guest_mem::CurrentMmMemory;

use super::abi_args::HostFd;
use super::fd_table::{HostFdRef, HostWriteKind};
use super::fs;
use super::outcome::{BlockingWrite, DispatchOutcome, FdWaitCompletion};
use super::wait_authority::{WaitFdAuthority, WaitFds};
use crate::kernel::objects::FileSlotAuthority;
use carrick_vfs::errno::HostSyscallResult as _;

pub(crate) const MAX_RW_COUNT: usize = 0x7fff_f000;
const SMALL_HOST_READ_BUF: usize = 8192;

/// Deferred readiness authority for a host pipe operation.
///
/// Avoids allocating heap buffers for `WaitFdAuthority` during routine,
/// non-blocking forwarded reads and writes by retaining only the scalar
/// `FileSlotAuthority` until an operation actually returns `EAGAIN` / `EINTR`.
#[derive(Clone, Debug)]
pub(crate) enum HostPipeAuthority {
    Full(WaitFdAuthority),
    Slot(FileSlotAuthority),
}

impl HostPipeAuthority {
    #[inline]
    pub(crate) fn into_wait_authority(self) -> WaitFdAuthority {
        match self {
            Self::Full(auth) => auth,
            Self::Slot(slot) => WaitFdAuthority::logical(slot),
        }
    }
}

impl From<WaitFdAuthority> for HostPipeAuthority {
    #[inline]
    fn from(auth: WaitFdAuthority) -> Self {
        Self::Full(auth)
    }
}

impl From<FileSlotAuthority> for HostPipeAuthority {
    #[inline]
    fn from(slot: FileSlotAuthority) -> Self {
        Self::Slot(slot)
    }
}

/// Runner for host I/O operations that can block and need to release
/// guest CPU (P) and MM participation via host-wait handoff.
pub(crate) trait HostWaitRunner {
    fn run_with_host_wait(&self, op: &mut dyn FnMut())
    -> Result<(), super::outcome::DispatchError>;
}

/// Captured host-read endpoint, readiness authority, and optional UNIX flow.
#[derive(Clone)]
pub(crate) struct HostPipeReadTarget<'a> {
    pub host_fd: i32,
    pub host_fd_owner: Option<HostFdRef>,
    pub nonblocking: bool,
    pub authority: HostPipeAuthority,
    pub socket_flow: Option<&'a Arc<crate::kernel::UnixFlow>>,
    pub is_stream: bool,
    pub offset: Option<i64>,
    pub host_wait: Option<&'a (dyn HostWaitRunner + 'a)>,
}

impl<'a> HostPipeReadTarget<'a> {
    pub(crate) fn new(
        host_fd: i32,
        host_fd_owner: Option<HostFdRef>,
        nonblocking: bool,
        authority: impl Into<HostPipeAuthority>,
    ) -> Self {
        Self {
            host_fd,
            host_fd_owner,
            nonblocking,
            authority: authority.into(),
            socket_flow: None,
            is_stream: false,
            offset: None,
            host_wait: None,
        }
    }

    pub(crate) fn with_socket_flow(
        mut self,
        socket_flow: Option<&'a Arc<crate::kernel::UnixFlow>>,
        is_stream: bool,
    ) -> Self {
        self.socket_flow = socket_flow;
        self.is_stream = is_stream;
        self
    }

    pub(crate) fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub(crate) fn with_host_wait(
        mut self,
        host_wait: Option<&'a (dyn HostWaitRunner + 'a)>,
    ) -> Self {
        self.host_wait = host_wait;
        self
    }
}

fn host_read_into(
    buf: &mut [u8],
    target: &HostPipeReadTarget<'_>,
) -> Result<isize, super::outcome::DispatchError> {
    let read_fn = |buf: &mut [u8]| -> isize {
        #[cfg(test)]
        crate::dispatch::budget_meter::record_host_read();
        if let Some(flow) = target.socket_flow {
            let mut ledger = flow.lock_ledger();
            let n = unsafe {
                match target.offset {
                    Some(off) => libc::pread(
                        target.host_fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        off as libc::off_t,
                    ),
                    None => libc::read(target.host_fd, buf.as_mut_ptr() as *mut _, buf.len()),
                }
            };
            if n > 0 {
                if target.is_stream {
                    ledger.consume_stream(n as usize);
                } else {
                    ledger.consume_dgram();
                }
            }
            n
        } else {
            unsafe {
                match target.offset {
                    Some(off) => libc::pread(
                        target.host_fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        off as libc::off_t,
                    ),
                    None => libc::read(target.host_fd, buf.as_mut_ptr() as *mut _, buf.len()),
                }
            }
        }
    };
    let mut n = 0isize;
    if let Some(hw) = target.host_wait {
        hw.run_with_host_wait(&mut || n = read_fn(buf))?;
    } else {
        n = read_fn(buf);
    }
    crate::probes::host_pipe_io(target.host_fd, 0, n as i64);
    Ok(n)
}

fn read_host_pipe_into_owner(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    buf: &mut [u8],
    target: HostPipeReadTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    let mut delivered = 0usize;
    while delivered < buf.len() {
        let Some(address) = guest_addr.checked_add(delivered as u64) else {
            return Ok(DispatchOutcome::returned_len_or_errno(delivered));
        };
        let page_left = (4096 - (address as usize & 4095)).min(buf.len() - delivered);
        let Some(range) =
            carrick_guest_mem::GuestWriteRange::new(carrick_guest_mem::GuestVa(address), page_left)
        else {
            return Ok(if delivered > 0 {
                DispatchOutcome::returned_len_or_errno(delivered)
            } else {
                DispatchOutcome::errno(LINUX_EFAULT)
            });
        };
        let prepared = match memory.prepare_write(&[range]) {
            Ok(prepared) => prepared,
            Err(error) if delivered > 0 => {
                // The previous prepared chunks were committed and exactly
                // their bytes were consumed. Linux returns that real prefix.
                let _ = error;
                return Ok(DispatchOutcome::returned_len_or_errno(delivered));
            }
            Err(carrick_guest_mem::MemoryPrepareError::OwnerWait(wait)) => {
                return Ok(DispatchOutcome::OwnerMemoryWait { wait });
            }
            Err(carrick_guest_mem::MemoryPrepareError::Physical(wait)) => {
                return Ok(DispatchOutcome::OwnerPhysicalWait { wait });
            }
            Err(carrick_guest_mem::MemoryPrepareError::Supply(request)) => {
                return Ok(match request {
                    carrick_guest_mem::MemorySupplyRequest::Metadata { observed, .. } => {
                        DispatchOutcome::OwnerMemoryWait { wait: observed }
                    }
                    _ => DispatchOutcome::OwnerMemorySupply { request },
                });
            }
            Err(carrick_guest_mem::MemoryPrepareError::Fault(_)) => {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Err(carrick_guest_mem::MemoryPrepareError::Limit(limit)) => {
                return Err(super::outcome::DispatchError::MemoryPreparation(format!(
                    "one owner read chunk exceeds prepared range: {limit:?}"
                )));
            }
        };
        // A positioned read must advance the explicit offset by the prefix;
        // ordinary read advances the shared host description itself.
        let chunk_target = if let Some(base) = target.offset {
            let Some(offset) = base.checked_add(delivered as i64) else {
                return Err(super::outcome::DispatchError::MemoryPreparation(
                    "positioned host read offset overflow".into(),
                ));
            };
            target.clone().with_offset(offset).with_host_wait(None)
        } else {
            target.clone().with_host_wait(None)
        };
        // No permit survives a readiness wait. Commit is infallible once the
        // nonblocking host read has consumed this bounded chunk.
        let n = host_read_into(&mut buf[delivered..delivered + page_left], &chunk_target)?;
        if let Err(errno) = n.host_syscall_errno() {
            return Ok(if delivered > 0 {
                DispatchOutcome::returned_len_or_errno(delivered)
            } else if errno == LINUX_EAGAIN || errno == LINUX_EINTR {
                would_block_outcome(
                    target.host_fd,
                    libc::POLLIN,
                    target.nonblocking,
                    target.host_fd_owner,
                    target.authority.into_wait_authority(),
                )
            } else {
                DispatchOutcome::errno(errno)
            });
        }
        let count = n as usize;
        prepared.commit(&[&buf[delivered..delivered + count]]);
        delivered += count;
        if count < page_left || (target.socket_flow.is_some() && !target.is_stream) {
            break;
        }
    }
    Ok(DispatchOutcome::returned_len_or_errno(delivered))
}

/// read(2) on a host-backed fd (pipe/socket/file). Host-backed descriptions are
/// adopted non-blocking at creation time, so EAGAIN means a blocking-mode guest
/// fd hands off to the runtime's lockless kqueue wait via WaitOnFds while a
/// non-blocking guest fd gets EAGAIN. Never blocks under the dispatcher lock.
/// `nonblocking` is the guest's intended mode (status_flags / O_NONBLOCK).
pub(crate) fn read_host_pipe_into(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    buf: &mut [u8],
    target: HostPipeReadTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    if memory.user_memory_venue() == carrick_guest_mem::UserMemoryVenue::Owner {
        return read_host_pipe_into_owner(memory, guest_addr, buf, target);
    }
    let HostPipeReadTarget {
        host_fd,
        host_fd_owner,
        nonblocking,
        authority,
        socket_flow,
        is_stream,
        offset,
        host_wait,
    } = target;
    // BLOCKING-IO-OK: host-backed descriptions are made O_NONBLOCK at creation
    // or adoption sites; EAGAIN becomes WaitOnFds for blocking guest fds.
    let mut n = 0isize;
    let read_fn = |buf: &mut [u8]| -> isize {
        #[cfg(test)]
        crate::dispatch::budget_meter::record_host_read();
        if let Some(flow) = socket_flow {
            let mut ledger = flow.lock_ledger();
            let n = unsafe {
                match offset {
                    Some(off) => libc::pread(
                        host_fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        off as libc::off_t,
                    ),
                    None => libc::read(host_fd, buf.as_mut_ptr() as *mut _, buf.len()),
                }
            };
            if n > 0 {
                if is_stream {
                    ledger.consume_stream(n as usize);
                } else {
                    ledger.consume_dgram();
                }
            }
            drop(ledger);
            n
        } else {
            unsafe {
                match offset {
                    Some(off) => libc::pread(
                        host_fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        off as libc::off_t,
                    ),
                    None => libc::read(host_fd, buf.as_mut_ptr() as *mut _, buf.len()),
                }
            }
        }
    };
    if let Some(hw) = host_wait {
        hw.run_with_host_wait(&mut || {
            n = read_fn(buf);
        })?;
    } else {
        n = read_fn(buf);
    }
    crate::probes::host_pipe_io(host_fd, 0, n as i64);
    if let Err(e) = n.host_syscall_errno() {
        // EINTR: interrupted by a HOST signal. Don't surface it to the guest —
        // carrick's internal machinery raises frequent host signals (e.g. the
        // SIGURG vCPU kick), and leaking their EINTR spins the guest's read in
        // an infinite retry loop. Route through the readiness wait, which
        // retries transparently and only returns guest-EINTR when a deliverable
        // guest signal is actually pending (has_pending_for). Same discipline as
        // host_sleep_interruptible.
        if e == LINUX_EAGAIN || e == LINUX_EINTR {
            return Ok(would_block_outcome(
                host_fd,
                libc::POLLIN,
                nonblocking,
                host_fd_owner,
                authority.into_wait_authority(),
            ));
        }
        return Ok(DispatchOutcome::Errno { errno: e });
    }
    let n_usize = n as usize;
    #[cfg(feature = "trace-io")]
    if n_usize > 0 {
        // Offset the read STARTED at. Without it a buffer beginning with an
        // `ar` member header is ambiguous: normal at a nonzero offset, corrupt
        // at 0. The read has already advanced the description, so subtract.
        let start = fs::host_fd_offset(HostFd(host_fd))
            .map(|end| end.saturating_sub(n_usize as u64))
            .map_or_else(|| "?".to_owned(), |start| start.to_string());
        eprintln!(
            "[IODBG] READ host_fd={host_fd} off={start} n={n_usize} bytes={:02x?}",
            &buf[..n_usize.min(64)]
        );
    }
    if n_usize > 0 && memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() {
        // Linux advances a regular file's offset only by the bytes it
        // delivered to user memory: a destination the guest cannot write
        // yields EFAULT with the offset untouched, and a fault part-way
        // through yields the delivered prefix (faults are page-granular).
        // The host `read` already consumed `n` bytes, so deliver what the
        // destination can take and hand the rest back to the host offset.
        let delivered = deliver_writable_prefix(memory, guest_addr, &buf[..n_usize]);
        if offset.is_none() {
            let undelivered = n_usize - delivered;
            // A pipe, socket or tty cannot give bytes back (ESPIPE); those
            // stay consumed, which is the documented residual of this path.
            // SAFETY: plain lseek on a host fd this dispatch owns for the call.
            let _ = unsafe { libc::lseek(host_fd, -(undelivered as libc::off_t), libc::SEEK_CUR) };
        }
        if delivered == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        return Ok(DispatchOutcome::returned_len_or_errno(delivered));
    }
    Ok(DispatchOutcome::returned_isize_or_errno(n))
}

/// Copy `bytes` to `guest_addr` one guest page at a time and stop at the
/// first page the destination refuses; returns the bytes delivered. Only the
/// slow path after a whole-range copy failed pays this, so it never adds
/// work to a read that lands in full.
fn deliver_writable_prefix(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    bytes: &[u8],
) -> usize {
    const PAGE: u64 = 4096;
    let mut delivered = 0usize;
    while delivered < bytes.len() {
        let cursor = guest_addr + delivered as u64;
        let page_end = (cursor & !(PAGE - 1)) + PAGE;
        let chunk = ((page_end - cursor) as usize).min(bytes.len() - delivered);
        if memory
            .write_bytes(cursor, &bytes[delivered..delivered + chunk])
            .is_err()
        {
            break;
        }
        delivered += chunk;
    }
    delivered
}

pub(crate) fn read_host_pipe_at(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    length: usize,
    offset: i64,
    target: HostPipeReadTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    read_host_pipe(memory, guest_addr, length, target.with_offset(offset))
}

/// Read from a host fd straight into a raw guest-memory destination, without
/// ever constructing a Rust slice over guest memory. The caller retains the
/// backing via a [`HostWriteGuard`](carrick_guest_mem::HostWriteGuard) for
/// the whole call; this function uses the raw pointer directly in the host
/// syscall. A concurrent guest write to those bytes is a guest race (matches
/// Linux) and tolerated.
fn read_host_pipe_raw(
    dst: *mut u8,
    len: usize,
    target: HostPipeReadTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    let HostPipeReadTarget {
        host_fd,
        host_fd_owner,
        nonblocking,
        authority,
        socket_flow,
        is_stream,
        offset,
        host_wait,
    } = target;
    let mut n = 0isize;
    let read_fn = |dst: *mut u8, len: usize| -> isize {
        #[cfg(test)]
        crate::dispatch::budget_meter::record_host_read();
        if let Some(flow) = socket_flow {
            let mut ledger = flow.lock_ledger();
            let n = unsafe {
                match offset {
                    Some(off) => libc::pread(host_fd, dst as *mut _, len, off as libc::off_t),
                    None => libc::read(host_fd, dst as *mut _, len),
                }
            };
            if n > 0 {
                if is_stream {
                    ledger.consume_stream(n as usize);
                } else {
                    ledger.consume_dgram();
                }
            }
            drop(ledger);
            n
        } else {
            unsafe {
                match offset {
                    Some(off) => libc::pread(host_fd, dst as *mut _, len, off as libc::off_t),
                    None => libc::read(host_fd, dst as *mut _, len),
                }
            }
        }
    };
    if let Some(hw) = host_wait {
        hw.run_with_host_wait(&mut || {
            n = read_fn(dst, len);
        })?;
    } else {
        n = read_fn(dst, len);
    }
    crate::probes::host_pipe_io(host_fd, 0, n as i64);
    if let Err(e) = n.host_syscall_errno() {
        if e == LINUX_EAGAIN || e == LINUX_EINTR {
            return Ok(would_block_outcome(
                host_fd,
                libc::POLLIN,
                nonblocking,
                host_fd_owner,
                authority.into_wait_authority(),
            ));
        }
        return Ok(DispatchOutcome::Errno { errno: e });
    }
    Ok(DispatchOutcome::returned_isize_or_errno(n))
}

pub(crate) fn read_host_pipe(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    length: usize,
    target: HostPipeReadTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    if length == 0 {
        return Ok(DispatchOutcome::Returned { value: 0 });
    }
    // Clamp to Linux's MAX_RW_COUNT before staging a host buffer; a huge guest
    // count would otherwise be a one-syscall OOM-abort of the runtime.
    let length = length.min(MAX_RW_COUNT);
    if memory.user_memory_venue() == carrick_guest_mem::UserMemoryVenue::Owner {
        if length <= SMALL_HOST_READ_BUF {
            let mut buf = [0u8; SMALL_HOST_READ_BUF];
            return read_host_pipe_into_owner(memory, guest_addr, &mut buf[..length], target);
        }
        let mut buf = vec![0u8; length];
        return read_host_pipe_into_owner(memory, guest_addr, &mut buf, target);
    }
    if let Some(host_ptr) = memory.host_ptr_for_write(guest_addr, length) {
        let range = [carrick_guest_mem::HostWriteRange {
            guest: carrick_guest_mem::GuestVa(guest_addr),
            len: length,
            host: carrick_guest_mem::HostVa(host_ptr as usize),
        }];
        let _host_write = match carrick_guest_mem::HostWriteGuard::new(memory, &range) {
            Ok(g) => g,
            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
        };
        // No Rust slice over guest memory: pass the raw pointer straight to
        // the host syscall. The HostWriteGuard retains the backing and the
        // raw pointer discipline matches the write side (HostWritePayload::Guest).
        read_host_pipe_raw(host_ptr, length, target)
    } else if length <= SMALL_HOST_READ_BUF {
        let mut buf = [0u8; SMALL_HOST_READ_BUF];
        read_host_pipe_into(memory, guest_addr, &mut buf[..length], target)
    } else {
        let mut buf = vec![0u8; length];
        read_host_pipe_into(memory, guest_addr, &mut buf, target)
    }
}

enum HostWritePayload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
    /// The first `len` bytes of an admitted guest source, retained for the
    /// whole call. Read only through raw pointers: never a Rust slice over
    /// guest memory another vCPU may write.
    Guest {
        read: &'a carrick_guest_mem::HostRead,
        len: usize,
    },
}

#[derive(Clone)]
pub struct HostPipeWriteTarget<'a> {
    pub(crate) host_fd: i32,
    pub(crate) host_fd_owner: Option<HostFdRef>,
    pub(crate) nonblocking: bool,
    pub(crate) write_kind: HostWriteKind,
    pub(crate) pipe_state: Option<(i64, usize)>,
    pub(crate) tid: crate::thread::ThreadId,
    pub(crate) sigpipe_on_epipe: bool,
    pub(crate) authority: HostPipeAuthority,
    /// The carrier's host-signal bridge: a pending unblocked signal ends a
    /// partially completed blocking write with the bytes so far.
    pub(crate) host_signal: &'a dyn carrick_hal::HostSignalBridge,
    pub(crate) socket_flow: Option<Arc<crate::kernel::UnixFlow>>,
    pub(crate) socket_cred: Option<crate::kernel::SocketPeerCred>,
    pub(crate) is_stream: bool,
    pub(crate) offset: Option<i64>,
    pub(crate) is_append: bool,
    pub(crate) host_wait: Option<&'a (dyn HostWaitRunner + 'a)>,
}

impl<'a> HostPipeWriteTarget<'a> {
    pub(crate) fn new(
        host_fd: i32,
        host_fd_owner: Option<HostFdRef>,
        nonblocking: bool,
        write_kind: HostWriteKind,
        tid: crate::thread::ThreadId,
        authority: impl Into<HostPipeAuthority>,
        host_signal: &'a dyn carrick_hal::HostSignalBridge,
    ) -> Self {
        Self {
            host_fd,
            host_fd_owner,
            nonblocking,
            write_kind,
            pipe_state: None,
            tid,
            sigpipe_on_epipe: false,
            authority: authority.into(),
            host_signal,
            socket_flow: None,
            socket_cred: None,
            is_stream: false,
            offset: None,
            is_append: false,
            host_wait: None,
        }
    }

    pub(crate) fn with_pipe_state(mut self, pipe_state: Option<(i64, usize)>) -> Self {
        self.pipe_state = pipe_state;
        self
    }

    pub(crate) fn with_sigpipe(mut self, sigpipe_on_epipe: bool) -> Self {
        self.sigpipe_on_epipe = sigpipe_on_epipe;
        self
    }

    pub(crate) fn with_socket_flow(
        mut self,
        socket_flow: Option<Arc<crate::kernel::UnixFlow>>,
        socket_cred: Option<crate::kernel::SocketPeerCred>,
        is_stream: bool,
    ) -> Self {
        self.socket_flow = socket_flow;
        self.socket_cred = socket_cred;
        self.is_stream = is_stream;
        self
    }

    pub(crate) fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub(crate) fn with_append(mut self, is_append: bool) -> Self {
        self.is_append = is_append;
        self
    }

    pub(crate) fn with_host_wait(
        mut self,
        host_wait: Option<&'a (dyn HostWaitRunner + 'a)>,
    ) -> Self {
        self.host_wait = host_wait;
        self
    }
}

impl<'a> HostWritePayload<'a> {
    fn len(&self) -> usize {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes.len(),
            HostWritePayload::Owned(bytes) => bytes.len(),
            HostWritePayload::Guest { len, .. } => *len,
        }
    }

    /// Base pointer of the payload, valid for `len()` bytes while `self` lives.
    fn as_ptr(&self) -> *const u8 {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes.as_ptr(),
            HostWritePayload::Owned(bytes) => bytes.as_ptr(),
            HostWritePayload::Guest { read, .. } => read.as_ptr(),
        }
    }

    /// Private copy of the first `dst.len()` bytes (fewer if shorter), for
    /// content predicates.
    fn head<'b>(&self, dst: &'b mut [u8]) -> &'b [u8] {
        let len = dst.len().min(self.len());
        // SAFETY: `as_ptr` is valid for `len()` bytes; `dst` is private.
        unsafe { std::ptr::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr(), len) };
        &dst[..len]
    }

    #[cfg(any(feature = "trace-io", feature = "trace-tty"))]
    fn trace_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; self.len()];
        self.head(&mut bytes);
        bytes
    }

    fn into_owned(self) -> Vec<u8> {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes.to_vec(),
            HostWritePayload::Owned(bytes) => bytes,
            HostWritePayload::Guest { read, len } => {
                let mut bytes = vec![0_u8; len];
                read.copy_into(&mut bytes);
                bytes
            }
        }
    }
}

/// write(2) on a host-backed fd. Same lockless discipline as `read_host_pipe`.
/// Host fds that have received an `ar` archive magic write, with the length
/// written and a monotonic sequence number.
///
/// Only touched on the two rare archive predicates (roughly 67 magic writes in
/// a whole cold `go build`), never on the ordinary write path. Its sole
/// purpose is to answer, when a member header is caught being written at
/// offset 0, whether that same description had previously received the magic.
static AR_MAGIC_WRITES: std::sync::LazyLock<parking_lot::Mutex<HashMap<i32, (usize, u64)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
static AR_MAGIC_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Stream writes may wait for a guest peer to drain or close the endpoint, so
/// they must lend their executor while the host call runs. A regular-file
/// write has no guest-driven readiness dependency: running it inline matches a
/// native host thread and avoids a scheduler/MM handoff around every scalar
/// write. Slow storage can occupy this executor, but cannot deadlock on guest
/// progress; other persistent executors remain runnable.
fn write_requires_host_wait(write_kind: HostWriteKind) -> bool {
    write_kind != HostWriteKind::RegularFile
}

fn note_ar_magic_write(host_fd: i32, length: usize) {
    let seq = AR_MAGIC_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    AR_MAGIC_WRITES.lock().insert(host_fd, (length, seq));
}

/// `(length, sequence)` of the last magic write seen on `host_fd`, if any.
fn prior_ar_magic_write(host_fd: i32) -> Option<(usize, u64)> {
    AR_MAGIC_WRITES.lock().get(&host_fd).copied()
}

pub(crate) fn write_host_pipe(
    bytes: &[u8],
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    write_host_pipe_payload(HostWritePayload::Borrowed(bytes), target)
}

/// Write the first `len` bytes of an admitted guest source straight from guest
/// memory; `read` retains its backing for the whole call.
pub(crate) fn write_host_pipe_guest(
    read: &carrick_guest_mem::HostRead,
    len: usize,
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    write_host_pipe_payload(
        HostWritePayload::Guest {
            read,
            len: len.min(read.len()),
        },
        target,
    )
}

pub(crate) fn write_host_pipe_owned(
    bytes: Vec<u8>,
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    write_host_pipe_payload(HostWritePayload::Owned(bytes), target)
}

pub(crate) fn write_host_pipe_at(
    bytes: &[u8],
    offset: i64,
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    write_host_pipe(bytes, target.with_offset(offset))
}

pub(crate) fn write_host_pipe_owned_at(
    bytes: Vec<u8>,
    offset: i64,
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    write_host_pipe_owned(bytes, target.with_offset(offset))
}

pub(crate) fn host_pipe_write_room(capacity: i64, queued: usize) -> Option<usize> {
    let capacity = usize::try_from(capacity).ok()?;
    Some(capacity.saturating_sub(queued))
}

fn write_host_pipe_payload(
    payload: HostWritePayload<'_>,
    target: HostPipeWriteTarget<'_>,
) -> Result<DispatchOutcome, super::outcome::DispatchError> {
    let HostPipeWriteTarget {
        host_fd,
        host_fd_owner,
        nonblocking,
        write_kind,
        pipe_state,
        tid,
        sigpipe_on_epipe,
        authority,
        host_signal,
        socket_flow,
        socket_cred,
        is_stream,
        offset: file_offset,
        is_append,
        host_wait,
    } = target;

    // Always-on, near-zero-cost detector for archive corruption. The predicate
    // is a byte compare on the payload head; only a match pays the `lseek`.
    // See `event_ring::ARWRITE` for why this is not in the `trace-io` log.
    // Correlate the magic write with the member write that should follow it on
    // the same description: if both land on one host fd the magic write was
    // lost or rewound, and if they land on different fds the description was
    // swapped underneath the guest. This is NORMAL traffic — roughly 67 writes
    // per cold `go build` — so it goes to the lock-free ring only. Logging it
    // would be debug spam on a healthy run, and the per-write cost is what
    // made `trace-io` perturb this bug out of existence.
    let mut head_buf = [0_u8; 64];
    let head = payload.head(&mut head_buf);
    if crate::event_ring::payload_starts_at_ar_magic(head) {
        let offset = fs::host_fd_offset(HostFd(host_fd)).map_or(-1, |offset| offset as u32 as i32);
        crate::event_ring::rec(
            crate::event_ring::ARMAGIC,
            host_fd,
            offset,
            payload.len() as u32 as i32,
        );
        note_ar_magic_write(host_fd, payload.len());
    }
    if crate::event_ring::payload_starts_at_ar_member_header(head) {
        let offset = fs::host_fd_offset(HostFd(host_fd));
        crate::event_ring::rec(
            crate::event_ring::ARWRITE,
            host_fd,
            offset.map_or(-1, |offset| offset as u32 as i32),
            payload.len() as u32 as i32,
        );
        // Offset 0 means the archive magic is being skipped: the file will not
        // be a valid `ar` archive. Report it once, at the moment it happens.
        // This is a genuine data-corruption event, not trace output — it fires
        // at most a handful of times in a whole build, so it cannot perturb
        // timing the way a per-I/O log does.
        if offset == Some(0) {
            // Did THIS description ever receive the magic? The answer picks the
            // fix: "never" means the magic write went to a different host fd,
            // i.e. the description was swapped underneath the guest; "yes"
            // means it reached this fd and the offset was then lost or rewound.
            let prior_magic = prior_ar_magic_write(host_fd);
            tracing::error!(
                target: "carrick::dispatch::fs",
                host_fd,
                length = payload.len(),
                ?prior_magic,
                "ar member header written at offset 0; the archive will lack its magic"
            );
        }
    }

    #[cfg(feature = "trace-io")]
    if payload.len() != 0 {
        let bytes = payload.trace_bytes();
        // Offset the write will START at, captured before it advances the
        // description. A buffer beginning with an `ar` member header is normal
        // at a nonzero offset and corrupt at 0.
        let start = fs::host_fd_offset(HostFd(host_fd))
            .map_or_else(|| "?".to_owned(), |start| start.to_string());
        eprintln!(
            "[IODBG] WRITE host_fd={host_fd} off={start} n={} bytes={:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(64)]
        );
    }
    // A blocking large pipe write may make partial progress before the host fd
    // reports EAGAIN. At that point we cannot re-dispatch the original syscall
    // (it would re-send the written prefix), but we also cannot park inside the
    // dispatcher because a sibling guest thread may be the reader/closer needed
    // to unblock this write. Hand the staged bytes to the runtime so it can wait
    // with dispatcher progress released.
    let block_until_complete = !nonblocking && write_kind == HostWriteKind::PipeLike;
    let mut offset = 0usize;
    loop {
        #[cfg(feature = "trace-tty")]
        if payload.trace_bytes().contains(&0x0a) {
            unsafe {
                let isatty = libc::isatty(host_fd);
                let mut t: libc::termios = core::mem::zeroed();
                let tg = libc::tcgetattr(host_fd, &mut t);
                let mut outq: libc::c_int = -1;
                libc::ioctl(host_fd, libc::TIOCOUTQ, &mut outq);
                let fl = libc::fcntl(host_fd, libc::F_GETFL);
                let mut st: libc::stat = core::mem::zeroed();
                libc::fstat(host_fd, &mut st);
                let oflag = t.c_oflag;
                let lflag = t.c_lflag;
                let rdev = st.st_rdev;
                let blen = payload.len();
                eprintln!(
                    "[TTYDBG-PRE] host_fd={host_fd} isatty={isatty} tg={tg} oflag=0x{oflag:x} lflag=0x{lflag:x} outq={outq} flags=0x{fl:x} rdev={rdev} n={blen}"
                );
            }
        }
        // host_fd was made O_NONBLOCK when adopted; an EAGAIN here routes
        // through would_block_outcome / wait_pipe_writable, which park with the
        // dispatcher lock released. BLOCKING-IO-OK: non-blocking by
        // construction, the lock is never held across a blocking write.
        let n = {
            let base = payload.as_ptr();
            let mut len = payload.len() - offset;
            if write_kind == HostWriteKind::PipeLike
                && let Some((capacity, queued)) = pipe_state
                && let Some(room) = host_pipe_write_room(capacity, queued.saturating_add(offset))
            {
                if room == 0 {
                    // A blocking pipe write that already made partial progress
                    // (offset > 0) must RESUME from `offset` — re-dispatching the
                    // guest write(2) from 0 (what would_block_outcome does) would
                    // re-send the delivered prefix and duplicate every byte past
                    // the first pipe-full (corrupting any >64 KiB stream, e.g.
                    // dpkg's data.tar). Hand the staged bytes to the runtime the
                    // same way the EAGAIN branch does.
                    if block_until_complete && offset > 0 {
                        if host_signal
                            .has_unblocked_pending_for(tid.raw(), carrick_abi::SigBlockMask::NONE)
                        {
                            return Ok(DispatchOutcome::returned_len_or_errno(offset));
                        }
                        return match BlockingWrite::from_vec(
                            host_fd,
                            payload.into_owned(),
                            offset,
                            tid,
                            sigpipe_on_epipe,
                        ) {
                            Ok(write) => Ok(DispatchOutcome::BlockingWrite(write)),
                            Err(_) => Ok(DispatchOutcome::returned_len_or_errno(offset)),
                        };
                    }
                    return Ok(would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                        authority.clone().into_wait_authority(),
                    ));
                }
                if nonblocking && offset == 0 && len <= 4096 && len > room {
                    return Ok(would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                        authority.clone().into_wait_authority(),
                    ));
                }
                len = len.min(room);
            }
            // BLOCKING-IO-OK: host_fd was adopted O_NONBLOCK; EAGAIN routes to
            // the lockless wait path below.
            let write_fn = || -> isize {
                #[cfg(test)]
                crate::dispatch::budget_meter::record_host_write();
                if let (Some(flow), Some(cred)) = (&socket_flow, socket_cred) {
                    let mut ledger = flow.lock_ledger();
                    let n = unsafe {
                        match file_offset {
                            Some(off) => {
                                if is_append {
                                    let saved = libc::lseek(host_fd, 0, libc::SEEK_CUR);
                                    libc::lseek(host_fd, 0, libc::SEEK_END);
                                    let w = libc::write(host_fd, base.add(offset) as *const _, len);
                                    if saved >= 0 {
                                        libc::lseek(host_fd, saved, libc::SEEK_SET);
                                    }
                                    w
                                } else {
                                    libc::pwrite(
                                        host_fd,
                                        base.add(offset) as *const _,
                                        len,
                                        (off + offset as i64) as libc::off_t,
                                    )
                                }
                            }
                            None => libc::write(host_fd, base.add(offset) as *const _, len),
                        }
                    };
                    if n > 0 {
                        if is_stream {
                            ledger.push_stream(n as usize, cred);
                        } else {
                            ledger.push_dgram(n as usize, cred);
                        }
                    }
                    drop(ledger);
                    n
                } else {
                    unsafe {
                        match file_offset {
                            Some(off) => {
                                if is_append {
                                    let saved = libc::lseek(host_fd, 0, libc::SEEK_CUR);
                                    libc::lseek(host_fd, 0, libc::SEEK_END);
                                    let w = libc::write(host_fd, base.add(offset) as *const _, len);
                                    if saved >= 0 {
                                        libc::lseek(host_fd, saved, libc::SEEK_SET);
                                    }
                                    w
                                } else {
                                    libc::pwrite(
                                        host_fd,
                                        base.add(offset) as *const _,
                                        len,
                                        (off + offset as i64) as libc::off_t,
                                    )
                                }
                            }
                            None => libc::write(host_fd, base.add(offset) as *const _, len),
                        }
                    }
                }
            };
            let mut n = 0isize;
            if let Some(hw) = host_wait.filter(|_| write_requires_host_wait(write_kind)) {
                hw.run_with_host_wait(&mut || {
                    n = write_fn();
                })?;
            } else {
                n = write_fn();
            }
            n
        };
        #[cfg(feature = "trace-tty")]
        if payload.trace_bytes().contains(&0x0a) {
            unsafe {
                let mut outq: libc::c_int = -1;
                libc::ioctl(host_fd, libc::TIOCOUTQ, &mut outq);
                eprintln!("[TTYDBG-POST] host_fd={host_fd} wrote={n} outq_after={outq}");
            }
        }
        crate::probes::host_pipe_io(host_fd, 1, n as i64);
        if let Err(e) = n.host_syscall_errno() {
            // FreeBSD's AF_UNIX (notably DGRAM) write returns ENOBUFS when the peer
            // receive buffer is full; Linux reports EAGAIN for a non-blocking socket
            // that can't proceed (and blocks a blocking one until it drains). LTP
            // sendfile07 fills an out_fd socket buffer in a loop, treating EAGAIN as
            // "full, stop" but ENOBUFS as a hard setup error. Route a socket-write
            // ENOBUFS through the same readiness path as EAGAIN (EAGAIN if
            // non-blocking, else park on POLLOUT). No-op on Linux, which uses EAGAIN.
            #[cfg(not(target_os = "linux"))]
            if e == crate::linux_abi::LINUX_ENOBUFS && write_kind == HostWriteKind::SocketLike {
                return Ok(would_block_outcome(
                    host_fd,
                    libc::POLLOUT,
                    nonblocking,
                    host_fd_owner.clone(),
                    authority.clone().into_wait_authority(),
                ));
            }
            // EINTR: interrupted by an internal host signal (e.g. SIGURG vCPU kick).
            // Route through the readiness wait rather than leaking it to the guest
            // (see read_host_pipe).
            if e == LINUX_EAGAIN || e == LINUX_EINTR {
                if e == LINUX_EAGAIN
                    && nonblocking
                    && offset == 0
                    && write_kind != HostWriteKind::RegularFile
                    && let Some(result) = try_small_nonblocking_write(
                        host_fd,
                        payload.as_ptr(),
                        payload.len(),
                        socket_flow.as_ref(),
                        socket_cred,
                        is_stream,
                    )
                {
                    return match result {
                        Ok(written) => Ok(DispatchOutcome::returned_len_or_errno(written)),
                        Err(errno) => Ok(DispatchOutcome::Errno { errno }),
                    };
                }
                if block_until_complete && offset > 0 {
                    if host_signal
                        .has_unblocked_pending_for(tid.raw(), carrick_abi::SigBlockMask::NONE)
                    {
                        return Ok(DispatchOutcome::returned_len_or_errno(offset));
                    }
                    return match BlockingWrite::from_vec(
                        host_fd,
                        payload.into_owned(),
                        offset,
                        tid,
                        sigpipe_on_epipe,
                    ) {
                        Ok(write) => Ok(DispatchOutcome::BlockingWrite(write)),
                        Err(_) => Ok(DispatchOutcome::returned_len_or_errno(offset)),
                    };
                }
                return Ok(would_block_outcome(
                    host_fd,
                    libc::POLLOUT,
                    nonblocking,
                    host_fd_owner.clone(),
                    authority.clone().into_wait_authority(),
                ));
            }
            return Ok(DispatchOutcome::Errno { errno: e });
        }
        if block_until_complete {
            offset += n as usize;
            if offset < payload.len() {
                // A signal that arrives mid-write interrupts it on Linux,
                // returning the partial count; check between chunks so a long
                // write doesn't ignore an armed alarm (or a pending quiesce).
                if host_signal.has_unblocked_pending_for(tid.raw(), carrick_abi::SigBlockMask::NONE)
                    || crate::fork_quiesce::is_quiescing()
                {
                    if crate::fork_quiesce::is_quiescing() {
                        return match BlockingWrite::from_vec(
                            host_fd,
                            payload.into_owned(),
                            offset,
                            tid,
                            sigpipe_on_epipe,
                        ) {
                            Ok(write) => Ok(DispatchOutcome::BlockingWrite(write)),
                            Err(_) => Ok(DispatchOutcome::returned_len_or_errno(offset)),
                        };
                    }
                    return Ok(DispatchOutcome::returned_len_or_errno(offset));
                }
                continue;
            }
            return Ok(DispatchOutcome::returned_len_or_errno(payload.len()));
        }
        return Ok(DispatchOutcome::returned_isize_or_errno(n));
    }
}

#[cfg(test)]
mod host_wait_policy_tests {
    use super::*;

    #[test]
    fn regular_file_writes_stay_inline_while_waitable_streams_release_the_executor() {
        assert!(!write_requires_host_wait(HostWriteKind::RegularFile));
        assert!(write_requires_host_wait(HostWriteKind::PipeLike));
        assert!(write_requires_host_wait(HostWriteKind::SocketLike));
        assert!(write_requires_host_wait(HostWriteKind::Other));
    }
}

/// The zero-copy destination path through `read_host_pipe` must use raw
/// pointers, never a Rust slice over guest memory. `read_host_pipe_raw`
/// accepts `(*mut u8, usize)` — the old `read_host_pipe_direct(&mut [u8])`
/// signature would be a compile error here.
///
/// This test exercises the path: `host_ptr_for_write` → `HostWriteGuard` →
/// `read_host_pipe_raw` → `libc::read`, then verifies the data landed in
/// guest memory correctly and the budget stayed zero-allocation.
#[cfg(test)]
mod host_pipe_read_pin_tests {
    use super::*;
    use crate::dispatch::budget_meter;
    use crate::dispatch::outcome::LinearMemory;
    use carrick_guest_mem::{
        GuestMemory, GuestWriteRange, MemoryError, MemoryPrepareError, PreparedGuestWrite,
        UserMemoryVenue,
    };
    use std::sync::{Arc, Mutex};

    const MEM_BASE: u64 = 0x1000_0000;
    const MEM_LEN: usize = 0x10_0000; // 1 MiB

    struct OwnerMemory {
        bytes: Arc<Mutex<Vec<u8>>>,
        prepared_lengths: Arc<Mutex<Vec<usize>>>,
        fail_prepare: bool,
        wait_prepare: Option<carrick_el1_abi::PortalOwnerWait>,
    }

    struct OwnerPermit {
        bytes: Arc<Mutex<Vec<u8>>>,
        offset: usize,
        capacity: usize,
    }

    impl PreparedGuestWrite for OwnerPermit {
        fn commit(self: Box<Self>, outputs: &[&[u8]]) {
            assert_eq!(outputs.len(), 1);
            assert!(outputs[0].len() <= self.capacity);
            self.bytes.lock().unwrap()[self.offset..self.offset + outputs[0].len()]
                .copy_from_slice(outputs[0]);
        }
    }

    impl GuestMemory for OwnerMemory {
        fn user_memory_venue(&self) -> UserMemoryVenue {
            UserMemoryVenue::Owner
        }

        fn prepare_write(
            &mut self,
            ranges: &[GuestWriteRange],
        ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
            assert_eq!(ranges.len(), 1);
            let range = ranges[0];
            self.prepared_lengths.lock().unwrap().push(range.len());
            if let Some(wait) = self.wait_prepare.take() {
                return Err(MemoryPrepareError::OwnerWait(wait));
            }
            if self.fail_prepare {
                return Err(MemoryPrepareError::Fault(MemoryError::OutOfBounds {
                    address: range.address().raw(),
                    length: range.len(),
                }));
            }
            let offset = (range.address().raw() - MEM_BASE) as usize;
            Ok(Box::new(OwnerPermit {
                bytes: Arc::clone(&self.bytes),
                offset,
                capacity: range.len(),
            }))
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let offset = (address - MEM_BASE) as usize;
            Ok(self.bytes.lock().unwrap()[offset..offset + length].to_vec())
        }

        fn write_bytes_raw(&mut self, _address: u64, _bytes: &[u8]) -> Result<(), MemoryError> {
            panic!("owner read bypassed its prepared copyout permit")
        }
    }
    impl CurrentMmMemory for OwnerMemory {}

    #[test]
    fn owner_pipe_read_prepares_each_chunk_and_preserves_second_read() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload: Vec<u8> = (0..6000).map(|n| (n % 251) as u8).collect();
        assert_eq!(
            unsafe { libc::write(fds[1], payload.as_ptr().cast(), payload.len()) },
            6000
        );
        let lengths = Arc::new(Mutex::new(Vec::new()));
        let mut memory = OwnerMemory {
            bytes: Arc::new(Mutex::new(vec![0; MEM_LEN])),
            prepared_lengths: Arc::clone(&lengths),
            fail_prepare: false,
            wait_prepare: None,
        };
        let target = || {
            HostPipeReadTarget::new(
                fds[0],
                None,
                true,
                crate::dispatch::wait_authority::WaitFdAuthority::Empty,
            )
        };
        assert_eq!(
            read_host_pipe(&mut memory, MEM_BASE + 123, 5000, target()).unwrap(),
            DispatchOutcome::Returned { value: 5000 },
        );
        assert_eq!(
            read_host_pipe(&mut memory, MEM_BASE + 5123, 1000, target()).unwrap(),
            DispatchOutcome::Returned { value: 1000 },
        );
        assert_eq!(memory.read_bytes(MEM_BASE + 123, 6000).unwrap(), payload);
        assert!(lengths.lock().unwrap().iter().all(|&len| len <= 4096));
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn owner_prepare_fault_does_not_consume_pipe_bytes() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload = b"retained pipe payload";
        assert_eq!(
            unsafe { libc::write(fds[1], payload.as_ptr().cast(), payload.len()) },
            payload.len() as isize
        );
        let mut memory = OwnerMemory {
            bytes: Arc::new(Mutex::new(vec![0; MEM_LEN])),
            prepared_lengths: Arc::new(Mutex::new(Vec::new())),
            fail_prepare: true,
            wait_prepare: None,
        };
        let outcome = read_host_pipe(
            &mut memory,
            MEM_BASE,
            payload.len(),
            HostPipeReadTarget::new(
                fds[0],
                None,
                true,
                crate::dispatch::wait_authority::WaitFdAuthority::Empty,
            ),
        )
        .unwrap();
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
        let mut remaining = [0u8; 21];
        assert_eq!(
            unsafe { libc::read(fds[0], remaining.as_mut_ptr().cast(), remaining.len()) },
            payload.len() as isize
        );
        assert_eq!(&remaining, payload);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn owner_wait_suspends_pipe_read_before_consuming_bytes() {
        use carrick_el1_abi::{El1MmHandle, PortalOwnerWait, PortalWaitCause, ReservationMm};
        use std::num::NonZeroU64;

        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload = b"waited owner payload";
        assert_eq!(
            unsafe { libc::write(fds[1], payload.as_ptr().cast(), payload.len()) },
            payload.len() as isize
        );
        // SAFETY: this mock's revision models the exact admitted source
        // observed before its deliberately failed reservation probe.
        let wait = unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(1).unwrap(),
                    ReservationMm::new(2).unwrap(),
                    NonZeroU64::new(3).unwrap(),
                ),
                PortalWaitCause::Reservations,
                7,
            )
        };
        let mut memory = OwnerMemory {
            bytes: Arc::new(Mutex::new(vec![0; MEM_LEN])),
            prepared_lengths: Arc::new(Mutex::new(Vec::new())),
            fail_prepare: false,
            wait_prepare: Some(wait),
        };
        let outcome = read_host_pipe(
            &mut memory,
            MEM_BASE,
            payload.len(),
            HostPipeReadTarget::new(
                fds[0],
                None,
                true,
                crate::dispatch::wait_authority::WaitFdAuthority::Empty,
            ),
        )
        .unwrap();
        assert!(
            matches!(outcome, DispatchOutcome::OwnerMemoryWait { wait: actual } if actual == wait)
        );
        let mut remaining = [0u8; 20];
        assert_eq!(
            unsafe { libc::read(fds[0], remaining.as_mut_ptr().cast(), remaining.len()) },
            payload.len() as isize
        );
        assert_eq!(&remaining, payload);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// Verify that `read_host_pipe` takes the zero-copy raw-pointer path
    /// (not the staging-buffer path) when `host_ptr_for_write` succeeds,
    /// and that host data lands in guest memory without constructing a Rust
    /// slice over it.
    #[test]
    fn host_pipe_read_uses_raw_pointer_not_slice() {
        // Enforce the destination API independently of the wrapper: restoring
        // the old slice-taking helper must fail to compile this contract.
        let _raw_read: fn(
            *mut u8,
            usize,
            HostPipeReadTarget<'_>,
        )
            -> Result<DispatchOutcome, super::super::outcome::DispatchError> = read_host_pipe_raw;
        // Create a host pipe and pre-fill the write end with known data.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // Make the read end non-blocking so read_host_pipe won't park.
        unsafe { libc::fcntl(read_fd, libc::F_SETFL, libc::O_NONBLOCK) };

        let payload = vec![0xABu8; 128];
        let written = unsafe { libc::write(write_fd, payload.as_ptr() as *const _, payload.len()) };
        assert_eq!(written as usize, payload.len());

        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let guest_addr = MEM_BASE + 0x1000;
        let length = payload.len();

        // Confirm LinearMemory provides host_ptr_for_write (zero-copy path).
        assert!(
            memory.host_ptr_for_write(guest_addr, length).is_some(),
            "LinearMemory must provide a host pointer for the zero-copy path"
        );

        let target = HostPipeReadTarget::new(
            read_fd,
            None,
            true, // nonblocking
            crate::dispatch::wait_authority::WaitFdAuthority::Empty,
        );

        let (outcome, snapshot) = budget_meter::measure_no_allocations(|| {
            read_host_pipe(&mut memory, guest_addr, length, target)
                .expect("read_host_pipe should succeed")
        });

        // Verify the read returned the full payload length.
        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: length as i64
            },
            "read_host_pipe should return the payload length"
        );

        // Verify the data landed in guest memory correctly.
        let received = memory
            .read_bytes(guest_addr, length)
            .expect("guest memory read");
        assert_eq!(
            received, payload,
            "host data must land in guest memory through the raw-pointer path"
        );

        // The zero-copy path must not allocate.
        assert_eq!(
            snapshot.allocations, 0,
            "zero-copy read must not allocate: got {} ({} bytes)",
            snapshot.allocations, snapshot.allocated_bytes
        );

        // Exactly one host read.
        assert_eq!(snapshot.host_reads, 1, "expected exactly 1 host read");

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }
}

fn try_small_nonblocking_write(
    host_fd: i32,
    base: *const u8,
    total: usize,
    socket_flow: Option<&Arc<crate::kernel::UnixFlow>>,
    socket_cred: Option<crate::kernel::SocketPeerCred>,
    is_stream: bool,
) -> Option<Result<usize, LinuxErrno>> {
    if total <= 1 {
        return None;
    }
    const RETRIES: [usize; 6] = [16 * 1024, 4 * 1024, 1024, 256, 64, 1];
    for cap in RETRIES {
        let len = total.min(cap);
        if len == 0 || len == total {
            continue;
        }
        // BLOCKING-IO-OK: this path is reached only after a prior write to the
        // same fd returned EAGAIN (see the caller's `e == LINUX_EAGAIN &&
        // nonblocking` guard), so host_fd is non-blocking and libc::write cannot
        // block — the loop treats EAGAIN as "retry a smaller chunk".
        let n = if let (Some(flow), Some(cred)) = (socket_flow, socket_cred) {
            let mut ledger = flow.lock_ledger();
            let n = unsafe { libc::write(host_fd, base.cast(), len) };
            if n > 0 {
                if is_stream {
                    ledger.push_stream(n as usize, cred);
                } else {
                    ledger.push_dgram(n as usize, cred);
                }
            }
            drop(ledger);
            n
        } else {
            unsafe { libc::write(host_fd, base.cast(), len) }
        };
        match n.host_syscall_errno() {
            Ok(value) if value > 0 => return Some(Ok(value as usize)),
            Ok(_) => continue,
            Err(errno) if errno == LINUX_EAGAIN || errno == LINUX_EINTR => continue,
            Err(errno) => return Some(Err(errno)),
        }
    }
    None
}

/// A host op returned EAGAIN: a non-blocking guest fd gets EAGAIN; a blocking
/// one gets a WaitOnFds hand-off so the runtime waits on readiness with the
/// dispatcher lock RELEASED (per-thread kqueue), then re-dispatches.
pub(crate) fn would_block_outcome(
    host_fd: i32,
    events: i16,
    nonblocking: bool,
    host_fd_owner: Option<HostFdRef>,
    authority: WaitFdAuthority,
) -> DispatchOutcome {
    if nonblocking {
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        }
    } else {
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::anchored_one(host_fd, events, host_fd_owner).with_authority(authority),
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd {
                on_timeout: LINUX_EAGAIN.guest_retval(),
            },
        }
    }
}
