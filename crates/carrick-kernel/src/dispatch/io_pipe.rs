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
use carrick_vfs::errno::HostSyscallResult as _;

pub(crate) const MAX_RW_COUNT: usize = 0x7fff_f000;
const SMALL_HOST_READ_BUF: usize = 8192;

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
    pub authority: WaitFdAuthority,
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
        authority: WaitFdAuthority,
    ) -> Self {
        Self {
            host_fd,
            host_fd_owner,
            nonblocking,
            authority,
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
                authority,
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
    if length <= SMALL_HOST_READ_BUF {
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
    pub(crate) authority: WaitFdAuthority,
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
        authority: WaitFdAuthority,
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
            authority,
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
    fn as_slice(&self) -> &[u8] {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes,
            HostWritePayload::Owned(bytes) => bytes,
        }
    }

    fn into_owned(self) -> Vec<u8> {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes.to_vec(),
            HostWritePayload::Owned(bytes) => bytes,
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
    if crate::event_ring::payload_starts_at_ar_magic(payload.as_slice()) {
        let offset = fs::host_fd_offset(HostFd(host_fd)).map_or(-1, |offset| offset as u32 as i32);
        crate::event_ring::rec(
            crate::event_ring::ARMAGIC,
            host_fd,
            offset,
            payload.as_slice().len() as u32 as i32,
        );
        note_ar_magic_write(host_fd, payload.as_slice().len());
    }
    if crate::event_ring::payload_starts_at_ar_member_header(payload.as_slice()) {
        let offset = fs::host_fd_offset(HostFd(host_fd));
        crate::event_ring::rec(
            crate::event_ring::ARWRITE,
            host_fd,
            offset.map_or(-1, |offset| offset as u32 as i32),
            payload.as_slice().len() as u32 as i32,
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
                length = payload.as_slice().len(),
                ?prior_magic,
                "ar member header written at offset 0; the archive will lack its magic"
            );
        }
    }

    #[cfg(feature = "trace-io")]
    if !payload.as_slice().is_empty() {
        let bytes = payload.as_slice();
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
        if payload.as_slice().contains(&0x0a) {
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
                let blen = payload.as_slice().len();
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
            let bytes = payload.as_slice();
            let mut len = bytes.len() - offset;
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
                        authority.clone(),
                    ));
                }
                if nonblocking && offset == 0 && len <= 4096 && len > room {
                    return Ok(would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                        authority.clone(),
                    ));
                }
                len = len.min(room);
            }
            // BLOCKING-IO-OK: host_fd was adopted O_NONBLOCK; EAGAIN routes to
            // the lockless wait path below.
            let write_fn = || -> isize {
                if let (Some(flow), Some(cred)) = (&socket_flow, socket_cred) {
                    let mut ledger = flow.lock_ledger();
                    let n = unsafe {
                        match file_offset {
                            Some(off) => {
                                if is_append {
                                    let saved = libc::lseek(host_fd, 0, libc::SEEK_CUR);
                                    libc::lseek(host_fd, 0, libc::SEEK_END);
                                    let w = libc::write(
                                        host_fd,
                                        bytes[offset..].as_ptr() as *const _,
                                        len,
                                    );
                                    if saved >= 0 {
                                        libc::lseek(host_fd, saved, libc::SEEK_SET);
                                    }
                                    w
                                } else {
                                    libc::pwrite(
                                        host_fd,
                                        bytes[offset..].as_ptr() as *const _,
                                        len,
                                        (off + offset as i64) as libc::off_t,
                                    )
                                }
                            }
                            None => libc::write(host_fd, bytes[offset..].as_ptr() as *const _, len),
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
                                    let w = libc::write(
                                        host_fd,
                                        bytes[offset..].as_ptr() as *const _,
                                        len,
                                    );
                                    if saved >= 0 {
                                        libc::lseek(host_fd, saved, libc::SEEK_SET);
                                    }
                                    w
                                } else {
                                    libc::pwrite(
                                        host_fd,
                                        bytes[offset..].as_ptr() as *const _,
                                        len,
                                        (off + offset as i64) as libc::off_t,
                                    )
                                }
                            }
                            None => libc::write(host_fd, bytes[offset..].as_ptr() as *const _, len),
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
        if payload.as_slice().contains(&0x0a) {
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
                    authority.clone(),
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
                        payload.as_slice(),
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
                    authority.clone(),
                ));
            }
            return Ok(DispatchOutcome::Errno { errno: e });
        }
        if block_until_complete {
            offset += n as usize;
            if offset < payload.as_slice().len() {
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
            return Ok(DispatchOutcome::returned_len_or_errno(
                payload.as_slice().len(),
            ));
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

fn try_small_nonblocking_write(
    host_fd: i32,
    bytes: &[u8],
    socket_flow: Option<&Arc<crate::kernel::UnixFlow>>,
    socket_cred: Option<crate::kernel::SocketPeerCred>,
    is_stream: bool,
) -> Option<Result<usize, LinuxErrno>> {
    if bytes.len() <= 1 {
        return None;
    }
    const RETRIES: [usize; 6] = [16 * 1024, 4 * 1024, 1024, 256, 64, 1];
    for cap in RETRIES {
        let len = bytes.len().min(cap);
        if len == 0 || len == bytes.len() {
            continue;
        }
        // BLOCKING-IO-OK: this path is reached only after a prior write to the
        // same fd returned EAGAIN (see the caller's `e == LINUX_EAGAIN &&
        // nonblocking` guard), so host_fd is non-blocking and libc::write cannot
        // block — the loop treats EAGAIN as "retry a smaller chunk".
        let n = if let (Some(flow), Some(cred)) = (socket_flow, socket_cred) {
            let mut ledger = flow.lock_ledger();
            let n = unsafe { libc::write(host_fd, bytes.as_ptr().cast(), len) };
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
            unsafe { libc::write(host_fd, bytes.as_ptr().cast(), len) }
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
