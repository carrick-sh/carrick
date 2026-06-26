//! POSIX message queues (`mq_open`/`mq_unlink`/`mq_timedsend`/
//! `mq_timedreceive`/`mq_notify`/`mq_getsetattr`) on top of host files under
//! `/tmp/carrick-mqueue/`.
//!
//! macOS has NO POSIX message-queue API, so carrick emulates it. The design
//! mirrors the SysV shared-memory subsystem in [`super::sysv`]: each named queue
//! `/name` is a real host FILE, so a forked guest child (a separate carrick host
//! process) and its parent resolve the same `/name` to the same inode and see
//! the same queue — an in-process `HashMap` would NOT be fork-coherent and would
//! silently diverge.
//!
//! # File layout (carrick-private, little-endian — NOT a Linux ABI)
//!
//! A fixed header (`magic`, `mq_maxmsg`, `mq_msgsize`, `curmsgs`, an
//! insertion sequence counter, and a one-shot `mq_notify` registration) followed
//! by a fixed ring of `mq_maxmsg` slots. Each slot is a [`SLOT_HEADER`]
//! (`used`, `prio`, `len`, `seq`) followed by exactly `mq_msgsize` payload bytes.
//! `ftruncate` sizes the file to `HEADER_SIZE + maxmsg * slot_stride` at create.
//!
//! Send appends to a free slot stamped with the next sequence number; receive
//! picks the highest-priority slot, breaking ties by the lowest sequence number
//! (FIFO within a priority — mq_overview(7)). The `seq` field is a carrick
//! addition to the layout the task sketched (`used`/`prio`/`len`/payload) so the
//! FIFO-within-priority ordering POSIX requires is exact rather than
//! slot-index-dependent.
//!
//! # Mutual exclusion
//!
//! Every read-modify-write of the file is guarded by an `F_OFD_SETLKW` lock on a
//! FRESH host fd opened against the path for that operation. OFD locks belong to
//! the open file description; a `libc::fork`-shared description's lock would be
//! self-re-entrant (no serialization between parent and child), so each
//! operation opens its own fd. macOS has OFD locks natively
//! (`F_OFD_SETLK`/`SETLKW`/`GETLK` = 90/91/92), the same primitive
//! `forward_record_lock` (in `super::fs`) forwards for guest `fcntl`.
//!
//! # What is and isn't implemented
//!
//!   - `mq_open` O_CREAT/O_EXCL, default `mq_maxmsg=10`/`mq_msgsize=8192`
//!     (matching the `/proc/sys/fs/mqueue` values carrick advertises).
//!   - `mq_timedsend`/`mq_timedreceive` with `EMSGSIZE`/`EAGAIN`/`ETIMEDOUT`,
//!     priority ordering, and an absolute `CLOCK_REALTIME` timeout (a poll loop,
//!     like `sysv_semop`'s timed wait).
//!   - `mq_getsetattr` (report `mq_attr`; set only `O_NONBLOCK`).
//!   - `mq_notify` SIGEV_SIGNAL/SIGEV_NONE one-shot registration fired on the
//!     empty→non-empty transition in `mq_timedsend`. SIGEV_THREAD is glibc
//!     layered on SIGEV_SIGNAL, so the kernel surface here is enough. The
//!     registration is recorded in the file header (fork-coherent), and cross-
//!     process delivery uses `libc::kill` with the host signal number.

use super::*;
use std::path::PathBuf;

syscall_table! {
    /// Per-module syscall routing for the POSIX message-queue subsystem.
    /// `resolve_handler` in `dispatch/mod.rs` chains this with the other
    /// modules' tables. (x86_64 maps 240–245 → 180–185 at the GuestArch seam.)
    pub(crate) fn dispatch_mqueue;
    180 => mq_open,
    181 => mq_unlink,
    182 => mq_timedsend,
    183 => mq_timedreceive,
    184 => mq_notify,
    185 => mq_getsetattr,
}

/// Host directory for POSIX message-queue backing files. World-writable +
/// sticky so any carrick guest process (including a forked child running as the
/// same uid) can open a queue a peer created.
const MQ_DIR: &str = "/tmp/carrick-mqueue";

/// File magic identifying a carrick mqueue backing file.
const MQ_MAGIC: u32 = 0x4d51_524b; // "MQRK"

/// Defaults from mq_overview(7) / the `/proc/sys/fs/mqueue` values carrick
/// advertises in `vfs/proc.rs`.
const DEFAULT_MAXMSG: u32 = 10;
const DEFAULT_MSGSIZE: u32 = 8192;

/// Upper bounds (queues_max-adjacent guard rails). A guest `mq_open` with an
/// `attr` exceeding these gets EINVAL, like Linux with no privilege.
const MAX_MAXMSG: u32 = 65_536;
const MAX_MSGSIZE: u32 = 16 * 1024 * 1024;

/// `NAME_MAX` for the queue name (mq_overview(7): a name is `/` + up to
/// `NAME_MAX` (255) further chars).
const NAME_MAX: usize = 255;

// Header byte offsets (little-endian).
const OFF_MAGIC: usize = 0;
const OFF_MAXMSG: usize = 4;
const OFF_MSGSIZE: usize = 8;
const OFF_CURMSGS: usize = 12;
const OFF_NEXT_SEQ: usize = 16;
const OFF_NOTIFY_PID: usize = 20;
const OFF_SIGEV_NOTIFY: usize = 24;
const OFF_SIGEV_SIGNO: usize = 28;
/// Guest euid of the queue's creator, stamped at create time so `mq_unlink` can
/// enforce the same owner check Linux applies to removing the name from the
/// (sticky) mqueue filesystem — a non-root, non-owner unlink is EACCES
/// (mq_unlink01 entry 1, `as_nobody`).
const OFF_OWNER_UID: usize = 32;
const HEADER_SIZE: usize = 40;

// Per-slot header byte offsets (relative to the slot start).
const SLOT_USED: usize = 0;
const SLOT_PRIO: usize = 4;
const SLOT_LEN: usize = 8;
const SLOT_SEQ: usize = 12;
const SLOT_HEADER: usize = 16;

/// Read a little-endian u32 from `buf` at `off` (0 if out of range).
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    match buf.get(off..off + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

/// Write a little-endian u32 into `buf` at `off` (no-op if out of range).
fn wr_u32(buf: &mut [u8], off: usize, v: u32) {
    if let Some(b) = buf.get_mut(off..off + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

/// Per-slot stride in the backing file for the given message size.
fn slot_stride(msg_size: usize) -> usize {
    SLOT_HEADER.saturating_add(msg_size)
}

/// Total backing-file size for `maxmsg` slots of `msg_size`.
fn file_size(maxmsg: usize, msg_size: usize) -> usize {
    HEADER_SIZE.saturating_add(maxmsg.saturating_mul(slot_stride(msg_size)))
}

/// Ensure `/tmp/carrick-mqueue/` exists with 0o1777 (sticky + world-write), so
/// forked siblings can share queues. Best-effort, like `SysvShmState::ensure_dir`.
fn ensure_dir() {
    let _ = std::fs::create_dir_all(MQ_DIR);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(MQ_DIR, std::fs::Permissions::from_mode(0o1777));
}

/// Validate a guest mqueue name and map it to a backing-file path. The name must
/// start with `/`, contain no other `/`, be non-empty after the slash, and be at
/// most `NAME_MAX` chars (mq_overview(7)). Returns `Err(errno)` otherwise.
fn name_to_path(name: &str) -> Result<PathBuf, i32> {
    // The mq_open(2) SYSCALL receives the queue name with the leading '/' already
    // stripped by the C library (glibc/musl validate the leading slash in the
    // mq_open(3) wrapper, then pass name+1 to the syscall — the kernel keys the
    // mqueue fs on the bare entry name). A raw syscall may still include the '/'.
    // Accept an optional single leading '/', then require one non-empty component
    // with no embedded '/'.
    let rest = name.strip_prefix('/').unwrap_or(name);
    if rest.is_empty() || rest.contains('/') {
        return Err(LINUX_EINVAL);
    }
    if rest.len() > NAME_MAX {
        return Err(crate::linux_abi::LINUX_ENAMETOOLONG);
    }
    Ok(PathBuf::from(MQ_DIR).join(rest))
}

/// An OFD write lock held on a freshly-opened host fd for the duration of one
/// read-modify-write of a backing file. Dropping it releases the lock and closes
/// the fd, so every RMW is serialized across processes and across `libc::fork`.
struct MqLock {
    fd: i32,
}

impl MqLock {
    /// Open `path` O_RDWR and take an `F_OFD_SETLKW` write lock over the whole
    /// file (l_start=0, l_len=0 means "to EOF and beyond"). Blocks until granted.
    fn acquire(path: &str) -> Result<Self, i32> {
        let cpath = std::ffi::CString::new(path.as_bytes()).map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) }.host_syscall_errno()?;
        let mut fl: libc::flock = unsafe { core::mem::zeroed() };
        // `flock.l_type`/`l_whence` are c_short (i16); the libc F_*LCK / SEEK_*
        // constants are i16 on Darwin but i32 on Linux, so narrow to the field
        // width (a no-op cast on Darwin — same reason fs::forward_record_lock
        // allows it).
        #[allow(clippy::unnecessary_cast)]
        {
            fl.l_type = libc::F_WRLCK as i16;
            fl.l_whence = libc::SEEK_SET as i16;
        }
        fl.l_start = 0;
        fl.l_len = 0;
        // BLOCKING-IO-OK: the OFD lock wait is bounded by peer RMWs (each is a
        // header+slot memcpy, microseconds), not by guest I/O.
        let rc = unsafe { libc::fcntl(fd, libc::F_OFD_SETLKW, &mut fl as *mut libc::flock) };
        if let Err(errno) = rc.host_syscall_errno() {
            unsafe { libc::close(fd) };
            return Err(errno);
        }
        Ok(Self { fd })
    }

    /// pread the whole backing file under the lock.
    fn read_all(&self, size: usize) -> Result<Vec<u8>, i32> {
        let mut buf = vec![0u8; size];
        let mut done = 0usize;
        while done < size {
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf[done..].as_mut_ptr() as *mut libc::c_void,
                    size - done,
                    done as libc::off_t,
                )
            };
            let n = n.host_syscall_errno()?;
            if n == 0 {
                break; // short file (a peer truncated): treat the tail as zeros.
            }
            done += n as usize;
        }
        Ok(buf)
    }

    /// pwrite a range back into the backing file under the lock.
    fn write_at(&self, off: usize, bytes: &[u8]) -> Result<(), i32> {
        let mut done = 0usize;
        while done < bytes.len() {
            let n = unsafe {
                libc::pwrite(
                    self.fd,
                    bytes[done..].as_ptr() as *const libc::c_void,
                    bytes.len() - done,
                    (off + done) as libc::off_t,
                )
            };
            let n = n.host_syscall_errno()?;
            if n == 0 {
                return Err(crate::linux_abi::LINUX_EIO);
            }
            done += n as usize;
        }
        Ok(())
    }
}

impl Drop for MqLock {
    fn drop(&mut self) {
        // Releasing the fd's OFD lock is implicit on close.
        unsafe { libc::close(self.fd) };
    }
}

/// Readiness for poll(2)/select(2): `(readable, writable)`. Reads the backing
/// file's header under the OFD lock. On any error the queue reports
/// "writable, not readable" (a closed/odd queue should not wedge a poll loop).
pub(super) fn poll_readiness(_host_fd: i32, _max_msg: usize) -> (bool, bool) {
    // The persistent description fd can't be locked self-coherently after fork,
    // and poll has no path handy here, so derive readiness from the persistent
    // fd's CURRENT contents via a positional read of the header (no lock — a
    // torn count only mis-times a wakeup, which the next poll corrects).
    let mut hdr = [0u8; HEADER_SIZE];
    let n = unsafe {
        libc::pread(
            _host_fd,
            hdr.as_mut_ptr() as *mut libc::c_void,
            HEADER_SIZE,
            0,
        )
    };
    if n < HEADER_SIZE as isize {
        return (false, true);
    }
    let curmsgs = rd_u32(&hdr, OFF_CURMSGS);
    let maxmsg = rd_u32(&hdr, OFF_MAXMSG);
    (curmsgs > 0, curmsgs < maxmsg)
}

/// The mqueue fd state pulled out of the fd table for a syscall.
struct MqFd {
    host_fd: i32,
    path: String,
    msg_size: usize,
    max_msg: usize,
    /// O_RDONLY/O_WRONLY/O_RDWR (the access-mode bits of the description).
    access: u64,
    nonblock: bool,
}

impl SyscallDispatcher {
    /// Pull the Mqueue description for `fd`, or `Err(EBADF)` if `fd` is not an
    /// open message-queue descriptor.
    fn mq_fd(&self, fd: i32) -> Result<MqFd, i32> {
        let open_file = self.open_file(fd).ok_or(LINUX_EBADF)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::Mqueue {
                base,
                host_fd,
                path,
                msg_size,
                max_msg,
            } => {
                let flags = base.status_flags();
                Ok(MqFd {
                    host_fd: *host_fd,
                    path: path.clone(),
                    msg_size: *msg_size,
                    max_msg: *max_msg,
                    access: flags & LINUX_O_ACCMODE,
                    nonblock: flags & LINUX_O_NONBLOCK != 0,
                })
            }
            _ => Err(LINUX_EBADF),
        }
    }

    define_syscall! {
        /// mq_open(name, oflag, mode, attr). Opens (and optionally creates) a
        /// message queue and returns a `mqd_t` (a real guest fd). O_CREAT/O_EXCL
        /// follow `open(2)` semantics (exists+EXCL+CREAT → EEXIST; !exists+!CREAT
        /// → ENOENT). The optional `attr` (NULL → defaults) sets `mq_maxmsg`/
        /// `mq_msgsize` only at creation.
        fn mq_open(this, cx, name: GuestPtr, oflag: u64, mode: u64, attr: GuestPtr) {
            let _ = mode;
            let name = match read_guest_c_string(&*cx.memory, name.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let path = match name_to_path(&name) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let path_str = path.to_string_lossy().into_owned();

            let access = oflag & LINUX_O_ACCMODE;
            if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let create = oflag & LINUX_O_CREAT != 0;
            let exclusive = oflag & LINUX_O_EXCL != 0;

            ensure_dir();
            let exists = path.exists();
            if exists && create && exclusive {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EEXIST));
            }
            if !exists && !create {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }

            // Resolve maxmsg/msgsize: from `attr` when creating with a non-NULL
            // attr, else the defaults. (On an existing queue the stored values
            // win; they're re-read from the header below.)
            let (mut maxmsg, mut msgsize) = (DEFAULT_MAXMSG, DEFAULT_MSGSIZE);
            if !exists && attr.0 != 0 {
                let mq_attr: crate::linux_abi::LinuxMqAttr =
                    match read_kernel_struct(&*cx.memory, attr.0) {
                        Ok(a) => a,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                let req_max = mq_attr.mq_maxmsg;
                let req_size = mq_attr.mq_msgsize;
                if req_max <= 0 || req_size <= 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if req_max as u64 > MAX_MAXMSG as u64 || req_size as u64 > MAX_MSGSIZE as u64 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                maxmsg = req_max as u32;
                msgsize = req_size as u32;
            }

            // Open (or create) the backing file. O_RDWR | O_CREAT regardless of
            // the guest access mode — the backing store is read+write; the guest
            // access mode is enforced in mq_timedsend/receive.
            let cpath = match std::ffi::CString::new(path_str.as_bytes()) {
                Ok(c) => c,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            let host_fd =
                match unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) }
                    .host_syscall_errno()
                {
                    Ok(fd) => fd,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };

            if !exists {
                // Fresh queue: size the file and write the header. Initialize
                // curmsgs/next_seq/notify to zero (ftruncate already zeroed).
                let total = file_size(maxmsg as usize, msgsize as usize);
                if let Err(errno) =
                    unsafe { libc::ftruncate(host_fd, total as libc::off_t) }.host_syscall_errno()
                {
                    unsafe { libc::close(host_fd) };
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mut hdr = [0u8; HEADER_SIZE];
                wr_u32(&mut hdr, OFF_MAGIC, MQ_MAGIC);
                wr_u32(&mut hdr, OFF_MAXMSG, maxmsg);
                wr_u32(&mut hdr, OFF_MSGSIZE, msgsize);
                // Stamp the creator's guest euid (fork-coherent in the file) so
                // mq_unlink can enforce the owner check Linux applies.
                wr_u32(&mut hdr, OFF_OWNER_UID, this.cred_snapshot().euid);
                let written = unsafe {
                    libc::pwrite(
                        host_fd,
                        hdr.as_ptr() as *const libc::c_void,
                        HEADER_SIZE,
                        0,
                    )
                };
                if let Err(errno) = written.host_syscall_errno() {
                    unsafe { libc::close(host_fd) };
                    return Ok(DispatchOutcome::errno(errno));
                }
            } else {
                // Existing queue: read maxmsg/msgsize back from the header so the
                // description reflects the queue's real geometry.
                let mut hdr = [0u8; HEADER_SIZE];
                let n = unsafe {
                    libc::pread(host_fd, hdr.as_mut_ptr() as *mut libc::c_void, HEADER_SIZE, 0)
                };
                if n == HEADER_SIZE as isize && rd_u32(&hdr, OFF_MAGIC) == MQ_MAGIC {
                    maxmsg = rd_u32(&hdr, OFF_MAXMSG);
                    msgsize = rd_u32(&hdr, OFF_MSGSIZE);
                }
            }

            // Install the mqd as a real fd. status_flags carries the access mode
            // and O_NONBLOCK; the fd-flags carry O_CLOEXEC. The host fd is owned
            // by the OpenFile so close(2)/dup(2) reclaim it.
            let status_flags = access | (oflag & LINUX_O_NONBLOCK);
            let description = OpenDescription::Mqueue {
                base: OpenDescriptionBase::new(status_flags),
                host_fd,
                path: path_str,
                msg_size: msgsize as usize,
                max_msg: maxmsg as usize,
            };
            let open_file = OpenFile::with_host_fd(
                std::sync::Arc::new(parking_lot::RwLock::new(description)),
                linux_fd_flags_from_open_flags(oflag),
                host_fd,
            );
            match this.install_fd_at_or_above(0, open_file) {
                Ok(fd) => Ok(DispatchOutcome::Returned { value: fd as i64 }),
                Err(_) => Ok(DispatchOutcome::errno(crate::dispatch::linux_errno::EMFILE)),
            }
        }

        /// mq_unlink(name). Remove the queue's name; the backing file is
        /// unlinked. Existing open descriptors keep working (Linux semantics:
        /// the queue persists until the last close).
        ///
        /// Removing the name is a directory operation on the (sticky)
        /// `/dev/mqueue` filesystem, so Linux requires the caller to own the
        /// queue (or be root): a non-root euid that did not create the queue
        /// gets EACCES (mq_unlink01 entry 1, `as_nobody`). carrick stores the
        /// creator's guest euid in the backing-file header and enforces the same
        /// check against the calling guest's euid here.
        fn mq_unlink(this, cx, name: GuestPtr) {
            let name = match read_guest_c_string(&*cx.memory, name.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let path = match name_to_path(&name) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let path_str = path.to_string_lossy().into_owned();
            let cpath = match std::ffi::CString::new(path_str.as_bytes()) {
                Ok(c) => c,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };

            // Owner check: a non-root guest may only unlink a queue it created.
            // Read the stored creator euid from the header; root (euid 0)
            // bypasses, matching the kernel's CAP_FOWNER / dir-owner allowances.
            let euid = this.cred_snapshot().euid;
            if euid != 0 {
                if let Some(owner) = read_queue_owner(&path_str) {
                    if owner != euid {
                        return Ok(DispatchOutcome::errno(LINUX_EACCES));
                    }
                }
            }

            match unsafe { libc::unlink(cpath.as_ptr()) }.host_syscall_errno() {
                Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// mq_timedsend(mqd, msg_ptr, msg_len, prio, abs_timeout). Enqueue a
        /// message. EBADF if the queue was opened O_RDONLY; EMSGSIZE if
        /// `msg_len > mq_msgsize`. Under the file lock: if the queue has room,
        /// write a slot and (if the queue was empty and a notify registration
        /// exists) fire the registration once. Otherwise O_NONBLOCK → EAGAIN, a
        /// blocking send polls until the absolute CLOCK_REALTIME deadline and
        /// returns ETIMEDOUT on expiry.
        fn mq_timedsend(this, cx, mqd: u64, msg_ptr: GuestPtr, msg_len: u64, prio: u64, abs_timeout: GuestPtr) {
            let mq = match this.mq_fd(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if mq.access == LINUX_O_RDONLY {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let len = msg_len as usize;
            if len > mq.msg_size {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            // mq priorities are 0..=MQ_PRIO_MAX-1 (32768). Above that → EINVAL.
            if prio >= 32768 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payload = match cx.memory.read_bytes(msg_ptr.0, len) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };

            let deadline = match read_abs_deadline(&*cx.memory, abs_timeout.0) {
                Ok(d) => d,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            // The current guest thread, so the blocking poll can return EINTR
            // when a deliverable signal arrives (mq_timedsend01 entry 14).
            let tid = cx.tid();
            loop {
                match mq_try_send(&mq, prio as u32, &payload) {
                    Ok(true) => return Ok(DispatchOutcome::Returned { value: 0 }),
                    Ok(false) => {
                        // Full.
                        if mq.nonblock {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        if deadline_expired(deadline) {
                            return Ok(DispatchOutcome::errno(LINUX_ETIMEDOUT));
                        }
                        // A deliverable signal interrupts the block (carrick does
                        // not auto-restart). It wins over the deadline.
                        if mq_wait_interrupted(this, tid) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
        }

        /// mq_timedreceive(mqd, buf_ptr, buf_len, prio_ptr, abs_timeout).
        /// Dequeue the highest-priority (FIFO-within-priority) message. EBADF if
        /// the queue was opened O_WRONLY; EMSGSIZE if `buf_len < mq_msgsize`.
        /// Empty + O_NONBLOCK → EAGAIN; empty + blocking → poll until the
        /// absolute deadline → ETIMEDOUT. On success writes the payload and the
        /// message priority to `*prio_ptr`, and returns the byte count.
        fn mq_timedreceive(this, cx, mqd: u64, buf_ptr: GuestPtr, buf_len: u64, prio_ptr: GuestPtr, abs_timeout: GuestPtr) {
            let mq = match this.mq_fd(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if mq.access == LINUX_O_WRONLY {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // The receive buffer must be at least mq_msgsize (Linux EMSGSIZE).
            if (buf_len as usize) < mq.msg_size {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            let deadline = match read_abs_deadline(&*cx.memory, abs_timeout.0) {
                Ok(d) => d,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            // The current guest thread, captured before the loop (it is `Copy`)
            // so the later `cx.memory` mutable use in the success arm does not
            // conflict with the immutable `cx.tid()` borrow. Lets the blocking
            // poll return EINTR on a deliverable signal (mq_timedreceive01 entry
            // 14).
            let tid = cx.tid();
            loop {
                match mq_try_receive(&mq) {
                    Ok(Some((prio, payload))) => {
                        if prio_ptr.0 != 0
                            && cx
                                .memory
                                .write_bytes(prio_ptr.0, &prio.to_le_bytes())
                                .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let n = payload.len();
                        if !payload.is_empty()
                            && cx.memory.write_bytes(buf_ptr.0, &payload).is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::Returned { value: n as i64 });
                    }
                    Ok(None) => {
                        // Empty.
                        if mq.nonblock {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        if deadline_expired(deadline) {
                            return Ok(DispatchOutcome::errno(LINUX_ETIMEDOUT));
                        }
                        // A deliverable signal interrupts the block (carrick does
                        // not auto-restart). It wins over the deadline.
                        if mq_wait_interrupted(this, tid) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
        }

        /// mq_notify(mqd, sevp). Register (NULL → unregister) a one-shot
        /// notification for the empty→non-empty transition. SIGEV_NONE records
        /// "no signal"; SIGEV_SIGNAL records (this pid, signo). EBUSY if a
        /// DIFFERENT pid is already registered. Delivery happens in
        /// mq_timedsend.
        fn mq_notify(this, cx, mqd: u64, sevp: GuestPtr) {
            let me = std::process::id() as i32;

            if sevp.0 == 0 {
                // Clear THIS pid's registration (and only this pid's). The
                // unregister path has no sigevent to validate, so it needs the
                // descriptor up front.
                let mq = match this.mq_fd(mqd as i32) {
                    Ok(v) => v,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(match mq_clear_notify(&mq, me) {
                    Ok(()) => DispatchOutcome::Returned { value: 0 },
                    Err(errno) => DispatchOutcome::errno(errno),
                });
            }

            // Validate the sigevent BEFORE resolving the descriptor: Linux reports
            // a bad sigev_notify as EINVAL even when the descriptor is itself
            // invalid (LTP mq_notify02: mq_notify(0, &bad_sevp) is EINVAL, not the
            // EBADF that the descriptor lookup would otherwise produce first).
            let sev: crate::linux_abi::LinuxSigevent =
                match read_kernel_struct(&*cx.memory, sevp.0) {
                    Ok(s) => s,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
            let signo = match sev.sigev_notify {
                crate::linux_abi::LINUX_SIGEV_NONE => 0,
                // SIGEV_THREAD is glibc layered on SIGEV_SIGNAL; the kernel
                // surface is the signal, so treat it like SIGEV_SIGNAL.
                crate::linux_abi::LINUX_SIGEV_SIGNAL | crate::linux_abi::LINUX_SIGEV_THREAD => {
                    // Copy out of the #[repr(packed)] sigevent before taking a ref.
                    // SIGEV_SIGNAL requires a valid signal number; an out-of-range
                    // signo is EINVAL (LTP mq_notify02's second bad-sevp case).
                    let s = sev.sigev_signo;
                    if !(1..=64).contains(&s) {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    s
                }
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            let mq = match this.mq_fd(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            Ok(match mq_register_notify(&mq, me, sev.sigev_notify, signo) {
                Ok(()) => DispatchOutcome::Returned { value: 0 },
                Err(errno) => DispatchOutcome::errno(errno),
            })
        }

        /// mq_getsetattr(mqd, newattr, oldattr). If `oldattr` is non-NULL, write
        /// the current `mq_attr` (mq_flags=(O_NONBLOCK?), mq_maxmsg, mq_msgsize,
        /// mq_curmsgs). If `newattr` is non-NULL, only `mq_flags`'s O_NONBLOCK is
        /// settable on the description.
        fn mq_getsetattr(this, cx, mqd: u64, newattr: GuestPtr, oldattr: GuestPtr) {
            let mq = match this.mq_fd(mqd as i32) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };

            // Read the live curmsgs from the header (a positional read is fine —
            // a torn count only mis-reports by one transiently).
            let mut hdr = [0u8; HEADER_SIZE];
            let n = unsafe {
                libc::pread(mq.host_fd, hdr.as_mut_ptr() as *mut libc::c_void, HEADER_SIZE, 0)
            };
            let curmsgs = if n == HEADER_SIZE as isize {
                rd_u32(&hdr, OFF_CURMSGS) as i64
            } else {
                0
            };

            if oldattr.0 != 0 {
                let out = crate::linux_abi::LinuxMqAttr {
                    mq_flags: if mq.nonblock { LINUX_O_NONBLOCK as i64 } else { 0 },
                    mq_maxmsg: mq.max_msg as i64,
                    mq_msgsize: mq.msg_size as i64,
                    mq_curmsgs: curmsgs,
                    __reserved: [0; 4],
                };
                if cx
                    .memory
                    .write_bytes(oldattr.0, zerocopy::IntoBytes::as_bytes(&out))
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }

            if newattr.0 != 0 {
                let new_attr: crate::linux_abi::LinuxMqAttr =
                    match read_kernel_struct(&*cx.memory, newattr.0) {
                        Ok(a) => a,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                let want_nonblock = new_attr.mq_flags & LINUX_O_NONBLOCK as i64 != 0;
                if let Some(open_file) = this.open_file(mqd as i32) {
                    let mut open = open_file.description.write();
                    let cur = open.status_flags();
                    let next = if want_nonblock {
                        cur | LINUX_O_NONBLOCK
                    } else {
                        cur & !LINUX_O_NONBLOCK
                    };
                    open.set_status_flags(next);
                }
            }

            Ok(DispatchOutcome::Returned { value: 0 })
        }
    }
}

/// Read the creator's guest euid stamped in a queue's backing-file header.
/// Returns `None` if the queue does not exist, is unreadable, or predates the
/// owner field (a torn/legacy file): callers treat "owner unknown" as "no extra
/// restriction" and fall back to the host `unlink` result. The owner is
/// immutable after create, so a lock-free positional header read is sufficient.
fn read_queue_owner(path: &str) -> Option<u32> {
    let cpath = std::ffi::CString::new(path.as_bytes()).ok()?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut hdr = [0u8; HEADER_SIZE];
    let n = unsafe { libc::pread(fd, hdr.as_mut_ptr() as *mut libc::c_void, HEADER_SIZE, 0) };
    unsafe { libc::close(fd) };
    if n != HEADER_SIZE as isize || rd_u32(&hdr, OFF_MAGIC) != MQ_MAGIC {
        return None;
    }
    Some(rd_u32(&hdr, OFF_OWNER_UID))
}

/// Does a deliverable signal want to interrupt a blocking mq op? Checks all
/// three pending stores: the dispatcher's injected set, the HVF cross-process
/// xsignal ring (where a `kill` from another guest process lands), and
/// signal-core's process/thread pending (the KVM cross-process path). carrick
/// does not auto-restart, so a deliverable pending signal -> EINTR.
fn mq_wait_interrupted(this: &SyscallDispatcher, tid: crate::thread::ThreadId) -> bool {
    this.has_deliverable_dispatch_pending_for_wait(tid, 0, false)
        || carrick_signal_core::xsig::xsig_has_unblocked_for_self(0)
        || carrick_signal_core::has_pending_for(tid)
}

/// Parse an absolute-timeout `struct timespec` pointer for a timed mq op. NULL
/// means "block forever" (`None`). Linux validates the WHOLE timespec before
/// blocking: `tv_sec` must be >= 0 and `tv_nsec` in `[0, 1e9)` — any of a
/// negative `tv_sec`, a negative `tv_nsec`, or an out-of-range `tv_nsec` is
/// EINVAL (mq_timedsend01/mq_timedreceive01 entries 10/11/12). Returns the
/// deadline as a wall-clock `(secs, nsecs)`, or `None` for "no timeout".
fn read_abs_deadline(memory: &impl GuestMemory, addr: u64) -> Result<Option<(i64, i64)>, i32> {
    if addr == 0 {
        return Ok(None);
    }
    let ts = read_timespec(memory, addr)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LINUX_EINVAL);
    }
    Ok(Some((ts.tv_sec, ts.tv_nsec)))
}

/// Has the absolute CLOCK_REALTIME `deadline` passed? `None` never expires.
fn deadline_expired(deadline: Option<(i64, i64)>) -> bool {
    let Some((sec, nsec)) = deadline else {
        return false;
    };
    let mut now: libc::timespec = unsafe { core::mem::zeroed() };
    // SAFETY: clock_gettime writes a timespec for a valid clock id.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let now_sec = now.tv_sec as i64;
    let now_nsec = now.tv_nsec as i64;
    (now_sec, now_nsec) >= (sec, nsec)
}

/// Try to enqueue one message. Returns `Ok(true)` if enqueued, `Ok(false)` if
/// the queue is full, `Err(errno)` on a host/file error. Fires a one-shot
/// `mq_notify` registration on the empty→non-empty transition.
fn mq_try_send(mq: &MqFd, prio: u32, payload: &[u8]) -> Result<bool, i32> {
    let lock = MqLock::acquire(&mq.path)?;
    let size = file_size(mq.max_msg, mq.msg_size);
    let mut buf = lock.read_all(size)?;
    if rd_u32(&buf, OFF_MAGIC) != MQ_MAGIC {
        return Err(LINUX_EINVAL);
    }
    let maxmsg = rd_u32(&buf, OFF_MAXMSG) as usize;
    let msgsize = rd_u32(&buf, OFF_MSGSIZE) as usize;
    let curmsgs = rd_u32(&buf, OFF_CURMSGS) as usize;
    if curmsgs >= maxmsg {
        return Ok(false);
    }
    let was_empty = curmsgs == 0;
    let stride = slot_stride(msgsize);

    // Find the first free slot.
    let mut free_idx = None;
    for i in 0..maxmsg {
        let base = HEADER_SIZE + i * stride;
        if rd_u32(&buf, base + SLOT_USED) == 0 {
            free_idx = Some(i);
            break;
        }
    }
    let Some(idx) = free_idx else {
        // curmsgs < maxmsg but no free slot: inconsistent file; treat as full.
        return Ok(false);
    };

    let seq = rd_u32(&buf, OFF_NEXT_SEQ);
    let base = HEADER_SIZE + idx * stride;
    wr_u32(&mut buf, base + SLOT_USED, 1);
    wr_u32(&mut buf, base + SLOT_PRIO, prio);
    wr_u32(&mut buf, base + SLOT_LEN, payload.len() as u32);
    wr_u32(&mut buf, base + SLOT_SEQ, seq);
    let data_off = base + SLOT_HEADER;
    if let Some(slot_data) = buf.get_mut(data_off..data_off + payload.len()) {
        slot_data.copy_from_slice(payload);
    }
    wr_u32(&mut buf, OFF_NEXT_SEQ, seq.wrapping_add(1));
    wr_u32(&mut buf, OFF_CURMSGS, (curmsgs + 1) as u32);

    // One-shot notify on the empty→non-empty transition: read the registration,
    // clear it, deliver, and write the whole (cleared) header+slot back.
    let mut notify: Option<(i32, i32, i32)> = None; // (pid, sigev_notify, signo)
    if was_empty {
        let pid = rd_u32(&buf, OFF_NOTIFY_PID) as i32;
        if pid != 0 {
            let sigev = rd_u32(&buf, OFF_SIGEV_NOTIFY) as i32;
            let signo = rd_u32(&buf, OFF_SIGEV_SIGNO) as i32;
            notify = Some((pid, sigev, signo));
            // Clear the one-shot registration.
            wr_u32(&mut buf, OFF_NOTIFY_PID, 0);
            wr_u32(&mut buf, OFF_SIGEV_NOTIFY, 0);
            wr_u32(&mut buf, OFF_SIGEV_SIGNO, 0);
        }
    }

    // Persist the header + the written slot. Write the whole buffer back; it is
    // small (header + maxmsg * (16 + msgsize)) and a single pwrite keeps the
    // header counters and the new slot atomic under the lock.
    lock.write_at(0, &buf)?;
    drop(lock);

    // Deliver the notification AFTER releasing the lock (kill could block on a
    // stopped target; never hold the file lock across it).
    if let Some((pid, sigev, signo)) = notify {
        if sigev != crate::linux_abi::LINUX_SIGEV_NONE && signo > 0 {
            if pid == std::process::id() as i32 {
                crate::host_signal::raise_for_self(signo);
            } else {
                let host_signo = crate::host_signal::linux_to_host_signum(signo);
                unsafe { libc::kill(pid, host_signo) };
            }
        }
    }
    Ok(true)
}

/// Try to dequeue the highest-priority (FIFO-within-priority) message. Returns
/// `Ok(Some((prio, payload)))`, `Ok(None)` if empty, `Err(errno)` on error.
fn mq_try_receive(mq: &MqFd) -> Result<Option<(u32, Vec<u8>)>, i32> {
    let lock = MqLock::acquire(&mq.path)?;
    let size = file_size(mq.max_msg, mq.msg_size);
    let mut buf = lock.read_all(size)?;
    if rd_u32(&buf, OFF_MAGIC) != MQ_MAGIC {
        return Err(LINUX_EINVAL);
    }
    let maxmsg = rd_u32(&buf, OFF_MAXMSG) as usize;
    let msgsize = rd_u32(&buf, OFF_MSGSIZE) as usize;
    let curmsgs = rd_u32(&buf, OFF_CURMSGS) as usize;
    if curmsgs == 0 {
        return Ok(None);
    }
    let stride = slot_stride(msgsize);

    // Pick the used slot with the highest priority; ties broken by lowest seq
    // (FIFO within a priority — mq_overview(7)).
    let mut best: Option<(usize, u32, u32)> = None; // (idx, prio, seq)
    for i in 0..maxmsg {
        let base = HEADER_SIZE + i * stride;
        if rd_u32(&buf, base + SLOT_USED) == 0 {
            continue;
        }
        let prio = rd_u32(&buf, base + SLOT_PRIO);
        let seq = rd_u32(&buf, base + SLOT_SEQ);
        let take = match best {
            None => true,
            Some((_, bp, bs)) => prio > bp || (prio == bp && seq < bs),
        };
        if take {
            best = Some((i, prio, seq));
        }
    }
    let Some((idx, prio, _)) = best else {
        // curmsgs > 0 but no used slot: inconsistent file; report empty.
        return Ok(None);
    };

    let base = HEADER_SIZE + idx * stride;
    let len = rd_u32(&buf, base + SLOT_LEN) as usize;
    let len = len.min(msgsize);
    let data_off = base + SLOT_HEADER;
    let payload = buf
        .get(data_off..data_off + len)
        .map(|s| s.to_vec())
        .unwrap_or_default();

    // Free the slot and decrement curmsgs.
    wr_u32(&mut buf, base + SLOT_USED, 0);
    wr_u32(&mut buf, OFF_CURMSGS, (curmsgs - 1) as u32);
    lock.write_at(0, &buf)?;
    drop(lock);
    Ok(Some((prio, payload)))
}

/// Clear `pid`'s notify registration (mq_notify(NULL)). A no-op if a different
/// pid (or no one) is registered — Linux's mq_notify(NULL) only removes the
/// CALLER's registration.
fn mq_clear_notify(mq: &MqFd, pid: i32) -> Result<(), i32> {
    let lock = MqLock::acquire(&mq.path)?;
    let size = file_size(mq.max_msg, mq.msg_size);
    let mut buf = lock.read_all(size)?;
    if rd_u32(&buf, OFF_MAGIC) != MQ_MAGIC {
        return Err(LINUX_EINVAL);
    }
    if rd_u32(&buf, OFF_NOTIFY_PID) as i32 == pid {
        wr_u32(&mut buf, OFF_NOTIFY_PID, 0);
        wr_u32(&mut buf, OFF_SIGEV_NOTIFY, 0);
        wr_u32(&mut buf, OFF_SIGEV_SIGNO, 0);
        lock.write_at(0, &buf[..HEADER_SIZE])?;
    }
    Ok(())
}

/// Register `pid`'s one-shot notify (mq_notify(non-NULL)). EBUSY if a DIFFERENT
/// pid is already registered (mq_notify(3)).
fn mq_register_notify(mq: &MqFd, pid: i32, sigev_notify: i32, signo: i32) -> Result<(), i32> {
    let lock = MqLock::acquire(&mq.path)?;
    let size = file_size(mq.max_msg, mq.msg_size);
    let mut buf = lock.read_all(size)?;
    if rd_u32(&buf, OFF_MAGIC) != MQ_MAGIC {
        return Err(LINUX_EINVAL);
    }
    let cur_pid = rd_u32(&buf, OFF_NOTIFY_PID) as i32;
    if cur_pid != 0 && cur_pid != pid {
        return Err(crate::linux_abi::LINUX_EBUSY);
    }
    wr_u32(&mut buf, OFF_NOTIFY_PID, pid as u32);
    wr_u32(&mut buf, OFF_SIGEV_NOTIFY, sigev_notify as u32);
    wr_u32(&mut buf, OFF_SIGEV_SIGNO, signo as u32);
    lock.write_at(0, &buf[..HEADER_SIZE])?;
    Ok(())
}
