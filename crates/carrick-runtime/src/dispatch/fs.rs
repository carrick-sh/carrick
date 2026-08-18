//! Filesystem syscall handlers — VFS-routed file I/O.
//!
//! These are methods on [`SyscallDispatcher`] (see `super` for the dispatcher
//! struct, the normalized dispatch table, and the [`DispatchOutcome`] protocol).
//! This module and its `fs/` submodules implement every path- and fd-bearing
//! syscall: `openat`/`read`/`write`/`close`, the `*stat*` family, directory
//! ops, `rename`/`link`/`unlink`, `fcntl` (incl. POSIX record locks),
//! `sendfile`/`copy_file_range`, xattrs, and the access checks.
//!
//! # Routing: VFS mount table first, rootfs+overlay fallthrough
//!
//! A path-bearing syscall is resolved against [`fs::FsState`] in two layers.
//! First the unified VFS mount table ([`fs::FsState::vfs_mounts`]) — `DevVfs` at
//! `/dev`, `ProcVfs` at `/proc`, `SysVfs` at `/sys`. If a mount claims the path
//! and handles the operation, its answer wins. Otherwise the call *falls
//! through* (`VfsOpenAttempt::FallThrough`) to the `/` mount
//! ([`fs::FsState::rootfs_vfs`]): an immutable OCI rootfs layered under a
//! writable overlay. Reads see the overlay shadowing the rootfs; writes,
//! creates, and metadata changes land in the overlay (the base image is never
//! mutated). The rootfs/overlay is held as a typed field rather than a regular
//! mount because ~50 legacy call sites still reach into it directly.
//!
//! With `--fs host`, regular-file opens are backed by a real macOS fd
//! (`OpenDescription::HostFile`) so the guest sees the host's APFS, mediated by
//! cap-std; in the default in-memory mode an `openat` of a rootfs/overlay file
//! materializes its bytes into an `OpenDescription::File`/`Directory`. Either
//! way the descriptor lands in the fd table (see [`fd_table`]).
//!
//! # Linux↔Darwin translation lives here
//!
//! macOS does the heavy lifting (real `libc` calls under the hood for host
//! backends), but the *shapes* differ and every divergence is reconciled in
//! this module: the `struct flock` field order and `l_type` constants
//! (`forward_record_lock`), the `struct stat`/`statx` wire layout
//! (`fs/stat.rs`), `AT_*`/`O_*` flag bits, `S_IF*` type bits, the `dirent64`
//! record format, and the magic `/proc/self/fd/N` re-open symlinks. The guiding
//! rule is "be Linux, on Darwin": where a constant or layout collides, the Linux
//! value is what the guest must observe.
//!
//! # Submodules (`fs/`)
//!
//! Pure `impl SyscallDispatcher` splits (WS-F3), type-transparent to callers:
//! `state` (the [`fs::FsState`]/[`fs::RuntimeIo`] owned state), `fd_helpers`
//! (the lowest-free-fd allocator + `install_fd*` + typed fd-kind accessors),
//! `pathres` (layered path/symlink resolution across the rootfs layers),
//! `stat` (fd stat/statx record assembly), `sendfile` (data-movement +
//! the Darwin `copyfile`/`fclonefileat` fast path), `access` (DAC checks),
//! and `xattr`.
use super::*;

syscall_table! {
    /// Per-module syscall routing for the `fs` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `fs` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_fs;
    0 => io_setup,
    1 => io_destroy,
    2 => io_submit,
    3 => io_cancel,
    4 => io_getevents,
    17 => getcwd,
    23 => dup,
    24 => dup3,
    carrick_abi::CARRICK_PRIVATE_X86_DUP2 => dup2,
    carrick_abi::CARRICK_PRIVATE_X86_STAT => x86_stat,
    carrick_abi::CARRICK_PRIVATE_X86_FSTAT => x86_fstat,
    carrick_abi::CARRICK_PRIVATE_X86_LSTAT => x86_lstat,
    carrick_abi::CARRICK_PRIVATE_X86_NEWFSTATAT => x86_newfstatat,
    25 => fcntl,
    26 => inotify_init1,
    27 => inotify_add_watch,
    28 => inotify_rm_watch,
    29 => ioctl,
    32 => flock,
    33 => mknodat,
    46 => ftruncate,
    47 => fallocate,
    48 => faccessat,
    34 => mkdirat,
    35 => unlinkat,
    36 => symlinkat,
    37 => linkat,
    38 => renameat,
    49 => chdir,
    50 => fchdir,
    51 => chroot,
    52 => fchmod,
    53 => fchmodat,
    452 => fchmodat2, // validates the flags arg (nr 53 ignores it)
    54 => fchownat,
    55 => fchown,
    56 => openat,
    57 => close,
    59 => pipe2,
    61 => getdents64,
    62 => lseek,
    63 => read,
    64 => write,
    65 => readv,
    66 => writev,
    67 => pread64,
    68 => pwrite64,
    69 => preadv,
    70 => pwritev,
    71 => sendfile,
    75 => vmsplice,
    76 => splice,
    78 => readlinkat,
    79 => newfstatat,
    80 => fstat,
    81 => sync,
    82 => fsync,
    83 => fdatasync,
    88 => utimensat,
    262 => fanotify_init,
    263 => fanotify_mark,
    267 => syncfs,
    84 => sync_file_range,
    451 => cachestat,
    276 => renameat2,
    279 => memfd_create,
    285 => copy_file_range,
    // preadv2/pwritev2: positional vectored I/O plus a RWF_* flags arg. The
    // flags are advisory for our backing — RWF_HIPRI (high-priority hint),
    // RWF_{D,}SYNC (durability; we don't buffer), RWF_NOWAIT (a regular file
    // never blocks) — so we route to preadv/pwritev, whose 5-arg handlers
    // ignore the trailing flags. (A future RWF_APPEND need would want its own
    // pwritev2 handler that writes at EOF.)
    286 => preadv,
    287 => pwritev,
    291 => statx,
    436 => close_range,
    437 => openat2,
    439 => faccessat2,
    5 => sys_setxattr_path,
    6 => sys_lsetxattr_path,
    7 => sys_setxattr_fd,
    8 => sys_getxattr_path,
    9 => sys_lgetxattr_path,
    10 => sys_getxattr_fd,
    11 => sys_listxattr_path,
    12 => sys_llistxattr_path,
    13 => sys_listxattr_fd,
    14 => sys_removexattr_path,
    15 => sys_lremovexattr_path,
    16 => sys_removexattr_fd,
    43 => sys_statfs,
    44 => sys_fstatfs,
    45 => sys_truncate,
    77 => tee,
}

/// Canonical (AArch64) numbers of the syscalls that STRUCTURALLY mutate the path
/// namespace — create/remove/rename a directory, symlink, or special node.
/// These are the only fs syscalls that can change how an UNRELATED path
/// resolves, so a successful one must invalidate the fork-coherent resolve
/// cache ([`crate::fs_resolve_cache`]). The numbers mirror the `=> handler` arms
/// in the `syscall_table!` above; content-only writes (write/pwrite/ftruncate)
/// are deliberately EXCLUDED so a syscall-bound write loop keeps its cached
/// resolves. Bumping is unconditional (even on a failed mutation) — a spurious
/// invalidation only costs a re-resolve, whereas missing one would serve a
/// stale path, and these syscalls are never in a hot loop.
pub(crate) fn is_structural_namespace_mutation(canonical_nr: u64) -> bool {
    matches!(
        canonical_nr,
        33      // mknodat
            | 34  // mkdirat
            | 35  // unlinkat  (unlink + rmdir via AT_REMOVEDIR)
            | 36  // symlinkat
            | 37  // linkat
            | 38  // renameat
            | 276 // renameat2
    )
}

mod access;
mod fd_helpers;
mod legacy_aio;
mod pathres;
mod sendfile;
mod stat;
mod state;
mod xattr;
use state::*;
pub(super) use state::{FsState, RuntimeIo, host_fd_offset};
pub(crate) use state::{LegacyAioContextId, SplicePushback};

fn get_last_error() -> i32 {
    carrick_portable::errno()
}

/// Derive a stable opaque Carrick stream identity from a host fd, used to
/// stamp BOTH ends of a freshly-created pipe with one shared FASYNC join key.
/// Include both host device and inode: inode numbers are only unique within a
/// device, and Carrick adopts streams from devfs and several filesystems. The
/// value is read before fork and copied to the other pipe end, so both ends
/// retain one Linux identity even though BSD assigns them different inodes.
/// Returns `0` if fstat fails; `0` is never a valid armed FASYNC key.
fn host_inode_pipe_id(host_fd: i32) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut st) } != 0 {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in (st.st_dev as u64)
        .to_le_bytes()
        .into_iter()
        .chain((st.st_ino as u64).to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if hash == 0 { 1 } else { hash }
}

fn host_pipe_readable_bytes(host_fd: i32) -> Result<usize, LinuxErrno> {
    let mut readable: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut readable) };
    rc.host_syscall_errno()?;
    usize::try_from(readable).map_err(|_| LINUX_EINVAL)
}

fn linux_termio_bytes(termios: &LinuxTermios) -> [u8; LINUX_TERMIO_SIZE] {
    let mut cc = [0u8; 8];
    cc.copy_from_slice(&termios.c_cc[..8]);
    let termio = carrick_abi::LinuxTermio {
        c_iflag: termios.c_iflag as u16,
        c_oflag: termios.c_oflag as u16,
        c_cflag: termios.c_cflag as u16,
        c_lflag: termios.c_lflag as u16,
        c_line: termios.c_line,
        c_cc: cc,
    };
    let mut out = [0u8; LINUX_TERMIO_SIZE];
    // `struct termio` is 17 bytes of fields PADDED to sizeof 18 (its u16
    // members give it alignment 2). The packed Rust mirror serializes the 17
    // real bytes; the trailing pad stays zero. Copying into the full array
    // panicked the runtime on length mismatch — a guest-reachable abort via
    // any TCGETA (probe `ioctlcluster`).
    let bytes = termio.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn write_linux_termio(
    memory: &mut impl GuestMemory,
    address: u64,
    termios: &LinuxTermios,
) -> DispatchOutcome {
    write_packed(memory, address, &linux_termio_bytes(termios))
}

fn host_fd_matches_device(host_fd: i32, path: &str) -> bool {
    let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut fd_stat) } != 0 {
        return false;
    }
    let Ok(c_path) = std::ffi::CString::new(path) else {
        return false;
    };
    let mut path_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c_path.as_ptr(), &mut path_stat) } != 0 {
        return false;
    }
    (fd_stat.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && (path_stat.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && fd_stat.st_rdev == path_stat.st_rdev
}

fn fd_is_random_device(this: &SyscallDispatcher, fd: i32) -> bool {
    this.open_file(fd).is_some_and(|open_file| {
        let open = open_file.description.read();
        let OpenDescription::HostPipe { host_fd, .. } = &*open else {
            return false;
        };
        host_fd_matches_device(host_fd.raw(), "/dev/random")
            || host_fd_matches_device(host_fd.raw(), "/dev/urandom")
    })
}

fn gather_bounded_iovec_bytes(
    memory: &impl GuestMemory,
    iovecs: &[LinuxIovec],
) -> Result<Option<Vec<u8>>, LinuxErrno> {
    let mut total = 0usize;
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        total = total.checked_add(len).ok_or(LINUX_EINVAL)?;
        if total > crate::dispatch::MAX_RW_COUNT {
            return Ok(None);
        }
    }

    let mut bytes = Vec::with_capacity(total);
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        if len == 0 {
            continue;
        }
        let chunk = memory
            .read_bytes(iovec.iov_base, len)
            .map_err(|_| LINUX_EFAULT)?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

enum PwritevPayloads {
    Borrowed(Vec<libc::iovec>),
    Staged(Vec<Vec<u8>>),
}

fn prepare_pwritev_payloads(
    memory: &impl GuestMemory,
    iovecs: &[LinuxIovec],
) -> Result<PwritevPayloads, LinuxErrno> {
    let mut borrowed_iovecs = Vec::with_capacity(iovecs.len());
    let mut all_borrowed = true;
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        if iov_len == 0 {
            continue;
        }
        let Some(ptr) = memory.host_ptr_for_read(iovec.iov_base, iov_len) else {
            all_borrowed = false;
            break;
        };
        borrowed_iovecs.push(libc::iovec {
            iov_base: ptr as *mut libc::c_void,
            iov_len,
        });
    }
    if all_borrowed {
        return Ok(PwritevPayloads::Borrowed(borrowed_iovecs));
    }

    let mut staged_iovecs = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        // A zero-length iovec segment is permitted and must NOT fault, even
        // with a NULL/invalid base.
        let bytes = if iov_len == 0 {
            Vec::new()
        } else {
            memory
                .read_bytes(iovec.iov_base, iov_len)
                .map_err(|_| LINUX_EFAULT)?
        };
        staged_iovecs.push(bytes);
    }
    Ok(PwritevPayloads::Staged(staged_iovecs))
}

struct PreparedReadvTargets {
    host_iovecs: Vec<libc::iovec>,
    guest_ranges: Vec<(u64, usize)>,
}

fn prepare_readv_targets(
    memory: &mut impl GuestMemory,
    iovecs: &[LinuxIovec],
) -> Result<Option<PreparedReadvTargets>, LinuxErrno> {
    let mut borrowed_iovecs = Vec::with_capacity(iovecs.len());
    let mut guest_ranges = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        if iov_len == 0 {
            continue;
        }
        let Some(ptr) = memory.host_ptr_for_write(iovec.iov_base, iov_len) else {
            return Ok(None);
        };
        borrowed_iovecs.push(libc::iovec {
            iov_base: ptr as *mut libc::c_void,
            iov_len,
        });
        guest_ranges.push((iovec.iov_base, iov_len));
    }
    Ok(Some(PreparedReadvTargets {
        host_iovecs: borrowed_iovecs,
        guest_ranges,
    }))
}

/// If `path` is a `/proc/{self,thread-self,curproc,this}/fd/N` magic symlink,
/// return the descriptor number N. Used to serve `open()` of these (Linux
/// re-opens the file behind fd N); Apple Rosetta opens its main-binary fd this
/// way.
/// Forward a classic POSIX record lock (F_SETLK/F_SETLKW/F_GETLK) on a
/// host-backed fd to the host kernel's real `fcntl` locking, translating the
/// `struct flock` between the Linux-aarch64 and macOS layouts (which differ in
/// BOTH field order and the `l_type` constants). `host_syscall_errno` maps the
/// host errno back to Linux (covering the EAGAIN↔EDEADLK number swap).
///
/// Linux aarch64 flock (32 bytes): l_type:i16@0, l_whence:i16@2, l_start:i64@8,
///   l_len:i64@16, l_pid:i32@24. l_type: RDLCK=0, WRLCK=1, UNLCK=2.
/// macOS flock (`libc::flock`): l_start:i64, l_len:i64, l_pid:i32, l_type:i16,
///   l_whence:i16. l_type: RDLCK=1, UNLCK=2, WRLCK=3. cmd: GETLK=7/SETLK=8/SETLKW=9.
fn forward_record_lock<M: GuestMemory>(
    this: &SyscallDispatcher,
    cx: &mut SyscallCtx<'_, M>,
    host_fd: i32,
    linux_cmd: u64,
    arg: u64,
) -> DispatchOutcome {
    // OFD locks (F_OFD_*) are owned by the open file description, not the process.
    // macOS has them natively (F_OFD_SETLK/SETLKW/GETLK = 90/91/92), so we forward
    // exactly like the classic commands; the only divergence is that F_OFD_GETLK
    // reports l_pid = -1 for a conflicting lock (OFD locks are not process-owned).
    let is_ofd = matches!(
        linux_cmd,
        LINUX_F_OFD_GETLK | LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW
    );

    let flock: LinuxFlock64 = match cx.memory.read_struct(arg) {
        Ok(f) => f,
        Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
    };
    let l_type_linux = flock.l_type;
    let l_whence = flock.l_whence;
    let l_start = flock.l_start;
    let l_len = flock.l_len;

    // l_whence must be SEEK_SET/SEEK_CUR/SEEK_END; Linux rejects anything else
    // with EINVAL in flock_to_posix_lock, before attempting the lock.
    if !(0..=2).contains(&l_whence) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    // struct flock.l_type is c_short (i16) on both OSes, but the libc F_*LCK
    // constants are i16 on Darwin / i32 on Linux — narrow to the field width.
    // (The LINUX_F_*LCK consts are i32, so widen the guest i16 for the match.)
    #[allow(clippy::unnecessary_cast)] // libc F_*LCK: i16 on Darwin, i32 on Linux
    let l_type_host: i16 = match i32::from(l_type_linux) {
        LINUX_F_RDLCK => libc::F_RDLCK as i16,
        LINUX_F_WRLCK => libc::F_WRLCK as i16,
        LINUX_F_UNLCK => libc::F_UNLCK as i16,
        _ => return DispatchOutcome::errno(LINUX_EINVAL),
    };
    let host_cmd: i32 = match linux_cmd {
        LINUX_F_GETLK => libc::F_GETLK,
        LINUX_F_SETLK => libc::F_SETLK,
        LINUX_F_SETLKW => libc::F_SETLKW,
        LINUX_F_OFD_GETLK => carrick_portable::F_OFD_GETLK,
        LINUX_F_OFD_SETLK => carrick_portable::F_OFD_SETLK,
        LINUX_F_OFD_SETLKW => carrick_portable::F_OFD_SETLKW,
        _ => return DispatchOutcome::errno(LINUX_EINVAL),
    };

    if this.execution_backend() == crate::page_profile::ExecutionBackend::HvPatch && !is_ofd {
        let file = match logical_record_lock_file(host_fd) {
            Ok(file) => file,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let range = match normalize_logical_record_lock_range(host_fd, l_whence, l_start, l_len) {
            Ok(range) => range,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let owner = LogicalRecordLockOwner::from(cx.kernel.task().key());
        if l_type_linux == LINUX_F_UNLCK as i16 {
            if linux_cmd == LINUX_F_GETLK {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            this.fs.classic_record_locks.unlock(&file, owner, range);
            return DispatchOutcome::Returned { value: 0 };
        }
        let request = LogicalRecordLockRequest {
            file,
            owner,
            range,
            write: l_type_linux == LINUX_F_WRLCK as i16,
        };
        if linux_cmd == LINUX_F_GETLK {
            let conflict = this.fs.classic_record_locks.conflict(&request);
            return write_logical_record_lock_conflict(&mut *cx.memory, arg, conflict);
        }
        match this.fs.classic_record_locks.try_set(request.clone()) {
            Ok(()) => return DispatchOutcome::Returned { value: 0 },
            Err(errno) if linux_cmd == LINUX_F_SETLK => {
                return DispatchOutcome::errno(errno);
            }
            Err(errno) if errno != LINUX_EAGAIN => return DispatchOutcome::errno(errno),
            Err(_) => {
                let wait = LogicalRecordLockWait::new(
                    Arc::clone(&this.fs.classic_record_locks),
                    request,
                    cx.tid(),
                );
                return DispatchOutcome::BlockingRecordLock(BlockingRecordLock::logical(wait));
            }
        }
    }

    if matches!(linux_cmd, LINUX_F_SETLKW | LINUX_F_OFD_SETLKW) {
        return match BlockingRecordLock::new(
            host_fd,
            host_cmd,
            l_start,
            l_len,
            l_type_host,
            l_whence,
        ) {
            Ok(lock) => DispatchOutcome::BlockingRecordLock(lock),
            Err(errno) => DispatchOutcome::errno(errno),
        };
    }

    let mut fl: libc::flock = unsafe { core::mem::zeroed() };
    fl.l_start = l_start as libc::off_t;
    fl.l_len = l_len as libc::off_t;
    fl.l_type = l_type_host;
    fl.l_whence = l_whence;
    let rc = unsafe { libc::fcntl(host_fd, host_cmd, &mut fl as *mut libc::flock) };
    if let Err(errno) = rc.host_syscall_errno() {
        return DispatchOutcome::errno(errno);
    }

    // F_GETLK / F_OFD_GETLK: write the (possibly conflicting) lock back in Linux
    // layout.
    if matches!(linux_cmd, LINUX_F_GETLK | LINUX_F_OFD_GETLK) {
        let host_type = fl.l_type as i32;
        if host_type == libc::F_UNLCK as i32 {
            // No conflicting lock. Linux leaves the caller's struct UNCHANGED
            // except l_type = F_UNLCK — in particular l_pid keeps the value the
            // caller passed (LTP fcntl05 pre-sets l_pid = getpid() and checks it
            // survives). carrick previously rewrote the whole struct from the
            // macOS flock result, which zeroes l_pid. Touch only l_type@0
            // (an i16 field, so narrow the i32 const to 2 wire bytes).
            let mut flock: LinuxFlock64 = match cx.memory.read_struct(arg) {
                Ok(f) => f,
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            };
            flock.l_type = LINUX_F_UNLCK as i16;
            if cx.memory.write_struct(arg, &flock).is_err() {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        } else {
            // Conflicting lock found: report its full details (Linux fills the
            // whole struct, including the holder's l_pid).
            let l_type_back: i16 = if host_type == libc::F_RDLCK as i32 {
                LINUX_F_RDLCK as i16
            } else {
                LINUX_F_WRLCK as i16
            };
            // OFD locks are not process-owned: Linux reports a conflicting OFD
            // lock's l_pid as -1. A classic lock's holder pid comes back from
            // macOS flock as the HOST pid; present it in the caller's PID
            // namespace (LTP fcntl11/17/19/20/21/31/32 assert l_pid == the
            // holder's ns-pid, the same translation gettid/semctl(GETPID) use).
            let l_pid_back: i32 = if is_ofd {
                -1
            } else {
                crate::namespace::pid::host_to_ns_or_self(fl.l_pid as u32) as i32
            };
            let out = LinuxFlock64 {
                l_type: l_type_back,
                l_whence: fl.l_whence,
                __pad1: [0; 4],
                l_start: fl.l_start as i64,
                l_len: fl.l_len as i64,
                l_pid: l_pid_back,
                __pad2: [0; 4],
            };
            if cx.memory.write_struct(arg, &out).is_err() {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        }
    }
    DispatchOutcome::Returned { value: 0 }
}

/// Front-door `struct flock` validation Linux performs for F_GETLK/F_SETLK/
/// F_SETLKW BEFORE acting on the lock, regardless of the fd's backing: a bad
/// pointer → EFAULT, an out-of-range `l_type` or `l_whence` → EINVAL. carrick's
/// non-host-backed no-op path (e.g. fd=1, in-memory/synthetic files) skipped
/// this, so LTP fcntl13 (fd=1 with a bad address / bad l_whence) wrongly
/// succeeded. Mirrors the host-backed path's checks in `forward_record_lock`.
fn validate_flock_arg<M: GuestMemory>(memory: &M, arg: u64) -> Result<(), LinuxErrno> {
    let flock: LinuxFlock64 = memory.read_struct(arg).map_err(|_| LINUX_EFAULT)?;
    let l_type = flock.l_type;
    let l_whence = flock.l_whence;
    // l_type: RDLCK=0/WRLCK=1/UNLCK=2; l_whence: SEEK_SET=0/SEEK_CUR=1/SEEK_END=2.
    if !(0..=2).contains(&l_type) || !(0..=2).contains(&l_whence) {
        return Err(LINUX_EINVAL);
    }
    Ok(())
}

/// Linux path-length limits enforced at resolution time: NAME_MAX (255) per
/// component, PATH_MAX (4096) for the whole path. Either overflow →
/// ENAMETOOLONG. (`PATH_MAX` includes the NUL, so the usable length is 4095.)
fn check_path_length(path: &str) -> Result<(), LinuxErrno> {
    const NAME_MAX: usize = 255;
    const PATH_MAX: usize = 4096;
    if path.len() >= PATH_MAX {
        return Err(LINUX_ENAMETOOLONG);
    }
    for component in path.split('/') {
        if component.len() > NAME_MAX {
            return Err(LINUX_ENAMETOOLONG);
        }
    }
    Ok(())
}

fn path_is_under_or_equal(path: &str, root: &str) -> bool {
    let path = path.trim_end_matches('/');
    let root = root.trim_end_matches('/');
    if root.is_empty() || root == "/" {
        return true;
    }
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Host passthrough for tee(2). On Linux the guest pipes are real host kernel
/// pipes, so the host tee(2) gives exact zero-consume semantics; on hosts
/// without tee(2) (macOS/BSD) `SyscallDispatcher::userspace_tee` emulates it.
#[cfg(target_os = "linux")]
fn tee_host_passthrough(
    in_fd: HostFd,
    out_fd: HostFd,
    count: usize,
    flags: LinuxSpliceFlags,
) -> Result<DispatchOutcome, DispatchError> {
    // Raw escape at the libc boundary: Linux SPLICE_F_* values are identical
    // to the guest's, so the bits pass straight through.
    let n = unsafe {
        libc::tee(
            in_fd.get(),
            out_fd.get(),
            count,
            flags.bits() as libc::c_uint,
        )
    };
    Ok(DispatchOutcome::Returned {
        value: n.host_syscall_errno()? as i64,
    })
}

/// Same-file identity used for F_SETLEASE conflict accounting (see
/// [`SyscallDispatcher::same_file_other_openers`]). Two open descriptions
/// conflict for lease purposes iff they name the same underlying file: the host
/// inode under `--fs host`, or the guest open-path for the in-memory backing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LeaseFileId {
    Inode { dev: u64, ino: u64 },
    Path(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LogicalRecordLockOwner {
    pid: i32,
    serial: u64,
}

impl From<crate::kernel::TaskKey> for LogicalRecordLockOwner {
    fn from(key: crate::kernel::TaskKey) -> Self {
        Self {
            pid: key.id.raw(),
            serial: key.serial.raw(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalRecordLockRange {
    start: u64,
    end: u64,
}

impl LogicalRecordLockRange {
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalRecordLock {
    file: LeaseFileId,
    owner: LogicalRecordLockOwner,
    range: LogicalRecordLockRange,
    write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogicalRecordLockRequest {
    file: LeaseFileId,
    owner: LogicalRecordLockOwner,
    range: LogicalRecordLockRange,
    write: bool,
}

/// The lock set and the wait-for graph, under ONE mutex.
///
/// They must not be separately lockable: `EDEADLK` is decided by walking the
/// graph against the lock set, and a walk that could observe them at different
/// instants would both miss real cycles and invent false ones.
#[derive(Default)]
struct LogicalRecordLockState {
    locks: Vec<LogicalRecordLock>,
    /// Which owner each currently-BLOCKED owner is waiting on. An entry exists
    /// only while that owner is parked in `wait_set_interruptibly`.
    waiting_on: std::collections::HashMap<LogicalRecordLockOwner, LogicalRecordLockOwner>,
}

#[derive(Default)]
pub(crate) struct LogicalRecordLocks {
    state: parking_lot::Mutex<LogicalRecordLockState>,
    changed: parking_lot::Condvar,
}

impl LogicalRecordLocks {
    fn conflict_locked(
        locks: &[LogicalRecordLock],
        request: &LogicalRecordLockRequest,
    ) -> Option<LogicalRecordLock> {
        locks
            .iter()
            .filter(|lock| {
                lock.file == request.file
                    && lock.owner != request.owner
                    && lock.range.overlaps(request.range)
                    && (lock.write || request.write)
            })
            .min_by_key(|lock| lock.range.start)
            .cloned()
    }

    fn replace_owner_range(
        locks: &mut Vec<LogicalRecordLock>,
        file: &LeaseFileId,
        owner: LogicalRecordLockOwner,
        range: LogicalRecordLockRange,
    ) {
        let mut retained = Vec::with_capacity(locks.len() + 2);
        for lock in locks.drain(..) {
            if &lock.file != file || lock.owner != owner || !lock.range.overlaps(range) {
                retained.push(lock);
                continue;
            }
            if lock.range.start < range.start {
                let mut prefix = lock.clone();
                prefix.range.end = range.start;
                retained.push(prefix);
            }
            if range.end < lock.range.end {
                let mut suffix = lock;
                suffix.range.start = range.end;
                retained.push(suffix);
            }
        }
        *locks = retained;
    }

    fn try_set(&self, request: LogicalRecordLockRequest) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        if Self::conflict_locked(&state.locks, &request).is_some() {
            return Err(LINUX_EAGAIN);
        }
        Self::replace_owner_range(
            &mut state.locks,
            &request.file,
            request.owner,
            request.range,
        );
        state.locks.push(LogicalRecordLock {
            file: request.file,
            owner: request.owner,
            range: request.range,
            write: request.write,
        });
        self.changed.notify_all();
        Ok(())
    }

    fn unlock(
        &self,
        file: &LeaseFileId,
        owner: LogicalRecordLockOwner,
        range: LogicalRecordLockRange,
    ) {
        let mut state = self.state.lock();
        Self::replace_owner_range(&mut state.locks, file, owner, range);
        self.changed.notify_all();
    }

    fn conflict(&self, request: &LogicalRecordLockRequest) -> Option<LogicalRecordLock> {
        Self::conflict_locked(&self.state.lock().locks, request)
    }

    fn release_file_owner(&self, file: &LeaseFileId, owner: LogicalRecordLockOwner) {
        let mut state = self.state.lock();
        state
            .locks
            .retain(|lock| lock.file != *file || lock.owner != owner);
        self.changed.notify_all();
    }

    pub(crate) fn release_owner(&self, owner: crate::kernel::TaskKey) {
        let owner = LogicalRecordLockOwner::from(owner);
        let mut state = self.state.lock();
        state.locks.retain(|lock| lock.owner != owner);
        self.changed.notify_all();
    }

    /// Would `me` blocking on `blocker` close a cycle in the wait-for graph?
    ///
    /// fcntl(2): "EDEADLK — It was detected that the specified F_SETLKW command
    /// would cause a deadlock." Linux walks the wait-for graph over blocked
    /// POSIX-lock waiters; so do we. Follow the chain from the owner that would
    /// block us: if it leads back to us, waiting would deadlock.
    ///
    /// The hop bound is the number of blocked waiters, which is the longest a
    /// simple path can be. Exceeding it means the graph contains a cycle we
    /// entered from outside, so report a deadlock rather than looping.
    fn would_deadlock(
        state: &LogicalRecordLockState,
        me: LogicalRecordLockOwner,
        blocker: LogicalRecordLockOwner,
    ) -> bool {
        let mut hop = blocker;
        for _ in 0..=state.waiting_on.len() {
            if hop == me {
                return true;
            }
            match state.waiting_on.get(&hop) {
                Some(next) => hop = *next,
                None => return false,
            }
        }
        true
    }

    fn wait_set_interruptibly(
        &self,
        request: &LogicalRecordLockRequest,
        tid: crate::thread::ThreadId,
    ) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        // Every exit from the loop must retract this owner's wait-for edge, or
        // a later waiter would walk a stale one and see a deadlock that no
        // longer exists. The closure keeps that unmissable across all four
        // exits (acquired / EDEADLK / EINTR / and any future one).
        let result = loop {
            let Some(blocker) = Self::conflict_locked(&state.locks, request) else {
                Self::replace_owner_range(
                    &mut state.locks,
                    &request.file,
                    request.owner,
                    request.range,
                );
                state.locks.push(LogicalRecordLock {
                    file: request.file.clone(),
                    owner: request.owner,
                    range: request.range,
                    write: request.write,
                });
                self.changed.notify_all();
                break Ok(());
            };
            if Self::would_deadlock(&state, request.owner, blocker.owner) {
                break Err(crate::linux_abi::LINUX_EDEADLK);
            }
            // Publish the edge only while actually parked, and refresh it each
            // iteration: the owner that blocks us can change as locks move.
            state.waiting_on.insert(request.owner, blocker.owner);
            if crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            ) {
                break Err(LINUX_EINTR);
            }
            self.changed
                .wait_for(&mut state, std::time::Duration::from_millis(10));
        };
        state.waiting_on.remove(&request.owner);
        // A retracted edge can unblock somebody else's deadlock verdict.
        self.changed.notify_all();
        result
    }
}

#[derive(Clone)]
pub(crate) struct LogicalRecordLockWait {
    locks: Arc<LogicalRecordLocks>,
    request: LogicalRecordLockRequest,
    tid: crate::thread::ThreadId,
}

impl LogicalRecordLockWait {
    fn new(
        locks: Arc<LogicalRecordLocks>,
        request: LogicalRecordLockRequest,
        tid: crate::thread::ThreadId,
    ) -> Self {
        Self {
            locks,
            request,
            tid,
        }
    }

    pub(crate) fn acquire(&self) -> Result<(), LinuxErrno> {
        self.locks.wait_set_interruptibly(&self.request, self.tid)
    }
}

impl PartialEq for LogicalRecordLockWait {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.locks, &other.locks)
            && self.request == other.request
            && self.tid == other.tid
    }
}

impl Eq for LogicalRecordLockWait {}

impl std::fmt::Debug for LogicalRecordLockWait {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogicalRecordLockWait")
            .field("request", &self.request)
            .field("tid", &self.tid)
            .finish_non_exhaustive()
    }
}

fn logical_record_lock_file(host_fd: i32) -> Result<LeaseFileId, LinuxErrno> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(host_fd, &mut stat) }.host_syscall_errno()?;
    Ok(LeaseFileId::Inode {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    })
}

fn normalize_logical_record_lock_range(
    host_fd: i32,
    whence: i16,
    start: i64,
    len: i64,
) -> Result<LogicalRecordLockRange, LinuxErrno> {
    let origin = match i32::from(whence) {
        libc::SEEK_SET => 0_i128,
        libc::SEEK_CUR => {
            let offset = unsafe { libc::lseek(host_fd, 0, libc::SEEK_CUR) };
            if offset < 0 {
                return Err(crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL),
                ));
            }
            i128::from(offset)
        }
        libc::SEEK_END => {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::fstat(host_fd, &mut stat) }.host_syscall_errno()?;
            i128::from(stat.st_size)
        }
        _ => return Err(LINUX_EINVAL),
    };
    let anchor = origin.checked_add(i128::from(start)).ok_or(LINUX_EINVAL)?;
    let (range_start, range_end) = match len.cmp(&0) {
        std::cmp::Ordering::Greater => (
            anchor,
            anchor.checked_add(i128::from(len)).ok_or(LINUX_EINVAL)?,
        ),
        std::cmp::Ordering::Equal => (anchor, i128::from(i64::MAX) + 1),
        std::cmp::Ordering::Less => (
            anchor.checked_add(i128::from(len)).ok_or(LINUX_EINVAL)?,
            anchor,
        ),
    };
    if range_start < 0 || range_end <= range_start || range_end > i128::from(i64::MAX) + 1 {
        return Err(LINUX_EINVAL);
    }
    Ok(LogicalRecordLockRange {
        start: u64::try_from(range_start).map_err(|_| LINUX_EINVAL)?,
        end: u64::try_from(range_end).map_err(|_| LINUX_EINVAL)?,
    })
}

fn write_logical_record_lock_conflict(
    memory: &mut impl GuestMemory,
    arg: u64,
    conflict: Option<LogicalRecordLock>,
) -> DispatchOutcome {
    let Some(conflict) = conflict else {
        return if memory
            .write_bytes(arg, &(LINUX_F_UNLCK as i16).to_le_bytes())
            .is_ok()
        {
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::errno(LINUX_EFAULT)
        };
    };
    let mut out = [0_u8; 32];
    let lock_type = if conflict.write {
        LINUX_F_WRLCK
    } else {
        LINUX_F_RDLCK
    } as i16;
    let len = if conflict.range.end == i64::MAX as u64 + 1 {
        0_i64
    } else {
        i64::try_from(conflict.range.end.saturating_sub(conflict.range.start)).unwrap_or(i64::MAX)
    };
    out[0..2].copy_from_slice(&lock_type.to_le_bytes());
    out[2..4].copy_from_slice(&(libc::SEEK_SET as i16).to_le_bytes());
    out[8..16].copy_from_slice(&(conflict.range.start as i64).to_le_bytes());
    out[16..24].copy_from_slice(&len.to_le_bytes());
    out[24..28].copy_from_slice(&conflict.owner.pid.to_le_bytes());
    if memory.write_bytes(arg, &out).is_err() {
        DispatchOutcome::errno(LINUX_EFAULT)
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

/// `/dev/fd` and `/dev/std{in,out,err}` are symlinks into `/proc/self/fd` on
/// Linux — bash process substitution (`cat <(...)`) passes `/dev/fd/N` to the
/// spawned command, which `open()`s it to dup the pipe. Rewrite an ABSOLUTE
/// such path to its `/proc/self/fd` equivalent so the existing magic-fd
/// machinery serves it (open → dup N; lstat/readlink as a per-fd symlink).
/// Returns `None` for anything else. Only EXACT matches map: `/dev/fd0` (a
/// floppy) must not become `/proc/self/fd0`.
fn rewrite_dev_fd_alias(path: &str) -> Option<String> {
    match path {
        "/dev/fd" => Some("/proc/self/fd".to_string()),
        "/dev/stdin" => Some("/proc/self/fd/0".to_string()),
        "/dev/stdout" => Some("/proc/self/fd/1".to_string()),
        "/dev/stderr" => Some("/proc/self/fd/2".to_string()),
        _ => path
            .strip_prefix("/dev/fd/")
            .map(|rest| format!("/proc/self/fd/{rest}")),
    }
}

#[cfg(test)]
static FD_OPEN_PATH_INSERTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static FD_OPEN_PATH_LOOKUPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn reset_fd_open_path_inserts() {
    FD_OPEN_PATH_INSERTS.store(0, std::sync::atomic::Ordering::SeqCst);
    FD_OPEN_PATH_LOOKUPS.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn fd_open_path_inserts() -> usize {
    FD_OPEN_PATH_INSERTS.load(std::sync::atomic::Ordering::SeqCst)
}

/// True if `path` is the synthetic sentinel carrick stamps on an ANONYMOUS file
/// description — an `O_TMPFILE` inode (`/__carrick_o_tmpfile`) or a
/// `memfd_create` inode (`/memfd:<name>`). Such a file has no real directory
/// entry, so `linkat(/proc/self/fd/<n>, AT_SYMLINK_FOLLOW)` must MATERIALIZE it
/// at the target rather than hard-link a nonexistent source path.
fn is_anon_overlay_path(path: &str) -> bool {
    path == "/__carrick_o_tmpfile" || path.starts_with("/memfd:")
}

fn proc_self_fd_number(path: &str) -> Option<i32> {
    let rest = path
        .strip_prefix("/proc/self/fd/")
        .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))
        .or_else(|| path.strip_prefix("/proc/curproc/fd/"))
        .or_else(|| path.strip_prefix("/proc/this/fd/"))
        .or_else(|| {
            // /proc/<pid>/fd/N — carrick is one guest process, so any numeric
            // pid component refers to "self".
            let after = path.strip_prefix("/proc/")?;
            let (pid, tail) = after.split_once('/')?;
            if pid.chars().all(|c| c.is_ascii_digit()) && !pid.is_empty() {
                tail.strip_prefix("fd/")
            } else {
                None
            }
        })?;
    rest.parse::<i32>().ok()
}

/// If `path` is a `/proc/{self,thread-self,curproc,this,<pid>}/{exe,cwd,root}`
/// magic symlink, which one it is. These readlink to live dispatcher state
/// (the executable path, the cwd, the root), so they are resolved here rather
/// than in the pure `ProcVfs`. carrick is one guest process, so any numeric pid
/// component refers to "self".
fn proc_self_magic_link(path: &str) -> Option<&'static str> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, leaf) = rest.split_once('/')?;
    // ONLY this process resolves exe/cwd/root from the live dispatcher state.
    // A foreign guest pid must NOT masquerade as self (that would readlink
    // /proc/<other>/exe to OUR executable_path); for those, fall through so the
    // path resolves to ENOENT rather than leaking the inspector's identity.
    let is_self = matches!(pid, "self" | "thread-self" | "curproc" | "this")
        || pid
            .parse::<u32>()
            .is_ok_and(|n| n == std::process::id() || n == crate::namespace::pid::self_ns_pid());
    if !is_self {
        return None;
    }
    match leaf {
        "exe" => Some("exe"),
        "cwd" => Some("cwd"),
        "root" => Some("root"),
        _ => None,
    }
}

/// If `path` is a `/proc/{self,thread-self,curproc,this,<pid>}/ns/<type>` magic
/// symlink of a LIVE process, the namespace `<type>` (e.g. `"uts"`). These are
/// `nsfs` magic links: open(2) resolves them to an opaque namespace OBJECT, NOT
/// by following the `<type>:[<inode>]` readlink target as a path. The liveness
/// gate (`proc_live_pid`) makes a dead or foreign pid return `None` → ENOENT,
/// mirroring `proc_self_magic_link`. carrick models exactly one initial ns per
/// type, so every live pid's link names the same object.
fn proc_ns_link(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, leaf) = rest.split_once('/')?;
    crate::vfs::proc::proc_live_pid(pid)?;
    let ns_type = leaf.strip_prefix("ns/")?;
    crate::vfs::proc::ns_type_inode(ns_type).map(|_| ns_type)
}

/// The `CLONE_NEW*` flag identifying namespace `<type>` — the value `NS_GET_NSTYPE`
/// returns (ioctl_ns(2)). `*_for_children` map to their base type's flag. `None`
/// for an unrecognised type.
fn ns_type_clone_flag(ns_type: &str) -> Option<u64> {
    Some(match ns_type {
        "mnt" => LINUX_CLONE_NEWNS,
        "uts" => LINUX_CLONE_NEWUTS,
        "ipc" => LINUX_CLONE_NEWIPC,
        "net" => LINUX_CLONE_NEWNET,
        "pid" | "pid_for_children" => LINUX_CLONE_NEWPID,
        "user" => LINUX_CLONE_NEWUSER,
        "cgroup" => LINUX_CLONE_NEWCGROUP,
        "time" | "time_for_children" => LINUX_CLONE_NEWTIME,
        _ => return None,
    })
}

/// The fd number `N` of a `/proc/<self>/fdinfo/N` path, if it is one. Self only
/// (the contents are this process's live fd state); a foreign pid falls through.
fn proc_self_fdinfo_number(path: &str) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, tail) = rest.split_once('/')?;
    let is_self = matches!(pid, "self" | "thread-self" | "curproc" | "this")
        || pid
            .parse::<u32>()
            .is_ok_and(|n| n == std::process::id() || n == crate::namespace::pid::self_ns_pid());
    if !is_self {
        return None;
    }
    tail.strip_prefix("fdinfo/")?.parse::<i32>().ok()
}

/// The file STATUS flags reportable via `fcntl(F_GETFL)` and `/proc/<pid>/fdinfo`.
/// Linux consumes creation-only flags at `open()` and clears them from
/// `f_flags`, so they must not be reported back; only the access mode and the
/// file status flags (O_APPEND/O_NONBLOCK/O_DIRECT/O_SYNC/…) remain. (audit M8)
fn reportable_status_flags(raw: u64) -> u64 {
    const CREATION_ONLY: u64 = LINUX_O_CREAT
        | LINUX_O_EXCL
        | LINUX_O_TRUNC
        | LINUX_O_DIRECTORY
        | LINUX_O_CLOEXEC
        | 0o400 // O_NOCTTY
        | 0o100000 // O_NOFOLLOW
        | 0o20000000; // O_TMPFILE
    raw & !CREATION_ONLY
}

/// One host interface with an IPv4 address: `(name, flags_host, sin_addr_be)`
/// where `flags_host` is the host's raw `ifa_flags` and `sin_addr_be` is the
/// 4-byte network-order IPv4 address. Built from `getifaddrs(3)`, which every
/// supported host provides. SIOCGIFCONF reports Carrick's Linux-facing
/// interface view, not Darwin's raw names.
struct HostInet4Iface {
    name: String,
    flags_host: u32,
    addr_be: [u8; 4],
}

/// Enumerate host interfaces that have an IPv4 address, in `getifaddrs` order.
/// Used to service the `SIOCGIFCONF`/`SIOCGIFFLAGS`/`SIOCGIFADDR` family — we
/// normalize names to the same guest-visible `lo`/`eth0` namespace as rtnetlink
/// and `/proc/net`.
fn host_inet4_interfaces() -> Vec<HostInet4Iface> {
    let mut out: Vec<HostInet4Iface> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a non-null node in the getifaddrs list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is non-null; sa_family is the first field.
        if unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        // SAFETY: an AF_INET ifa_addr is a sockaddr_in.
        let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let addr_be = sin.sin_addr.s_addr.to_ne_bytes();
        // SAFETY: ifa_name is a non-null NUL-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        out.push(HostInet4Iface {
            name,
            flags_host: ifa.ifa_flags,
            addr_be,
        });
    }
    // SAFETY: free the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    linux_guest_inet4_interfaces(out)
}

fn linux_guest_inet4_interfaces(ifaces: Vec<HostInet4Iface>) -> Vec<HostInet4Iface> {
    let eth_host_name = ifaces
        .iter()
        .map(|iface| iface.name.as_str())
        .filter(|name| name.starts_with("en"))
        .min()
        .map(str::to_owned);

    let mut out = Vec::new();
    let mut have_lo = false;
    let mut have_eth = false;
    for mut iface in ifaces {
        if iface.name == "lo0" || iface.name == "lo" {
            if have_lo {
                continue;
            }
            have_lo = true;
            iface.name = "lo".to_owned();
            out.push(iface);
        } else if eth_host_name.as_deref() == Some(iface.name.as_str()) {
            if have_eth {
                continue;
            }
            have_eth = true;
            iface.name = "eth0".to_owned();
            out.push(iface);
        }
    }
    out
}

fn linux_if_indextoname(index: i32) -> Option<&'static str> {
    match index {
        1 => Some("lo"),
        2 => Some("eth0"),
        _ => None,
    }
}

fn linux_if_nametoindex(name: &str) -> Option<i32> {
    match name {
        "lo" => Some(1),
        "eth0" => Some(2),
        _ => None,
    }
}

/// Translate a host's BSD/Linux `ifa_flags` bitmask to the Linux `IFF_*` flag
/// values a guest expects in `ifr_flags`. Most low bits (UP/BROADCAST/DEBUG/
/// LOOPBACK/POINTOPOINT/RUNNING/NOARP/PROMISC) share values across BSD and
/// Linux; MULTICAST differs (BSD 0x8000 vs Linux 0x1000) — translate by name
/// via the host's `libc::IFF_*` so this is correct on every host.
/// Whether the `--fs host` trusted-dirfd fast lane is armed. Default ON;
/// `CARRICK_FS_TRUSTED_LANE=0` is the exact escape hatch (AGENTS.md: new work
/// ships on, with one switch that restores the historical path for
/// bisection). Read once per process.
fn trusted_fs_lane_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_FS_TRUSTED_LANE").as_deref() != Some(std::ffi::OsStr::new("0"))
    })
}

fn host_iff_to_linux(flags_host: u32) -> u16 {
    // The Linux IFF_* consts are u32 in carrick-abi; `ifr_flags` is a u16
    // field, and every translated bit (<= 0x1000) fits the narrow width.
    use crate::linux_abi::{
        LINUX_IFF_BROADCAST, LINUX_IFF_DEBUG, LINUX_IFF_LOOPBACK, LINUX_IFF_MULTICAST,
        LINUX_IFF_NOARP, LINUX_IFF_POINTOPOINT, LINUX_IFF_PROMISC, LINUX_IFF_RUNNING, LINUX_IFF_UP,
    };
    let h = flags_host as i32;
    let mut out: u16 = 0;
    let set = |out: &mut u16, host_bit: i32, linux_bit: u32| {
        if h & host_bit != 0 {
            *out |= linux_bit as u16;
        }
    };
    set(&mut out, libc::IFF_UP, LINUX_IFF_UP);
    set(&mut out, libc::IFF_BROADCAST, LINUX_IFF_BROADCAST);
    set(&mut out, libc::IFF_DEBUG, LINUX_IFF_DEBUG);
    set(&mut out, libc::IFF_LOOPBACK, LINUX_IFF_LOOPBACK);
    set(&mut out, libc::IFF_POINTOPOINT, LINUX_IFF_POINTOPOINT);
    set(&mut out, libc::IFF_RUNNING, LINUX_IFF_RUNNING);
    set(&mut out, libc::IFF_NOARP, LINUX_IFF_NOARP);
    set(&mut out, libc::IFF_PROMISC, LINUX_IFF_PROMISC);
    set(&mut out, libc::IFF_MULTICAST, LINUX_IFF_MULTICAST);
    out
}

/// Build one Linux `struct ifreq` (40 bytes) carrying `name` and an
/// `AF_INET` `ifr_addr` for `addr_be`. The trailing union bytes are zero.
fn linux_ifreq_inet4(name: &str, addr_be: [u8; 4]) -> LinuxIfreq {
    let mut ifr_name = [0u8; LINUX_IFNAMSIZ];
    let nb = name.as_bytes();
    let n = nb.len().min(LINUX_IFNAMSIZ - 1);
    ifr_name[..n].copy_from_slice(&nb[..n]);
    let mut ifr_ifru = [0u8; 24];
    // ifr_addr starts at offset 0 of union: sockaddr_in { family(2) port(2) addr(4) }.
    ifr_ifru[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
    ifr_ifru[4..8].copy_from_slice(&addr_be);
    LinuxIfreq { ifr_name, ifr_ifru }
}

struct RenameAtRequest {
    olddirfd: u64,
    oldpath: u64,
    newdirfd: u64,
    newpath: u64,
    flags: u64,
    target_tid: Option<crate::thread::ThreadId>,
}

impl SyscallDispatcher {
    fn record_fd_open_path(&self, fd: i32, path: String) {
        #[cfg(test)]
        FD_OPEN_PATH_INSERTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.captured_file_table()
            .write_fd_open_paths()
            .insert(fd, path);
    }

    fn lookup_recorded_fd_open_path(&self, fd: i32) -> Option<String> {
        #[cfg(test)]
        FD_OPEN_PATH_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.captured_file_table()
            .read_fd_open_paths()
            .get(&fd)
            .cloned()
    }

    pub fn register_mount(
        &mut self,
        point: impl Into<std::path::PathBuf>,
        vfs: Box<dyn crate::vfs::Vfs>,
    ) {
        self.fs.vfs_mounts_mut().mount(point, vfs);
    }

    pub(super) fn write_shared_supported(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return true;
        };
        let open = open_file.description.read();
        matches!(
            &*open,
            OpenDescription::EventFd { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::HostFile { .. }
                // In-memory regular files (incl. the unnamed O_TMPFILE inode and
                // overlay-backed `SyntheticFile`s) carry their `contents`/`offset`
                // behind the description's own `RwLock`, and the overlay backend
                // is interior-mutable (`set_file_contents(&self, …)`). The `write`
                // handler's File arm is therefore safe on the multi-threaded shared
                // path. Without this, a write(2) to such an fd from a *threaded*
                // guest (e.g. CPython) fell through `dispatch_threaded_shared` →
                // ENOSYS — `tempfile.TemporaryFile()` (O_TMPFILE) writes failed
                // only under multithreading, surfacing as 58 ERRORs in test_csv.
                | OpenDescription::File { .. }
                | OpenDescription::SyntheticFile { .. }
        )
    }

    fn record_unimplemented_virtual_file(
        reporter: &CompatReporter,
        path: &str,
    ) -> Option<DispatchOutcome> {
        if path.starts_with("/proc/") {
            reporter.record(CompatEvent::proc_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else if path.starts_with("/sys/") {
            // /sys paths that are synthesized must not be recorded as unimplemented;
            // they are handled by the synthetic open path before reaching ENOENT.
            if crate::vfs::sys::synthetic_file(path).is_some() {
                return None;
            }
            reporter.record(CompatEvent::sys_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else {
            None
        }
    }

    fn tty_ioctl_fd_kind(&self, fd: i32) -> Result<TtyFdKind, LinuxErrno> {
        if is_stdio_fd(fd) && !self.stdio_is_closed(fd) {
            Ok(TtyFdKind::Stdio)
        } else if self.fd_table_contains(fd) {
            Ok(TtyFdKind::Other)
        } else {
            Err(LINUX_EBADF)
        }
    }

    /// If `fd` is a pty master/slave end, return its role and the backing
    /// host fd in one fd-table lookup.
    fn pty_info(&self, fd: i32) -> Option<(crate::vfs::PtyRole, i32)> {
        self.open_file(fd)
            .and_then(|of| match &*of.description.read() {
                OpenDescription::HostPipe {
                    host_fd,
                    pty: Some(role),
                    ..
                } => Some((*role, host_fd.raw())),
                _ => None,
            })
    }

    pub(super) fn fd_is_valid(&self, fd: i32) -> bool {
        (is_stdio_fd(fd) && !self.stdio_is_closed(fd)) || self.fd_table_contains(fd)
    }

    /// Access modes (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) of every OTHER open file
    /// description that refers to the SAME underlying file as `fd` — i.e. a
    /// distinct `open(2)` of the same inode, not a `dup(2)` (which shares the
    /// description, identified by `Arc` pointer identity). Used by F_SETLEASE to
    /// enforce Linux's lease-conflict rules: "a write lease may be placed on a
    /// file only if there are no other open file descriptors for the file".
    ///
    /// Same-file identity is the host inode under `--fs host` (`fstat` dev+ino on
    /// the HostFile's kernel fd, which is fork-coherent), falling back to the
    /// guest open-path for the in-memory `File` backing. Descriptions that are
    /// not regular files (pipes/sockets/anon-inodes) never share inode identity
    /// with a regular-file lease target and are skipped.
    fn same_file_other_openers(&self, fd: i32) -> Vec<u64> {
        let Some(target) = self.open_file(fd) else {
            return Vec::new();
        };
        let target_id = {
            let desc = target.description.read();
            Self::lease_file_identity(&desc)
        };
        let Some(target_id) = target_id else {
            return Vec::new();
        };
        let mut others = Vec::new();
        for (other_fd, open_file) in self.captured_file_table().read_open_files().iter() {
            if *other_fd == fd {
                continue;
            }
            // A `dup(2)`/inherited fd shares the same description `Arc`; it is the
            // same open file description, not a separate opener, so it does not
            // conflict.
            if Arc::ptr_eq(&open_file.description, &target.description) {
                continue;
            }
            let desc = open_file.description.read();
            if Self::lease_file_identity(&desc).as_ref() == Some(&target_id) {
                others.push(desc.status_flags() & LINUX_O_ACCMODE);
            }
        }
        others
    }

    /// Inode-level identity used to decide whether two open descriptions name the
    /// same file for lease-conflict accounting. `None` for descriptions that
    /// cannot be a lease target's peer (pipes, sockets, anon-inodes).
    fn lease_file_identity(desc: &OpenDescription) -> Option<LeaseFileId> {
        match desc {
            OpenDescription::HostFile { host_fd, .. } => {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0 {
                    Some(LeaseFileId::Inode {
                        dev: st.st_dev as u64,
                        ino: st.st_ino as u64,
                    })
                } else {
                    None
                }
            }
            OpenDescription::File { path, .. } => Some(LeaseFileId::Path(path.clone())),
            _ => None,
        }
    }

    pub(super) fn release_hvpatch_classic_record_locks(
        &self,
        owner: crate::kernel::TaskKey,
        open_file: &OpenFile,
    ) {
        if self.execution_backend() != crate::page_profile::ExecutionBackend::HvPatch {
            return;
        }
        let file = {
            let description = open_file.description.read();
            Self::lease_file_identity(&description)
        };
        if let Some(file) = file {
            self.fs
                .classic_record_locks
                .release_file_owner(&file, LogicalRecordLockOwner::from(owner));
        }
    }

    /// True if `fd` was opened with `O_PATH`. Such a descriptor names a
    /// filesystem location but is not "open" for I/O: read/write/fchmod/fchown/
    /// ioctl/fgetxattr must all fail with EBADF (LTP open13). The flag is
    /// preserved in the description's status_flags at open time.
    pub(super) fn fd_is_o_path(&self, fd: i32) -> bool {
        self.open_file(fd)
            .is_some_and(|of| of.description.read().is_path())
    }

    /// Build a [`StatRecord`] from a real backing stat, applying the `mknod(2)`
    /// device-node override (S_IFCHR/S_IFBLK type + st_rdev) when `path` is a
    /// device marker. The marker's FULL guest mode (including the device type
    /// bits) is carried VERBATIM in `RealStat.mode` (the host backend stores it
    /// raw in `CARRICK_MODE_XATTR`); `from_real`/`linux_mode` masks those type
    /// bits off, so we recover the device type from `real.mode` here WITHOUT a
    /// second xattr read — the common stat hot path pays nothing. Only when the
    /// type bits actually name a device do we fetch the (rare) `st_rdev` xattr.
    /// A plain regular file (no device type bits) is returned unchanged.
    pub(super) fn stat_record_with_device(
        &self,
        path: &str,
        real: &crate::fs_backend::RealStat,
    ) -> StatRecord {
        let mut record = StatRecord::from_real(path, real);
        let type_bits = real.mode & LINUX_S_IFMT;
        if type_bits == LINUX_S_IFCHR || type_bits == LINUX_S_IFBLK {
            let rdev = self
                .fs
                .rootfs_vfs
                .overlay
                .device_node(path)
                .map(|(_, dev)| dev)
                .unwrap_or(0);
            record.apply_device_node(Some((type_bits, rdev)));
        }
        record
    }

    /// Give a layered-lookup result the identity of the host inode that
    /// actually backs it.
    ///
    /// The layered resolver owns EXISTENCE and kind — whiteouts, copy-up,
    /// cross-layer symlinks. It cannot own identity: `vfs::Metadata` and
    /// `RootFsMetadata` carry no inode, no link count and no timestamps, so
    /// `StatRecord::from_metadata` hashes the path instead. That is fine for a
    /// synthetic entry, but an entry only the immutable cache lower holds is a
    /// REAL host file — `open()` hands back its host fd, `fstat` reports its
    /// APFS inode and `getdents64` already publishes that inode as `d_ino`.
    /// A path hash here made `stat(p).st_ino != fstat(open(p)).st_ino`, which
    /// GNU coreutils `cp` reads as the source being replaced mid-copy
    /// (`cp: skipping file '…', as it was replaced while being copied` →
    /// LTP `execve02` TBROK once the cached lower was enabled for HvPatch).
    ///
    /// Kind agreement gates the adoption: a mismatch means the resolver landed
    /// on something other than the lower entry of that name, so its answer
    /// stands.
    pub(super) fn layered_identity_record(
        &self,
        path: &str,
        follow: bool,
        metadata: &RootFsMetadata,
    ) -> StatRecord {
        match self.fs.rootfs_vfs.immutable_lower_real_stat(path, follow) {
            Some(real) if real.kind == metadata.kind => StatRecord::from_real(path, &real),
            _ => StatRecord::from_metadata(metadata),
        }
    }

    /// `statx` twin of [`stat_record_with_device`](Self::stat_record_with_device):
    /// write a statx record from a real backing stat with the `mknod(2)`
    /// device-node override applied (S_IFCHR/S_IFBLK + stx_rdev_{major,minor}).
    fn write_statx_real_with_device(
        &self,
        memory: &mut impl GuestMemory,
        statxbuf: u64,
        path: &str,
        real: &crate::fs_backend::RealStat,
    ) -> DispatchOutcome {
        write_statx_record(memory, statxbuf, &self.stat_record_with_device(path, real))
    }

    fn path_stat_record(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Result<StatRecord, LinuxErrno> {
        if path.is_empty() {
            // AT_EMPTY_PATH stats the dirfd/fd itself; without it an empty
            // pathname is ENOENT — NOT a stat of the cwd (lstat02/stat02 case 2).
            if flags & LINUX_AT_EMPTY_PATH != 0 {
                return self.fd_stat_record(dirfd as i32);
            }
            return Err(LINUX_ENOENT);
        }

        // `--fs host` trusted-dirfd fast lane: `newfstatat(dirfd, name)` on
        // getdents output — the other half of the fs-walk hot loop — served
        // straight off the trusted host dirfd, skipping `resolve_at_path`
        // (anchor re-verify + parent validation) and the layered stat stack.
        // A single component can never carry the trailing-slash directory
        // forcing handled below.
        if let Some(result) = self.try_trusted_dirfd_stat(dirfd, path) {
            return result;
        }

        // A trailing "/" or "/." forces directory semantics on the FINAL
        // component: the symlink is FOLLOWED even under AT_SYMLINK_NOFOLLOW
        // (lstat("link/") of a symlink-to-dir reports the directory, not the
        // link), and a non-directory final is ENOTDIR. Capture this from the
        // raw path before resolve_at_path normalizes the slash away.
        let requires_dir = path.ends_with('/') || path.ends_with("/.");

        // Dispatch-level stat-cache fast path (default on; CARRICK_FS_STATCACHE=0
        // opts out): a repeat stat of a plain absolute path is served by one
        // revalidating fstatat through a cached, contained parent fd. Gated so
        // normalize(path) equals the resolved path (the cache key).
        if !requires_dir
            && dirfd == LINUX_AT_FDCWD
            && path.starts_with('/')
            && !path.starts_with("/proc")
            && !path.starts_with("/sys")
            && !path.split('/').any(|c| c == "..")
            // The cache answers from a contained parent fd and therefore skips
            // `resolve_at_path`, which is where `check_search_access` enforces
            // execute permission on every ancestor. Serving a hit to a caller
            // that has dropped privilege would let it stat through a directory
            // it cannot search — so the fast path is for DAC-override callers
            // only, the same guard `try_trusted_dirfd_stat` carries. That is
            // also the hot case: the overwhelming majority of guests run as
            // root, so the measured win is kept.
            && self.dac_overrides_permissions()
            && let Some(real) = self.fs.rootfs_vfs.overlay.stat_cache_lookup(path)
        {
            return Ok(self.stat_record_with_device(path, &real));
        }

        let path = self.resolve_at_path(dirfd, path)?;
        // Second stat-cache consult, AFTER dirfd resolution: find-style
        // dirfd-relative stats (newfstatat(dirfd, name) on getdents output)
        // failed the pre-resolution gate above and paid the full multi-walk
        // slow path — measured at ~17.6 host calls per guest stat on the
        // fs-walk workload. The resolved path is absolute by construction and
        // the same gates apply; a cache hit implies a non-symlink entry
        // (revalidation rejects S_IFLNK), so follow and no-follow coincide.
        if !requires_dir
            && !path.starts_with("/proc")
            && !path.starts_with("/sys")
            && !path.split('/').any(|c| c == "..")
            // Same DAC-override guard as the pre-resolution consult above.
            // `resolve_at_path` has run by here, but it resolves the path — it
            // does not re-check the leaf, and a cache hit still bypasses the
            // per-ancestor search checks for a dropped-privilege caller.
            && self.dac_overrides_permissions()
            && let Some(real) = self.fs.rootfs_vfs.overlay.stat_cache_lookup(&path)
        {
            return Ok(self.stat_record_with_device(&path, &real));
        }
        {
            // One context assembly serves both consults: it takes the proc lock
            // and snapshots the address space, so building it twice per stat
            // would double a hot path's cost.
            let proc_ctx = self.synthetic_proc_context(context);
            if let Some(contents) = crate::vfs::proc::synthetic_file(&path, &proc_ctx) {
                return Ok(StatRecord::synthetic(
                    &path,
                    contents.len(),
                    LINUX_S_IFREG | 0o444,
                ));
            }
            // `/proc/<pid>` and `/proc/<pid>/task` for a PEER exist only in the
            // kernel task graph — `Vfs::lookup` carries no context and answers
            // from Darwin's process table, which on HVPatch describes the one
            // carrier every Linux process is a thread of. Without this consult
            // `stat("/proc/<peer>")` was ENOENT while `cat /proc/<peer>/stat`
            // worked.
            if crate::vfs::proc::synthetic_dir_entries(&path, &proc_ctx).is_some() {
                return Ok(StatRecord::synthetic(&path, 0, LINUX_S_IFDIR | 0o555));
            }
        }
        if let Some(contents) = crate::vfs::sys::synthetic_file(&path) {
            return Ok(StatRecord::synthetic(
                &path,
                contents.len(),
                LINUX_S_IFREG | 0o444,
            ));
        }

        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0 || requires_dir;
        if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
            if requires_dir && real.kind != RootFsEntryKind::Directory {
                return Err(LINUX_ENOTDIR);
            }
            return Ok(self.stat_record_with_device(&path, &real));
        }
        if follow
            && let Some(link) = self.fs.rootfs_vfs.overlay.real_stat(&path, false)
            && link.kind == RootFsEntryKind::Symlink
        {
            return Err(LINUX_ENOENT);
        }

        let path = if follow {
            self.canonicalize_following(&path).unwrap_or(path)
        } else {
            path
        };
        if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
            return Ok(self.stat_record_with_device(&path, &real));
        }

        use crate::vfs::Vfs as _;
        if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
            if let Some(real) = m.vfs.real_stat(&m.full_path, follow) {
                return Ok(StatRecord::from_real(&path, &real));
            }
            if let Ok(md) = if follow {
                m.vfs.lookup(&m.full_path)
            } else {
                m.vfs.lookup_nofollow(&m.full_path)
            } {
                return Ok(StatRecord::from_metadata(&vfs_md_to_rootfs_md(&path, &md)));
            }
        }

        let lookup = if follow {
            self.fs.rootfs_vfs.lookup(&path)
        } else {
            self.fs.rootfs_vfs.lookup_nofollow(&path)
        };
        lookup
            .map(|md| self.layered_identity_record(&path, follow, &vfs_md_to_rootfs_md(&path, &md)))
    }

    fn statfs(
        &self,
        pathname: GuestPtr,
        buffer: GuestPtr,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(memory, pathname.0)?;
        // An empty pathname is ENOENT (statfs has no AT_EMPTY_PATH form). glibc
        // pathconf(path, _PC_LINK_MAX) validates the path via statfs, so
        // statfs("") must fail rather than succeed and yield LINK_MAX
        // (pathconf02 empty-string case).
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let path = self.resolve_at_path(LINUX_AT_FDCWD, &path)?;
        // statfs(2) follows symlinks; a symlink CYCLE is ELOOP. resolve_at_path
        // doesn't cap symlink depth, so canonicalize here to surface a cycle as
        // ELOOP (LTP statfs02/statvfs02). Other resolution errors fall through to
        // layered_metadata, which reports ENOENT/ENOTDIR/ENAMETOOLONG as before.
        let path = match self.canonicalize_following(&path) {
            Ok(resolved) => resolved,
            Err(e) if e == crate::linux_abi::LINUX_ELOOP => return Ok(DispatchOutcome::errno(e)),
            Err(_) => path,
        };
        // Consult the layered view (overlay/disk first, then rootfs) so
        // that files the guest created in the overlay are visible here
        // too — a rootfs-direct lookup would miss them.
        if let Err(errno) = self.layered_metadata(&path) {
            return Ok(DispatchOutcome::errno(errno));
        }
        Ok(write_statfs(memory, buffer.0))
    }

    fn fstatfs(&self, fd: Fd, buf: GuestPtr, memory: &mut impl GuestMemory) -> DispatchOutcome {
        if !self.fd_table_contains(fd.0) {
            return DispatchOutcome::errno(LINUX_EBADF);
        }
        write_statfs(memory, buf.0)
    }

    /// `EFBIG` iff growing a file to `length` would exceed this process's
    /// `RLIMIT_FSIZE` soft limit.
    ///
    /// truncate(2)/ftruncate(2): "EFBIG — the argument `length` is larger than
    /// the maximum file size", and getrlimit(2) defines RLIMIT_FSIZE as that
    /// maximum. carrick consulted no limit at all, so LTP truncate03's
    /// `{ TEST_FILE3, MAX_FSIZE*2, EFBIG }` case simply succeeded.
    ///
    /// DELIBERATE DIVERGENCE, stated plainly: Linux also generates SIGXFSZ
    /// alongside the errno. carrick returns the errno only. Raising a signal
    /// whose default disposition terminates the process is not something to
    /// add speculatively; it is tracked separately and gated on a probe that
    /// observes what the Docker oracle actually delivers.
    fn rlimit_fsize_errno(&self, length: i64) -> Option<LinuxErrno> {
        let limit = self
            .effective_resource_limit(carrick_abi::LINUX_RLIMIT_FSIZE)
            .rlim_cur;
        if limit == carrick_abi::LINUX_RLIM_INFINITY {
            return None;
        }
        (length as u64 > limit).then_some(crate::linux_abi::LINUX_EFBIG)
    }

    fn truncate(
        &self,
        context: &crate::kernel::KernelContext,
        pathname: GuestPtr,
        length: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let length = i64::from_ne_bytes(length.to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        let path = read_guest_c_string(memory, pathname.0)?;
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved = self.resolve_at_path(LINUX_AT_FDCWD, &path)?;
        if crate::vfs::is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context(context)) {
            return Ok(DispatchOutcome::errno(LINUX_EROFS));
        }
        // Layered metadata (overlay/disk first, then rootfs) — not rootfs-only,
        // so guest-created files are seen too.
        let kind = match self.layered_metadata(&resolved) {
            Ok(md) => md.kind,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        if kind == RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::errno(LINUX_EISDIR));
        }
        // DAC: truncating a file writes it, so a caller without write permission
        // is EACCES (truncate03 sets euid to nobody and truncates a 0444 file).
        // Root bypasses; `--fs memory` (no real owner/mode) falls through.
        if let Some(errno) = self.may_write(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(errno) = self.rlimit_fsize_errno(length) {
            return Ok(DispatchOutcome::errno(errno));
        }
        // Disk-backed: open the real file and ftruncate it. The whole rootfs
        // is materialised on the cap-std scratch under --fs host, so this
        // works for both rootfs and guest-created files. MemoryBackend has no
        // raw fd → EROFS (path-based truncate stays unsupported in-memory).
        match self
            .fs
            .rootfs_vfs
            .overlay
            .open_raw_fd(&resolved, true, false, false)
        {
            Some(host_fd) => {
                let err = unsafe { libc::ftruncate(host_fd, length as libc::off_t) }
                    .host_syscall_errno()
                    .err();
                unsafe { libc::close(host_fd) };
                if let Some(err) = err {
                    Ok(DispatchOutcome::errno(err))
                } else {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }
            None => Ok(DispatchOutcome::errno(LINUX_EROFS)),
        }
    }

    fn open_at_path<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<'_, M>,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        mode: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(&*cx.memory, pathname)?;
        self.open_at_path_string(
            cx.kernel,
            cx.thread.as_ref().map(|thread| thread.registry),
            dirfd,
            &path,
            flags,
            mode,
            cx.reporter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn open_at_path_string(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        dirfd: u64,
        path: &str,
        flags: u64,
        mode: u64,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let access = flags & LINUX_O_ACCMODE;
        if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        // Path opens can be much slower under HVF than native Linux because
        // every guest open is a trap plus host VFS work. Keep the guest's
        // RLIMIT_NOFILE at Docker's 1M default, but bound path-open pressure so
        // fd-fill tests reach the post-open assertion quickly while
        // descriptor-only duplication can still allocate within RLIMIT_NOFILE.
        if crate::dispatch::fs::state::PATH_OPEN_FD_PRESSURE
            .is_exhausted_by(self.captured_file_table().read_open_files().len())
        {
            return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
        }
        let writable_request = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        // Parse the open flags once; `flags` (raw u64) is still used below where
        // the access-mode bits or a raw mask (e.g. `flags & !O_CLOEXEC`) is needed.
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
        let want_excl = open_flags.contains(LinuxOpenFlags::EXCL);
        let want_trunc = open_flags.contains(LinuxOpenFlags::TRUNC);

        // O_TMPFILE: `pathname` names a directory; the result is an unnamed,
        // writable regular file. It's never linked anywhere — exactly the
        // "unlinked temp file" semantics tmpfile(3)/build tools rely on.
        // Requires write access (the kernel rejects O_RDONLY|O_TMPFILE with
        // EINVAL). (linkat(AT_EMPTY_PATH) to later materialize it is a separate
        // follow-up.)
        //
        // Back it with a REAL anonymous host fd when the backend can give us one
        // (--fs host: mkstemp + immediate unlink). A real kernel fd is shared by
        // fork(2) AND inherited across exec(2), so a forked+exec'd child's write
        // reaches the PARENT's read — which is what test_faulthandler's
        // tempfile.TemporaryFile()-to-a-subprocess pattern needs. An in-memory
        // File is PER-PROCESS (copied, not shared, across fork) so the child's
        // write never reached the parent → FAIL. MemoryBackend has no kernel fd
        // (open_anon_fd → None) and keeps the in-memory File fallback.
        if open_flags.contains(LinuxOpenFlags::TMPFILE) {
            if !writable_request {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let creds = self.cred_snapshot();
            let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
            if let Some(host_fd) = self.fs.rootfs_vfs.overlay.open_anon_fd(create_mode) {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let description = OpenDescription::HostFile {
                    host_fd: HostFdRef::new(host_fd),
                    metadata: RootFsMetadata {
                        path: Path::new("/__carrick_o_tmpfile").to_path_buf(),
                        kind: RootFsEntryKind::File,
                        mode: create_mode,
                        size: 0,
                    },
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable: true,
                };
                let open_file = OpenFile::from_open_description(
                    Arc::new(RwLock::new(description)),
                    linux_fd_flags_from_open_flags(flags),
                );
                return match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => Ok(DispatchOutcome::Returned { value: fd as i64 }),
                    Err(_) => Ok(DispatchOutcome::errno(linux_errno::EMFILE)),
                };
            }
            let description = OpenDescription::File {
                path: "/__carrick_o_tmpfile".to_string(),
                metadata: RootFsMetadata {
                    path: Path::new("/__carrick_o_tmpfile").to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                },
                contents: FileContents::dense(Vec::new()),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable: true,
            };
            return Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)));
        }

        // An empty pathname is never valid for open()/openat(): the kernel's
        // path walk requires at least one component and returns ENOENT for ""
        // (openat has no AT_EMPTY_PATH — that flag is only for the *at() metadata
        // syscalls). carrick's resolver would otherwise treat "" as the dirfd's
        // directory and wrongly succeed — test_ctypes' libc.open(b"", 0) and
        // glibc's own open("") both expect -1/ENOENT.
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        // Cached-lower absolute read lane: glibc/Node issue their loader,
        // locale, and package reads as absolute AT_FDCWD opens. When the fresh
        // sparse upper proves it cannot affect that path, open the immutable
        // lower file directly instead of paying resolve_at_path's repeated
        // intermediate layered lstat walks.
        if let Some(outcome) = self.try_immutable_lower_absolute_open(dirfd, path, flags) {
            return Ok(outcome);
        }
        // `--fs host` trusted-dirfd fast lane: a single-component,
        // non-creating openat through a trusted directory fd is served
        // DIRECTLY against the host dirfd — the fs-walk hot loop — skipping
        // `resolve_at_path` and the layered open stack entirely.
        if let Some(outcome) = self.try_trusted_dirfd_openat(dirfd, path, flags) {
            return Ok(outcome);
        }
        // A trailing slash forces directory semantics on the final component.
        // Linux's open(2): `O_CREAT` of a path that ends in `/` can NEVER
        // create a regular file there (a directory name is implied) and fails
        // EISDIR — whether the path exists as a dir, exists as a file, or
        // doesn't exist at all (verified against the Docker oracle). carrick's
        // path normalization strips the trailing slash, so a guest
        // `open(".../does_not_exist/", O_WRONLY|O_CREAT)` wrongly SUCCEEDED in
        // creating a file. shutil.copyfile relies on that EISDIR
        // (test_copyfile_nonexistent_dir). Note the raw guest bytes, before
        // resolution collapses the slash.
        let had_trailing_slash = path.len() > 1 && path.ends_with('/');
        let path = self.resolve_at_path(dirfd, path)?;
        if want_create && had_trailing_slash {
            return Ok(DispatchOutcome::errno(LINUX_EISDIR));
        }

        // Trace every open attempt. The per-backend `path_open` calls further
        // down only fire for the legacy synthetic/overlay/rootfs chain, so
        // VFS-mount opens (/dev, /proc, /sys) and the /proc/self/{exe,fd}
        // resolutions below were invisible to `carrick trace`.
        crate::probes::path_open(&path, 0, 0);

        // `/proc/self/fd/N` (and the pid/thread-self/curproc aliases) re-open the
        // file behind descriptor N — Linux lets you open() the magic symlink to
        // get a fresh fd referring to the same open file. Rosetta opens its
        // main-binary fd this way. Serve it by duplicating N (works for host-fd
        // backed files, which carry no guest path to re-resolve).
        if let Some(n) = proc_self_fd_number(&path) {
            // O_TRUNC on the reopened magic symlink truncates the underlying
            // (shared) in-memory inode — memfd_create01 reopens /proc/self/fd/N
            // with O_TRUNC and expects size 0. Applied before the dup and gated
            // by F_SEAL_SHRINK/GROW (a sealed truncate → EPERM, and the open
            // fails).
            if flags & LINUX_O_TRUNC != 0
                && let Some(open_file) = self.open_file(n)
            {
                let mut truncated_path: Option<String> = None;
                {
                    let mut open = open_file.description.write();
                    if let OpenDescription::File {
                        base,
                        path,
                        contents,
                        metadata,
                        writable,
                        ..
                    } = &mut *open
                        && *writable
                        && contents.len() != 0
                    {
                        if let Err(errno) = memfd_seal_resize_check(base.seals(), 0, contents.len())
                        {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        contents.truncate(0);
                        metadata.size = 0;
                        truncated_path = Some(path.clone());
                    }
                }
                // Sync the empty contents to the overlay backing so a later
                // fstat (which resolves the memfd's `/memfd:` path) reports 0.
                if let Some(path) = truncated_path {
                    let _ = self
                        .fs
                        .rootfs_vfs
                        .overlay
                        .set_file_contents(&path, Vec::new());
                }
            }
            return Ok(self.duplicate_fd(n, 0, flags & LINUX_O_CLOEXEC));
        }

        // `/proc/self/fdinfo/N` renders the fd's pos/flags/mnt_id/ino from the
        // live fd table — built here (it needs the fd table + a host lseek for
        // overlay files) and installed as a synthetic read-only file. ENOENT if
        // fd N isn't open.
        if let Some(n) = proc_self_fdinfo_number(&path) {
            return Ok(match self.fdinfo_bytes(n) {
                Some(bytes) => self.install_proc_synthetic_bytes(&path, bytes, flags),
                None => DispatchOutcome::errno(LINUX_ENOENT),
            });
        }

        // `/proc/<pid>/ns/<type>` is an nsfs magic link: open(2) resolves it to
        // an opaque namespace OBJECT, NOT by following the `<type>:[<inode>]`
        // readlink as a path. Intercept BEFORE canonicalize_following — which
        // would lstat→Symlink, readlink to "uts:[…]", JOIN it as a relative
        // component, and ENOENT. Install a 0-byte SyntheticFile (an nsfs fd is
        // not read(2) by the ioctl_ns tests); its recorded `path` is what the
        // NS_GET_* ioctl handler keys on. O_RDONLY|O_CLOEXEC are covered by
        // install_proc_synthetic_bytes / OpenDescriptionBase.
        if proc_ns_link(&path).is_some() {
            return Ok(self.install_proc_synthetic_bytes(&path, Vec::new(), flags));
        }

        // `/proc/self/exe` (and the thread-self/curproc/this aliases) are
        // symlinks to the running executable that Linux lets you open() directly
        // to get an fd on the backing file. Resolve to the executable path so
        // the open hits the real file. Apple's Rosetta opens this at startup
        // (and runs its licensing ioctl on the resulting fd); under translation
        // the executable path points at the bind-mounted Rosetta interpreter.

        // The self exe/cwd/root magic symlinks resolve to live dispatcher state
        // so an open() follows them to the real backing object (the executable
        // for exe, the working dir for cwd, the root for root) — `cat`/`ls`/
        // `realpath` of /proc/self/{cwd,root} were failing because only exe was
        // mapped here (the VFS readlink can't see the cwd).
        let mut path = match proc_self_magic_link(&path) {
            Some("exe") => {
                let exe = self.proc.lock().executable_path.clone();
                // Avoid the circular default (`executable_path` is itself
                // "/proc/self/exe" until an image is loaded).
                if exe.starts_with("/proc/") { path } else { exe }
            }
            Some("cwd") => self.cwd(),
            Some("root") => "/".to_string(),
            _ => path,
        };

        // Follow a trailing symlink (unless O_NOFOLLOW, or an exclusive create),
        // matching kernel path resolution: opening Alpine's /bin/uname must
        // resolve to /bin/busybox and return the busybox ELF, not the symlink's
        // 12-byte target string. Rosetta open()s its main x86 binary by name and
        // parses the result as an ELF, so a returned symlink corrupts it.
        // Best-effort: a non-symlink or not-yet-existent (O_CREAT) path is left
        // unchanged.
        if !(open_flags.contains(LinuxOpenFlags::NOFOLLOW) || (want_create && want_excl)) {
            // Follow the trailing symlink. A genuine symlink CYCLE surfaces here
            // as ELOOP (canonicalize_following caps at 40 hops); Linux open(2)
            // returns ELOOP for it, so propagate that rather than swallowing the
            // error and opening the cyclic path (libuv fs_file_loop). Other
            // errors (e.g. a not-yet-existent O_CREAT target, or a cross-mount
            // symlink we can't follow) are still ignored so open proceeds.
            // O_CREAT (without O_EXCL) follows a trailing DANGLING symlink and
            // creates its target — so resolve to the (possibly-missing) target
            // path here and let the create below make it. A plain open keeps the
            // strict resolver (a broken symlink is ENOENT).
            let resolved = if want_create {
                self.canonicalize_following_allow_missing(&path)
            } else {
                self.canonicalize_following(&path)
            };
            match resolved {
                Ok(resolved) => path = resolved,
                Err(e) if e == crate::linux_abi::LINUX_ELOOP => {
                    return Ok(DispatchOutcome::errno(e));
                }
                Err(_) => {}
            }
        } else if !(want_create && want_excl) {
            // O_NOFOLLOW is set (the `== 0` branch above did not match). A symlink
            // LEAF must NOT be followed: Linux open(2) returns ELOOP for a final
            // symlink component (ENOTDIR when O_DIRECTORY is also set, since a link
            // is not a directory). You cannot obtain a descriptor on the link
            // itself via open(2) without O_PATH, which carrick does not model.
            // Without this, carrick fell through and FOLLOWED the link, so Go's
            // os.Root walker — which opens each component O_NOFOLLOW and keys on
            // ELOOP to detect a symlink, readlinkat it, then re-walk with escape
            // checks — never saw the link, so containment/escape detection silently
            // broke (TestRootOpen_File/Directory/OpenRoot/Create, TestOpenInRoot,
            // TestRootSymlinkToRoot). Decide on the leaf KIND alone via a
            // non-following lstat (a DANGLING symlink is still ELOOP/ENOTDIR) — do
            // NOT probe the target. Placed before the FIFO/VFS/rootfs routing so a
            // symlink-to-FIFO leaf can't be followed either.
            if let Ok(md) = self.layered_lstat(&path)
                && md.kind == RootFsEntryKind::Symlink
            {
                if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                // O_PATH | O_NOFOLLOW on a symlink is the ONE way open(2) yields a
                // descriptor to the LINK ITSELF (not its target): the fd is opened
                // only for path operations, so readlinkat(fd,"")/fstatat(fd,"",
                // AT_EMPTY_PATH) operate on the link (readlinkat01 case 6). Model
                // it as an O_PATH File carrying the symlink's own lstat metadata;
                // every I/O op already rejects an O_PATH fd with EBADF.
                if open_flags.contains(LinuxOpenFlags::PATH) {
                    let open_file = OpenFile::from_open_description(
                        Arc::new(RwLock::new(OpenDescription::File {
                            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                            path: path.clone(),
                            metadata: md,
                            contents: FileContents::dense(Vec::new()),
                            offset: 0,
                            writable: false,
                        })),
                        linux_fd_flags_from_open_flags(flags),
                    );
                    let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
                        return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                    };
                    self.record_fd_open_path(fd, path.clone());
                    return Ok(DispatchOutcome::Returned { value: fd as i64 });
                }
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP));
            }
        }

        // VFS-mount routing. DevVfs serves /dev/*, ProcVfs serves
        // /proc/*, SysVfs serves /sys/*. The dispatcher converts each
        // VfsHandle variant into the matching OpenDescription, then
        // falls back to the legacy synthetic-then-overlay-then-rootfs
        // chain for any path no mount claims (or that the mount
        // returns ENOSYS for).
        // O_CREAT mode for a mount-served file: the requested bits masked by the
        // guest umask (the kernel applies `mode & ~umask`). Threaded into the
        // mount's open so e.g. glibc sem_open's `open(/dev/shm/sem.X, O_CREAT,
        // 0600)` materialises a 0600 node — without it the bind mount created
        // the file with mode 0, and a later O_RDWR reopen (multiprocessing
        // SemLock._rebuild in a forkserver child) hit EACCES.
        let vfs_create_mode = if want_create {
            (mode as u32 & 0o7777) & !(self.cred_snapshot().umask & 0o777)
        } else {
            0
        };
        // A write-intent open (O_CREAT or write access) of an OVERRIDABLE
        // single-file injection (/etc/services, /etc/resolv.conf) DETACHES the
        // injection: the read-only synthetic mount would otherwise EACCES on the
        // write. Record the override, then let the open fall through to the
        // writable overlay (after override_path, `resolve` returns None so
        // `try_vfs_open` no longer claims the path).
        if (writable_request || want_create)
            && let Some(m) = self.fs.vfs_mounts.resolve(&path)
            && m.vfs.overridable()
        {
            self.fs.vfs_mounts.override_path(&path);
        }
        // For inotify, note whether a VFS-mounted (bind/dev/proc) path already
        // existed before the open, so a created child emits IN_CREATE (not just
        // IN_OPEN). Only when something is watched, to avoid a wasted lookup.
        let vfs_preexisted = if want_create && !self.fs.inotify_registry.is_empty() {
            self.path_exists(&path)
        } else {
            true
        };
        // `--fs host` trusted-dirfd lane SEED: an O_DIRECTORY read-only open
        // outside every mount gets ONE contained openat + containment proof —
        // no eager per-child materialization, no double kind probe below —
        // and carries the trusted host dirfd the walk's dirfd-relative
        // recursion rides on. Gated on O_DIRECTORY so a regular-file open
        // never pays a wasted directory probe (fts/opendir walks always pass
        // it); gated on root because the DAC/O_NOATIME checks further down
        // are no-ops only for euid 0.
        if !want_create
            && !want_trunc
            && !writable_request
            && open_flags.contains(LinuxOpenFlags::DIRECTORY)
            && self.cred_snapshot().euid.is_root()
            && let Some(outcome) = self.try_open_trusted_dir(&path, flags)
        {
            return Ok(outcome);
        }
        // Validate O_DIRECTORY before a mount can apply O_TRUNC/O_CREAT. Linux
        // rejects a non-directory without mutating it; checking only after
        // `try_vfs_open` had already truncated or created bind-mounted files.
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            match self.inotify_path_kind(&path) {
                Some(false) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                None if want_create => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                _ => {}
            }
        }
        let vfs_outcome =
            self.try_vfs_open(context, registry, &path, access, flags, vfs_create_mode);
        match vfs_outcome {
            VfsOpenAttempt::Installed(fd) => {
                // VFS mounts return before the overlay/rootfs O_DIRECTORY gate
                // below. Enforce it here too: GNU mv opens its destination with
                // O_PATH|O_DIRECTORY to decide whether to append the source
                // basename. Accepting a regular bind-mounted file made mv try
                // `dest/source` and left configure's conftest files stale.
                let directory_errno = if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
                    match self.fd_stat_record(fd) {
                        Ok(record) if record.mode & LINUX_S_IFMT == LINUX_S_IFDIR => None,
                        Ok(_) => Some(LINUX_ENOTDIR),
                        Err(errno) => Some(errno),
                    }
                } else {
                    None
                };
                if let Some(errno) = directory_errno {
                    let removed = self.captured_file_table().write_open_files().remove(&fd);
                    self.captured_file_table().write_fd_open_paths().remove(&fd);
                    if let Some(open_file) = removed {
                        self.release_hvpatch_classic_record_locks(context.task().key(), &open_file);
                        self.close_open_file_and_free_pty(&open_file);
                    }
                    self.note_fd_closed(fd);
                    if (0..3).contains(&fd) {
                        // Installation reused a deliberately closed stdio slot
                        // and cleared its marker. The rejected open must leave
                        // that slot closed, just as if no open had occurred.
                        self.captured_file_table().lock_closed_stdio()[fd as usize] = true;
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
                // inotify: a VFS-mount open bypasses the rootfs tail below, so
                // synthesize its events here. A freshly-created child is
                // IN_CREATE on the parent dir; every successful open is IN_OPEN
                // on the object. The fd's path is recorded by try_vfs_open's
                // install path already (host-backed) or below for read hooks.
                if !self.fs.inotify_registry.is_empty()
                    && !crate::fanotify::internal_open_in_progress()
                {
                    let is_dir = self.inotify_path_kind(&path).unwrap_or(false);
                    if want_create && !vfs_preexisted {
                        self.inotify_child(&path, carrick_abi::LINUX_IN_CREATE, is_dir);
                    }
                    self.fs
                        .inotify_registry
                        .notify_self(&path, carrick_abi::LINUX_IN_OPEN, is_dir);
                    // Ensure read/write/close hooks can recover this fd's path.
                    if self.lookup_recorded_fd_open_path(fd).is_none() {
                        self.record_fd_open_path(fd, path.clone());
                    }
                }
                // Same for fanotify. Kept as its own block (rather than folded
                // into the inotify one) because it must fire when a fanotify
                // mark exists and NO inotify watch does — the two registries
                // are independent, and sharing the `is_empty` guard would make
                // fanotify silently depend on an unrelated inotify watch.
                if !self.fs.fanotify_registry.is_empty()
                    && !crate::fanotify::internal_open_in_progress()
                {
                    self.fanotify_notify(context, &path, carrick_abi::LinuxFanotifyEvents::OPEN);
                    if self.lookup_recorded_fd_open_path(fd).is_none() {
                        self.record_fd_open_path(fd, path.clone());
                    }
                }
                return Ok(DispatchOutcome::Returned { value: fd as i64 });
            }
            VfsOpenAttempt::Errno(errno) => {
                return Ok(DispatchOutcome::errno(errno));
            }
            VfsOpenAttempt::FallThrough => {}
        }

        // DAC on open (--fs host, non-root): an existing file needs the
        // requested access (read unless O_WRONLY, write for O_WRONLY/O_RDWR)
        // plus search on every ancestor; creating a new file needs write+search
        // on the parent dir. Root bypasses (handled in dac_check).
        if let Some(errno) = self.dac_open_check(&path, access, want_create) {
            return Ok(DispatchOutcome::errno(errno));
        }

        // O_NOATIME may only be requested by the file's owner (or a holder of
        // CAP_FOWNER, modeled here as euid==0). Linux's do_dentry_open rejects a
        // non-owner with EPERM (fs/open.c -> inode_owner_or_capable). Only
        // enforce when the backing file exists and reports a real owner; a
        // not-yet-existent O_CREAT target has no owner to compare against.
        if open_flags.contains(LinuxOpenFlags::NOATIME) {
            let creds = self.cred_snapshot();
            if !creds.euid.is_root()
                && let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, true)
                && real.uid != creds.euid
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
        }

        // FIFO (named pipe): open the REAL host FIFO in NON-BLOCKING mode and
        // model it as a HostPipe. A blocking host open of a writer-less
        // O_RDONLY FIFO would wedge the single dispatcher thread; opening
        // O_NONBLOCK returns immediately and the guest's blocking read/write
        // then parks on the kqueue WaitOnFds path (with the dispatcher lock
        // released). An O_RDWR FIFO is bidirectional (e.g. LTP select01).
        if self.fs.rootfs_vfs.overlay.may_have_fifo_nodes()
            && let Ok(md) = self.layered_metadata(&path)
            && md.kind == RootFsEntryKind::Fifo
        {
            // An existing FIFO + O_CREAT|O_EXCL must fail like the kernel.
            if want_create && want_excl {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // Linux O_ACCMODE is 0=RDONLY, 1=WRONLY, 2=RDWR.
            let access_idx = (access & LINUX_O_ACCMODE) as u32;
            match self
                .fs
                .rootfs_vfs
                .overlay
                .open_fifo_nonblock(&path, access_idx)
            {
                Some(host_fd) => {
                    // Track this FIFO end for kernel-backed writer-close EOF
                    // readiness (macOS won't report it — see dispatch::fifo_beacon).
                    crate::dispatch::fifo_beacon::register_open(host_fd, access_idx);
                    crate::dispatch::net::set_host_nonblocking(host_fd);
                    let description = OpenDescription::HostPipe {
                        // A named FIFO's two ends are opened separately but share
                        // ONE on-disk inode, so the host inode is a join key both
                        // ends agree on (the FASYNC arm/trigger across ends works
                        // for FIFOs as it does for anonymous pipes).
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        is_read_end: access != LINUX_O_WRONLY,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                        pty: None,
                        bidirectional: access == LINUX_O_RDWR,
                        write_kind: HostWriteKind::PipeLike,
                    };
                    let open_file = OpenFile::from_open_description(
                        Arc::new(RwLock::new(description)),
                        linux_fd_flags_from_open_flags(flags),
                    );
                    let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
                        return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                    };
                    self.record_fd_open_path(fd, path.clone());
                    return Ok(DispatchOutcome::Returned { value: fd as i64 });
                }
                // The non-blocking open failed — most commonly O_WRONLY with no
                // reader (ENXIO, the correct O_NONBLOCK errno). A blocking
                // O_WRONLY open that should wait for a reader is a known
                // unimplemented case (it would block the dispatcher).
                None => return Ok(DispatchOutcome::errno(linux_errno::ENXIO)),
            }
        }

        // /proc/* and /sys/* synthetic file opens now flow through
        // ProcVfs / SysVfs (mounted in `SyscallDispatcher::new`). Any
        // unknown /proc or /sys path returns ENOSYS from the mount
        // and falls through to the overlay+rootfs lookup below, which
        // handles directory entries like /proc itself.

        if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
            return Ok(outcome);
        }
        // Layered overlay+rootfs lookup with full openat semantics
        // (O_CREAT/O_EXCL/O_TRUNC, write-promotion of rootfs-only
        // files) lives in RootFsVfs::open_for_dispatch.
        let dispatch_result = self.fs.rootfs_vfs.open_for_dispatch(
            &path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        );
        // USDT probe: every guest path-level open, with the resolved
        // path string and resulting size/errno. Lets dtrace operators
        // see exactly what bytes each forked carrick process is
        // serving for paths like /etc/hosts during the apt-resolver
        // run.
        match &dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File { contents, .. }) => {
                crate::probes::path_open(&path, contents.len() as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { .. }) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Err(errno) => {
                crate::probes::path_open(&path, 0, errno.get());
            }
        }
        // O_DIRECTORY: opening anything that isn't a directory fails ENOTDIR
        // (LTP open08). Close a host fd the dispatch already opened so it
        // doesn't leak.
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            match &dispatch_result {
                Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. }) => {
                    unsafe {
                        libc::close(*host_fd);
                    }
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                Ok(crate::vfs::rootfs::OpenDispatchResult::File { .. }) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile { .. }) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                _ => {}
            }
        }
        // Remember the guest path so readlink(/proc/self/fd/N) can recover it
        // (host-fd-backed descriptions store no path of their own).
        let record_path = path.clone();
        // Whether this open materialized a new file (O_CREAT on a missing path):
        // the inotify hook below emits IN_CREATE for it vs IN_OPEN for an
        // existing-file open. Captured before the match consumes `dispatch_result`.
        let inotify_created = matches!(
            &dispatch_result,
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate)
        );
        let description = match dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents: FileContents::dense(contents),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents: FileContents::shared_backed(contents.base, contents.dirty, contents.len),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            }) => {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                OpenDescription::HostFile {
                    host_fd: HostFdRef::new(host_fd),
                    metadata,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { metadata, entries }) => {
                // A directory can never be the target of a write-intent open
                // (O_WRONLY/O_RDWR) nor of an O_CREAT open — Linux returns
                // EISDIR in both cases (a directory is never "created" by
                // open(), and its dentry rejects write access). O_RDONLY
                // without O_CREAT still yields a readable directory fd.
                if writable_request || want_create {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::Directory {
                    path,
                    metadata,
                    entries,
                    offset: 0,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    // The trusted lane (`try_open_trusted_dir`) already
                    // declined this open (mount/inotify/backend), so the
                    // description keeps the historical untrusted model.
                    trusted_host_dir: None,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                // O_CREAT path: validate the parent directory exists,
                // create the empty overlay entry, return a writable
                // File description.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    if !self.path_is_directory(&parent_str) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    }
                }
                // O_CREAT mode: the requested mode masked by the guest umask,
                // exactly like the kernel (`mode & ~umask`). Only applies to a
                // freshly-created file (this branch only runs when no file
                // existed). Previously hardcoded to 0o644, so creat(f, 0777)
                // always yielded 644 and umask had no effect.
                let creds = self.cred_snapshot();
                let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                let metadata = RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                };
                // Disk-backed overlay (--fs host): create + open a real
                // host fd so the new file is fork-shareable. Falls back
                // to the in-memory File for MemoryBackend.
                // A new file is owned by the creating process's effective
                // uid/gid (Linux semantics). carrick stamps it so a guest that
                // setuid()'d to e.g. "nobody" before creating sees the right
                // owner. Root (0,0) is the default, so only stamp non-root.
                let create_uid = creds.fsuid;
                let mut create_gid = creds.fsgid;
                // A new file in a SETGID directory inherits THAT directory's
                // group, not the creator's fsgid (creat08/open10/mknod05). The
                // file's own setgid bit is carried by `mode`; here we only fix
                // the owning group.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    if let Ok(pmd) = self.layered_metadata(&parent_str)
                        && pmd.mode & 0o2000 != 0
                        && let Some((_, pgid)) = self.fs.rootfs_vfs.overlay.get_owner(&parent_str)
                    {
                        create_gid = pgid;
                    }
                }
                let stamp_owner = !create_uid.is_root() || !create_gid.is_root();
                if let Some(host_fd) = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .open_raw_fd(&path, true, true, want_trunc)
                {
                    crate::dispatch::net::set_host_nonblocking(host_fd);
                    // The host create used the host process umask; force the
                    // guest-requested mode onto the new file.
                    let _ = self.fs.rootfs_vfs.overlay.set_mode(&path, create_mode);
                    if stamp_owner {
                        let _ = self.fs.rootfs_vfs.overlay.set_owner(
                            &path,
                            Some(create_uid),
                            Some(create_gid),
                        );
                    }
                    OpenDescription::HostFile {
                        host_fd: HostFdRef::new(host_fd),
                        metadata,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                        // A newly-created file's GUEST writability is its
                        // access mode, NOT the O_CREAT flag: O_RDONLY|O_CREAT
                        // creates the file but a later write/ftruncate on the
                        // fd is EINVAL (ftruncate03 read_fd). The host fd is
                        // still opened RW above so creation/overlay works.
                        writable: writable_request,
                    }
                } else {
                    if self.fs.rootfs_vfs.overlay.create_file(&path).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let _ = self.fs.rootfs_vfs.overlay.set_mode(&path, create_mode);
                    if stamp_owner {
                        let _ = self.fs.rootfs_vfs.overlay.set_owner(
                            &path,
                            Some(create_uid),
                            Some(create_gid),
                        );
                    }
                    OpenDescription::File {
                        path,
                        metadata,
                        contents: FileContents::dense(Vec::new()),
                        offset: 0,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                        // Guest writability follows the access mode, not
                        // O_CREAT (O_RDONLY|O_CREAT → read-only fd).
                        writable: writable_request,
                    }
                }
            }
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };

        let needs_recorded_path = !matches!(
            &description,
            OpenDescription::File { .. } | OpenDescription::Directory { .. }
        );
        let opened_is_dir = matches!(&description, OpenDescription::Directory { .. });
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(description)),
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        // Always record the path for the inotify AND fanotify read/write/close
        // hooks, even for in-memory File/Directory descriptions (they otherwise
        // skip recording); the recorded entry is dropped when the fd closes.
        // This is the only path by which a later read(2)/write(2)/close(2)
        // recovers the watched guest path.
        //
        // The fanotify half is load-bearing for a DIRECTORY: under `--fs host`
        // a regular file gets a `HostFile` description (which records anyway)
        // but a directory gets `Directory`, which does not. Omitting fanotify
        // here silently dropped `FAN_CLOSE_NOWRITE` for `close(2)` on a marked
        // directory — fanotify02's eighth and final event — while every event
        // on a file still worked, which is exactly the kind of gap that reads
        // as "delivery works" until one case disagrees.
        if needs_recorded_path
            || !self.fs.inotify_registry.is_empty()
            || !self.fs.fanotify_registry.is_empty()
        {
            self.record_fd_open_path(fd, record_path.clone());
        }
        // inotify: O_CREAT that created the file is IN_CREATE on the parent dir;
        // any other successful open is IN_OPEN on the object itself (and, for a
        // directory open, IN_OPEN|IN_ISDIR). The registry fast-exits when nothing
        // is watched, so this is ~free in the common case.
        if !self.fs.inotify_registry.is_empty() && !crate::fanotify::internal_open_in_progress() {
            if inotify_created {
                self.inotify_child(&record_path, carrick_abi::LINUX_IN_CREATE, opened_is_dir);
            }
            // Any successful open is IN_OPEN, delivered BOTH to a watch on the
            // object itself (self) AND to a watch on its parent directory (child,
            // name = basename) — the kernel reports a child's open to the dir
            // watch with the child's name (inotify02 watches the dir and asserts
            // IN_OPEN with name=test_file1). A create also "opens" the new file.
            // Parent (child) event precedes the self event, matching Linux
            // fsnotify ordering (inotify10).
            self.inotify_child(&record_path, carrick_abi::LINUX_IN_OPEN, opened_is_dir);
            self.inotify_self(&record_path, carrick_abi::LINUX_IN_OPEN);
        }
        // fanotify FAN_OPEN. One event per open regardless of how many marks
        // match; `opened_is_dir` is passed through because it is already known
        // here and gates FAN_ONDIR.
        self.fanotify_notify_kind(
            context,
            &record_path,
            carrick_abi::LinuxFanotifyEvents::OPEN,
            opened_is_dir,
        );
        if inotify_created {
            self.dnotify_child(context, &record_path, LinuxDnotifyMask::CREATE);
        }
        Ok(DispatchOutcome::Returned { value: fd as i64 })
    }

    // === Trusted-dirfd fast lane (`--fs host`) ===
    //
    // A directory opened through the host backend's contained fast path
    // carries a TRUSTED host dirfd (see [`TrustedHostDir`]): its real host
    // path byte-equals sandbox_root + guest path, so a SINGLE-component child
    // name resolved against it with `O_NOFOLLOW` cannot escape (no "..", no
    // symlink following) — structural containment, NO per-op `F_GETPATH`.
    // That serves the fs-walk hot loop (openat / newfstatat / faccessat on
    // getdents output, and getdents itself) at host-syscall parity instead of
    // paying the per-op dispatch resolution stack (anchor re-verify,
    // validate_parents_fast, canonicalize probe, layered stat). Trust only
    // ever flows from the contained fast path; the VFS synthetic mounts and
    // the memory backend keep today's paths.

    /// The single path component `path` names, when the trusted-dirfd lane
    /// may serve it: non-empty, no '/', not "."/"..", within NAME_MAX, and
    /// ASCII — a non-ASCII leaf could be a Unicode alias of a
    /// differently-normalized on-disk name, which only the slow path's
    /// byte-exact readdir guard can reject.
    pub(super) fn trusted_lane_component(path: &str) -> Option<&str> {
        if path.is_empty()
            || path.len() > 255
            || !path.is_ascii()
            || path == "."
            || path == ".."
            || path.contains('/')
        {
            return None;
        }
        Some(path)
    }

    /// The guest directory path + trusted host dirfd behind guest fd `dirfd`,
    /// when its open description is a trusted Directory. `None` for AT_FDCWD,
    /// negative fds, and every untrusted description.
    pub(super) fn trusted_dir_of(&self, dirfd: u64) -> Option<(String, TrustedHostDir)> {
        let fd = dirfd as i32;
        if fd < 0 {
            return None; // AT_FDCWD and friends
        }
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::Directory {
                path,
                trusted_host_dir: Some(trusted),
                ..
            } => Some((path.clone(), trusted.clone())),
            _ => None,
        }
    }

    /// Compose `dir/name` and gate it for the trusted lane: the child must be
    /// outside every synthetic tree and VFS mount (a bind mount or /proc /sys
    /// /dev target under the trusted dir is claimed by its mount, never by
    /// the scratch). `None` ⇒ the caller takes the full path.
    pub(super) fn trusted_child_path(&self, dir: &str, name: &str) -> Option<String> {
        let full = if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        };
        if full.starts_with("/proc") || full.starts_with("/sys") || full.starts_with("/dev") {
            return None;
        }
        if self.fs.vfs_mounts.resolve(&full).is_some() {
            return None;
        }
        Some(full)
    }

    /// Direct absolute read from an upper-absent immutable cached lower.
    /// Every shape whose Linux semantics need the full resolver (relative
    /// dirfds, final-component nofollow, creates/writes, directories, mounts,
    /// chroot, DAC/inotify) fails closed to the historical path.
    fn try_immutable_lower_absolute_open(
        &self,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        use std::os::fd::IntoRawFd as _;

        if !trusted_fs_lane_enabled()
            || dirfd != LINUX_AT_FDCWD
            || !path.starts_with('/')
            || !self.cred_snapshot().euid.is_root()
            || !self.fs.inotify_registry.is_empty()
        {
            return None;
        }
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        if flags & LINUX_O_ACCMODE != LINUX_O_RDONLY
            || open_flags.intersects(
                LinuxOpenFlags::CREAT
                    | LinuxOpenFlags::TRUNC
                    | LinuxOpenFlags::EXCL
                    | LinuxOpenFlags::TMPFILE
                    | LinuxOpenFlags::PATH
                    | LinuxOpenFlags::DIRECTORY
                    | LinuxOpenFlags::NOFOLLOW,
            )
        {
            return None;
        }
        if self
            .captured_fs_context()
            .chroot_root()
            .as_deref()
            .is_some_and(|root| root != "/")
            || path.starts_with("/proc")
            || path.starts_with("/sys")
            || path.starts_with("/dev")
            || self.fs.vfs_mounts.resolve(path).is_some()
        {
            return None;
        }
        let (file, metadata) = match self.fs.rootfs_vfs.open_immutable_lower_readonly(path) {
            crate::fs_backend::ImmutableHostFileOpen::Served { file, metadata } => (file, metadata),
            crate::fs_backend::ImmutableHostFileOpen::Missing => {
                return Some(DispatchOutcome::errno(LINUX_ENOENT));
            }
            crate::fs_backend::ImmutableHostFileOpen::Fallback => return None,
        };
        let raw = file.into_raw_fd();
        crate::dispatch::net::set_host_nonblocking(raw);
        crate::probes::path_open(path, metadata.size as u64, 0);
        let description = OpenDescription::HostFile {
            host_fd: HostFdRef::new(raw),
            metadata,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            writable: false,
        };
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(description)),
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        self.record_fd_open_path(fd, path.to_owned());
        Some(DispatchOutcome::Returned { value: fd as i64 })
    }

    /// `--fs host` trusted directory open — the lane SEED. A plain read-only
    /// directory open outside every mount is served by ONE contained
    /// `openat(O_DIRECTORY)` with a byte-exact containment proof
    /// ([`FsBackend::open_trusted_dir_fd`]), skipping `open_for_dispatch`'s
    /// eager per-child directory materialization entirely (entries stream on
    /// the first getdents64). `find`-style walks open the walk root once by
    /// absolute path, then recurse `openat(dirfd, name)` through
    /// [`Self::try_trusted_dirfd_openat`], which keeps every served child
    /// directory on the lane. Every dispatch-level gate (DAC, O_NOATIME, the
    /// FIFO interception) has already run when this is consulted.
    fn try_open_trusted_dir(&self, path: &str, flags: u64) -> Option<DispatchOutcome> {
        use std::os::fd::IntoRawFd;
        // Default ON with an exact `=0` escape hatch (AGENTS.md): this is the
        // SEED of the whole trusted-dirfd lane — with no directory ever
        // trusted, every dependent fast path (`try_trusted_dirfd_openat`,
        // `try_trusted_dirfd_stat`, the F_OK lane, streamed getdents) falls
        // back to the resolving path on its own, so one switch bisects the
        // entire lane against the historical behaviour.
        if !trusted_fs_lane_enabled() {
            return None;
        }
        // Inotify hooks must keep today's path; chroot rebases absolute
        // resolution, so keep the lane out of it.
        if !self.fs.inotify_registry.is_empty() {
            return None;
        }
        if self
            .captured_fs_context()
            .chroot_root()
            .as_deref()
            .is_some_and(|root| root != "/")
        {
            return None;
        }
        if path.starts_with("/proc") || path.starts_with("/sys") || path.starts_with("/dev") {
            return None;
        }
        if self.fs.vfs_mounts.resolve(path).is_some() {
            return None;
        }
        let trusted = if let Some(rootfs) = self.fs.rootfs_vfs.rootfs.as_ref() {
            // A lower anchor is exact only while the sparse upper contributes
            // nothing at this directory. Sample the fork-shared structural
            // generation around both proofs so a concurrent mutation makes
            // the anchor stale before it can serve a child.
            let generation = crate::fs_resolve_cache::current_generation();
            if !self.fs.rootfs_vfs.overlay.fast_nofollow_absent(path) {
                return None;
            }
            let host_fd = rootfs.open_trusted_dir_fd(path)?;
            if crate::fs_resolve_cache::current_generation() != generation {
                return None;
            }
            TrustedHostDir::immutable_lower(HostFdRef::new(host_fd.into_raw_fd()), generation)
        } else {
            let host_fd = self.fs.rootfs_vfs.overlay.open_trusted_dir_fd(path)?;
            TrustedHostDir::new(HostFdRef::new(host_fd.into_raw_fd()))
        };
        crate::probes::path_open(path, 0, 0);
        let metadata = RootFsMetadata {
            path: Path::new(path).to_path_buf(),
            kind: RootFsEntryKind::Directory,
            // Parity with open_for_dispatch's Directory arm, which reports a
            // fixed 0o755 on directory open descriptions.
            mode: 0o755,
            size: 0,
        };
        let description = OpenDescription::Directory {
            path: path.to_owned(),
            metadata,
            entries: Vec::new(),
            offset: 0,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            trusted_host_dir: Some(trusted),
        };
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(description)),
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        Some(DispatchOutcome::Returned { value: fd as i64 })
    }

    /// Single-component `openat` through a TRUSTED host dirfd: service the
    /// open DIRECTLY against the host dirfd (one openat + fstat + one
    /// flistxattr-gated xattr peek), skipping `resolve_at_path` and the
    /// layered open stack. `None` ⇒ take the full path. A served directory is
    /// itself trusted (the walk's recursion stays on the lane); symlink
    /// children (`ELOOP`), FIFOs, marker nodes, and every surprise fall back
    /// to the exact slow path.
    fn try_trusted_dirfd_openat(
        &self,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        // Creating/truncating opens and the special modes keep the full path
        // (sandboxed parent creation, exact O_TRUNC, O_TMPFILE/O_PATH
        // modeling).
        if open_flags.intersects(
            LinuxOpenFlags::CREAT
                | LinuxOpenFlags::TRUNC
                | LinuxOpenFlags::EXCL
                | LinuxOpenFlags::TMPFILE
                | LinuxOpenFlags::PATH,
        ) {
            return None;
        }
        let name = Self::trusted_lane_component(path)?;
        let (dir_path, trusted_dir) = self.trusted_dir_of(dirfd)?;
        if !trusted_dir.namespace_is_current() {
            return None;
        }
        let host_dir = &trusted_dir.fd;
        let full = self.trusted_child_path(&dir_path, name)?;
        // inotify watches need the slow path's IN_OPEN bookkeeping; a
        // non-root euid needs its DAC checks (root — the overwhelming
        // default — bypasses both DAC and search permission).
        if !self.fs.inotify_registry.is_empty() || !self.cred_snapshot().euid.is_root() {
            return None;
        }
        let access = flags & LINUX_O_ACCMODE;
        let write = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        let name_c = std::ffi::CString::new(name).ok()?;
        // Mirrors `fast_open_for_guest`: O_NONBLOCK so a racing FIFO can
        // never block the dispatcher; O_NOFOLLOW so a symlink child is ELOOP
        // (the slow path re-roots its target under the GUEST root); O_NOCTTY
        // defensively; RW-first even for read-only requests (HVF rejects
        // hv_vm_map of a MAP_SHARED file VMA whose backing fd caps
        // max-protection at read).
        let base = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY;
        let last_errno = || std::io::Error::last_os_error().raw_os_error();
        // A read-only O_DIRECTORY request (every walker's dir open) needs no
        // RW-first probe: directories always refuse O_RDWR with EISDIR, so
        // the probe was a guaranteed wasted openat. Open the directory
        // directly; the kernel's O_DIRECTORY gives authoritative ENOTDIR.
        let raw = if open_flags.contains(LinuxOpenFlags::DIRECTORY) && !write {
            let raw = unsafe {
                libc::openat(
                    host_dir.raw(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | base,
                )
            };
            if raw < 0 {
                // ONLY a missing name is authoritative. ENOTDIR here does NOT
                // mean the guest's answer is ENOTDIR: this probe carries
                // O_NOFOLLOW, and macOS reports ENOTDIR (not ELOOP) for a
                // SYMLINK-to-directory child under O_DIRECTORY|O_NOFOLLOW —
                // which the guest, having asked for neither O_NOFOLLOW nor a
                // refusal, must see FOLLOWED to the target directory. Serving
                // ENOTDIR broke test_glob's symlink cases. Everything except
                // ENOENT falls back to the resolving slow path.
                return match last_errno() {
                    Some(libc::ENOENT) => Some(DispatchOutcome::errno(LINUX_ENOENT)),
                    _ => None,
                };
            }
            raw
        } else {
            let mut raw =
                unsafe { libc::openat(host_dir.raw(), name_c.as_ptr(), libc::O_RDWR | base, 0) };
            if raw < 0 {
                if last_errno() == Some(libc::ELOOP) {
                    return None; // symlink child → full path (guest O_NOFOLLOW → ELOOP there)
                }
                if write {
                    // A missing name is AUTHORITATIVE under a trusted dir: the
                    // scratch is the merged truth, no mount claims the path,
                    // and O_CREAT was excluded above. Every other error →
                    // slow path.
                    return if last_errno() == Some(libc::ENOENT) {
                        Some(DispatchOutcome::errno(LINUX_ENOENT))
                    } else {
                        None
                    };
                }
                raw = unsafe {
                    libc::openat(host_dir.raw(), name_c.as_ptr(), libc::O_RDONLY | base, 0)
                };
                if raw < 0 {
                    return if last_errno() == Some(libc::ENOENT) {
                        Some(DispatchOutcome::errno(LINUX_ENOENT))
                    } else {
                        None
                    };
                }
            }
            raw
        };
        // SAFETY: freshly-opened owned fd; drop closes it on every fallback.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0 {
            return None;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        if typ == libc::S_IFDIR as u32 {
            // Write-intent dir opens never reach here (the O_RDWR attempt
            // fails EISDIR → fallback → the slow path's exact EISDIR).
            crate::probes::path_open(&full, 0, 0);
            let metadata = RootFsMetadata {
                path: Path::new(&full).to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            };
            let description = OpenDescription::Directory {
                path: full,
                metadata,
                entries: Vec::new(),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                // Single-component + O_NOFOLLOW under a trusted dir preserves
                // the byte-exact anchor: the served dir is itself trusted.
                trusted_host_dir: Some(match trusted_dir.immutable_lower_generation {
                    Some(generation) => TrustedHostDir::immutable_lower(
                        HostFdRef::new(fd.into_raw_fd()),
                        generation,
                    ),
                    None => TrustedHostDir::new(HostFdRef::new(fd.into_raw_fd())),
                }),
            };
            let open_file = OpenFile::from_open_description(
                Arc::new(RwLock::new(description)),
                linux_fd_flags_from_open_flags(flags),
            );
            let Ok(new_fd) = self.install_fd_at_or_above(0, open_file) else {
                return Some(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            return Some(DispatchOutcome::Returned {
                value: new_fd as i64,
            });
        }
        if typ != libc::S_IFREG as u32 {
            // FIFO (must route through the non-blocking FIFO machinery),
            // real device/socket nodes: exact slow path. The O_NONBLOCK
            // probe fd closes here without ever blocking.
            return None;
        }
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            // O_DIRECTORY of a regular child: authoritative ENOTDIR.
            return Some(DispatchOutcome::errno(LINUX_ENOTDIR));
        }
        // Marker nodes (bound AF_UNIX sockets, mknod devices) carry their
        // guest TYPE in xattrs; the slow path owns their open semantics.
        // With the root markers proving no metadata xattrs or marker nodes
        // exist anywhere, the pass is skipped outright.
        let (override_mode, _uid, _gid, is_socket) =
            if self.fs.rootfs_vfs.overlay.serves_plain_metadata() {
                (None, None, None, false)
            } else {
                crate::fs_backend::fd_carrick_meta(raw)
            };
        if is_socket || override_mode.is_some_and(|m| m & LINUX_S_IFMT != 0) {
            return None;
        }
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let mode = override_mode
            .map(|m| m & 0o7777)
            .unwrap_or(if on_disk_mode == 0 {
                0o644
            } else {
                on_disk_mode
            });
        // Clear the probe-only O_NONBLOCK, then track host-side nonblocking
        // exactly as the slow HostFile arm does; the guest's OWN flags live
        // in the description, not the host fd.
        unsafe {
            libc::fcntl(raw, libc::F_SETFL, 0);
        }
        crate::dispatch::net::set_host_nonblocking(raw);
        crate::probes::path_open(&full, st.st_size as u64, 0);
        let metadata = RootFsMetadata {
            path: Path::new(&full).to_path_buf(),
            kind: RootFsEntryKind::File,
            mode,
            size: st.st_size as usize,
        };
        let description = OpenDescription::HostFile {
            host_fd: HostFdRef::new(fd.into_raw_fd()),
            metadata,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            writable: write,
        };
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(description)),
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(new_fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        // readlink(/proc/self/fd/N) recovers the guest path from
        // fd_open_paths for host-fd-backed descriptions (slow-arm parity).
        self.record_fd_open_path(new_fd, full);
        Some(DispatchOutcome::Returned {
            value: new_fd as i64,
        })
    }

    /// Single-component `newfstatat`/`statx` through a TRUSTED host dirfd:
    /// one `fstatat(host_dirfd, name, AT_SYMLINK_NOFOLLOW)` plus (on a
    /// regular-file/dir hit) one no-atime leaf open for the carrick xattr
    /// metadata — replacing the anchor re-verify + parent validation + the
    /// layered stat stack. A non-symlink hit makes follow and no-follow
    /// coincide, so the caller's AT_SYMLINK_NOFOLLOW needs no case split; a
    /// symlink child falls back (exact lstat semantics INCLUDING the
    /// link-owner xattrs stay on the slow path). Missing is authoritative
    /// (`Some(Err(ENOENT))`); `None` ⇒ take the full path.
    fn try_trusted_dirfd_stat(
        &self,
        dirfd: u64,
        path: &str,
    ) -> Option<Result<StatRecord, LinuxErrno>> {
        use std::os::fd::{FromRawFd, OwnedFd};
        // fts walkers (GNU find, and every fts-based tool) stat each
        // directory they descend as "." relative to the directory's OWN fd.
        // The trusted dir IS the object: serve fstat(host_dirfd) directly —
        // no component gate, no leaf probe (the metadata pass reads the
        // already-open fd when metadata xattrs may exist anywhere).
        if path == "." {
            let (dir_path, host_dir) = self.trusted_dir_of(dirfd)?;
            if !host_dir.namespace_is_current() {
                return None;
            }
            if host_dir.immutable_lower_generation.is_some() {
                // A lower dirfd's own identity is now the cache directory's
                // real host inode either way (`layered_identity_record`), so
                // this is no longer about which inode to report — it is that
                // the anchor may have been whiteout-shadowed or copied up
                // since it was opened, which only the layered walk can see.
                return None;
            }
            if !self.cred_snapshot().euid.is_root() {
                return None;
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(host_dir.fd.raw(), &mut st) } != 0 {
                return None;
            }
            if st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFDIR as u32 {
                return None;
            }
            let (override_mode, uid, gid, _) = if self.fs.rootfs_vfs.overlay.serves_plain_metadata()
            {
                (None, None, None, false)
            } else {
                crate::fs_backend::fd_carrick_meta(host_dir.fd.raw())
            };
            let on_disk_mode = st.st_mode as u32 & 0o7777;
            let real = crate::fs_backend::RealStat {
                kind: RootFsEntryKind::Directory,
                ino: st.st_ino,
                nlink: st.st_nlink as u32,
                mode: override_mode
                    .map(|m| m & 0o7777)
                    .unwrap_or(if on_disk_mode == 0 {
                        0o755
                    } else {
                        on_disk_mode
                    }),
                uid: uid.unwrap_or(carrick_abi::NsUid::ROOT),
                gid: gid.unwrap_or(carrick_abi::NsGid::ROOT),
                size: st.st_size as u64,
                atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
                mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
                ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
            };
            return Some(Ok(self.stat_record_with_device(&dir_path, &real)));
        }
        let name = Self::trusted_lane_component(path)?;
        let (dir_path, host_dir) = self.trusted_dir_of(dirfd)?;
        if !host_dir.namespace_is_current() {
            return None;
        }
        if host_dir.immutable_lower_generation.is_some() {
            return None;
        }
        let full = self.trusted_child_path(&dir_path, name)?;
        // A non-root fsuid needs the ancestor search-permission checks. fsuid,
        // not euid: it is the identity every DAC check uses (setfsuid(2)), and
        // a bypass keyed on the other one is how a permission check gets
        // skipped for a caller that has genuinely dropped privilege.
        if !self.dac_overrides_permissions() {
            return None;
        }
        let name_c = std::ffi::CString::new(name).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                host_dir.fd.raw(),
                name_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Some(Err(LINUX_ENOENT))
            } else {
                None
            };
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        let is_dir = typ == libc::S_IFDIR as u32;
        if !is_dir && typ != libc::S_IFREG as u32 {
            // Symlink (follow-vs-lstat + link-owner xattrs), FIFO (must never
            // be opened), real device: exact slow path.
            return None;
        }
        // Carrick metadata (mode/owner/socket) via one flistxattr-gated pass
        // on a no-atime fd — the same fill pattern (and the same benign
        // fstatat→openat window) as the stat cache's
        // `stat_cache_get_or_fill`. Skipped entirely when the root markers
        // prove NO entry anywhere carries metadata xattrs or marker nodes:
        // the fstatat above is then the complete guest answer, and the whole
        // stat costs ONE host syscall.
        let (override_mode, uid, gid, is_socket) =
            if self.fs.rootfs_vfs.overlay.serves_plain_metadata() {
                (None, None, None, false)
            } else {
                #[cfg(target_os = "macos")]
                const O_EVTONLY: libc::c_int = 0x8000;
                #[cfg(not(target_os = "macos"))]
                const O_EVTONLY: libc::c_int = libc::O_RDONLY;
                let leaf_flags = O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
                let raw =
                    unsafe { libc::openat(host_dir.fd.raw(), name_c.as_ptr(), leaf_flags, 0) };
                if raw < 0 {
                    return None;
                }
                // SAFETY: freshly-opened owned fd, closed on drop.
                let leaf = unsafe { OwnedFd::from_raw_fd(raw) };
                let meta = crate::fs_backend::fd_carrick_meta(raw);
                drop(leaf);
                meta
            };
        let kind = if is_dir {
            RootFsEntryKind::Directory
        } else if is_socket {
            RootFsEntryKind::Socket
        } else {
            RootFsEntryKind::File
        };
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let default_mode = if is_dir { 0o755 } else { 0o644 };
        let real = crate::fs_backend::RealStat {
            kind,
            ino: st.st_ino,
            nlink: st.st_nlink as u32,
            // The override is carried VERBATIM (device markers keep their
            // type bits) — `stat_record_with_device` below recovers them,
            // exactly like the stat-cache hit path.
            mode: override_mode.unwrap_or(if on_disk_mode == 0 {
                default_mode
            } else {
                on_disk_mode
            }),
            uid: uid.unwrap_or(carrick_abi::NsUid::ROOT),
            gid: gid.unwrap_or(carrick_abi::NsGid::ROOT),
            size: st.st_size as u64,
            atime: (st.st_atime, carrick_portable::stat_atime_nsec(&st)),
            mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(&st)),
            ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(&st)),
        };
        Some(Ok(self.stat_record_with_device(&full, &real)))
    }

    /// Materialize a trusted directory's entries: STREAM the host dirfd (one
    /// readdir batch — d_name/d_type/d_ino straight off the kernel, zero
    /// per-child stats) when nothing can make the raw stream lie about the
    /// guest view, else the exact layered merge. Runs once per description
    /// (again after an lseek-0 rewind refresh).
    fn materialize_trusted_dir_entries(
        &self,
        dir_path: &str,
        trusted: &mut TrustedHostDir,
        entries: &mut Vec<RootFsDirEntry>,
    ) {
        let streamed = if self.fs.rootfs_vfs.rootfs.is_none()
            && !self
                .fs
                .rootfs_vfs
                .overlay
                .dir_has_overlay_interference(dir_path)
        {
            read_host_dir_entries(trusted.fd.raw(), dir_path)
        } else {
            None
        };
        *entries = match streamed {
            Some(list) => list,
            // Interference (marker nodes) or a stream surprise (DT_UNKNOWN):
            // the layered path classifies each child exactly, as today. A
            // directory deleted since the open reads as empty.
            None => crate::overlay::layered_directory_entries(
                self.fs.rootfs_vfs.overlay.as_ref(),
                self.fs.rootfs_vfs.rootfs.as_ref(),
                dir_path,
            )
            .unwrap_or_default(),
        };
        trusted.entries_loaded = true;
    }

    /// Render `/proc/self/fdinfo/N` (proc_pid_fdinfo(5)): pos, the open flags
    /// (octal), a synthetic mnt_id, and the fd's inode. Pulls the live position
    /// (the in-memory cursor, or a host `lseek` for an overlay-backed file) and
    /// the status flags from the live fd table. `None` if fd N is not open.
    fn fdinfo_bytes(&self, n: i32) -> Option<Vec<u8>> {
        let of = self.open_file(n)?;
        let desc = of.description.read();
        let cloexec = of.fd_flags & LINUX_FD_CLOEXEC != 0;
        // The open status flags (access mode + O_NONBLOCK/O_APPEND/…) with
        // O_CLOEXEC folded in — the bits callers parse to recover an inherited
        // fd's mode. (O_LARGEFILE is elided: arch-specific and not load-bearing.)
        // Like F_GETFL, fdinfo's `flags:` reports status flags only; creation
        // flags are consumed by open(). (audit M8)
        let flags = reportable_status_flags(desc.status_flags())
            | if cloexec { LINUX_O_CLOEXEC } else { 0 };
        let pos = match &*desc {
            OpenDescription::File { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. }
            | OpenDescription::Directory { offset, .. } => *offset as u64,
            OpenDescription::HostFile { host_fd, .. } => {
                host_fd_offset(host_fd.view()).unwrap_or(0)
            }
            _ => 0,
        };
        drop(desc);
        let ino = self.fd_stat_record(n).map(|r| r.ino).unwrap_or(0);
        let mut out = format!("pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t24\nino:\t{ino}\n");
        // An inotify fd's fdinfo also carries one `inotify wd:...mask:...` line
        // per live watch (proc_pid_fdinfo(5)); inotify12 parses the mask from it.
        if let Some(state) = self.inotify_state(n) {
            out.push_str(&state.fdinfo_lines());
        }
        Some(out.into_bytes())
    }

    /// Install a read-only synthetic-bytes fd (e.g. a rendered fdinfo file).
    /// The namespace type (`"uts"`, `"user"`, …) for an fd opened on a
    /// `/proc/<pid>/ns/<type>` nsfs magic link, or `None` if the fd is not such
    /// a link. The fd is a 0-byte `SyntheticFile` whose recorded `path` is the
    /// magic-link path; `proc_ns_link` recognises it. Keys the `NS_GET_*` ioctls.
    fn fd_ns_link_type(&self, fd: i32) -> Option<String> {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        let open_file = table.get(&fd)?;
        let description = open_file.description.read();
        let path = description.open_path()?;
        proc_ns_link(path).map(|t| t.to_owned())
    }

    fn install_proc_synthetic_bytes(
        &self,
        path: &str,
        contents: Vec<u8>,
        flags: u64,
    ) -> DispatchOutcome {
        let open_file = OpenFile::from_open_description(
            Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                path: path.to_string(),
                contents,
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            })),
            linux_fd_flags_from_open_flags(flags),
        );
        match self.install_fd_at_or_above(0, open_file) {
            Ok(fd) => DispatchOutcome::Returned { value: fd as i64 },
            Err(_) => DispatchOutcome::errno(linux_errno::EMFILE),
        }
    }

    /// `close_range(first, last, flags)` — close every fd in `[first, last]`
    /// (inclusive). Used by glibc's posix_spawn / apt's pre-fork cleanup
    /// to drop inherited fds in O(1) syscalls instead of an O(N) fcntl
    /// or close loop. Without this, apt walks fd 3..NR_OPEN issuing a
    /// fcntl per fd and burns 100k+ traps before exec.
    /// When the guest dups a *bare stdio* fd that is the `-t` controlling pty
    /// slave, the duplicate must keep its tty identity. bash's
    /// `initialize_job_control` does `dup(fileno(stderr))`, moves it to a high
    /// fd, and runs `tcgetpgrp`/`tcsetpgrp` on *that* fd — so if the duplicate
    /// lands as a plain (`pty: None`) HostPipe it is classified `TtyFdKind::Other`
    /// and every tty ioctl returns ENOTTY; `tcgetpgrp` then returns -1 and bash
    /// prints "cannot set terminal process group (-1)" / "no job control". Tag it
    /// with the controlling slave role so it flows through the pty passthrough
    /// (TCGETS2 / TIOCGPGRP / TIOCSPGRP / TIOCGWINSZ) to the duplicated host fd.
    /// Non-tty stdio (a pipe/file redirect) returns `None` and stays a plain pipe.
    fn dup_stdio_pty_role(&self, old_fd: i32) -> Option<crate::vfs::PtyRole> {
        if crate::host_tty::host_isatty(old_fd) {
            let index = self.pty_table().lock().controlling().unwrap_or(0);
            Some(crate::vfs::PtyRole {
                index,
                is_master: false,
            })
        } else {
            None
        }
    }

    /// Resolve the host fd a winsize ioctl should target for a pty end. macOS
    /// rejects `TIOCGWINSZ`/`TIOCSWINSZ` on a pty MASTER with ENOTTY — the
    /// winsize is a property of the slave tty — whereas Linux honours them on
    /// the master (a `forkpty`/`openpty` + `TIOCSWINSZ(master)` is the standard
    /// way to size a pty, and a guest program doing so otherwise fails with
    /// "Setting TIOCSWINSZ for master fd N failed!"). For a master role, target
    /// the guest's already-open SLAVE fd for the same pts (the one the child
    /// uses): macOS resets a pts's winsize when its last slave fd closes, so a
    /// transient open could not hold it — only the persistent slave the child
    /// shares (via fork) carries the size. Returns the slave host fd, or `None`
    /// when no slave is open yet (caller treats a set as a best-effort no-op so
    /// the guest does not see a spurious ENOTTY). A slave role targets `host_fd`.
    fn pty_winsize_target(&self, role: crate::vfs::PtyRole, host_fd: i32) -> Option<i32> {
        if !role.is_master {
            return Some(host_fd);
        }
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for of in table.values() {
            if let OpenDescription::HostPipe {
                host_fd: slave_host_fd,
                pty: Some(slave_role),
                ..
            } = &*of.description.read()
                && !slave_role.is_master
                && slave_role.index == role.index
            {
                return Some(slave_host_fd.raw());
            }
        }
        None
    }

    fn duplicate_fd(&self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        // The description Arc alone carries the backing host fd's liveness:
        // the OWNED HostFdRef lives inside the description, so `Arc::clone`
        // here is the whole dup — one refcount, no separate owner to keep in
        // lockstep.
        let description = match self.open_file(old_fd).as_ref() {
            Some(open_file) => Arc::clone(&open_file.description),
            // A closed-and-not-reopened stdio fd is genuinely closed: dup is
            // EBADF, not a host-fd grab. (The closed check must precede the
            // is_stdio_fd grab below.)
            None if is_stdio_fd(old_fd) && self.stdio_is_closed(old_fd) => {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            None if is_stdio_fd(old_fd) => {
                // dup/fcntl(F_DUPFD) of the process's bare stdio fds:
                // mirror what dup3 does and grab the host fd into a
                // HostPipe so future reads/writes still hit the right
                // host endpoint (this is what dpkg-query needs at
                // startup to redirect its diagnostic fd, and what most
                // glibc fork+exec helpers expect to succeed).
                let duped = match (unsafe { libc::dup(old_fd) }).host_syscall_errno() {
                    Ok(duped) => duped,
                    Err(errno) => return DispatchOutcome::errno(errno),
                };
                crate::dispatch::net::set_host_nonblocking(duped);
                let write_kind = HostWriteKind::for_host_fd(duped);
                let pty = self.dup_stdio_pty_role(old_fd);
                kernel_file_description(Arc::new(RwLock::new(OpenDescription::HostPipe {
                    // A duped stdio fd has no separate pipe peer to coordinate
                    // a FASYNC arm/trigger with; the host inode is still a
                    // unique id (FASYNC is not exercised on bare stdio).
                    pipe_id: host_inode_pipe_id(duped),
                    // `duped` is a genuinely NEW host fd, so this fresh owned
                    // handle is its one owner.
                    host_fd: HostFdRef::new(duped),
                    is_read_end: old_fd == 0,
                    base: OpenDescriptionBase::new(0),
                    pty,
                    bidirectional: false,
                    write_kind,
                })))
            }
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };
        let open_file = OpenFile::new(description, fd_flags);
        let new_fd = match self.install_fd_at_or_above(min_fd, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    fn duplicate_fd_to(
        &self,
        owner: crate::kernel::TaskKey,
        old_fd: i32,
        new_fd: i32,
        fd_flags: u64,
        same_fd_is_noop: bool,
    ) -> DispatchOutcome {
        let nofile_cur = self.nofile_limit();
        if !(0..nofile_cur).contains(&new_fd) {
            return DispatchOutcome::errno(LINUX_EBADF);
        }
        if old_fd == new_fd {
            if !same_fd_is_noop {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            return if self.fd_is_valid(old_fd) {
                DispatchOutcome::Returned {
                    value: new_fd as i64,
                }
            } else {
                DispatchOutcome::errno(LINUX_EBADF)
            };
        }

        // As in `duplicate_fd`: the description Arc alone carries the host
        // fd's liveness (the owned HostFdRef lives inside the description).
        let description = match self.open_file(old_fd).as_ref() {
            Some(open_file) => Arc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) && self.stdio_is_closed(old_fd) => {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            None if is_stdio_fd(old_fd) => {
                let duped = match (unsafe { libc::dup(old_fd) }).host_syscall_errno() {
                    Ok(duped) => duped,
                    Err(errno) => return DispatchOutcome::errno(errno),
                };
                crate::dispatch::net::set_host_nonblocking(duped);
                let write_kind = HostWriteKind::for_host_fd(duped);
                let pty = self.dup_stdio_pty_role(old_fd);
                kernel_file_description(Arc::new(RwLock::new(OpenDescription::HostPipe {
                    // A duped stdio fd has no separate pipe peer to coordinate
                    // a FASYNC arm/trigger with; the host inode is still a
                    // unique id (FASYNC is not exercised on bare stdio).
                    pipe_id: host_inode_pipe_id(duped),
                    // `duped` is a genuinely NEW host fd, so this fresh owned
                    // handle is its one owner.
                    host_fd: HostFdRef::new(duped),
                    is_read_end: old_fd == 0,
                    base: OpenDescriptionBase::new(0),
                    pty,
                    bidirectional: false,
                    write_kind,
                })))
            }
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };

        // dup2/dup3 closes `new_fd` before installing the duplicate.  Carrick's
        // epoll emulation keys its interest map by guest-fd number, so the
        // detach must happen while that slot still names the DISPLACED open-file
        // description.  Detaching after insertion resolves `new_fd` through the
        // replacement and can tear down the parent's inherited registration
        // for the old description (the HvPatch Go os/exec two-pipe hang).
        //
        // Linux attaches epoll interest to the open-file description.  A forked
        // parent's reference therefore keeps the registration alive when the
        // child replaces its numeric slot; only the final logical fd reference
        // is allowed to trigger automatic close-detach.
        self.detach_fd_from_epolls(new_fd);
        self.discard_splice_pushback_if_final(new_fd);

        {
            let files = self.captured_file_table();
            let mut table = files.write_open_files();
            if let Some(replaced) = table.remove(&new_fd) {
                let pid = self.event_ring_guest_pid();
                self.record_fd_close_owner(new_fd, pid, &replaced);
                self.release_hvpatch_classic_record_locks(owner, &replaced);
                self.close_open_file_and_free_pty(&replaced);
            }
            retain_open_file(&description);
            table.insert(new_fd, OpenFile::new(description, fd_flags));
        }
        self.clear_closed_stdio(new_fd);
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    fn try_vfs_open(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        path: &str,
        access: u64,
        flags: u64,
        create_mode: u32,
    ) -> VfsOpenAttempt {
        let Some(m) = self.fs.vfs_mounts.resolve(path) else {
            return VfsOpenAttempt::FallThrough;
        };
        // `/proc` and other synthetic mounts render address-space state. Hold
        // alias exclusion across the complete snapshot so it cannot describe
        // stale VMA metadata while a host replacement is installing.
        let _host_alias_dispatch = self.begin_host_alias_dispatch();

        // Build the OpenContext only after a mount claims the path. Rootfs and
        // overlay fallthrough opens are the hot path and do not need proc, fd,
        // signal, or memory snapshots for VFS mounts.
        let proc = self.proc.lock();
        let exec_path = proc.executable_path.clone();
        let argv = proc.argv.clone();
        let task_comm = linux_task_name_to_string(&proc.task_name);
        let timerslack_ns = proc.timerslack;
        let env = proc.env.clone();
        let guest_arch = proc.reported_arch();
        let guest_hostname = proc.guest_hostname().to_string();
        drop(proc);
        let open_fds = self.open_fd_numbers();
        let mem = self.mem_snapshot();
        let mut address_space_regions = mem.address_space_regions.clone();
        if !mem.dynamic_maps.is_empty() {
            match &mut address_space_regions {
                Some(regions) => regions.extend(mem.dynamic_maps.clone()),
                None => address_space_regions = Some(mem.dynamic_maps.clone()),
            }
        }
        let creds = self.cred_snapshot();
        let groups = self.current_groups();
        let (sig_ignored, sig_caught, sig_shdpnd) = self.proc_status_signal_masks(context);
        let (sig_ignored, sig_caught, sig_shdpnd) =
            (sig_ignored.raw(), sig_caught.raw(), sig_shdpnd.raw());
        let sysvipc_shm = self.sysvipc_shm_table();
        let sysvipc_sem = self.sysvipc_sem_table();
        let sysvipc_msg = self.sysvipc_msg_table();
        let proc_threads = self.synthetic_proc_threads(context, registry);
        // See `synthetic_proc_context`: the kernel graph is the only authority
        // that can distinguish two Linux processes sharing this Darwin process.
        let proc_oom_score_adj = self
            .hvpatch_process()
            .map(|process| process.kernel_graph().registry().oom_score_adj_by_pid());
        // The caller's own capabilities and user-namespace view; `/proc/self`'s
        // `status`, `uid_map`, `gid_map` and `setgroups` render from this.
        let proc_creds_ns = context.task().creds_ns();
        let proc_processes = Self::synthetic_proc_processes(self.hvpatch_process().as_ref());
        let proc_zombies = self.hvpatch_process().map(|process| {
            process
                .kernel_graph()
                .registry()
                .zombies()
                .into_iter()
                .map(|zombie| crate::vfs::SyntheticProcZombie {
                    pid: zombie.key.id.raw() as u32,
                    ppid: zombie
                        .parent
                        .map_or(carrick_abi::LINUX_BOOTSTRAP_PID as u32, |parent| {
                            parent.id.raw() as u32
                        }),
                    pgrp: zombie.process_group.raw() as u32,
                    session: zombie.session.raw() as u32,
                    comm: zombie.diagnostic_name,
                })
                .collect::<Vec<_>>()
        });
        let ctx = crate::vfs::OpenContext {
            executable_path: Some(exec_path.as_str()),
            argv: Some(argv.as_slice()),
            task_comm: Some(task_comm.as_str()),
            timerslack_ns,
            guest_arch,
            guest_hostname: Some(guest_hostname.as_str()),
            environ: Some(env.as_slice()),
            open_fds: Some(open_fds.as_slice()),
            network: Some(&self.network.spec),
            auxv: Some(mem.linux_auxv_image.as_slice()),
            address_space_regions: address_space_regions.as_deref(),
            locked_memory: Some(mem.locked_ranges.as_slice()),
            brk_current: mem.brk_current,
            mmap_next: mem.mmap_next,
            heap_base: mem.layout.heap_base,
            native_guest_va: self.page_geometry().native_geometry().is_some(),
            ruid: creds.ruid,
            euid: creds.euid,
            suid: creds.suid,
            rgid: creds.rgid,
            egid: creds.egid,
            sgid: creds.sgid,
            groups: Some(groups.as_slice()),
            sig_ignored,
            sig_caught,
            sig_shdpnd,
            identity: self.synthetic_proc_identity(context),
            oom_score_adj: proc_oom_score_adj.as_ref(),
            creds_ns: Some(&proc_creds_ns),
            processes: proc_processes.as_deref(),
            threads: proc_threads.as_deref(),
            zombies: proc_zombies.as_deref(),
            sysvipc_shm: Some(sysvipc_shm.as_str()),
            sysvipc_sem: Some(sysvipc_sem.as_str()),
            sysvipc_msg: Some(sysvipc_msg.as_str()),
        };
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        let vfs_flags = crate::vfs::OpenFlags {
            read: matches!(access, LINUX_O_RDONLY | LINUX_O_RDWR),
            write: matches!(access, LINUX_O_WRONLY | LINUX_O_RDWR),
            nonblock: open_flags.contains(LinuxOpenFlags::NONBLOCK),
            cloexec: open_flags.contains(LinuxOpenFlags::CLOEXEC),
            append: open_flags.contains(LinuxOpenFlags::APPEND),
            trunc: open_flags.contains(LinuxOpenFlags::TRUNC),
            create: open_flags.contains(LinuxOpenFlags::CREAT),
            excl: open_flags.contains(LinuxOpenFlags::EXCL),
            directory: open_flags.contains(LinuxOpenFlags::DIRECTORY),
            nofollow: open_flags.contains(LinuxOpenFlags::NOFOLLOW),
            mode: create_mode,
        };
        let handle = match m.vfs.open(&m.full_path, vfs_flags, &ctx) {
            Ok(h) => h,
            Err(errno) if errno == LINUX_ENOSYS => {
                return VfsOpenAttempt::FallThrough;
            }
            Err(errno) => {
                return VfsOpenAttempt::Errno(errno);
            }
        };
        match handle {
            crate::vfs::VfsHandle::HostFd {
                host_fd,
                is_read_end,
                status_flags,
            } => {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                // A VFS-served (e.g. bind-mounted) REGULAR file must become a
                // seekable HostFile, not a HostPipe — otherwise lseek/pread-at-
                // offset and sendfile/splice reject it (EINVAL), since a pipe
                // isn't seekable. Only genuine streams (devices, fifos) stay
                // HostPipe. fstat the real fd to decide.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let write_kind = if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
                    HostWriteKind::from_host_mode(st.st_mode)
                } else {
                    HostWriteKind::Other
                };
                let is_regular = write_kind == HostWriteKind::RegularFile;
                let description = if is_regular {
                    OpenDescription::HostFile {
                        host_fd: HostFdRef::new(host_fd),
                        metadata: crate::rootfs::RootFsMetadata {
                            path: std::path::PathBuf::from(path),
                            kind: RootFsEntryKind::File,
                            mode: (st.st_mode & 0o7777) as u32,
                            size: st.st_size.max(0) as usize,
                        },
                        base: OpenDescriptionBase::new(status_flags as u64),
                        writable: !is_read_end,
                    }
                } else {
                    OpenDescription::HostPipe {
                        // A VFS host stream (e.g. /dev/null, a chardev) has no
                        // separate pipe peer; the host inode is a unique id.
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        is_read_end,
                        base: OpenDescriptionBase::new(status_flags as u64),
                        pty: None,
                        // A VFS stream opened O_RDWR must serve BOTH directions
                        // (mirrors the O_RDWR FIFO open above). DevVfs encodes
                        // only `is_read_end = !write`, so an O_RDWR /dev/null —
                        // exactly what CPython's subprocess DEVNULL opens —
                        // came back write-only and the spawned child's
                        // `sys.stdin.read()` EBADFed (test_subprocess
                        // test_stdin_devnull's child traceback; Docker reads
                        // EOF). Shared with HVF: same latent gap there.
                        bidirectional: access == LINUX_O_RDWR,
                        write_kind,
                    }
                };
                let open_file = OpenFile::from_open_description(
                    Arc::new(RwLock::new(description)),
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Bytes {
                path,
                contents,
                status_flags,
            } => {
                let open_file = OpenFile::from_open_description(
                    Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                        path,
                        contents,
                        offset: 0,
                        base: OpenDescriptionBase::new(
                            ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC,
                        ),
                    })),
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Pty {
                host_fd,
                pts_index,
                is_master,
                status_flags,
            } => {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let open_file = OpenFile::from_open_description(
                    Arc::new(RwLock::new(OpenDescription::HostPipe {
                        // A pty end's host inode is a unique id (FASYNC is not
                        // exercised on ptys).
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        // A pty end is bidirectional; route reads and
                        // writes through the host fd like /dev/null.
                        is_read_end: true,
                        base: OpenDescriptionBase::new(status_flags as u64),
                        pty: Some(crate::vfs::PtyRole {
                            index: pts_index,
                            is_master,
                        }),
                        // pty bidirectionality is already expressed by `pty`.
                        bidirectional: false,
                        write_kind: HostWriteKind::Other,
                    })),
                    linux_fd_flags_from_open_flags(flags),
                );
                // Remember where this pty's MASTER lives. The slave's close
                // path has to rescue the master's queued bytes before Darwin
                // destroys them, and it cannot look the master up through the
                // file table from inside the close (see
                // `dispatch::pty_registry`).
                if is_master {
                    crate::dispatch::pty_registry::register_master(
                        pts_index,
                        host_fd,
                        open_file.description.id(),
                    );
                }
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                // Record the open path (/dev/ptmx or /dev/pts/N) so
                // readlink(/proc/self/fd/<fd>) resolves it — glibc's ttyname_r
                // needs this to reopen a pty slave.
                self.record_fd_open_path(new_fd, path.to_string());
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Directory {
                path,
                entries,
                status_flags,
            } => {
                // Convert synthetic VFS DirEnt entries into the RootFsDirEntry
                // shape that OpenDescription::Directory + getdents64 expects.
                let rootfs_entries: Vec<RootFsDirEntry> = entries
                    .into_iter()
                    .map(|e| {
                        let kind = match e.kind {
                            crate::vfs::EntryKind::Directory => RootFsEntryKind::Directory,
                            crate::vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
                            crate::vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
                            crate::vfs::EntryKind::Fifo => RootFsEntryKind::Fifo,
                            crate::vfs::EntryKind::Socket => RootFsEntryKind::Socket,
                            crate::vfs::EntryKind::File => RootFsEntryKind::File,
                        };
                        RootFsDirEntry {
                            name: e.name.clone(),
                            metadata: RootFsMetadata {
                                path: std::path::Path::new(&path).join(&e.name).to_path_buf(),
                                kind,
                                mode: 0o666,
                                size: 0,
                            },
                            ino: 0,
                        }
                    })
                    .collect();
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                };
                let open_file = OpenFile::from_open_description(
                    Arc::new(RwLock::new(OpenDescription::Directory {
                        path,
                        metadata,
                        entries: rootfs_entries,
                        offset: 0,
                        base: OpenDescriptionBase::new(status_flags as u64),
                        // VFS-mount (synthetic) directories never take the
                        // trusted host-dirfd lane.
                        trusted_host_dir: None,
                    })),
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
        }
    }

    // === Normalized shim-wrappers ===
    // Thin adapters giving each remaining legacy handler the uniform
    // SyscallCtx<M> contract so it can live in the `dispatch_fs`
    // table. The inner fns are unchanged (already tested); these forward
    // `ctx.request` (Copy) and `ctx.memory`. Once every syscall has a
    // wrapper the legacy match in `dispatch()` is deleted and the macro
    // table becomes the single authoritative syscall registry.

    fn host_file_fd_for_flush(&self, fd: i32) -> Result<Option<i32>, LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                Ok(None)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let open = open_file.description.read();
        Ok(match &*open {
            OpenDescription::HostFile { host_fd, .. } => Some(host_fd.raw()),
            _ => None,
        })
    }

    /// The fork-coherent FASYNC join key behind a guest `fd`, if it is a
    /// host-backed pipe or socket. For a `HostPipe` it is the shared `pipe_id`
    /// stamped on BOTH ends at creation (identical on the read and write ends,
    /// inherited unchanged across fork — the property an inode key lacks on
    /// macOS, where a pipe's two ends have different `st_ino`). For a
    /// `HostSocket` there is no creation-time shared id, so the socket's host
    /// inode is used (the existing socket-fasync behaviour). `None` for
    /// non-pipe/socket fds, a `pipe_id` of `0` (no real pipe object), or a failed
    /// socket fstat.
    fn host_pipe_pipe_id(&self, fd: i32) -> Option<u64> {
        let open_file = self.open_file(fd)?;
        let host_socket_fd = match &*open_file.description.read() {
            OpenDescription::HostPipe { pipe_id, .. } => {
                return (*pipe_id != 0).then_some(*pipe_id);
            }
            OpenDescription::HostSocket { host_fd, .. } => host_fd.raw(),
            _ => return None,
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(host_socket_fd, &mut st) } != 0 {
            return None;
        }
        let ino = st.st_ino as u64;
        (ino != 0).then_some(ino)
    }

    fn pipe_buffered_bytes(&self, fd: i32) -> Result<Option<usize>, LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                Ok(None)
            } else {
                Err(LINUX_EBADF)
            };
        };

        let open = open_file.description.read();
        match &*open {
            OpenDescription::PipeReader { pipe, .. } | OpenDescription::PipeWriter { pipe, .. } => {
                Ok(Some(pipe.lock().buffer.len()))
            }
            OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                ..
            } => host_pipe_readable_bytes(host_fd.raw())
                .map(|bytes| Some(bytes + self.staged_splice_pipe_bytes(fd))),
            OpenDescription::HostPipe {
                pipe_id,
                bidirectional,
                host_fd,
                ..
            } => {
                if *bidirectional {
                    return host_pipe_readable_bytes(host_fd.raw()).map(Some);
                }
                let pipe_id = *pipe_id;
                drop(open);
                let files = self.captured_file_table();
                let table = files.read_open_files();
                for other in table.values() {
                    let other_open = other.description.read();
                    if let OpenDescription::HostPipe {
                        host_fd,
                        is_read_end: true,
                        pipe_id: other_pipe_id,
                        ..
                    } = &*other_open
                        && *other_pipe_id == pipe_id
                    {
                        return host_pipe_readable_bytes(host_fd.raw()).map(Some);
                    }
                }
                Ok(Some(0))
            }
            _ => Ok(None),
        }
    }

    fn host_pipe_read_end_for_pipe_id(&self, pipe_id: u64) -> Option<(i32, HostFd)> {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for (fd, other) in table.iter() {
            let other_open = other.description.read();
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return Some((*fd, host_fd.view()));
            }
        }
        None
    }

    /// The host fd backing the WRITE end of the pipe object identified by
    /// `pipe_id`, if one is currently open. Symmetric to
    /// [`Self::host_pipe_read_end_for_pipe_id`]; the userspace `tee` uses it to
    /// restore the source pipe after peeking its buffered bytes on hosts that
    /// lack `tee(2)`.
    fn host_pipe_write_end_for_pipe_id(&self, pipe_id: u64) -> Option<HostFd> {
        if pipe_id == 0 {
            return None;
        }
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for (_fd, other) in table.iter() {
            let other_open = other.description.read();
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: false,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return Some(host_fd.view());
            }
        }
        None
    }

    /// True iff `fd` refers to a genuine pipe end — an anonymous pipe, a FIFO,
    /// or a pty — as opposed to a char device (e.g. `/dev/zero`, which carrick
    /// also models as a `HostPipe`), a socket, or a regular file. splice(2)
    /// requires at least one of its two fds to be a genuine pipe; a char-device
    /// `HostPipe` must NOT satisfy that requirement (splice07).
    fn is_genuine_pipe(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        match &*open_file.description.read() {
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                write_kind, pty, ..
            } => pty.is_some() || *write_kind == HostWriteKind::PipeLike,
            _ => false,
        }
    }

    /// True iff `fd` is a splice/tee SOURCE that is not open for reading, so
    /// splice(2) must reject it with EBADF: an `O_PATH` descriptor, a
    /// write-only regular file, or the write end of a one-way pipe (splice03's
    /// write-only case, splice07's `O_PATH`/pipe-write-end sources).
    fn splice_source_not_readable(&self, fd: i32) -> bool {
        if self.fd_is_o_path(fd) {
            return true;
        }
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::HostFile { .. } => {
                open.status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            }
            OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                is_read_end,
                pty,
                bidirectional,
                ..
            } => pty.is_none() && !*bidirectional && !*is_read_end,
            _ => false,
        }
    }

    /// tee(2): duplicate up to `count` bytes from the source pipe's read end to
    /// the destination pipe's write end WITHOUT consuming the source. On a Linux
    /// host the real `tee(2)` is exact; elsewhere (macOS/BSD lack `tee(2)`) fall
    /// back to a userspace peek-and-copy.
    fn host_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        #[cfg(target_os = "linux")]
        {
            let _ = in_pipe_id;
            tee_host_passthrough(in_read, out_write, count, flags)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.userspace_tee(in_read, in_pipe_id, out_write, count, flags)
        }
    }

    /// Userspace `tee(2)` for hosts without the syscall: drain the source pipe's
    /// currently-buffered bytes, write them back through the source's write end
    /// to restore it (FIFO order is preserved because the pipe is momentarily
    /// emptied first), then copy up to `count` of them into the destination
    /// pipe. The restore runs before the copy so a short/failed destination
    /// write still leaves the non-consumed source intact.
    #[cfg(not(target_os = "linux"))]
    fn userspace_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nonblock = flags.contains(LinuxSpliceFlags::NONBLOCK);
        let avail = host_pipe_readable_bytes(in_read.get()).unwrap_or(0);
        if avail == 0 {
            // Nothing buffered: a non-blocking tee is EAGAIN; a blocking tee
            // would wait for the writer, which this path does not park for under
            // the dispatcher lock, so report 0 (empty/writer-closed) instead.
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        // Drain the whole buffer so the writeback restores it in FIFO order.
        let mut buf = vec![0u8; avail];
        let n = unsafe {
            // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK and `avail`
            // was measured immediately before the read.
            libc::read(
                in_read.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                avail,
            )
        };
        let n = n.host_syscall_errno()?;
        if n <= 0 {
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        buf.truncate(n as usize);
        // Restore the source: write the drained bytes back via its write end. The
        // pipe was just emptied, so a non-blocking write of `n <= capacity`
        // completes in full and preserves order. If no write end is open (the
        // source's writer was closed) the source is consumed — a best-effort
        // fallback; tee01 keeps the source write end open.
        if let Some(write_fd) = self.host_pipe_write_end_for_pipe_id(in_pipe_id) {
            let mut off = 0usize;
            while off < buf.len() {
                let w = unsafe {
                    // BLOCKING-IO-OK: the source pipe was just drained, so this
                    // bounded restore writes back into known room.
                    libc::write(
                        write_fd.get(),
                        buf[off..].as_ptr().cast::<libc::c_void>(),
                        buf.len() - off,
                    )
                };
                match w.host_syscall_errno() {
                    Ok(c) if c > 0 => off += c as usize,
                    _ => break,
                }
            }
        }
        // Copy up to `count` bytes into the destination pipe.
        let copy_len = count.min(buf.len());
        let mut written = 0usize;
        while written < copy_len {
            let w = unsafe {
                // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK; a full
                // destination returns EAGAIN and is handled below.
                libc::write(
                    out_write.get(),
                    buf[written..copy_len].as_ptr().cast::<libc::c_void>(),
                    copy_len - written,
                )
            };
            match w.host_syscall_errno() {
                Ok(c) if c > 0 => written += c as usize,
                // A full destination with nothing copied yet is EAGAIN under
                // SPLICE_F_NONBLOCK; otherwise report whatever landed.
                Err(e) if e == LINUX_EAGAIN && written == 0 && nonblock => {
                    return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                }
                _ => break,
            }
        }
        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
    }

    fn host_pipe_splice_staging_target(&self, fd: i32) -> Option<(i32, usize)> {
        let (pipe_id, capacity) = {
            let open_file = self.open_file(fd)?;
            let open = open_file.description.read();
            match &*open {
                OpenDescription::HostPipe {
                    base,
                    is_read_end: false,
                    pipe_id,
                    pty: None,
                    bidirectional: false,
                    ..
                } if *pipe_id != 0 => (*pipe_id, base.pipe_capacity()),
                _ => return None,
            }
        };
        let (read_fd, _) = self.host_pipe_read_end_for_pipe_id(pipe_id)?;
        let capacity = usize::try_from(capacity).ok()?;
        let queued = self.host_pipe_read_end_buffered_bytes(pipe_id);
        Some((read_fd, capacity.saturating_sub(queued)))
    }

    /// Room in a host-pipe destination, in bytes — `None` when `fd` is not a
    /// host pipe. Uses the same accounting the write path applies
    /// ([`super::host_pipe_write_room`]), so a `splice(2)` that bounds its read
    /// window by this value never hands the writer more than the pipe can take.
    /// Unlike [`Self::host_pipe_splice_staging_target`] this accepts any host
    /// pipe write end, including pty and bidirectional ends.
    fn splice_pipe_write_room(&self, fd: i32) -> Option<usize> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        let OpenDescription::HostPipe {
            base,
            pipe_id,
            is_read_end,
            bidirectional,
            host_fd,
            ..
        } = &*open
        else {
            return None;
        };
        let (capacity, queued) = self.host_pipe_capacity_state(
            base,
            *pipe_id,
            *is_read_end,
            *bidirectional,
            host_fd.raw(),
        )?;
        super::host_pipe_write_room(capacity, queued)
    }

    pub(in crate::dispatch) fn host_pipe_capacity_state(
        &self,
        base: &OpenDescriptionBase,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<(i64, usize)> {
        let queued = if is_read_end || bidirectional {
            host_pipe_readable_bytes(host_fd).ok().unwrap_or(0)
        } else {
            self.host_pipe_read_end_buffered_bytes(pipe_id)
        };
        Some((base.pipe_capacity(), queued))
    }

    fn host_pipe_read_end_buffered_bytes(&self, pipe_id: u64) -> usize {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for other in table.values() {
            let Some(other_open) = other.description.try_read() else {
                continue;
            };
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return host_pipe_readable_bytes(host_fd.raw()).ok().unwrap_or(0)
                    + self.staged_splice_description_bytes(other.description.id());
            }
        }
        0
    }

    pub(super) fn staged_splice_pipe_bytes(&self, guest_fd: i32) -> usize {
        self.open_file(guest_fd).map_or(0, |file| {
            self.staged_splice_description_bytes(file.description.id())
        })
    }

    fn staged_splice_description_bytes(
        &self,
        description: crate::kernel::FileDescriptionId,
    ) -> usize {
        let queue = self
            .captured_file_table()
            .lock_splice_pushback()
            .get(&description)
            .cloned();
        queue.map_or(0, |queue| queue.lock().len())
    }

    pub(in crate::dispatch) fn discard_splice_pushback_if_final(&self, guest_fd: i32) {
        let Some(description) = self.open_file(guest_fd).map(|file| file.description) else {
            return;
        };
        if description.fd_ref_count() == 1 {
            self.captured_file_table()
                .lock_splice_pushback()
                .remove(&description.id());
        }
    }

    /// Reconcile the fork-coherent FASYNC registry with `fd`'s current
    /// description after an `O_ASYNC` / `F_SETOWN` / `F_SETSIG` change. If
    /// `O_ASYNC` is set on a host pipe/socket, arm `(dev, ino)` with the fd's
    /// owner + signal so a writer in another guest process can deliver the I/O
    /// signal on the readiness edge; if `O_ASYNC` is clear, disarm it. A no-op
    /// for non-pipe/socket fds (FASYNC delivery is only wired for the
    /// pipe/socket readiness edge carrick can observe).
    fn sync_fasync_registration(&self, fd: i32) {
        let Some(pipe_id) = self.host_pipe_pipe_id(fd) else {
            return;
        };
        let Some(open_file) = self.open_file(fd) else {
            return;
        };
        let desc = open_file.description.read();
        let armed = desc.is_async();
        if !armed {
            drop(desc);
            carrick_signal_core::fasync::disarm(pipe_id);
            return;
        }
        let (owner_type, owner_pid) = desc.owner();
        let sig = desc.async_sig();
        drop(desc);
        carrick_signal_core::fasync::arm(
            pipe_id,
            carrick_signal_core::fasync::FasyncOwner {
                owner_pid,
                owner_type,
                sig,
            },
        );
    }

    /// Resolve the host signal target for an fasync (signal-driven I/O) owner from
    /// the ns→host translation of its owner pid/pgid. Returns `None` — meaning DROP
    /// the SIGIO, deliver nothing — when the owner's ns id has no host mapping
    /// (`host_target == None`), matching the `kill(2)` path's ESRCH intent: a
    /// translation MISS must NOT fall back to the raw ns value reinterpreted as a
    /// host pid, which would signal an unrelated process. The `Some` target feeds
    /// `bootstrap_signal_send_as`: `F_OWNER_PGRP` is a HOST process group,
    /// `F_OWNER_TID` a HOST thread, anything else the owner's HOST pid.
    fn fasync_signal_target(
        owner_type: i32,
        host_target: Option<u32>,
    ) -> Option<crate::dispatch::signal::SignalTarget> {
        use crate::dispatch::signal::SignalTarget;
        let host = host_target?;
        Some(match owner_type {
            LINUX_F_OWNER_PGRP => SignalTarget::HostProcessGroup(HostPid(host)),
            LINUX_F_OWNER_TID => SignalTarget::HostThread(HostPid(host)),
            _ => SignalTarget::HostProcess(HostPid(host)),
        })
    }

    fn queue_self_sigpoll(
        &self,
        context: &crate::kernel::KernelContext,
        signum: i32,
        fd: i32,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        let info = carrick_abi::LinuxSiginfo::sigpoll(signum, carrick_abi::LINUX_POLL_MSG, 0, fd);
        let Some(tid) = target_tid.filter(|tid| *tid != crate::thread::ThreadId::NONE) else {
            self.mark_process_signal_pending_with_info(context, signum, Some(info));
            return;
        };
        self.record_pending_siginfo(context, tid, signum, info);
        if !self.signal_blocked(context, tid, signum)
            && let Some(action) = self.registered_signal_handler(context, signum)
        {
            self.record_pending_signal_action(context, tid, signum, action);
        }
        self.mark_signal_pending(context, tid, signum);
    }

    fn send_async_owner_signal(
        &self,
        context: &crate::kernel::KernelContext,
        owner_type: i32,
        owner_pid: i32,
        sig: i32,
        fd: i32,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        if owner_pid == 0 {
            return;
        }
        let signum = if sig == 0 { LINUX_SIGIO } else { sig };
        if owner_type != LINUX_F_OWNER_PGRP
            && u32::try_from(owner_pid).ok() == Some(crate::namespace::pid::self_ns_pid())
        {
            self.queue_self_sigpoll(context, signum, fd, target_tid);
            return;
        }
        let ns = owner_pid as u32;
        let host_target = match owner_type {
            LINUX_F_OWNER_PGRP => crate::namespace::pid::ns_to_host_pgid(ns),
            _ => crate::namespace::pid::ns_to_host_or_self(ns),
        };
        let Some(target) = Self::fasync_signal_target(owner_type, host_target) else {
            return;
        };
        if matches!(target, crate::dispatch::signal::SignalTarget::HostProcess(pid) if pid.0 == std::process::id())
            || matches!(target, crate::dispatch::signal::SignalTarget::HostThread(pid) if pid.0 == std::process::id())
        {
            self.queue_self_sigpoll(context, signum, fd, target_tid);
            return;
        }
        // Kernel-internal SIGIO delivery is not gated by the writer's euid.
        let _ = crate::dispatch::signal::bootstrap_signal_send_as(target, signum as u64, None);
    }

    /// Deliver the FASYNC (signal-driven I/O) signal after a guest write to a
    /// host pipe/socket made it readable. Looks up the pipe inode in the
    /// fork-coherent registry; if armed, sends the owner's `F_SETSIG` signal
    /// (default `SIGIO`) through the same cross-process kill path as a guest
    /// `kill(2)`. This is the readiness EDGE the writer can observe: a write that
    /// added bytes transitions the reader's fd to readable, which is exactly when
    /// Linux raises the owner's I/O signal. (`written <= 0` — a short/blocked
    /// write that added nothing — is not an edge and delivers nothing.)
    fn fasync_notify_after_write(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        written: i64,
    ) {
        if written <= 0 {
            return;
        }
        // Hot path: skip the per-write inode fstat entirely unless some fd
        // somewhere is armed for signal-driven I/O (the common case is none).
        if !carrick_signal_core::fasync::any_armed() {
            return;
        }
        let Some(pipe_id) = self.host_pipe_pipe_id(fd) else {
            return;
        };
        let Some(owner) = carrick_signal_core::fasync::lookup(pipe_id) else {
            return;
        };
        // owner_pid is the F_SETOWN value as the guest set it (a PID-namespace id
        // from the owner's getpid()); send_async_owner_signal translates it to a
        // HOST-domain target exactly as the guest kill(2) path does.
        self.send_async_owner_signal(
            context,
            owner.owner_type,
            owner.owner_pid,
            owner.sig,
            fd,
            None,
        );
    }

    fn dnotify_register(
        &self,
        fd: i32,
        mask: LinuxDnotifyMask,
        tid: crate::thread::ThreadId,
    ) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let path = match &*open_file.description.read() {
            OpenDescription::Directory { path, .. } => path.clone(),
            _ => match self.lookup_recorded_fd_open_path(fd) {
                Some(path) => path,
                None => return Err(LINUX_EINVAL),
            },
        };
        let path = self.normalize_dnotify_path(&path);
        let mut registry = self.fs.dnotify_registry.lock();
        if mask.is_empty() {
            registry.retain(|entry| entry.fd != fd);
            return Ok(());
        }
        {
            let mut desc = open_file.description.write();
            if desc.owner().1 == 0 {
                desc.set_owner(
                    LINUX_F_OWNER_PID,
                    crate::namespace::pid::self_ns_pid() as i32,
                );
            }
        }
        let effective_mask = mask - LinuxDnotifyMask::MULTISHOT;
        if let Some(entry) = registry.iter_mut().find(|entry| entry.fd == fd) {
            entry.path = path;
            entry.mask = effective_mask;
            entry.tid = tid;
        } else {
            registry.push(fs::DnotifyRegistration {
                fd,
                tid,
                path,
                mask: effective_mask,
            });
        }
        Ok(())
    }

    pub(in crate::dispatch) fn dnotify_close_fd(&self, fd: i32) {
        self.fs
            .dnotify_registry
            .lock()
            .retain(|entry| entry.fd != fd);
    }

    fn normalize_dnotify_path(&self, path: &str) -> String {
        let normalized = if Path::new(path).is_absolute() {
            normalize_abs_path(path)
        } else {
            normalize_abs_path(&format!("{}/{}", self.cwd().trim_end_matches('/'), path))
        };
        if normalized == "/private/tmp" {
            "/tmp".to_owned()
        } else if let Some(rest) = normalized.strip_prefix("/private/tmp/") {
            format!("/tmp/{rest}")
        } else {
            normalized
        }
    }

    fn dnotify_path_matches(&self, watched: &str, event: &str) -> bool {
        if watched == event {
            return true;
        }
        let watched_canon = self
            .canonicalize_following(watched)
            .map(|path| self.normalize_dnotify_path(&path))
            .unwrap_or_else(|_| watched.to_owned());
        let event_canon = self
            .canonicalize_following(event)
            .map(|path| self.normalize_dnotify_path(&path))
            .unwrap_or_else(|_| event.to_owned());
        watched_canon == event || watched == event_canon || watched_canon == event_canon
    }

    pub(in crate::dispatch) fn dnotify_child(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
    ) {
        self.dnotify_child_for_tid(context, path, mask, None);
    }

    fn dnotify_child_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        if !self.dnotify_event_supported(mask) {
            return;
        }
        let path = self.normalize_dnotify_path(path);
        let Some(parent) = Path::new(&path).parent() else {
            return;
        };
        let parent = display_rootfs_path(parent);
        self.dnotify_directory_for_tid(context, &parent, mask, target_tid);
    }

    fn dnotify_attrib(&self, context: &crate::kernel::KernelContext, path: &str) {
        self.dnotify_attrib_for_tid(context, path, None);
    }

    fn dnotify_attrib_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        let path = self.normalize_dnotify_path(path);
        let mut candidates = vec![path.clone()];
        if let Some(parent) = Path::new(&path).parent() {
            let parent = normalize_abs_path(&display_rootfs_path(parent));
            if !candidates.contains(&parent) {
                candidates.push(parent);
            }
        }
        self.dnotify_directories_for_tid(
            context,
            &candidates,
            LinuxDnotifyMask::ATTRIB,
            target_tid,
        );
    }

    fn dnotify_directory_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        if !self.dnotify_event_supported(mask) {
            return;
        }
        let path = self.normalize_dnotify_path(path);
        self.dnotify_directories_for_tid(context, &[path], mask, target_tid);
    }

    fn dnotify_directories_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        paths: &[String],
        mask: LinuxDnotifyMask,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        let registrations: Vec<_> = self
            .fs
            .dnotify_registry
            .lock()
            .iter()
            .filter(|entry| {
                entry.mask.intersects(mask)
                    && paths
                        .iter()
                        .any(|path| self.dnotify_path_matches(&entry.path, path))
            })
            .cloned()
            .collect();
        let mut notified = std::collections::HashSet::new();
        for entry in registrations {
            if !notified.insert(entry.fd) {
                continue;
            }
            if let Some(open_file) = self.open_file(entry.fd) {
                let (owner_type, owner_pid, sig) = {
                    let desc = open_file.description.read();
                    let (owner_type, owner_pid) = desc.owner();
                    (owner_type, owner_pid, desc.async_sig())
                };
                self.send_async_owner_signal(
                    context,
                    owner_type,
                    owner_pid,
                    sig,
                    entry.fd,
                    target_tid.or(Some(entry.tid)),
                );
            }
        }
    }

    fn dnotify_event_supported(&self, mask: LinuxDnotifyMask) -> bool {
        matches!(
            mask,
            LinuxDnotifyMask::CREATE
                | LinuxDnotifyMask::DELETE
                | LinuxDnotifyMask::RENAME
                | LinuxDnotifyMask::ATTRIB
        )
    }

    /// True iff `fd` refers to a pipe / socket / character device — kinds with
    /// no `->fsync` file op, so `fsync`/`fdatasync` on them is EINVAL on Linux
    /// (e.g. fdatasync02 on `/dev/null`, which carrick serves as a `HostPipe`).
    /// A directory (dir fsync is valid) and synthetic / in-memory files are a
    /// no-op success, so they return false.
    fn fd_lacks_fsync(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(
                &*of.description.read(),
                OpenDescription::HostPipe { .. }
                    | OpenDescription::HostSocket { .. }
                    | OpenDescription::PipeReader { .. }
                    | OpenDescription::PipeWriter { .. }
            )
        })
    }

    /// Write ALL of `bytes` to an inherited stdio host fd (the user's tty/pipe),
    /// looping until the whole buffer is queued. The dup2'd stdio pty slave can
    /// be O_NONBLOCK — a line editor that sets stdin non-blocking flips the
    /// SHARED slave description, so stdout/stderr go non-blocking too — and then
    /// a single `write` can short-write or EAGAIN and silently DROP the tail.
    /// That lost busybox ash's post-Enter newline (output ran onto the prompt
    /// line) and the tail of wide `ls` output. Polling for writability on EAGAIN
    /// restores Linux blocking-tty semantics (a tty write completes fully) without
    /// mutating the shared O_NONBLOCK flag the guest may rely on for reads.
    fn write_all_stdio(fd: i32, bytes: &[u8]) -> DispatchOutcome {
        let mut off = 0usize;
        while off < bytes.len() {
            // BLOCKING-IO-OK: a write to the inherited controlling tty/pipe
            // (stdout/stderr); blocking on backpressure is correct, and callers
            // release the stream_stdio lock before getting here (no dispatcher
            // lock is held across this write).
            // SAFETY: fd is a live inherited stdio fd; we write a sub-slice of `bytes`.
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n > 0 {
                off += n as usize;
                continue;
            }
            // SAFETY: reading the thread-local errno after a failed libc call.
            let e = get_last_error();
            if e == libc::EINTR {
                continue;
            }
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                // Wait for the slave to drain, then retry — never drop the tail.
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: single valid pollfd; blocking wait for writability.
                unsafe { libc::poll(&mut pfd, 1, -1) };
                continue;
            }
            // Hard error: report it if nothing was written, else the partial
            // count (matching write(2)).
            if off == 0 {
                return DispatchOutcome::errno(crate::host_to_linux_errno(e));
            }
            break;
        }
        DispatchOutcome::Returned { value: off as i64 }
    }

    fn read_host_pipe_iovecs<M: GuestMemory>(
        memory: &mut M,
        iovecs: &[LinuxIovec],
        host_fd: i32,
        host_fd_owner: Option<HostFdRef>,
        nonblocking: bool,
    ) -> DispatchOutcome {
        let mut total = 0i64;
        for iov in iovecs {
            let len = match usize::try_from(iov.iov_len) {
                Ok(len) => len,
                Err(_) => return DispatchOutcome::errno(LINUX_EINVAL),
            };
            if len == 0 {
                continue;
            }
            match read_host_pipe(
                memory,
                iov.iov_base,
                len,
                host_fd,
                host_fd_owner.clone(),
                nonblocking,
            ) {
                DispatchOutcome::Returned { value } => {
                    total += value;
                    if value == 0 || (value as usize) < len {
                        break;
                    }
                }
                _ if total > 0 => return DispatchOutcome::Returned { value: total },
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: total }
    }

    /// Write `bytes` to a splice/sendfile destination, honoring `off_out`: NULL
    /// (addr 0) writes at the fd's current position; non-NULL pwrites at the
    /// given offset on a regular HostFile and advances `*off_out` (Linux allows
    /// off_out when fd_out is a regular file even though fd_in is a pipe —
    /// test_os.test_splice_offset_out). off_out on a non-regular target → EINVAL.
    ///
    /// The destination is written with `splice(2)`'s PARTIAL contract
    /// ([`Self::write_output_fd_partial`]): a pipe or socket that fills
    /// mid-transfer yields a short count, never a park until every byte lands.
    /// Every caller either re-stages the undelivered tail
    /// ([`Self::restore_splice_pipe_bytes`], [`Self::restore_pipe_bytes`]) or
    /// never consumed it (`vmsplice` gathers from guest memory), so a short
    /// count loses nothing.
    fn splice_write_out<M: GuestMemory>(
        &self,
        out_fd: i32,
        off_out_addr: u64,
        bytes: &[u8],
        memory: &mut M,
        tid: crate::thread::ThreadId,
        nonblocking: bool,
    ) -> DispatchOutcome {
        if off_out_addr == 0 {
            return match self.write_output_fd_partial(out_fd, bytes, tid) {
                // The destination could not take a single byte. A blocking
                // `splice(2)` waits for room; the partial write path reports
                // that as `EAGAIN` because it asked non-blocking, so restore
                // the guest's own blocking mode here.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN && !nonblocking => {
                    self.splice_output_would_block(out_fd, false)
                }
                other => other,
            };
        }
        let out_off = match read_u64(memory, off_out_addr) {
            Ok(v) => v,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let host_fd = match self.open_file(out_fd).as_ref() {
            Some(of) => match &*of.description.read() {
                OpenDescription::HostFile {
                    host_fd,
                    writable: true,
                    ..
                } => host_fd.raw(),
                OpenDescription::HostFile { .. } => return DispatchOutcome::errno(LINUX_EBADF),
                _ => return DispatchOutcome::errno(LINUX_EINVAL),
            },
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };
        let n = unsafe {
            libc::pwrite(
                host_fd,
                bytes.as_ptr() as *const _,
                bytes.len(),
                out_off as libc::off_t,
            )
        };
        let n = match n.host_syscall_errno() {
            Ok(value) => value as usize,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        if memory
            .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
            .is_err()
        {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned { value: n as i64 }
    }

    /// Pull up to `count` bytes off a `splice(2)` SOURCE pipe.
    ///
    /// `Ok(Ok(bytes))` is the transfer (empty = EOF, the writers are gone).
    /// `Ok(Err(outcome))` is "nothing available": `EAGAIN` for a non-blocking
    /// splice, a `WaitOnFds` readiness park for a blocking one — the same
    /// classification `blocking_io`/`read_host_pipe` apply to every other host
    /// read. carrick's host pipe fds are FORCED `O_NONBLOCK` at creation, so a
    /// bare `read` here surfaced a host `EAGAIN` verbatim and a blocking guest
    /// `splice` on an empty pipe failed instead of waiting.
    fn take_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        host_fd: HostFd,
        host_fd_owner: Option<HostFdRef>,
        count: usize,
        nonblocking: bool,
    ) -> Result<Result<Vec<u8>, DispatchOutcome>, DispatchError> {
        let buf = self.take_staged_splice_pipe_bytes(guest_fd, count)?;
        // A pipe read returns the bytes already available without waiting to
        // fill the caller's whole buffer. The staged queue is the front of this
        // host pipe's logical byte stream, so do not probe the empty host fd
        // after consuming a short staged prefix (that would turn readable data
        // into EAGAIN and lose the prefix).
        if !buf.is_empty() {
            return Ok(Ok(buf));
        }

        let mut buf = vec![0; count];
        // BLOCKING-IO-OK: the host fd is O_NONBLOCK by construction; EAGAIN is
        // classified below rather than reaching the guest raw.
        let n = unsafe {
            libc::read(
                host_fd.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                count,
            )
        };
        let n = match n.host_syscall_errno() {
            Ok(n) => n,
            // EINTR is carrick's own machinery (the SIGURG vCPU kick), never
            // the guest's: route it through readiness like `read_host_pipe`.
            Err(errno) if errno == LINUX_EAGAIN || errno == LINUX_EINTR => {
                return Ok(Err(super::would_block_outcome(
                    host_fd.get(),
                    libc::POLLIN,
                    nonblocking,
                    host_fd_owner,
                )));
            }
            Err(errno) => return Err(DispatchError::Errno(errno)),
        };
        buf.truncate(n as usize);
        Ok(Ok(buf))
    }

    fn take_staged_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        count: usize,
    ) -> Result<Vec<u8>, DispatchError> {
        let description = self
            .open_file(guest_fd)
            .ok_or(DispatchError::Errno(LINUX_EBADF))?
            .description;
        let files = self.captured_file_table();
        let mut staged = files.lock_splice_pushback();
        let Some(queue) = staged.get(&description.id()).cloned() else {
            return Ok(Vec::new());
        };
        let mut queue = queue.lock();
        let bytes = queue.take_vec(count);
        let empty = queue.is_empty();
        drop(queue);
        if empty {
            staged.remove(&description.id());
        }
        Ok(bytes)
    }

    /// Stage `bytes` on an open description named by ID rather than by guest
    /// fd, for callers that must not touch the file table (see
    /// `dispatch::pty_registry`).
    pub(super) fn stage_splice_bytes_for_description(
        &self,
        description: crate::kernel::FileDescriptionId,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            return;
        }
        let files = self.captured_file_table();
        let queue = files
            .lock_splice_pushback()
            .entry(description)
            .or_insert_with(|| Arc::new(Mutex::new(SplicePushback::default())))
            .clone();
        queue.lock().push_back_owned(bytes);
        self.notify_inmem_epoll();
    }

    pub(super) fn stage_splice_pipe_bytes_owned(&self, guest_fd: i32, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(description) = self.open_file(guest_fd).map(|file| file.description) else {
            return;
        };
        let files = self.captured_file_table();
        let queue = files
            .lock_splice_pushback()
            .entry(description.id())
            .or_insert_with(|| Arc::new(Mutex::new(SplicePushback::default())))
            .clone();
        queue.lock().push_back_owned(bytes);
        // The payload is userspace-resident rather than in the host pipe, so a
        // host kqueue/poll edge cannot announce it. Wake epoll instances to
        // force their level-readiness recompute.
        self.notify_inmem_epoll();
    }

    /// Push an undelivered `splice(2)` tail back onto the FRONT of an
    /// in-memory pipe, the [`Self::restore_splice_pipe_bytes`] twin for the
    /// legacy `PipeReader` source. A short destination write must leave the
    /// source byte stream exactly as it found it minus what was delivered.
    fn restore_pipe_bytes(pipe: &PipeRef, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut pipe = pipe.lock();
        for byte in bytes.iter().rev() {
            pipe.buffer.push_front(*byte);
        }
    }

    /// The destination's readiness park for a blocking `splice`/`vmsplice`
    /// whose output could not take a single byte. Nothing has been consumed
    /// when this is reached, so the runtime re-dispatches the whole call after
    /// the wait; a non-blocking caller gets `EAGAIN` instead.
    fn splice_output_would_block(&self, fd: i32, nonblocking: bool) -> DispatchOutcome {
        let target = self.open_file(fd).and_then(|file| {
            let open = file.description.read();
            match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. } => {
                    Some((host_fd.raw(), Some(host_fd.clone())))
                }
                _ => None,
            }
        });
        match target {
            Some((host_fd, owner)) => {
                super::would_block_outcome(host_fd, libc::POLLOUT, nonblocking, owner)
            }
            // No host readiness source to park on (in-memory pipe destination):
            // report the condition rather than parking on nothing.
            None => DispatchOutcome::errno(LINUX_EAGAIN),
        }
    }

    fn restore_splice_pipe_bytes(&self, guest_fd: i32, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Some(description) = self.open_file(guest_fd).map(|file| file.description) else {
            return;
        };
        let files = self.captured_file_table();
        let queue = files
            .lock_splice_pushback()
            .entry(description.id())
            .or_insert_with(|| Arc::new(Mutex::new(SplicePushback::default())))
            .clone();
        queue.lock().push_front(bytes);
    }

    fn write_output_fd(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, false)
    }

    /// `splice(2)` flavour of [`Self::write_output_fd`]: the destination is
    /// written with non-blocking semantics, so a pipe that fills mid-transfer
    /// yields a SHORT count (or `EAGAIN` when nothing moved) instead of parking
    /// until every byte is delivered.
    ///
    /// `write(2)` must deliver the whole buffer and may block to do it;
    /// `splice(2)` explicitly may transfer fewer bytes than requested and
    /// leaves the loop to the caller. Using the `write(2)` contract for splice
    /// deadlocks whenever the only reader is the same single-threaded guest —
    /// it cannot drain the pipe until the splice it is blocked in returns.
    fn write_output_fd_partial(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, true)
    }

    fn write_output_fd_inner(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
        partial_ok: bool,
    ) -> DispatchOutcome {
        let nonblocking = partial_ok || self.io_is_nonblocking(fd, 0);
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.open_file(fd) {
            // Regular-file destinations need the overlay writeback to happen
            // AFTER the description borrow is dropped, so use the same
            // collect-then-write pattern as `write`. Non-file arms return
            // directly. This is what makes splice/copy_file_range/sendfile to a
            // regular file (off_out at the fd's current position) work, matching
            // real Linux (splice pipe->file).
            let outcome: DispatchOutcome;
            let writeback: Option<(String, usize, usize)>;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => return write_pipe(bytes, pipe),
                    OpenDescription::HostPipe {
                        base,
                        host_fd,
                        is_read_end,
                        pipe_id,
                        pty,
                        bidirectional,
                        write_kind,
                        ..
                    } => {
                        // pty ends and O_RDWR FIFOs are bidirectional; only real
                        // one-way pipe ends are gated by is_read_end.
                        #[cfg(feature = "trace-tty")]
                        if bytes.contains(&0x0a) {
                            let hf = host_fd.raw();
                            let tt = unsafe { libc::isatty(hf) };
                            eprintln!(
                                "[PTYWR2DBG-streamed] guest_fd={fd} desc_host_fd={hf} isatty={tt} pty={:?} is_read_end={is_read_end}",
                                pty.as_ref().map(|r| r.is_master)
                            );
                        }
                        return if *is_read_end && pty.is_none() && !*bidirectional {
                            DispatchOutcome::errno(LINUX_EBADF)
                        } else {
                            write_host_pipe(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: *write_kind,
                                    pipe_state: self.host_pipe_capacity_state(
                                        base,
                                        *pipe_id,
                                        *is_read_end,
                                        *bidirectional,
                                        host_fd.raw(),
                                    ),
                                    tid,
                                    sigpipe_on_epipe: false,
                                },
                            )
                        };
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        return write_host_pipe(
                            bytes,
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::SocketLike,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                            },
                        );
                    }
                    OpenDescription::HostFile {
                        base,
                        host_fd,
                        writable,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        if base.is_append() {
                            // Let the HOST kernel perform the append. Linux's
                            // O_APPEND seeks to end and writes as ONE atomic
                            // operation; emulating it as `lseek(SEEK_END)` then
                            // a separate `write` is a race, because anything
                            // touching the shared open description in between
                            // moves the write. A concurrent reader that seeks
                            // to the start sends the append to offset 0, which
                            // is how Go build-cache archives lost their
                            // `!<arch>\n` magic under a parallel `go build`.
                            // Darwin honours O_APPEND natively, so ensure the
                            // description carries it rather than approximating
                            // the offset ourselves.
                            let current = unsafe { libc::fcntl(host_fd.raw(), libc::F_GETFL, 0) };
                            if current >= 0 && current & libc::O_APPEND == 0 {
                                unsafe {
                                    libc::fcntl(
                                        host_fd.raw(),
                                        libc::F_SETFL,
                                        current | libc::O_APPEND,
                                    )
                                };
                            }
                        }
                        return write_host_pipe(
                            bytes,
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::RegularFile,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                            },
                        );
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        let write_offset = *offset;
                        if let Err(errno) = write_into_file_contents(contents, offset, bytes) {
                            return DispatchOutcome::errno(errno);
                        }
                        metadata.size = contents.len();
                        outcome = DispatchOutcome::Returned {
                            value: bytes.len() as i64,
                        };
                        writeback = Some((path.clone(), write_offset, contents.len()));
                    }
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
            }
            if let Some((path, offset, final_size)) = writeback {
                let _ = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .write_file_range(&path, offset, bytes, final_size);
            }
            return outcome;
        }
        if *self.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
            // BLOCKING-IO-OK: streamed write to the inherited stdout/stderr
            // (the user's tty/pipe). Blocking here is the correct backpressure
            // and isn't a guest socket on the server path.
            #[cfg(feature = "trace-io")]
            if !bytes.is_empty() {
                eprintln!(
                    "[IODBG] STREAMWRITE fd={fd} n={} bytes={:02x?}",
                    bytes.len(),
                    &bytes[..bytes.len().min(64)]
                );
            }
            return Self::write_all_stdio(fd, bytes);
        }
        match fd {
            1 => self.io.stdout.lock().extend_from_slice(bytes),
            2 => self.io.stderr.lock().extend_from_slice(bytes),
            _ => return DispatchOutcome::errno(LINUX_EBADF),
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }

    /// If `path` is `/proc/self/fd/{0,1,2}` (or `/proc/<pid>/fd/...`) and the
    /// guest's stdio is the `carrick run -t` controlling pty, return its
    /// `/dev/pts/N` path. This is the symlink glibc `ttyname(3)` reads to name
    /// the terminal. Only the three stdio fds are mapped (they're the pty
    /// slave under `-t`).
    fn proc_self_fd_tty_link(&self, path: &str) -> Option<String> {
        let fd_part = path
            .strip_prefix("/proc/self/fd/")
            .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))?;
        if !matches!(fd_part, "0" | "1" | "2") {
            return None;
        }
        let n = self.pty_table().lock().controlling()?;
        Some(format!("/dev/pts/{n}"))
    }

    /// Linux clears a regular file's set-user-ID (and set-group-ID, when the
    /// file is group-executable) bits on chown — a security measure so a
    /// chowned setuid binary can't grant the new owner's privileges. setgid
    /// without group-exec is a mandatory-locking marker and is left alone.
    fn clear_setid_on_chown(&self, path: &str) {
        let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(path, false) else {
            return;
        };
        if !matches!(real.kind, RootFsEntryKind::File) {
            return;
        }
        let mut mode = real.mode;
        let mut changed = false;
        if mode & 0o4000 != 0 {
            mode &= !0o4000;
            changed = true;
        }
        if mode & 0o2000 != 0 && mode & 0o0010 != 0 {
            mode &= !0o2000;
            changed = true;
        }
        if changed {
            let _ = self.fs.rootfs_vfs.overlay.set_mode(path, mode);
        }
    }

    /// Materialize an ANONYMOUS file fd (an `O_TMPFILE`/`memfd_create` inode that
    /// has no name in any directory) to `target` in the writable overlay. This
    /// is what `linkat(AT_FDCWD, "/proc/self/fd/<n>", AT_FDCWD, target,
    /// AT_SYMLINK_FOLLOW)` does on Linux: the magic `/proc/self/fd` symlink, when
    /// FOLLOWED, names the unnamed inode and gives it a directory entry, copying
    /// nothing — the inode is the SAME. carrick has no shared-inode primitive for
    /// the in-memory backing and the host anon inode is unlinked, so it
    /// materializes a fresh target from the fd's LIVE bytes + creation mode (the
    /// O_TMPFILE test only stats size + mode, never inode identity).
    ///
    /// Returns `None` if `fd` is not such an anonymous file (the caller falls
    /// through to ordinary hard-link handling), else the create result. The mode
    /// is the fd's stored creation mode (already `& ~umask` from open time), and
    /// the size is whatever the guest has written so far.
    fn materialize_anon_fd_to(&self, fd: i32, target: &str) -> Option<Result<(), LinuxErrno>> {
        let open_file = self.open_file(fd)?;
        let desc = open_file.description.read();
        let (bytes, mode) = match &*desc {
            // Real anonymous host inode (`--fs host` O_TMPFILE / memfd). The
            // metadata path is the synthetic "/__carrick_o_tmpfile" sentinel set
            // at open time — a name that exists in no namespace. Read its live
            // size + mode via fstat and its bytes via pread (the kernel owns the
            // offset; pread leaves it untouched).
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } if is_anon_overlay_path(&metadata.path.to_string_lossy()) => {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                    return Some(Err(LINUX_EBADF));
                }
                let size = st.st_size.max(0) as usize;
                let mut buf = vec![0u8; size];
                let mut read = 0usize;
                while read < size {
                    let n = unsafe {
                        libc::pread(
                            host_fd.raw(),
                            buf[read..].as_mut_ptr() as *mut libc::c_void,
                            size - read,
                            read as libc::off_t,
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    read = read.saturating_add(n as usize);
                }
                buf.truncate(read);
                // The GUEST creation mode is the one stamped on the description at
                // O_TMPFILE open time (`create_mode`), NOT the host inode's
                // fstat'd mode. macOS silently strips set-user-ID / set-group-ID
                // from a file an unprivileged process fchmods, so the host fstat
                // would report e.g. 01755 for a 07755 create — dropping the
                // setuid/setgid bits the guest asked for (open14/openat03 test03
                // links an O_TMPFILE created with 07777 and asserts the materialized
                // file keeps all 12 permission bits). Source the mode from the
                // stored metadata so set_mode below records the full guest mode in
                // the CARRICK_MODE_XATTR; only the SIZE/bytes come from the live fd.
                (buf, metadata.mode & 0o7777)
            }
            // In-memory O_TMPFILE / memfd fallback (`--fs memory`): the bytes and
            // creation mode live on the description itself.
            OpenDescription::File {
                path,
                contents,
                metadata,
                ..
            } if is_anon_overlay_path(path) => (contents.to_vec(), metadata.mode & 0o7777),
            _ => return None,
        };
        drop(desc);
        // Create the target from the captured bytes, then apply the creation
        // mode (set_file_contents creates with the host umask; set_mode forces
        // the O_TMPFILE create mode the test stats).
        if self
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents(target, bytes)
            .is_err()
        {
            return Some(Err(LINUX_EROFS));
        }
        let _ = self.fs.rootfs_vfs.overlay.set_mode(target, mode);
        Some(Ok(()))
    }

    fn do_renameat(
        &self,
        context: &crate::kernel::KernelContext,
        request: RenameAtRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        const RENAME_NOREPLACE: u64 = 1;
        const RENAME_EXCHANGE: u64 = 2;
        let RenameAtRequest {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
            target_tid,
        } = request;
        let old = read_guest_c_string(memory, oldpath)?;
        let new_path = read_guest_c_string(memory, newpath)?;
        if old.is_empty() || new_path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved_old = self.resolve_at_path(olddirfd, &old)?;
        let resolved_new = self.resolve_at_path(newdirfd, &new_path)?;
        if crate::vfs::is_synthetic_virtual_file(
            &resolved_old,
            &self.synthetic_proc_context(context),
        ) || crate::vfs::is_synthetic_virtual_file(
            &resolved_new,
            &self.synthetic_proc_context(context),
        ) {
            return Ok(DispatchOutcome::errno(LINUX_EROFS));
        }
        // RENAME_EXCHANGE: atomically swap two EXISTING entries. Both must
        // exist (a missing side → ENOENT, renameat201 case 3); the swap lands
        // in the writable overlay backend, which preserves each entry's
        // mode/contents (renameat202). EXCHANGE that touches a VFS mount
        // (/dev/shm, bind mounts) is not supported by the overlay swap → EINVAL.
        if flags & RENAME_EXCHANGE != 0 {
            if self.fs.vfs_mounts.resolve(&resolved_old).is_some()
                || self.fs.vfs_mounts.resolve(&resolved_new).is_some()
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let old_exists = self.layered_metadata(&resolved_old).is_ok();
            let new_exists = self.layered_metadata(&resolved_new).is_ok();
            if !old_exists || !new_exists {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // Capture dir-ness before the swap for inotify IN_ISDIR.
            let (old_is_dir, new_is_dir) = if self.fs.inotify_registry.is_empty() {
                (false, false)
            } else {
                (
                    self.inotify_path_kind(&resolved_old).unwrap_or(false),
                    self.inotify_path_kind(&resolved_new).unwrap_or(false),
                )
            };
            return match self
                .fs
                .rootfs_vfs
                .exchange_with_flags(&resolved_old, &resolved_new)
            {
                Ok(()) => {
                    if !self.fs.inotify_registry.is_empty() {
                        // A swap is two moves: each name now holds the other's
                        // object, so emit IN_MOVED_FROM/IN_MOVED_TO for both
                        // directions, cookie-tied per direction.
                        self.inotify_move(&resolved_old, &resolved_new, old_is_dir);
                        self.inotify_move(&resolved_new, &resolved_old, new_is_dir);
                    }
                    self.dnotify_child_for_tid(
                        context,
                        &resolved_old,
                        LinuxDnotifyMask::RENAME,
                        target_tid,
                    );
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        let no_replace = flags & RENAME_NOREPLACE != 0;
        // Renaming OVER an OVERRIDABLE single-file injection (/etc/services,
        // /etc/resolv.conf) DETACHES it: the read-only synthetic mount would
        // EROFS on the rename target. Record the override so the new path falls
        // through to the writable overlay (after this, `resolve(&resolved_new)`
        // returns None and the rename lands in the overlay below).
        if let Some(mnew) = self.fs.vfs_mounts.resolve(&resolved_new)
            && mnew.vfs.overridable()
        {
            self.fs.vfs_mounts.override_path(&resolved_new);
        }
        let old_is_vfs_mount = self.fs.vfs_mounts.resolve(&resolved_old).is_some();
        if let Some(mnew) = self.fs.vfs_mounts.resolve(&resolved_new) {
            if !old_is_vfs_mount {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
            }
            if no_replace && mnew.vfs.lookup(&mnew.full_path).is_ok() {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            return match mnew.vfs.rename(&resolved_old, &mnew.full_path) {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        if old_is_vfs_mount {
            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
        }
        // Capture the source kind before the move (for IN_ISDIR) only when
        // something is watching.
        let dnotify_rename_watched = !self.fs.dnotify_registry.lock().is_empty();
        let moved_is_dir = if self.fs.inotify_registry.is_empty() && !dnotify_rename_watched {
            false
        } else {
            self.inotify_path_kind(&resolved_old).unwrap_or(false)
        };
        match self
            .fs
            .rootfs_vfs
            .rename_with_flags(&resolved_old, &resolved_new, no_replace)
        {
            Ok(()) => {
                if !self.fs.inotify_registry.is_empty() {
                    // IN_MOVED_FROM (old name) + IN_MOVED_TO (new name), cookie-
                    // tied, to watches on the respective parent directories.
                    self.inotify_move(&resolved_old, &resolved_new, moved_is_dir);
                    // A watch ON the moved object follows it and also sees
                    // IN_MOVE_SELF (inotify02's directory self-rename). Emitted on
                    // the OLD path key, where the watch still lives, BEFORE the
                    // registry migrates the key to the new path.
                    self.inotify_self(&resolved_old, carrick_abi::LINUX_IN_MOVE_SELF);
                    self.fs
                        .inotify_registry
                        .rename_path(&resolved_old, &resolved_new);
                }
                if moved_is_dir {
                    self.dnotify_child_for_tid(
                        context,
                        &resolved_old,
                        LinuxDnotifyMask::RENAME,
                        target_tid,
                    );
                }
                // A process whose cwd IS the renamed directory (or sits under it)
                // must follow the move: Linux's cwd is an inode, but carrick tracks
                // it as a path string, so rewrite the prefix. Without this a later
                // relative path resolves against the stale cwd and returns ENOENT
                // (inotify02 renames its own cwd, then unlinks a child by relative
                // name). Same-process only; a cross-process ancestor rename does not
                // update another process's cwd string (its inode would, on Linux).
                let cwd = self.cwd();
                if cwd == resolved_old {
                    self.set_cwd(&resolved_new);
                } else if cwd.starts_with(&resolved_old)
                    && cwd.as_bytes().get(resolved_old.len()) == Some(&b'/')
                {
                    let rest = &cwd[resolved_old.len() + 1..];
                    self.set_cwd(&format!("{resolved_new}/{rest}"));
                }
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(errno) => Ok(DispatchOutcome::errno(errno)),
        }
    }

    /// Apply atime/mtime to an *open fd* — the `futimens(fd, …)` path.
    /// For a host-backed file we drive `futimens(2)` on the live host fd so a
    /// subsequent fstat/statx (which both read live on-disk times) observes
    /// the set value. For an in-memory `File`, we route through the overlay by
    /// path. `None` entries are UTIME_OMIT (left untouched).
    fn set_fd_times(
        &self,
        fd: i32,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostFile { host_fd, .. } => {
                let to_ts = |t: Option<(i64, i64)>| match t {
                    Some((sec, nsec)) => libc::timespec {
                        tv_sec: sec as libc::time_t,
                        tv_nsec: nsec as libc::c_long,
                    },
                    None => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                };
                let times = [to_ts(atime), to_ts(mtime)];
                let rc = unsafe { libc::futimens(host_fd.raw(), times.as_ptr()) };
                if rc < 0 {
                    // Best-effort: don't abort the caller on a failed
                    // timestamp set (see the path-branch rationale).
                    let e = std::io::Error::last_os_error();
                    crate::probes::fs_op(
                        "set_fd_times:futimens_err_besteffort",
                        &format!("fd={fd} {e}"),
                        e.raw_os_error().unwrap_or(0),
                    );
                }
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => {
                let path = metadata.path.to_string_lossy().into_owned();
                drop(open);
                if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                    return match m.vfs.set_times(&m.full_path, atime, mtime, false) {
                        Ok(()) => DispatchOutcome::Returned { value: 0 },
                        Err(errno) => DispatchOutcome::errno(errno),
                    };
                }
                // fd-based futimens: the descriptor already refers to the
                // resolved inode, so never re-follow (nofollow = false).
                match self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_times(&path, atime, mtime, false)
                {
                    Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                }
            }
            // Directories, synthetic /proc files, pipes, sockets, anon_inode
            // fds: accept as a no-op (matches Linux's permissive behaviour for
            // the cases tooling actually exercises; we can't persist times for
            // the non-file kinds).
            _ => DispatchOutcome::Returned { value: 0 },
        }
    }

    fn openat2_checked_path<'a>(
        &self,
        dirfd: u64,
        path: &'a str,
        resolve: u64,
    ) -> Result<std::borrow::Cow<'a, str>, LinuxErrno> {
        const RESOLVE_NO_XDEV: u64 = 0x01;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        const RESOLVE_IN_ROOT: u64 = 0x10;

        if resolve == 0 {
            return Ok(std::borrow::Cow::Borrowed(path));
        }

        let anchor = self.openat2_anchor_for_dirfd(dirfd)?;
        let effective_path = if resolve & RESOLVE_IN_ROOT != 0 && Path::new(path).is_absolute() {
            std::borrow::Cow::Owned(join_rootfs_path(&anchor, path.trim_start_matches('/')))
        } else {
            std::borrow::Cow::Borrowed(path)
        };

        if resolve & RESOLVE_BENEATH != 0 {
            if Path::new(path).is_absolute() {
                return Err(crate::linux_abi::LINUX_EXDEV);
            }
            let resolved = self.resolve_at_path(dirfd, path)?;
            if !path_is_under_or_equal(&resolved, &anchor) {
                return Err(crate::linux_abi::LINUX_EXDEV);
            }
        }

        if resolve & RESOLVE_IN_ROOT != 0 && !Path::new(path).is_absolute() {
            let resolved = self.resolve_at_path(dirfd, path)?;
            if !path_is_under_or_equal(&resolved, &anchor) {
                return Err(LINUX_ENOENT);
            }
        }

        if resolve & RESOLVE_NO_XDEV != 0
            && self.openat2_crosses_vfs_mount(&anchor, effective_path.as_ref())
        {
            return Err(crate::linux_abi::LINUX_EXDEV);
        }

        if resolve & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS) != 0
            && self.openat2_touches_magic_link(&anchor, effective_path.as_ref())
        {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }

        if resolve & RESOLVE_NO_SYMLINKS != 0
            && self.openat2_touches_symlink(&anchor, effective_path.as_ref())?
        {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }

        Ok(effective_path)
    }

    pub(super) fn openat2_anchor_for_dirfd(&self, dirfd: u64) -> Result<String, LinuxErrno> {
        let dirfd = (dirfd as i32) as i64 as u64;
        if dirfd == LINUX_AT_FDCWD {
            return Ok(self.cwd());
        }
        match self.open_file(dirfd as i32).as_ref() {
            Some(open_file) => match &*open_file.description.read() {
                OpenDescription::Directory { path, .. } => {
                    if self.layered_metadata(path).is_err() {
                        Err(LINUX_ENOENT)
                    } else {
                        Ok(path.clone())
                    }
                }
                _ => Err(LINUX_ENOTDIR),
            },
            None if self.fd_is_valid(dirfd as i32) => Err(LINUX_ENOTDIR),
            None => Err(LINUX_EBADF),
        }
    }

    fn openat2_absolute_walk_path(&self, anchor: &str, path: &str) -> String {
        if Path::new(path).is_absolute() {
            join_rootfs_path("/", path)
        } else {
            join_rootfs_path(anchor, path)
        }
    }

    fn openat2_crosses_vfs_mount(&self, anchor: &str, path: &str) -> bool {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            if self.fs.vfs_mounts.resolve(&prefix).is_some() {
                return true;
            }
        }
        false
    }

    fn openat2_touches_magic_link(&self, anchor: &str, path: &str) -> bool {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            if proc_self_fd_number(&prefix).is_some()
                || proc_self_magic_link(&prefix).is_some()
                || proc_ns_link(&prefix).is_some()
            {
                return true;
            }
        }
        false
    }

    fn openat2_touches_symlink(&self, anchor: &str, path: &str) -> Result<bool, LinuxErrno> {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            match self.layered_lstat(&prefix) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => return Ok(true),
                Ok(_) => {}
                Err(errno) if errno == LINUX_ENOENT => {}
                Err(errno) => return Err(errno),
            }
        }
        Ok(false)
    }

    pub(super) fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, LinuxErrno> {
        // Cache only AT_FDCWD absolute paths: their resolution is independent of
        // the cwd and of any dirfd, so the guest path string alone is a complete
        // key. (Relative / dirfd-anchored paths would need those in the key; they
        // are rare in the syscall-bound hot loops this targets.) The cache is
        // validated against a fork-coherent generation bumped on structural fs
        // mutations, so a create/delete/rename/symlink correctly invalidates it.
        // Only successful resolutions are cached; errors re-resolve.
        // Build a cache key when the resolution is fully determined by the
        // guest path plus (for a relative path) the cwd:
        //   - absolute path      -> the path itself (cwd/dirfd irrelevant)
        //   - AT_FDCWD + relative -> cwd + '\0' + path, so a later chdir keys a
        //     different entry rather than serving a stale one (LTP fuzzy-sync
        //     tests chdir into their tmpdir and pass a relative name).
        // A relative path through a REAL dirfd depends on that fd's directory,
        // so it is not keyed here.
        let is_atfdcwd = (dirfd as i32) as i64 as u64 == LINUX_AT_FDCWD;
        let fs_context = self.captured_fs_context();
        let cache_key: Option<String> = if std::path::Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => Some(format!("{root}\u{0}{path}")),
                _ => Some(path.to_owned()),
            }
        } else if is_atfdcwd {
            Some(format!("{}\u{0}{}", fs_context.cwd(), path))
        } else {
            None
        };
        // Sample the generation at ENTRY, before reading any fs state: a new
        // entry is stamped with this, so a mutation racing our resolve (which
        // bumps to a higher generation) leaves the entry born stale.
        let gen_at_entry = crate::fs_resolve_cache::current_generation();
        if let Some(ref key) = cache_key {
            // Validate the lookup against the FRESH current generation (read
            // now, not `gen_at_entry`) so a mutation between entry and here also
            // invalidates.
            if let Some(hit) = self
                .fs
                .resolve_cache
                .get(key, crate::fs_resolve_cache::current_generation())
            {
                // Still enforce DAC search permission per call — it depends on
                // live creds, not the path structure (a no-op for root, the hot
                // case). The resolution itself is what the cache elides.
                self.check_search_access(&hit)?;
                return Ok(hit);
            }
        }
        let resolved = match self.resolve_at_path_inner(dirfd, path) {
            Ok(resolved) => resolved,
            Err(errno) => {
                // Linux checks search (x) permission on EACH directory as it
                // descends, so a no-search-permission prefix reports EACCES
                // BEFORE a deeper ENOTDIR/ENOENT is discovered. carrick resolves
                // the whole path as host-root first (finding the deeper error),
                // so re-run the guest DAC search check on the input's directory
                // prefix and let an EACCES there take precedence (pathconf02:
                // abs_path = <mode-0 tmpdir>/testfile/testfile_1). No-op for root.
                if (errno == LINUX_ENOTDIR || errno == LINUX_ENOENT)
                    && let Some(abs) = self.absolute_input_path(dirfd, path)
                {
                    self.check_search_access(&abs)?;
                }
                return Err(errno);
            }
        };
        self.check_search_access(&resolved)?;
        if let Some(key) = cache_key {
            self.fs
                .resolve_cache
                .put(key, resolved.clone(), gen_at_entry);
        }
        Ok(resolved)
    }

    /// The lexical absolute form of a guest input path (anchor + path, ".."
    /// collapsed), WITHOUT existence/symlink resolution — used to run the DAC
    /// search-permission walk on a path whose full resolution already failed.
    /// `None` when the dirfd anchor can't be determined (not a directory fd).
    fn absolute_input_path(&self, dirfd: u64, path: &str) -> Option<String> {
        let dirfd = (dirfd as i32) as i64 as u64;
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match &*self.open_file(dirfd as i32)?.description.read() {
                OpenDescription::Directory { path: dir, .. } => (dir.clone(), path),
                _ => return None,
            }
        };
        Some(join_rootfs_path(&anchor, path))
    }

    /// Linux DAC search-permission check: resolving a path requires search
    /// (execute) permission on EVERY directory component leading to the final
    /// name. carrick runs every guest op as host-root, so the host kernel never
    /// enforces this — but when the guest has dropped to a non-root euid we
    /// must, or a no-search-permission component wrongly succeeds (lstat02,
    /// stat03, truncate03, readlink03, … all assert EACCES here). Root (euid 0)
    /// holds CAP_DAC_OVERRIDE and is exempt, which is also the hot path: the
    /// overwhelming majority of guests run as root, so this returns immediately.
    fn check_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid, not euid: setfsuid(2) moves every file-access check onto the
        // fsuid, and capabilities(7) drops CAP_DAC_READ_SEARCH on an fsuid
        // 0 -> nonzero transition. This function already selected its
        // permission class from `creds.fsuid` below while bypassing on
        // `creds.euid` — two identities in one check, so a process that had
        // dropped only its fsuid searched as root.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let trimmed = abs.trim_end_matches('/');
        let parent = match trimmed.rsplit_once('/') {
            Some((p, _)) if !p.is_empty() => p,
            _ => return Ok(()),
        };
        let mut prefix = String::new();
        for comp in parent.split('/').filter(|c| !c.is_empty()) {
            prefix.push('/');
            prefix.push_str(comp);
            // A missing or non-directory component is ENOENT/ENOTDIR, surfaced
            // by the existence checks elsewhere — not our concern here.
            let Ok(md) = self.layered_metadata(&prefix) else {
                return Ok(());
            };
            if md.kind != RootFsEntryKind::Directory {
                return Ok(());
            }
            let (uid, gid) = self
                .fs
                .rootfs_vfs
                .overlay
                .get_owner(&prefix)
                .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
            // Pick the permission class: owner, then group, else other. (carrick
            // tracks the primary fsgid, not the full supplementary set — a close
            // approximation that the LTP search-permission cases exercise.)
            let x_bit = if creds.fsuid == uid {
                0o100
            } else if creds.fsgid == gid {
                0o010
            } else {
                0o001
            };
            if md.mode & x_bit == 0 {
                return Err(LINUX_EACCES);
            }
        }
        Ok(())
    }

    fn check_directory_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid — same rule as `check_search_access`.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let md = self.layered_metadata(abs)?;
        if md.kind != RootFsEntryKind::Directory {
            return Ok(());
        }
        let (uid, gid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(abs)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        let x_bit = if creds.fsuid == uid {
            0o100
        } else if creds.fsgid == gid {
            0o010
        } else {
            0o001
        };
        if md.mode & x_bit == 0 {
            return Err(LINUX_EACCES);
        }
        Ok(())
    }

    fn resolve_at_path_inner(&self, dirfd: u64, path: &str) -> Result<String, LinuxErrno> {
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
        if path.is_empty() {
            return Ok(path.to_owned());
        }
        // `/dev/fd/N` and `/dev/std{in,out,err}` are Linux symlinks into
        // `/proc/self/fd`; rewrite to that so the magic-fd machinery (open → dup
        // N) serves them. The rewritten path is absolute, so it re-resolves
        // independently of `dirfd`. (Fixes bash process substitution `<(...)`.)
        if let Some(rewritten) = rewrite_dev_fd_alias(path) {
            return self.resolve_at_path(dirfd, &rewritten);
        }
        // ENAMETOOLONG: Linux rejects any single component > NAME_MAX (255) and
        // any total path > PATH_MAX (4096) at resolution time. carrick lacked
        // these limits, so a too-long path SUCCEEDED instead of failing
        // (LTP lstat02/stat03/truncate03/open13/… "returned 0, expected -1").
        check_path_length(path)?;
        // The anchor directory a relative path resolves against (already a real,
        // symlink-free path): "/" for an absolute path, the cwd for AT_FDCWD, else
        // the dirfd's directory.
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match self.open_file(dirfd as i32).as_ref() {
                Some(open_file) => match &*open_file.description.read() {
                    OpenDescription::Directory { path: dir, .. } => {
                        // A relative *at op through a dirfd whose directory has
                        // since been removed (rmdir) resolves to ENOENT on Linux:
                        // the open fd persists but its path no longer exists.
                        // carrick keeps the Directory description cached, so
                        // re-verify the anchor still exists in the layered view
                        // (symlinkat01/linkat01 deldirfd cases → ENOENT).
                        if self.layered_metadata(dir).is_err() {
                            return Err(LINUX_ENOENT);
                        }
                        (dir.clone(), path)
                    }
                    _ => return Err(LINUX_ENOTDIR),
                },
                // A valid fd that isn't in the table (e.g. a stdio fd) is still a
                // non-directory, so a relative path can't be anchored to it →
                // ENOTDIR; only a genuinely-invalid fd is EBADF (statx03 uses
                // dfd=1 → ENOTDIR, dfd=-1 → EBADF).
                None if self.fd_is_valid(dirfd as i32) => return Err(LINUX_ENOTDIR),
                None => return Err(LINUX_EBADF),
            }
        };
        // A ".." component must be applied AFTER following any preceding symlink
        // (Linux: "a/.." with a -> b/c lands in b, not lexically at the parent of
        // a). join_rootfs_path collapses ".." LEXICALLY, before symlink
        // resolution, so it gets this wrong. Take a symlink-aware walk only when a
        // ".." is present; the (overwhelmingly common) no-".." path keeps the
        // cheap lexical join + the existing intermediate-symlink rewrite, so the
        // hot path is unchanged. (Go os TestRootConsistency*/dotdot_in_path_after_symlink.)
        if path.split('/').any(|c| c == "..") || anchor.split('/').any(|c| c == "..") {
            return self.resolve_dotdot_symlink_aware(&anchor, path);
        }
        let abs = join_rootfs_path(&anchor, path);
        // Fast path: ONE kernel-walked openat+F_GETPATH of the PARENT chain
        // replaces both per-component O(K²) passes below (validate_intermediate_
        // dirs + resolve_intermediate_symlinks) for the common case — every
        // intermediate exists, is a directory, and involves no symlink or
        // Unicode-alias redirection. Anything non-trivial → the exact slow path.
        match self.fs.rootfs_vfs.overlay.validate_parents_fast(&abs) {
            crate::fs_backend::ParentResolve::AllDirsNoSymlink => return Ok(abs),
            crate::fs_backend::ParentResolve::NotDir => return Err(LINUX_ENOTDIR),
            crate::fs_backend::ParentResolve::Slow => {}
        }
        // ELOOP: Linux caps the CUMULATIVE symlinks followed across the whole path
        // at MAXSYMLINKS (40). carrick's per-component resolvers each cap at 40 but
        // don't share a budget, so a path stacking many shallow intermediate
        // symlinks (LTP stat03/lstat02/truncate03 build `test_eloop -> ../test_eloop`
        // repeated ~43×) would otherwise resolve to a directory instead of failing.
        // Surface the overflow here, on the slow (symlink-bearing) path only.
        if self.symlink_follow_budget_exceeded(&abs) {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }
        // ENOTDIR: an existing intermediate component that is not a directory
        // can't be traversed. carrick previously let the final lookup return
        // ENOENT (or leniently resolved through it). Synthesize ENOTDIR here so
        // `stat("/etc/passwd/foo")` & co match Linux (lstat02/stat03/…).
        self.validate_intermediate_dirs(&abs)?;
        // Collapse intermediate (non-final) directory symlinks so the returned
        // path is symlink-free in its parent chain. Downstream consumers
        // (real_stat via cap-std, layered_metadata, canonicalize_following's
        // final-component follow) cannot traverse an intermediate symlink whose
        // target is absolute (cap-std treats an absolute target as a sandbox
        // escape), so `stat("/link/f")` where `/link -> /realdir` would wrongly
        // return ENOENT. Rewriting to `/realdir/f` matches Linux path
        // resolution. The final component is intentionally NOT followed here —
        // each caller decides lstat-vs-stat semantics (AT_SYMLINK_NOFOLLOW).
        Ok(self.resolve_intermediate_symlinks(&abs))
    }

    /// Resolve a path containing ".." components symlink-AWARE: walk left to
    /// right, FOLLOWING each intermediate symlink before applying "..", so
    /// "a/../c" with `a -> b/c` lands in `b` (then `b/c`), matching Linux — not
    /// the lexical `/c` that `join_rootfs_path` would produce. The FINAL component
    /// is NOT followed (the caller decides lstat-vs-stat). A non-directory
    /// intermediate is ENOTDIR; a symlink cycle propagates ELOOP; a missing
    /// intermediate propagates ENOENT before any later `..` can collapse it.
    /// Only invoked when a ".." is actually present.
    fn resolve_dotdot_symlink_aware(&self, anchor: &str, path: &str) -> Result<String, LinuxErrno> {
        let mut all: Vec<&str> = Vec::new();
        if !Path::new(path).is_absolute() {
            all.extend(anchor.split('/').filter(|c| !c.is_empty() && *c != "."));
        }
        all.extend(path.split('/').filter(|c| !c.is_empty() && *c != "."));

        // `base` is the resolved, symlink-free prefix so far (no trailing slash;
        // empty string == root).
        let mut base = String::new();
        let last = all.len().saturating_sub(1);
        for (i, comp) in all.iter().enumerate() {
            if *comp == ".." {
                // Climb one resolved component (never above root).
                match base.rfind('/') {
                    Some(pos) => base.truncate(pos),
                    None => base.clear(),
                }
                continue;
            }
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            if i == last {
                // Final component: leave it unfollowed for the caller.
                base = candidate;
                break;
            }
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Symlink to a non-directory can't be traversed as an
                        // intermediate; ELOOP/other errors propagate.
                        Ok(_) => return Err(LINUX_ENOTDIR),
                        Err(e) => return Err(e),
                    }
                }
                // A real directory intermediate: descend.
                Ok(md) if md.kind == RootFsEntryKind::Directory => base = candidate,
                // An existing non-directory intermediate (regular file, device,
                // FIFO) can't be traversed → ENOTDIR.
                Ok(_) => return Err(LINUX_ENOTDIR),
                // A missing or otherwise inaccessible intermediate stops path
                // resolution immediately. In particular, `missing/..` is ENOENT
                // on Linux; it must not collapse back to the parent.
                Err(errno) => return Err(errno),
            }
        }
        Ok(if base.is_empty() {
            "/".to_owned()
        } else {
            base
        })
    }

    /// Rewrite `abs` so every intermediate (non-final) directory-symlink
    /// component is replaced by its resolved target, leaving the final
    /// component untouched. Best-effort: a component that doesn't resolve to a
    /// directory (dangling/non-dir symlink, ELOOP) leaves the path from that
    /// point unchanged, so the downstream lookup surfaces the correct
    /// ENOENT/ENOTDIR. Bounded by `canonicalize_following`'s own ELOOP guard.
    fn resolve_intermediate_symlinks(&self, abs: &str) -> String {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return abs.to_owned();
        }
        let mut base = String::new();
        for comp in &comps[..comps.len() - 1] {
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Unresolvable/non-dir symlink intermediate: stop
                        // rewriting; leave the rest for the downstream lookup.
                        _ => return abs.to_owned(),
                    }
                }
                // Plain directory (or not-yet-statable): keep walking.
                _ => {
                    base = candidate;
                }
            }
        }
        if let Some(name) = comps.last() {
            base.push('/');
            base.push_str(name);
        }
        if base.is_empty() {
            "/".to_owned()
        } else {
            base
        }
    }

    /// Walk the intermediate (non-final) components of an already-joined
    /// absolute guest path; if any EXISTING intermediate is a non-directory
    /// (regular file / char device), traversing it is ENOTDIR. A missing
    /// intermediate is left alone — the final lookup surfaces ENOENT, which is
    /// correct. Symlink intermediates are followed by the downstream resolver,
    /// so they're not flagged here. Cheap: short-circuits at the first missing
    /// component (so a fresh deep path costs one lookup).
    fn validate_intermediate_dirs(&self, abs: &str) -> Result<(), LinuxErrno> {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return Ok(()); // no intermediates
        }
        let mut prefix = String::new();
        for comp in &comps[..comps.len() - 1] {
            prefix.push('/');
            prefix.push_str(comp);
            match self.layered_lstat(&prefix) {
                Ok(md) => match md.kind {
                    RootFsEntryKind::Directory => {}
                    // A symlink intermediate is traversable IFF it resolves to a
                    // directory (Linux follows it). Resolve through the layered
                    // VFS — this handles an absolute in-rootfs target (e.g.
                    // `/tmp/sm_link -> /tmp/sm_real`) that a single-backend
                    // cap-std follow can't (it treats absolute as a sandbox
                    // escape). A symlink to a non-directory (or a dangling one)
                    // is ENOTDIR, matching Linux.
                    RootFsEntryKind::Symlink => match self.canonicalize_following(&prefix) {
                        Ok(target) if self.path_is_directory(&target) => {}
                        // A self-referential / over-deep intermediate symlink is
                        // a CYCLE → ELOOP, not ENOTDIR. canonicalize_following
                        // caps at 40 hops and returns ELOOP; propagate it rather
                        // than collapsing to the non-dir ENOTDIR below
                        // (lstat02/stat03/truncate03/readlink03 assert ELOOP on
                        // an intermediate self-linking component).
                        Err(e) if e == crate::linux_abi::LINUX_ELOOP => return Err(e),
                        _ => return Err(LINUX_ENOTDIR),
                    },
                    // A regular file / char device can't be a path component.
                    _ => return Err(LINUX_ENOTDIR),
                },
                // Intermediate doesn't exist (or isn't statable) → stop; the
                // final resolution returns ENOENT as Linux does.
                Err(_) => return Ok(()),
            }
        }
        Ok(())
    }

    /// Shared core of fchmodat / fchmodat2: resolve `pathname` against `dirfd`,
    /// then apply `mode` (with the setgid-clear rule) to the writable backend.
    /// Synthetic /proc /sys paths and the in-memory backend accept it as a
    /// no-op success as long as the path exists. Flag handling differs between
    /// the two callers, so it stays in the syscall wrappers.
    fn chmod_at(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(memory, pathname)?;
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved = self.resolve_at_path(dirfd, &path)?;
        // chmod(2) FOLLOWS a final symlink — it changes the TARGET's mode, not
        // the link's (test_posix.test_chmod_dir_symlink). resolve_at_path stops
        // at the link itself, so dereference it here. (fchmodat2's advisory
        // AT_SYMLINK_NOFOLLOW stays unmodeled on the disk-authoritative backend;
        // a dangling/failed follow falls back to the link path unchanged.)
        let resolved = self.canonicalize_following(&resolved).unwrap_or(resolved);
        if crate::vfs::is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context(context)) {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if let Err(errno) = self.layered_metadata(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(errno) = self.chmod_permission_errno(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        let mode = self.maybe_clear_setgid(&resolved, (mode & 0o7777) as u32);
        if let Some(m) = self.fs.vfs_mounts.resolve(&resolved) {
            return match m.vfs.chmod(&m.full_path, mode) {
                Ok(()) => {
                    self.inotify_attrib(&resolved);
                    self.dnotify_attrib(context, &resolved);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        match self.fs.rootfs_vfs.overlay.set_mode(&resolved, mode) {
            Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                self.inotify_attrib(&resolved);
                self.dnotify_attrib(context, &resolved);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
        }
    }

    /// Linux clears the setgid bit (S_ISGID) on a chmod by an UNPRIVILEGED
    /// process whose effective gid doesn't match the file's group — so a
    /// non-owner-group user can't make a file setgid to a group it isn't in
    /// (chmod05/fchmod05). Root (euid==0) keeps the bit. carrick tracks only the
    /// effective gid (not supplementary groups), which is what the LTP tests
    /// exercise. Returns the mode to actually apply.
    fn maybe_clear_setgid(&self, path: &str, mode: u32) -> u32 {
        const S_ISGID: u32 = 0o2000;
        if mode & S_ISGID == 0 {
            return mode;
        }
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return mode;
        }
        let file_gid = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(path)
            .map(|(_, g)| g)
            .unwrap_or(carrick_abi::NsGid::ROOT);
        if file_gid != creds.egid {
            return mode & !S_ISGID;
        }
        mode
    }

    fn chown_uid_arg(arg: u64) -> Option<carrick_abi::NsUid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsUid::new(value))
    }

    fn chown_gid_arg(arg: u64) -> Option<carrick_abi::NsGid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsGid::new(value))
    }

    /// Stamp the owner (and, when inherited, the setgid bit) on a freshly
    /// created special node (mknod FIFO/device/socket), mirroring mkdirat's
    /// rule: a new inode's group is the creator's egid, UNLESS the parent
    /// directory is setgid (S_ISGID), in which case it inherits the parent's
    /// group and the node itself becomes setgid. Without this the host assigns
    /// its own gid and a later stat reports the wrong st_gid (LTP mknod08
    /// expects st_gid == the process egid because the parent isn't setgid).
    /// Record the creating process as the owner of a just-created node, with
    /// Linux's setgid-parent gid inheritance. Called by every path that
    /// materialises a new node — `openat(O_CREAT)`, `mknod`, and `bind(2)` on an
    /// AF_UNIX socket (`dispatch::net`), which is why this is `pub(super)`.
    pub(super) fn stamp_new_node_owner(&self, path: &str, node_mode: u32) {
        const S_ISGID: u32 = 0o2000;
        let creds = self.cred_snapshot();
        let mut owner_gid = creds.egid;
        let mut inherited_gid = false;
        if let Some(parent) = Path::new(path).parent() {
            let parent_str = display_rootfs_path(parent);
            if let Ok(pmd) = self.layered_metadata(&parent_str)
                && pmd.mode & S_ISGID != 0
                && let Some((_, pgid)) = self.fs.rootfs_vfs.overlay.get_owner(&parent_str)
            {
                owner_gid = pgid;
                inherited_gid = true;
                let _ = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_mode(path, node_mode | S_ISGID);
            }
        }
        if !creds.euid.is_root() || !owner_gid.is_root() || inherited_gid {
            let _ = self
                .fs
                .rootfs_vfs
                .overlay
                .set_owner(path, Some(creds.euid), Some(owner_gid));
        }
    }

    fn chown_permission_errno(
        &self,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        if uid.is_some() {
            return Some(LINUX_EPERM);
        }
        if gid.is_some_and(|gid| gid != creds.egid) {
            return Some(LINUX_EPERM);
        }
        None
    }

    /// chmod(2)/fchmod(2) permission: only the file owner or a process with
    /// CAP_FOWNER (modeled as euid==0) may change a file's mode; everyone else
    /// gets EPERM (Linux fs/attr.c chmod_common -> inode_owner_or_capable). When
    /// the backend can't supply an owner (the in-memory backend has no real
    /// owner/mode), we don't enforce — matching the legacy root model used
    /// elsewhere on that backend (and mirroring `maybe_clear_setgid`'s lookup).
    fn chmod_permission_errno(&self, path: &str) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        match self.fs.rootfs_vfs.overlay.get_owner(path) {
            Some((owner_uid, _)) if owner_uid != creds.euid => Some(LINUX_EPERM),
            _ => None,
        }
    }

    /// Apply chown to the file backing an fd, recording the guest-visible owner
    /// on the backend (durable via xattr on `--fs host`). Shared by `fchown` and
    /// `fchownat(..., AT_EMPTY_PATH)` so both record the owner identically.
    /// `fd` must already be validated by the caller.
    fn fchown_by_fd(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> DispatchOutcome {
        let path = self
            .open_file(fd)
            .and_then(|of| match &*of.description.read() {
                OpenDescription::HostFile { metadata, .. }
                | OpenDescription::File { metadata, .. }
                | OpenDescription::Directory { metadata, .. } => {
                    Some(metadata.path.to_string_lossy().into_owned())
                }
                _ => None,
            });
        if let Some(path) = path {
            if let Some(errno) = self.chown_permission_errno(uid, gid) {
                return DispatchOutcome::errno(errno);
            }
            if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                if let Err(errno) = m.vfs.chown(&m.full_path, uid, gid, false) {
                    return DispatchOutcome::errno(errno);
                }
            } else {
                let _ = self.fs.rootfs_vfs.overlay.set_owner(&path, uid, gid);
            }
            self.clear_setid_on_chown(&path);
            self.dnotify_attrib(context, &path);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// Linux raises SIGPIPE on the writing thread when a write hits a broken
    /// pipe (the read end is closed → EPIPE), in addition to returning EPIPE
    /// (LTP write05). Mark it pending so the runtime delivers it per the
    /// disposition: a handler runs, SIG_DFL terminates, a blocked SIGPIPE stays
    /// pending. Skip the mark when SIGPIPE is ignored (the common case for
    /// pipe/socket-heavy programs) so we don't queue a signal that's discarded.
    fn raise_sigpipe_on_epipe<M: GuestMemory>(
        &self,
        cx: &SyscallCtx<M>,
        outcome: DispatchOutcome,
    ) -> DispatchOutcome {
        if matches!(&outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EPIPE)
            && !self.signal_is_ignored(cx.kernel, LINUX_SIGPIPE)
        {
            let tid = Self::ctx_tid(cx);
            self.mark_signal_pending(cx.kernel, tid, LINUX_SIGPIPE);
        }
        outcome
    }

    /// The RLIMIT_FSIZE soft cap the guest set via setrlimit/prlimit64, or
    /// `None` when unset / RLIM_INFINITY. A write whose bytes would land past
    /// this offset is EFBIG + SIGXFSZ on Linux (llseek01). Stored in the
    /// per-process override table (RLIMIT_FSIZE == resource 1).
    fn fsize_soft_limit(&self) -> Option<u64> {
        let ov = self
            .proc
            .lock()
            .rlimit_overrides
            .get(LINUX_RLIMIT_FSIZE as usize)
            .copied()
            .flatten()?;
        (ov.rlim_cur != LINUX_RLIM_INFINITY).then_some(ov.rlim_cur)
    }

    /// Enforce RLIMIT_FSIZE for a regular-file write starting at `offset` that
    /// would carry `len` bytes. Returns `Some(EFBIG)` (after queuing SIGXFSZ)
    /// when the write STARTS at or beyond the soft cap — the case Linux errors
    /// outright (a straddling write is truncated to the cap, not an error, and
    /// is left to the backend). `None` means the write may proceed.
    fn fsize_write_guard<M: GuestMemory>(
        &self,
        cx: &SyscallCtx<M>,
        offset: u64,
        len: usize,
    ) -> Option<LinuxErrno> {
        if len == 0 {
            return None;
        }
        let limit = self.fsize_soft_limit()?;
        if offset >= limit {
            if !self.signal_is_ignored(cx.kernel, LINUX_SIGXFSZ) {
                self.mark_signal_pending(cx.kernel, Self::ctx_tid(cx), LINUX_SIGXFSZ);
            }
            return Some(LINUX_EFBIG);
        }
        None
    }

    /// Linux DAC: may the calling guest create/remove an entry in directory
    /// `dir_path`? It needs WRITE + EXECUTE (search) on the directory for its
    /// permission class (owner/group/other), evaluated against the
    /// guest-tracked mode + owner xattrs and the guest fs-uid/gid. Root (euid 0
    /// = CAP_DAC_OVERRIDE) always passes; an unknown mode/owner fails OPEN so a
    /// directory carrick has no record for is never wrongly denied. Only bites
    /// when a guest drops to a non-root euid — the default root guest (incl. the
    /// apt/python demos) is unaffected.
    fn guest_can_modify_dir(&self, dir_path: &str) -> bool {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return true;
        }
        let Ok(md) = self.layered_metadata(dir_path) else {
            return true;
        };
        let mode = md.mode & 0o7777;
        let (ouid, ogid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(dir_path)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        let class_bits = if creds.fsuid == ouid {
            mode >> 6
        } else if creds.fsgid == ogid {
            mode >> 3
        } else {
            mode
        } & 0o7;
        // Need both write (2) and execute/search (1).
        class_bits & 0o3 == 0o3
    }

    /// Linux sticky-bit (S_ISVTX) protection for removing `entry_path` from its
    /// parent `dir_path`: in a sticky directory an unprivileged caller may
    /// remove an entry only if it owns the entry OR owns the directory; else
    /// EPERM (LTP rmdir03 case 2). Returns true (allowed) for root, a
    /// non-sticky dir, or unknown ownership (fail open).
    fn guest_sticky_delete_ok(&self, dir_path: &str, entry_path: &str) -> bool {
        const S_ISVTX: u32 = 0o1000;
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return true;
        }
        let Ok(md) = self.layered_metadata(dir_path) else {
            return true;
        };
        if md.mode & S_ISVTX == 0 {
            return true; // not sticky → no extra restriction
        }
        let dir_owner = self.fs.rootfs_vfs.overlay.get_owner(dir_path).map(|o| o.0);
        let entry_owner = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(entry_path)
            .map(|o| o.0);
        // Allowed only if the caller owns the entry or the directory.
        entry_owner == Some(creds.fsuid) || dir_owner == Some(creds.fsuid)
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn io_setup(this, cx, nr_events: u64, ctxp: GuestPtr) {
            legacy_aio::io_setup(this, cx, nr_events, ctxp)
        }

        fn io_destroy(this, _cx, raw_ctx: u64) {
            legacy_aio::io_destroy(this, raw_ctx)
        }

        fn io_submit(this, cx, raw_ctx: u64, raw_count: u64, iocbpp: GuestPtr) {
            legacy_aio::io_submit(this, cx, raw_ctx, raw_count, iocbpp)
        }

        fn io_cancel(this, cx, raw_ctx: u64, iocb: GuestPtr, result: GuestPtr) {
            legacy_aio::io_cancel(this, cx, raw_ctx, iocb, result)
        }

        fn io_getevents(this, cx, raw_ctx: u64, min_nr: u64, nr: u64, events: GuestPtr, _timeout: GuestPtr) {
            legacy_aio::io_getevents(this, cx, raw_ctx, min_nr, nr, events)
        }

        fn getcwd(this, cx, address: GuestPtr, size: u64) {

            let address = address.0;
            let size =
                usize::try_from(size).map_err(|_| DispatchError::LengthTooLarge(size))?;
            // carrick stores the GLOBAL cwd and does NOT re-root path
            // resolution, so getcwd(2) reports that global path verbatim in
            // almost every case — including a cwd set by a post-chroot chdir
            // (`chroot("/x"); chdir("/etc"); getcwd()` → "/etc", matching
            // Linux). The ONE exception is the CVE-2018-1000001 shape realpath01
            // exercises: the guest chroots into a SUBDIRECTORY of its cwd
            // without chdir'ing in, leaving the cwd ABOVE the new root. Such a
            // cwd is unreachable from the root, so getcwd returns ENOENT. A
            // chroot("/") is a no-op and never triggers this.
            let fs_context = this.captured_fs_context();
            let cwd = fs_context.cwd();
            let cwd = match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => {
                    if cwd == root {
                        // The guest chdir'd into the new root itself.
                        "/".to_owned()
                    } else if let Some(rel) = cwd.strip_prefix(&format!("{root}/")) {
                        // cwd lies inside the root subtree.
                        format!("/{rel}")
                    } else if cwd == "/" || root.starts_with(&format!("{cwd}/")) {
                        // cwd is a strict ANCESTOR of the new root: it is above
                        // the root and unreachable (realpath01 / CVE-2018-1000001).
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    } else {
                        // Neither inside nor above the root: report the global
                        // cwd verbatim (carrick does not re-root).
                        cwd
                    }
                }
                // No chroot, or the chroot("/") no-op.
                _ => cwd,
            };
            // The cwd is stored in the VFS layer's reversible escape form;
            // decode to the opaque path BYTES so getcwd is byte-exact for a
            // cwd that contains undecodable (non-UTF-8) components.
            let mut bytes = crate::pathcodec::decode_to_bytes(&cwd);
            bytes.push(0);
            if bytes.len() > size {
                return Ok(DispatchOutcome::errno(LINUX_ERANGE));
            }
            cx.memory.write_bytes(address, &bytes)?;
            // Linux getcwd(2) returns the LENGTH of the buffer filled (including
            // the terminating NUL), not the buffer address. glibc tolerates a
            // positive non-length, but tools that use the return value as a
            // length (and the kernel ABI) require the real count.
            Ok(DispatchOutcome::Returned {
                value: bytes.len() as i64,
            })

        }

        fn faccessat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {

            // Linux's `faccessat` (syscall 48) takes only (dirfd, pathname, mode).
            // The 4-arg form with flags is `faccessat2` (syscall 439). We were
            // erroneously reading x3 as flags here, which is whatever uninit
            // register state the caller had — making glibc see EINVAL for normal
            // access(F_OK)-style calls and abort with "stack smashing detected".
            this.access_at(cx.kernel, dirfd, pathname.0, mode, 0, &*cx.memory)

        }

        fn faccessat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            this.access_at(cx.kernel, dirfd, pathname.0, mode, flags, &*cx.memory)

        }

        fn chdir(this, cx, pathname: GuestPtr) {

            let pathname = pathname.0;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            // Follow a trailing directory symlink the way Linux chdir(2) does,
            // THROUGH the full VFS — so a symlink whose target lands in a
            // different mount (e.g. a /tmp scratch link → /run bind mount)
            // resolves instead of returning ENOTDIR (the per-backend real_stat
            // only follows within one backend). getcwd then reports the resolved
            // target's canonical path, matching the kernel. Uses the LAYERED
            // lookup so a freshly mkdir'd dir is visible (dpkg-deb chdir).
            let resolved = this.canonicalize_following(&path)?;
            let metadata = this.layered_metadata(&resolved)?;
            if metadata.kind != RootFsEntryKind::Directory {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            this.captured_fs_context()
                .set_cwd(display_rootfs_path(&metadata.path));
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn chroot(this, cx, pathname: GuestPtr) {

            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            // Resolve the path FIRST — the kernel does the lookup before the
            // capability check, so an over-long path is ENAMETOOLONG and a
            // missing/non-dir target is ENOENT/ENOTDIR even for an unprivileged
            // caller (chroot03 expects ENAMETOOLONG, not EPERM). resolve_at_path
            // already enforces the length limits.
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            let resolved = this.canonicalize_following(&path)?;
            let metadata = this.layered_metadata(&resolved)?;
            if metadata.kind != RootFsEntryKind::Directory {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            let new_root = display_rootfs_path(&metadata.path);
            if let Err(errno) = this.check_directory_search_access(&new_root) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // chroot(2) requires CAP_SYS_CHROOT. carrick models the capability
            // set as "effective uid 0"; a guest that has dropped to a non-root
            // euid no longer holds it (chroot01 expects EPERM).
            if !this.cred_snapshot().euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // The request is valid and we accept it. Full per-process root
            // enforcement inside resolve_at_path (so the guest's "/" maps under
            // the new root) is a tracked follow-up — chroot02 only needs the call
            // to succeed; chroot04 (EACCES from a no-search-permission component)
            // awaits that plus the DAC search-permission check. We DO record the
            // new root so getcwd can report a cwd left outside it as ENOENT
            // (realpath01 / CVE-2018-1000001).
            this.captured_fs_context().set_chroot_root(Some(new_root));
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchdir(this, cx, fd: Fd) {

            let fd: Fd = fd;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            Ok(match &*open {
                OpenDescription::Closed { .. } => DispatchOutcome::errno(LINUX_EBADF),
                OpenDescription::Directory { metadata, .. } => {
                    let dir_path = display_rootfs_path(&metadata.path);
                    // fchdir(2) requires search (execute) permission on the
                    // directory the fd refers to. The fd may have been opened
                    // O_RDONLY (needing only read) and the directory later
                    // chmod'd to drop its search bit — so re-stat to observe the
                    // CURRENT mode/owner rather than the value captured at open
                    // time. A non-root euid lacking X on the directory gets
                    // EACCES (fchdir03); root (euid 0) bypasses via
                    // CAP_DAC_OVERRIDE.
                    let creds = this.cred_snapshot();
                    if !creds.euid.is_root()
                        && let Some(real) =
                            this.fs.rootfs_vfs.overlay.real_stat(&dir_path, true)
                        && crate::dispatch::dac_check(
                            creds.euid,
                            creds.egid,
                            real.uid,
                            real.gid,
                            real.mode,
                            true,
                            LINUX_X_OK,
                        )
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EACCES));
                    }
                    this.captured_fs_context().set_cwd(dir_path);
                    DispatchOutcome::Returned { value: 0 }
                }
                OpenDescription::File { .. }
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => DispatchOutcome::errno(LINUX_ENOTDIR),
            })

        }

        fn pipe2(this, cx, pipefd: GuestPtr, flags: u64) {

            let address = pipefd.0;
            let memory = &mut *cx.memory;
            // Accept O_DIRECT as a no-op flag. Real Linux uses it to request
            // packet-mode pipes (each write becomes a discrete packet, reads
            // truncate at packet boundaries). Darwin pipes don't have that
            // semantic, but apps using it for a single-byte signal stream or a
            // 3-byte-write/big-buffer-read pattern work identically against a
            // regular pipe — and rejecting the flag breaks every Linux app that
            // probes for packet-mode availability. The probe `pipeextra` only
            // exercises the regular-pipe-compatible subset.
            // O_DIRECT is arch-specific. aarch64/arm: 0o200000 (0x10000).
            // The asm-generic value 0o40000 is NOT what musl/glibc ship for
            // aarch64 — checking the wrong value silently rejects every
            // O_DIRECT pipe2 call (the bit's still present in the flags).
            if LinuxPipe2Flags::from_bits(flags).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            if crate::dispatch::fs::state::HOST_PIPE_FD_PRESSURE
                .is_exhausted_by(this.captured_file_table().read_open_files().len())
            {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            }

            // Allocate a real host pipe so the two ends share state via the
            // kernel and survive `libc::fork(2)` natively. macOS's `pipe(2)`
            // returns two fds: [0] read end, [1] write end.
            let mut host_fds = [0i32; 2];
            if (unsafe { libc::pipe(host_fds.as_mut_ptr()) }) != 0 {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            }

            let host_read = host_fds[0];
            let host_write = host_fds[1];

            // The access mode must be encoded per end so fcntl(F_GETFL) reports
            // it: the read end is O_RDONLY (0), the write end O_WRONLY. Without
            // this, glibc's fdopen(write_end, "w") sees O_RDONLY via F_GETFL and
            // fails with EINVAL ("Failed to open new FD - fdopen") — apt's dpkg
            // status pipe hit exactly that.
            let nonblock = flags & LINUX_O_NONBLOCK;
            // Keep host pipe ends non-blocking regardless of the guest-visible
            // O_NONBLOCK bit. Blocking-mode guest calls park through WaitOnFds
            // after a host EAGAIN instead of blocking under dispatcher locks.
            for hfd in [host_read, host_write] {
                crate::dispatch::net::set_host_nonblocking(hfd);
            }
            let fd_flags = linux_fd_flags_from_open_flags(flags);
            // Both ends share ONE capacity cell so F_SETPIPE_SZ on either end is
            // observed by F_GETPIPE_SZ on the other (Linux: one buffer per pipe;
            // CPython test_subprocess.test_pipesizes sets on write, reads on read).
            let cap_cell = Arc::new(std::sync::atomic::AtomicI64::new(
                crate::linux_abi::LINUX_PIPE_BUF_SIZE,
            ));
            let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY | nonblock);
            read_base.set_pipe_capacity_cell(Arc::clone(&cap_cell));
            let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY | nonblock);
            write_base.set_pipe_capacity_cell(cap_cell);
            // One stable pipe id shared by BOTH ends — the fork-coherent FASYNC
            // join key (LTP fcntl31 arms the read end, the forked child writes
            // the write end). Derived from the read end's host (device, inode)
            // pair and assigned before any fork, so both ends inherit the SAME
            // id. BSD gives the two ends DIFFERENT st_ino values, so a per-fd
            // inode key would never match across ends.
            let pipe_id = host_inode_pipe_id(host_read);
            let read_open = OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: HostFdRef::new(host_read),
                    is_read_end: true,
                    pipe_id,
                    base: read_base,
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                })),
                fd_flags,
            );
            let write_open = OpenFile::from_open_description(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    host_fd: HostFdRef::new(host_write),
                    is_read_end: false,
                    pipe_id,
                    base: write_base,
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                })),
                fd_flags,
            );
            let Ok((read_fd, write_fd)) = this.install_fd_pair_at_or_above(3, read_open, write_open)
            else {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, address, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn dup(this, cx, fd: Fd) {

            let old_fd: Fd = fd;
            // dup(2) returns the LOWEST-numbered unused descriptor, with no
            // floor — including 0/1/2 when the caller has closed them. min_fd=0
            // (not 3) lets first_free_fd hand back a CLOSED stdio number while
            // still skipping an OPEN one. Flooring at 3 made `close(0); dup(fd)`
            // return a freed fd >= 3 instead of 0, so libuv's
            // uv_pipe_open(loop, 0) wrapped a dead fd 0 and uv_run crashed
            // (test pipe_close_stdout_read_stdin). dup3/F_DUPFD already use 0.
            Ok(this.duplicate_fd(old_fd.0, 0, 0))

        }

        fn dup3(this, cx, oldfd: Fd, newfd: Fd, flags: u64) {

            let old_fd: Fd = oldfd;
            let new_fd: Fd = newfd;
            // Linux dup3 only honours O_CLOEXEC in `flags` (else EINVAL), and
            // new_fd must be a valid descriptor number: out of range (negative or
            // >= RLIMIT_NOFILE soft limit) is EBADF, NOT EINVAL. old_fd == new_fd
            // is EINVAL (dup2 handles that case in glibc without reaching here).
            // new_fd 0/1/2 is allowed — that's how shells redirect std streams.
            let nofile_cur = this.nofile_limit();
            if flags & !LINUX_O_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !(0..nofile_cur).contains(&new_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if old_fd.0 == new_fd.0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(this.duplicate_fd_to(
                cx.kernel.task().key(),
                old_fd.0,
                new_fd.0,
                linux_fd_flags_from_open_flags(flags),
                false,
            ))

        }

        fn dup2(this, cx, oldfd: Fd, newfd: Fd) {

            let old_fd: Fd = oldfd;
            let new_fd: Fd = newfd;
            Ok(this.duplicate_fd_to(
                cx.kernel.task().key(),
                old_fd.0,
                new_fd.0,
                0,
                true,
            ))

        }

        fn fcntl(this, cx, fd: Fd, cmd: u64, arg: u64) {

            let fd: Fd = fd;
            let command = cmd;
            // A stdio fd the guest explicitly closed (and did not reopen) is a
            // genuinely closed descriptor: every fcntl on it is EBADF, NOT the
            // implicit-stdio fallbacks below (F_GETFL/F_GETFD/F_SETFL on bare
            // stdio). CPython's init_sys_streams uses fcntl(F_GETFL) to size up
            // each std fd at startup and treats EBADF as "stream is closed →
            // sys.stdin/out/err = None" (test_cmd_line.test_no_std*).
            if this.stdio_is_closed(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            Ok(match command {
                LINUX_F_DUPFD => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, 0),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_DUPFD_CLOEXEC => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, LINUX_FD_CLOEXEC),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_GETPIPE_SZ => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let open = open_file.description.read();
                    match &*open {
                        OpenDescription::PipeReader { .. }
                        | OpenDescription::PipeWriter { .. }
                        | OpenDescription::HostPipe { .. } => DispatchOutcome::Returned {
                            // The per-description capacity, set by a prior
                            // F_SETPIPE_SZ or the default pipe buffer size.
                            value: open.pipe_capacity(),
                        },
                        OpenDescription::HostSocket { .. } => DispatchOutcome::errno(LINUX_EBADF),
                        _ => DispatchOutcome::errno(LINUX_EBADF),
                    }
                }
                LINUX_F_SETPIPE_SZ => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // Only pipe ends have a capacity; everything else is EBADF
                    // (Linux: F_SETPIPE_SZ on a non-pipe fd is EBADF, mirroring
                    // F_GETPIPE_SZ above).
                    let is_pipe = matches!(
                        &*open_file.description.read(),
                        OpenDescription::PipeReader { .. }
                            | OpenDescription::PipeWriter { .. }
                            | OpenDescription::HostPipe { .. }
                    );
                    if !is_pipe {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    // Linux rounds the requested size up to a whole number of
                    // pages, enforces a one-page minimum, rejects impossible
                    // signed-int sizes, rejects growth above
                    // /proc/sys/fs/pipe-max-size without CAP_SYS_RESOURCE, and
                    // refuses to shrink below the bytes already queued in the
                    // pipe (fcntl37). Carrick does not model capabilities here,
                    // so guest root does not bypass the per-user pipe ceiling.
                    const PIPE_MAX_SIZE: u64 = 1 << 20; // 1 MiB, Linux default
                    if arg > i32::MAX as u64 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let page = LINUX_PAGE_SIZE;
                    let requested = arg.max(1);
                    let rounded = requested.div_ceil(page).saturating_mul(page);
                    if rounded > PIPE_MAX_SIZE {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    let Some(buffered) = this.pipe_buffered_bytes(fd.0)? else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    if rounded < buffered as u64 {
                        return Ok(DispatchOutcome::errno(LINUX_EBUSY));
                    }
                    let capacity = rounded.max(page) as i64;
                    open_file.description.write().set_pipe_capacity(capacity);
                    // macOS pipes expose no portable buffer-resize API, so this
                    // is bookkeeping only — but F_GETPIPE_SZ now reports it back
                    // exactly, which is the observable contract the guest checks.
                    DispatchOutcome::Returned { value: capacity }
                }
                // Directory-change notification (dnotify). It is obsolete, but
                // LTP still asserts create/delete/rename SIGIO delivery for
                // aarch64. Record a dispatch-layer directory watch and reuse the
                // fd's F_SETOWN/F_SETSIG async owner for signal delivery.
                LINUX_F_NOTIFY => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let Some(mask) = LinuxDnotifyMask::from_bits(arg) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    if let Err(errno) = this.dnotify_register(fd.0, mask, cx.tid()) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETFD => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        return Ok(DispatchOutcome::Returned {
                            value: open_file.fd_flags as i64,
                        });
                    }
                    // stdio without an OpenDescription: stdio is not CLOEXEC by
                    // default (Linux: stdio survives exec), but a prior
                    // F_SETFD FD_CLOEXEC must be reflected back. Read the
                    // remembered per-stdio-fd bit.
                    if is_stdio_fd(fd.0) {
                        let bit = if this.captured_file_table().lock_stdio_cloexec()[fd.0 as usize] {
                            LINUX_FD_CLOEXEC as i64
                        } else {
                            0
                        };
                        return Ok(DispatchOutcome::Returned { value: bit });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFD => {
                    let fd_flags = LinuxFdFlags::from_bits_truncate(arg);
                    if let Some(open_file) = this.captured_file_table().write_open_files().get_mut(&fd.0) {
                        open_file.fd_flags = fd_flags.bits();
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    // apt's http method fcntl(fd, F_SETFD, FD_CLOEXEC)s its
                    // inherited stdio fds on startup. Returning EBADF here
                    // makes apt abort with "Could not set close on exec".
                    // Carrick's exec inherits stdio via the host fd directly;
                    // CLOEXEC is largely cosmetic for our model (we don't exec
                    // anything host-side after the syscall returns) but we
                    // remember the bit so a subsequent F_GETFD reflects it,
                    // matching real Linux.
                    if is_stdio_fd(fd.0) {
                        this.captured_file_table().lock_stdio_cloexec()[fd.0 as usize] =
                            fd_flags.contains(LinuxFdFlags::CLOEXEC);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_GETFL => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        let open = open_file.description.read();
                        // Report only file STATUS flags; creation-only flags are
                        // consumed by open() and must not be reported. (audit M8)
                        let mut flags = reportable_status_flags(open.status_flags());
                        // A regular host file's open-description flags are
                        // already fork-coherent in the host kernel. Overlay the
                        // mutable bits from that authority so a parent's
                        // F_GETFL observes a child's F_SETFL after real host
                        // fork even though the Rust description shell is COW.
                        if let OpenDescription::HostFile { host_fd, .. } = &*open {
                            let host_flags = match (unsafe {
                                libc::fcntl(host_fd.raw(), libc::F_GETFL, 0)
                            })
                            .host_syscall_errno()
                            {
                                Ok(value) => value,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            // The host fd is only a truthful authority for a
                            // flag it actually carries. Carrick never opens an
                            // overlay/scratch host file with O_APPEND — the
                            // backend's `open_raw_fd` has no append parameter —
                            // so trusting the host bit unconditionally REPORTED
                            // O_APPEND AS ABSENT for every guest that opened
                            // with it, and the guest then wrote that answer
                            // back via the standard F_SETFL read-modify-write,
                            // destroying the flag for good. Go does exactly
                            // that in `syscall.SetNonblock`, which `os.OpenFile`
                            // runs on every file, and `cmd/go` opens archives
                            // with `O_WRONLY|O_APPEND`: the append branch in
                            // `write` then went dead and the member header
                            // landed at offset 0, corrupting the archive.
                            //
                            // Keep the host as the fork-coherent authority by
                            // making it TRUE rather than by believing it: push
                            // the description's O_APPEND down to the host fd,
                            // and only then read the flag back.
                            if flags & LINUX_O_APPEND != 0 && host_flags & libc::O_APPEND == 0 {
                                unsafe {
                                    libc::fcntl(
                                        host_fd.raw(),
                                        libc::F_SETFL,
                                        host_flags | libc::O_APPEND,
                                    )
                                };
                            }
                            flags &= !LINUX_O_NONBLOCK;
                            if host_flags & libc::O_NONBLOCK != 0 {
                                flags |= LINUX_O_NONBLOCK;
                            }
                        }
                        // A pty end is bidirectional (opened O_RDWR); report the
                        // O_RDWR access mode rather than the default O_RDONLY (0),
                        // so libc/readline see a read-write terminal.
                        if matches!(&*open, OpenDescription::HostPipe { pty: Some(_), .. }) {
                            flags |= LINUX_O_RDWR;
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: flags as i64,
                        });
                    }
                    // stdio without an OpenDescription: glibc cat/head/etc
                    // probe `fcntl(1, F_GETFL)` on startup to decide whether
                    // stdout is append-only. Returning O_RDWR (with the
                    // appropriate direction for fd 0 vs 1/2) keeps them happy
                    // instead of bailing with "Bad file descriptor".
                    if is_stdio_fd(fd.0) {
                        let flags: u64 = if fd.0 == 0 {
                            LINUX_O_RDONLY
                        } else {
                            LINUX_O_WRONLY
                        };
                        return Ok(DispatchOutcome::Returned {
                            value: flags as i64,
                        });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFL => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        // Bare stdio (0/1/2) has no OpenDescription, but real Linux
                        // lets you fcntl(F_SETFL) on stdin/stdout/stderr. apt's dpkg
                        // child sets stdin non-blocking via fcntl(0, F_SETFL,
                        // O_NONBLOCK) before exec and treats EBADF as fatal — it
                        // _exit(100)'d, failing `apt install` ("Sub-process dpkg
                        // returned an error code (100)"). Accept it, propagating
                        // O_NONBLOCK to the real host stdio fd when the guest's
                        // stdio is wired to our host fds (stream_stdio / --raw),
                        // mirroring the F_GETFD/F_SETFD/F_GETFL stdio special-cases.
                        if is_stdio_fd(fd.0) {
                            if *this.io.stream_stdio.lock() {
                                let want_nonblock = arg & LINUX_O_NONBLOCK != 0;
                                unsafe {
                                    let cur = libc::fcntl(fd.0, libc::F_GETFL, 0);
                                    if cur >= 0 {
                                        let next = if want_nonblock {
                                            cur | libc::O_NONBLOCK
                                        } else {
                                            cur & !libc::O_NONBLOCK
                                        };
                                        if next != cur {
                                            libc::fcntl(fd.0, libc::F_SETFL, next);
                                        }
                                    }
                                }
                            }
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // Linux F_SETFL changes ONLY the mutable file-status flags;
                    // it cannot change the access mode (O_RDONLY/WRONLY/RDWR) and
                    // ignores creation-only bits (O_CREAT/O_EXCL/O_TRUNC) and
                    // O_CLOEXEC. Preserve the description's access mode and take
                    // only the mutable status bits from `arg`, so a later F_GETFL
                    // reports the Linux-correct combination instead of whatever
                    // junk the guest passed. (audit M4; probe fsetfl)
                    // O_APPEND + O_NONBLOCK + O_ASYNC are the mutable status bits a
                    // guest realistically toggles via F_SETFL (O_DIRECT/O_NOATIME
                    // are still ignored). O_ASYNC enables signal-driven I/O (the
                    // kernel signals the F_SETOWN owner on a readiness edge).
                    const LINUX_F_SETFL_MUTABLE: u64 =
                        LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_ASYNC;
                    let open = open_file.description.read();
                    let next_flags =
                        (open.status_flags() & LINUX_O_ACCMODE) | (arg & LINUX_F_SETFL_MUTABLE);
                    // Regular host files delegate O_APPEND/O_NONBLOCK to the
                    // shared host open description, which is the only mutable
                    // state that remains coherent across a real host fork.
                    // Pipes/sockets stay host-nonblocking regardless of their
                    // Linux-visible flag so dispatcher operations cannot block
                    // while holding runtime locks.
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            let current = match (unsafe {
                                libc::fcntl(host_fd.raw(), libc::F_GETFL, 0)
                            })
                            .host_syscall_errno()
                            {
                                Ok(value) => value,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            let mut next = current & !(libc::O_APPEND | libc::O_NONBLOCK);
                            if next_flags & LINUX_O_APPEND != 0 {
                                next |= libc::O_APPEND;
                            }
                            if next_flags & LINUX_O_NONBLOCK != 0 {
                                next |= libc::O_NONBLOCK;
                            }
                            if next != current
                                && let Err(errno) = (unsafe {
                                    libc::fcntl(host_fd.raw(), libc::F_SETFL, next)
                                })
                                .host_syscall_errno()
                            {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                        }
                        OpenDescription::HostPipe { host_fd, .. }
                        | OpenDescription::HostSocket { host_fd, .. } => {
                            crate::dispatch::net::set_host_nonblocking(host_fd.raw());
                        }
                        _ => {}
                    }
                    drop(open);
                    open_file.description.write().set_status_flags(next_flags);
                    // Reflect the new O_ASYNC state into the fork-coherent FASYNC
                    // registry so a WRITER in another guest process can deliver the
                    // owner's signal on the readiness edge (the arming lives on the
                    // reader's description, invisible to the writer process).
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                // Classic POSIX advisory record locks (F_SETLK/F_SETLKW/
                // F_GETLK). Forward to the host fd's REAL fcntl locking — macOS
                // implements byte-range advisory locks with conflict and
                // deadlock (EDEADLK) detection, and carrick's guest processes
                // are separate host processes sharing the host file, so the
                // host kernel gives correct cross-process conflict detection
                // for free (the Darwin-native path). The `struct flock` layout
                // AND the l_type constants differ between Linux and macOS, so
                // both are translated; `host_syscall_errno` maps the host errno
                // (incl. the EAGAIN/EDEADLK swap) back to Linux. Falls back to
                // the historical no-op success when the fd isn't host-backed
                // (in-memory/synthetic files, --fs memory) so apt's
                // /var/lib/apt/lists/lock path keeps working.
                LINUX_F_SETLK | LINUX_F_SETLKW => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            forward_record_lock(this, cx, host_fd, command, arg)
                        }
                        // Not host-backed → preserve the single-tenant no-op,
                        // but still do the kernel's front-door flock validation
                        // (EFAULT/EINVAL) that precedes the lock attempt.
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                LINUX_F_GETLK => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            forward_record_lock(this, cx, host_fd, command, arg)
                        }
                        // Not host-backed → "no lock present": leave the
                        // caller's struct flock untouched (l_type=F_UNLCK is
                        // what callers re-read) and succeed — after the same
                        // front-door flock validation Linux applies first.
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                // OFD locks (F_OFD_*) are owned by the open file description, not
                // the process. macOS has them natively (F_OFD_SETLK/SETLKW/GETLK),
                // and carrick's fork model maps a guest OFD 1:1 onto a host OFD
                // (dup shares the description + host fd; clone(2) forks a real host
                // process that inherits the host fd table), so the macOS kernel
                // arbitrates OFD conflicts/inheritance with Linux semantics.
                // Forward exactly like the classic commands; fall back to the
                // single-tenant no-op for non-host-backed (--fs memory/synthetic)
                // fds, after the same front-door flock validation.
                LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW | LINUX_F_OFD_GETLK => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    if !carrick_portable::host_ofd_locks_supported() {
                        return Ok(match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::errno(LINUX_ENOTSUP),
                            Err(errno) => DispatchOutcome::errno(errno),
                        });
                    }
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            forward_record_lock(this, cx, host_fd, command, arg)
                        }
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                // File leases (F_SETLEASE/F_GETLEASE). macOS has no lease
                // primitive, so the lease type is recorded on the open-file
                // description (shared across dup). Conflict enforcement mirrors
                // fcntl(2): a WRITE lease (F_WRLCK) requires this to be the ONLY
                // open file description for the file; a READ lease (F_RDLCK)
                // requires no other description hold the file open for writing
                // (and that the calling fd itself be read-only). Conflicts return
                // EAGAIN. The opener census comes from `same_file_other_openers`
                // (host-inode identity under `--fs host`, path under `--fs
                // memory`); a dup'd fd shares the description and never conflicts.
                // Lease-break SIGIO delivery to a conflicting opener is a tracked
                // follow-up.
                LINUX_F_SETLEASE => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let lease = arg as i32;
                    if lease != LINUX_F_RDLCK
                        && lease != LINUX_F_WRLCK
                        && lease != LINUX_F_UNLCK
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let self_acc =
                        open_file.description.read().status_flags() & LINUX_O_ACCMODE;
                    match lease {
                        // A write lease demands exclusive access: any other open
                        // file description for the file is a conflict.
                        LINUX_F_WRLCK => {
                            if !this.same_file_other_openers(fd.0).is_empty() {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                        }
                        // A read lease forbids any writer. The calling fd must be
                        // read-only (an fd open for writing is itself a writer),
                        // and no other description may hold the file open for
                        // writing.
                        LINUX_F_RDLCK => {
                            if self_acc != LINUX_O_RDONLY {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                            let writer_exists = this
                                .same_file_other_openers(fd.0)
                                .into_iter()
                                .any(|acc| acc != LINUX_O_RDONLY);
                            if writer_exists {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                        }
                        // F_UNLCK: removing a lease never conflicts.
                        _ => {}
                    }
                    open_file.description.write().set_lease(lease);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETLEASE => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let lease = open_file.description.read().lease();
                    DispatchOutcome::Returned { value: lease as i64 }
                }
                // File sealing (memfd_create01). The seal set lives on the
                // open-file description (shared across dup). F_GET_SEALS returns
                // the current set; a non-sealable fd → EINVAL.
                LINUX_F_GET_SEALS => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    match open_file.description.read().seals() {
                        Some(seals) => DispatchOutcome::Returned {
                            value: i64::from(seals),
                        },
                        None => DispatchOutcome::errno(LINUX_EINVAL),
                    }
                }
                LINUX_F_ADD_SEALS => {
                    let Ok(new_seals_raw) = u32::try_from(arg) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let Some(new_seals) = carrick_abi::LinuxMemfdSeals::from_bits(new_seals_raw) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    // Hold the SAME alias-dispatch exclusion mmap/shmat use for
                    // publication, so a sibling cannot race between the seal
                    // check and the new seal becoming visible. Acquire it before
                    // any subsystem locks so we never wait while holding them.
                    let _host_alias_dispatch = this.begin_host_alias_dispatch();
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let mut open = open_file.description.write();
                    let Some(current_raw) = open.seals() else {
                        // Not a sealable fd (regular file, socket, …).
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let current = carrick_abi::LinuxMemfdSeals::from_bits_retain(current_raw);
                    // F_ADD_SEALS needs the fd open for writing.
                    if open.status_flags() & LINUX_O_ACCMODE == LINUX_O_RDONLY {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    // Already fully sealed → no further seals may be added.
                    if current.contains(carrick_abi::LinuxMemfdSeals::SEAL) {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    // F_SEAL_WRITE cannot be set while a shared, writable mapping
                    // of the memfd is live (Linux → EBUSY; memfd_create01
                    // test_share_mmap).
                    if new_seals.contains(carrick_abi::LinuxMemfdSeals::WRITE)
                        && this.memfd_has_writable_shared_map(&open_file.description)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EBUSY));
                    }
                    open.set_seals(Some((current | new_seals).bits()));
                    DispatchOutcome::Returned { value: 0 }
                }
                // Async-I/O owner + signal (F_SETOWN/F_GETOWN, F_SETOWN_EX/
                // F_GETOWN_EX, F_SETSIG/F_GETSIG). The owner (SIGIO/SIGURG target)
                // and signal are recorded on the open-file description (shared
                // across dup), giving the exact round-trip LTP fcntl31/32 read
                // back. Actual SIGIO delivery on fd readiness is a tracked
                // follow-up (carrick has no async-I/O readiness signal path yet).
                LINUX_F_SETOWN => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // fcntl(2): a positive arg is a process id, a negative arg is
                    // a process GROUP (-pgid).
                    let a = arg as i32;
                    let (owner_type, owner_pid) = if a < 0 {
                        (LINUX_F_OWNER_PGRP, a.wrapping_neg())
                    } else {
                        (LINUX_F_OWNER_PID, a)
                    };
                    open_file.description.write().set_owner(owner_type, owner_pid);
                    // Refresh the FASYNC registry if O_ASYNC is already armed on
                    // this fd (the owner can be set after O_ASYNC — LTP fcntl31).
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETOWN => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let (owner_type, owner_pid) = open_file.description.read().owner();
                    // A process-group owner reads back as a negative id.
                    let val = if owner_type == LINUX_F_OWNER_PGRP {
                        -owner_pid
                    } else {
                        owner_pid
                    };
                    DispatchOutcome::Returned { value: val as i64 }
                }
                LINUX_F_SETOWN_EX => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let owner: LinuxFOwnerEx = cx.memory.read_struct(arg)?;
                    if owner.owner_type != LINUX_F_OWNER_TID
                        && owner.owner_type != LINUX_F_OWNER_PID
                        && owner.owner_type != LINUX_F_OWNER_PGRP
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    open_file
                        .description
                        .write()
                        .set_owner(owner.owner_type, owner.owner_pid);
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETOWN_EX => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let (owner_type, owner_pid) = open_file.description.read().owner();
                    let owner = LinuxFOwnerEx {
                        owner_type,
                        owner_pid,
                    };
                    cx.memory.write_struct(arg, &owner)?;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_SETSIG => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // 0 = the default (SIGIO); otherwise a valid signal number.
                    let sig = arg as i32;
                    if !(0..=64).contains(&sig) {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    open_file.description.write().set_async_sig(sig);
                    // Refresh the registry: F_SETSIG can follow O_ASYNC + F_SETOWN
                    // (LTP fcntl31 sets the signal last), so the armed entry must
                    // pick up the new signal.
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETSIG => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let sig = open_file.description.read().async_sig();
                    DispatchOutcome::Returned { value: sig as i64 }
                }
                _ => DispatchOutcome::errno(LINUX_EINVAL),
            })

        }

        fn ioctl(this, cx, fd: Fd, request: u64, arg: u64) {

            let fd: Fd = fd;
            let ioctl_request = request & u32::MAX as u64;
            // A tty *control* ioctl (tcsetpgrp/tcsetattr/winsize) issued on the
            // host pty from a background process group raises SIGTTOU regardless
            // of TOSTOP and would STOP the real carrick process. Linux suppresses
            // that when the calling guest has SIGTTOU ignored or blocked (a
            // job-control shell always does, e.g. busybox ash's forkchild does
            // setpgid()+tcsetpgrp() while still background). Mirror it: block host
            // SIGTTOU around those passthroughs in exactly that case, so the host
            // op completes instead of stopping. A genuinely-default background
            // caller is NOT gated and still stops, matching Linux.
            let block_ttou = {
                let tid = Self::ctx_tid(cx);
                this.signal_is_ignored(cx.kernel, LINUX_SIGTTOU)
                    || this.signal_blocked(cx.kernel, tid, LINUX_SIGTTOU)
            };
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O — ioctl on it is EBADF
            // (open13 issues FIGETBSZ on an O_PATH fd).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            // ── Rosetta 2 virtualization handshake ──────────────────────────────────
            // At startup Apple's Rosetta issues a small set of ioctls on its
            // /proc/.../exe fd to confirm it is running inside an Apple
            // virtualization environment. The size field (bits [29:16]) of the
            // request encodes the expected response length. The licensing ioctl
            // (...6125) is `memcmp`'d against a verification string Rosetta keeps
            // embedded in its own binary — so we echo back exactly that blob,
            // read live from the installed Rosetta binary (never embedded in
            // carrick). The info ioctl (...6123) is not compared; Rosetta only
            // requires a non-negative return, so a zeroed buffer suffices.
            if let Some(outcome) =
                rosetta_handshake_ioctl(&mut *cx.memory, ioctl_request, arg)
            {
                return Ok(outcome);
            }

            // ── PTY ioctls ────────────────────────────────────────────────────────
            // If this fd is a pty master or slave, handle all tty ioctls here by
            // passing through to the host fd (real macOS pty). Return early so the
            // stdio-gated arms below never run for pty fds.
            if let Some((role, host_fd)) = this.pty_info(fd.0) {
                return Ok(match ioctl_request {
                    // TIOCGPTN is a MASTER-only ioctl: it returns the pts index
                    // of the master's slave. On a slave it is ENOTTY — which is
                    // exactly how libuv's uv__tty_is_slave detects a slave fd
                    // (and then reopens it non-blocking). Answering it for the
                    // slave too made libuv treat the slave as a master and leave
                    // UV_HANDLE_BLOCKING_WRITES set (tty_pty / tty_pty_partial).
                    LINUX_TIOCGPTN if role.is_master => {
                        write_packed(&mut *cx.memory, arg, &role.index.to_le_bytes())
                    }
                    LINUX_TIOCGPTN => DispatchOutcome::errno(LINUX_ENOTTY),
                    LINUX_TIOCSPTLCK => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let lock = i32::from_le_bytes(buf) != 0;
                        this.pty_table().lock().set_locked(role.index, lock);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_TCGETA | LINUX_TCGETS | LINUX_TCGETS2 => {
                        let termios = crate::host_tty::get_host_termios(host_fd)
                            .unwrap_or_else(LinuxTermios::default_cooked);
                        // glibc-aarch64 tcgetattr on a pty slave uses TCGETS2
                        // (the full 44-byte termios2); musl uses 36-byte TCGETS.
                        if ioctl_request == LINUX_TCGETS2 {
                            write_termios2(&mut *cx.memory, arg, &termios)
                        } else if ioctl_request == LINUX_TCGETA {
                            write_linux_termio(&mut *cx.memory, arg, &termios)
                        } else {
                            write_kernel_struct(&mut *cx.memory, arg, &termios)
                        }
                    }
                    LINUX_TCSETS
                    | LINUX_TCSETSW
                    | LINUX_TCSETSF
                    | LINUX_TCSETS2
                    | LINUX_TCSETSW2
                    | LINUX_TCSETSF2 => {
                        let want = if matches!(
                            ioctl_request,
                            LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2
                        ) {
                            LINUX_TERMIOS2_SIZE
                        } else {
                            LINUX_TERMIOS_KERNEL_SIZE
                        };
                        match cx.memory.read_bytes(arg, want) {
                            Ok(bytes) => {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..want].copy_from_slice(&bytes);
                                match LinuxTermios::read_from_bytes(&padded) {
                                    Ok(mut t) => {
                                        // Linux's pty driver never stores CS5-CS7.
                                        crate::host_tty::coerce_pty_termios(&mut t);
                                        let _ = crate::host_tty::with_sigttou_blocked(
                                            block_ttou,
                                            || crate::host_tty::set_host_termios(host_fd, &t),
                                        );
                                        DispatchOutcome::Returned { value: 0 }
                                    }
                                    Err(_) => DispatchOutcome::errno(LINUX_EINVAL),
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGWINSZ => {
                        // macOS rejects winsize ioctls on a master; read from the
                        // guest's open slave fd for a master role (see
                        // pty_winsize_target). No slave open yet → 80x24 stub.
                        let ws = match this.pty_winsize_target(role, host_fd) {
                            Some(ws_fd) => crate::host_tty::get_host_winsize(ws_fd)
                                .unwrap_or_else(LinuxWinsize::terminal_80x24),
                            None => LinuxWinsize::terminal_80x24(),
                        };
                        write_kernel_struct(&mut *cx.memory, arg, &ws)
                    }
                    LINUX_TIOCSWINSZ => {
                        match cx.memory.read_bytes(arg, 8) {
                            Ok(b) => {
                                let mut ws: libc::winsize = unsafe { core::mem::zeroed() };
                                ws.ws_row = u16::from_le_bytes([b[0], b[1]]);
                                ws.ws_col = u16::from_le_bytes([b[2], b[3]]);
                                ws.ws_xpixel = u16::from_le_bytes([b[4], b[5]]);
                                ws.ws_ypixel = u16::from_le_bytes([b[6], b[7]]);
                                // macOS rejects TIOCSWINSZ on a master (ENOTTY);
                                // apply it to the guest's open slave fd for a
                                // master role. If no slave is open yet, succeed as
                                // a no-op rather than hand the guest a spurious
                                // ENOTTY (Linux always accepts it on the master).
                                match this.pty_winsize_target(role, host_fd) {
                                    Some(ws_fd) => {
                                        // SAFETY: ws_fd is a live pty fd; &ws is valid.
                                        let r = crate::host_tty::with_sigttou_blocked(
                                            block_ttou,
                                            || unsafe {
                                                libc::ioctl(
                                                    ws_fd,
                                                    libc::TIOCSWINSZ as libc::c_ulong,
                                                    &ws,
                                                )
                                            },
                                        );
                                        if r < 0 {
                                            DispatchOutcome::errno(
                                                crate::host_to_linux_errno(get_last_error()),
                                            )
                                        } else {
                                            DispatchOutcome::Returned { value: 0 }
                                        }
                                    }
                                    None => DispatchOutcome::Returned { value: 0 },
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGPGRP => {
                        // SAFETY: host_fd is our live pty fd.
                        let pgrp = unsafe { libc::tcgetpgrp(host_fd) };
                        if pgrp < 0 {
                            DispatchOutcome::errno(crate::host_to_linux_errno(get_last_error()))
                        } else {
                            // The host pty's foreground pgrp is a HOST pgid;
                            // translate it to the value the guest's PID namespace
                            // sees, so a shell's `tcgetpgrp() == getpgrp()`
                            // foreground check holds (else it SIGTTIN-stops
                            // itself). Identity when namespaces are off.
                            let ns_pgrp =
                                crate::namespace::pid::host_to_ns_pgid(pgrp as u32) as i32;
                            write_packed(&mut *cx.memory, arg, &ns_pgrp.to_le_bytes())
                        }
                    }
                    LINUX_TIOCSPGRP => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let ns_pgrp = i32::from_le_bytes(buf);
                        // The guest names a pgrp in its OWN namespace; map it back
                        // to the host pgid before handing it to the host pty.
                        let Some(pgrp) = crate::namespace::pid::ns_to_host_pgid(ns_pgrp as u32)
                        else {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        };
                        let pgrp = pgrp as i32;
                        // SAFETY: host_fd is our live pty fd.
                        let r = crate::host_tty::with_sigttou_blocked(block_ttou, || unsafe {
                            libc::tcsetpgrp(host_fd, pgrp)
                        });
                        if r < 0 {
                            DispatchOutcome::errno(crate::host_to_linux_errno(get_last_error()))
                        } else {
                            DispatchOutcome::Returned { value: 0 }
                        }
                    }
                    LINUX_TIOCSCTTY => {
                        // SAFETY: host_fd is our live pty fd. Best-effort.
                        unsafe { libc::ioctl(host_fd, libc::TIOCSCTTY as libc::c_ulong, 0i32) };
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_FIONREAD => {
                        // A BSD pts supports FIONREAD/TIOCINQ on its input queue;
                        // forward to the live macOS pty fd. Without this arm a pty
                        // fd hits the catch-all below and returns ENOTTY, diverging
                        // from Linux (which reports the pending byte count).
                        let mut n: libc::c_int = 0;
                        // SAFETY: host_fd is our live pty fd; &mut n is valid stack storage.
                        let rc = unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut n) };
                        if rc < 0 {
                            DispatchOutcome::errno(crate::host_to_linux_errno(get_last_error()))
                        } else {
                            write_packed(&mut *cx.memory, arg, &(n as i32).to_le_bytes())
                        }
                    }
                    LINUX_FIONBIO => {
                        // os.set_blocking(master, False) issues FIONBIO on a pty
                        // master. Linux returns 0 and toggles O_NONBLOCK on the open
                        // description; without this arm the pty fd hit the catch-all
                        // below and returned ENOTTY. Mirror the generic FIONBIO
                        // handler: toggle Linux-visible O_NONBLOCK on the open
                        // description while keeping the host fd non-blocking so
                        // a later blocking-mode read still parks via WaitOnFds.
                        let Ok(bytes) = cx.memory.read_bytes(arg, 4) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        let enable =
                            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0;
                        if let Some(open_file) = this.open_file(fd.0) {
                            let mut open = open_file.description.write();
                            let mut status_flags = open.status_flags();
                            if enable {
                                status_flags |= LINUX_O_NONBLOCK;
                            } else {
                                status_flags &= !LINUX_O_NONBLOCK;
                            }
                            open.set_status_flags(status_flags);
                        }
                        crate::dispatch::net::set_host_nonblocking(host_fd);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    // ── Line-discipline control (tcdrain/tcflush/tcflow/tcsendbreak) ──
                    // glibc maps the POSIX tc* helpers onto these ioctls. `arg` here
                    // is a small integer selector (NOT a guest pointer), so it is
                    // consumed directly. Darwin has native tcdrain/tcflush/tcflow/
                    // tcsendbreak; we translate the Linux queue/action selectors to
                    // the Darwin ones (they differ numerically) inside host_tty.
                    LINUX_TCSBRK => {
                        // tcdrain → TCSBRK(arg!=0); tcsendbreak(dur==0) → TCSBRK(0).
                        // arg==0 sends a break; arg!=0 drains the output queue.
                        let res = if arg == 0 {
                            crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                crate::host_tty::host_tty_tcsendbreak(host_fd, 0)
                            })
                        } else {
                            crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                crate::host_tty::host_tty_tcdrain(host_fd)
                            })
                        };
                        match res {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCSBRKP => {
                        // tcsendbreak(duration!=0) → TCSBRKP(duration). arg is the
                        // duration in deciseconds (Linux semantics); pass through.
                        match crate::host_tty::with_sigttou_blocked(block_ttou, || {
                            crate::host_tty::host_tty_tcsendbreak(host_fd, arg as i32)
                        }) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCFLSH => {
                        // tcflush → TCFLSH(queue). host_tty_tcflush validates the
                        // Linux selector and returns EINVAL for out-of-range values
                        // (mirroring Linux's TCFLSH validation).
                        match crate::host_tty::host_tty_tcflush(host_fd, arg as i64) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCXONC => {
                        // tcflow → TCXONC(action). host_tty_tcflow validates the
                        // Linux action selector and returns EINVAL for out-of-range
                        // values (mirroring Linux's TCXONC validation).
                        match crate::host_tty::with_sigttou_blocked(block_ttou, || {
                            crate::host_tty::host_tty_tcflow(host_fd, arg as i64)
                        }) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            // ── nsfs NS_GET_* ioctls (ioctl_ns(2)) ──────────────────────────────────
            // When `fd` is an nsfs fd (opened from /proc/<pid>/ns/<type>), the
            // NS_GET_* ioctls introspect the namespace. carrick models exactly
            // ONE initial namespace per type, so the answers are synthetic but
            // stable. Gated on the fd being an ns-link SyntheticFile so a plain
            // file/tty fd still falls through to the tty/default arms below.
            if let Some(ns_type) = this.fd_ns_link_type(fd.0) {
                return Ok(match ioctl_request {
                    // The CLONE_NEW* flag for this link's type, as the RETURN
                    // value (not written to *arg).
                    LINUX_NS_GET_NSTYPE => match ns_type_clone_flag(&ns_type) {
                        Some(flag) => DispatchOutcome::Returned { value: flag as i64 },
                        None => DispatchOutcome::errno(LINUX_EINVAL),
                    },
                    // The owning user namespace's uid. The initial user ns is
                    // owned by root → 0. EINVAL on a non-user-ns fd (the kernel
                    // only answers this for a user namespace).
                    LINUX_NS_GET_OWNER_UID => {
                        if ns_type == "user" {
                            write_packed(&mut *cx.memory, arg, &0u32.to_le_bytes())
                        } else {
                            DispatchOutcome::errno(LINUX_EINVAL)
                        }
                    }
                    // Only hierarchical namespaces answer NS_GET_PARENT. The
                    // initial user/pid namespaces have no accessible parent
                    // here (EPERM); non-hierarchical namespaces reject the
                    // request with EINVAL.
                    LINUX_NS_GET_PARENT if ns_type == "user" || ns_type == "pid" => {
                        DispatchOutcome::errno(LINUX_EPERM)
                    }
                    LINUX_NS_GET_PARENT => DispatchOutcome::errno(LINUX_EINVAL),
                    // A namespace's owning user namespace is exposed for
                    // non-user namespaces. A user namespace fd itself has no
                    // "owning user ns" to return in this model; Docker's oracle
                    // reports EPERM for that shape (ioctl_ns04).
                    LINUX_NS_GET_USERNS if ns_type == "user" => {
                        DispatchOutcome::errno(LINUX_EPERM)
                    }
                    LINUX_NS_GET_USERNS => this.install_proc_synthetic_bytes(
                        "/proc/self/ns/user",
                        Vec::new(),
                        LINUX_O_RDONLY | LINUX_O_CLOEXEC,
                    ),
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            Ok(match ioctl_request {
                LINUX_TIOCGWINSZ if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) => {
                    // Prefer the live host window size when stdin/stdout/stderr
                    // is a real macOS terminal; fall back to the 80x24 stub so
                    // headless invocations (CI, redirected pipes that we still
                    // synthesize a TTY for in tests) keep prior behaviour.
                    let winsize = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_winsize(fd.0)
                            .unwrap_or_else(LinuxWinsize::terminal_80x24)
                    } else {
                        LinuxWinsize::terminal_80x24()
                    };
                    write_kernel_struct(&mut *cx.memory, arg, &winsize)
                }
                LINUX_TIOCGWINSZ => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TCGETA => {
                    if !cx.memory.guest_range_is_writable(arg, LINUX_TERMIO_SIZE) {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    if !fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) {
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    } else {
                        let termios = if crate::host_tty::host_isatty(fd.0) {
                            crate::host_tty::get_host_termios(fd.0)
                                .unwrap_or_else(LinuxTermios::default_cooked)
                        } else {
                            LinuxTermios::default_cooked()
                        };
                        write_linux_termio(&mut *cx.memory, arg, &termios)
                    }
                }
                LINUX_TCGETS | LINUX_TCGETS2 if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) => {
                    // Mirror the live host terminal modes when available so
                    // `less`, `vi`, and an interactive shell see the actual
                    // ICANON/ECHO state the user has configured.
                    let termios = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_termios(fd.0)
                            .unwrap_or_else(LinuxTermios::default_cooked)
                    } else {
                        LinuxTermios::default_cooked()
                    };
                    // TCGETS writes the 36-byte legacy `struct termios`
                    // (KernelAbi::ABI_SIZE). Writing the 44-byte termios2 there
                    // overran glibc's tcgetattr canary and crashed ls/dpkg.
                    // TCGETS2 — what glibc-aarch64 actually uses for tcgetattr/
                    // isatty — expects the full 44-byte `struct termios2`
                    // (the c_ispeed/c_ospeed tail). musl uses TCGETS, so a
                    // musl-only probe suite never exercised this path.
                    if ioctl_request == LINUX_TCGETS2 {
                        write_termios2(&mut *cx.memory, arg, &termios)
                    } else {
                        write_kernel_struct(&mut *cx.memory, arg, &termios)
                    }
                }
                LINUX_TCGETS | LINUX_TCGETS2 => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_RNDGETENTCNT => {
                    if !fd_is_random_device(this, fd.0) {
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    } else {
                        write_packed(&mut *cx.memory, arg, &256i32.to_le_bytes())
                    }
                }
                LINUX_FICLONE => {
                    let src_fd = match i32::try_from(arg) {
                        Ok(src_fd) => src_fd,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    };
                    if !this.fd_is_valid(src_fd) || this.fd_is_o_path(src_fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    DispatchOutcome::errno(LINUX_EOPNOTSUPP)
                }
                LINUX_TCSETS
                | LINUX_TCSETSW
                | LINUX_TCSETSF
                | LINUX_TCSETS2
                | LINUX_TCSETSW2
                | LINUX_TCSETSF2
                    if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) =>
                {
                    // Read exactly what the guest provided: 36 bytes for the
                    // legacy TCSETS*, 44 for the termios2 variants. Reading more
                    // than the guest's buffer would EFAULT at a stack-page
                    // boundary. Then pad to the 44-byte zerocopy struct to parse.
                    let want = if matches!(
                        ioctl_request,
                        LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2
                    ) {
                        LINUX_TERMIOS2_SIZE
                    } else {
                        LINUX_TERMIOS_KERNEL_SIZE
                    };
                    match cx.memory.read_bytes(arg, want) {
                        Ok(bytes) => {
                            if crate::host_tty::host_isatty(fd.0) {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..want].copy_from_slice(&bytes);
                                if let Ok(t) = LinuxTermios::read_from_bytes(&padded) {
                                    let _ = crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                        crate::host_tty::set_host_termios_tracking(fd.0, &t)
                                    });
                                }
                            }
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                    }
                }
                LINUX_TCSETS
                | LINUX_TCSETSW
                | LINUX_TCSETSF
                | LINUX_TCSETS2
                | LINUX_TCSETSW2
                | LINUX_TCSETSF2 => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TIOCSCTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        // Under `-t` fd 0/1/2 is a real pty slave: pass through to
                        // the host line discipline so job control works correctly.
                        if crate::host_tty::host_isatty(fd.0) {
                            match crate::host_tty::host_tty_tcgetpgrp(fd.0) {
                                // Translate the HOST foreground pgid into the value
                                // the guest's PID namespace sees, so a shell's
                                // `tcgetpgrp() == getpgrp()` foreground check holds
                                // (else it SIGTTIN-stops itself). Identity when off.
                                Ok(pgrp) => {
                                    let ns_pgrp =
                                        crate::namespace::pid::host_to_ns_pgid(pgrp as u32) as i32;
                                    write_packed(&mut *cx.memory, arg, &ns_pgrp.to_le_bytes())
                                }
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::host_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            // Headless / non-tty fallback: synthesise bootstrap pgid.
                            write_packed(&mut *cx.memory, arg, &LINUX_BOOTSTRAP_PGID.to_le_bytes())
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCSPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(bytes) => buf.copy_from_slice(&bytes),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let ns_pgid = i32::from_le_bytes(buf);
                        // Under `-t` fd 0/1/2 is a real pty slave: pass through so
                        // the host line discipline tracks the foreground pgrp, enabling
                        // Ctrl-C → SIGINT delivery to the correct guest pgrp. The guest
                        // names the pgrp in its OWN namespace; map it to the host pgid.
                        if crate::host_tty::host_isatty(fd.0) {
                            let Some(pgid) =
                                crate::namespace::pid::ns_to_host_pgid(ns_pgid as u32)
                            else {
                                return Ok(DispatchOutcome::errno(LINUX_EPERM));
                            };
                            let pgid = pgid as i32;
                            match crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                crate::host_tty::host_tty_tcsetpgrp(fd.0, pgid)
                            }) {
                                Ok(()) => DispatchOutcome::Returned { value: 0 },
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::host_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            // Headless fallback: accept the bootstrap pgid, EPERM others.
                            if ns_pgid == LINUX_BOOTSTRAP_PGID {
                                DispatchOutcome::Returned { value: 0 }
                            } else {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_FIONREAD => {
                    // Stdio, eventfd, timerfd, epoll, pipe writer, directory, regular file,
                    // synthetic file: writing 0 ("nothing pending") is benign. In-memory pipe
                    // reader gets the buffered byte count from the carrick pipe buffer; a host
                    // pipe (`pipe2(2)` backing) forwards the ioctl to the real host fd so the
                    // guest sees the kernel's actual queued-byte count.
                    let available: i32 = match this.open_file(fd.0).as_ref() {
                        Some(open_file) => match &*open_file.description.read() {
                            OpenDescription::PipeReader { pipe, .. } => {
                                let len = pipe.lock().buffer.len();
                                i32::try_from(len).unwrap_or(i32::MAX)
                            }
                            // FIONREAD on a pipe WRITE end reports the bytes
                            // currently buffered in the pipe (Linux). macOS
                            // FIONREAD on a write fd returns 0, so consult the
                            // paired read end's queued byte count instead — pipe12
                            // reads FIONREAD on fds[1] after filling the pipe.
                            OpenDescription::HostPipe {
                                is_read_end: false,
                                pipe_id,
                                pty: None,
                                bidirectional: false,
                                ..
                            } if *pipe_id != 0 => {
                                i32::try_from(this.host_pipe_read_end_buffered_bytes(*pipe_id))
                                    .unwrap_or(i32::MAX)
                            }
                            OpenDescription::HostPipe { host_fd, .. }
                            | OpenDescription::HostSocket { host_fd, .. } => {
                                let mut n: libc::c_int = 0;
                                let rc =
                                    unsafe { libc::ioctl(host_fd.raw(), libc::FIONREAD, &mut n) };
                                if rc == 0 { n as i32 } else { 0 }
                            }
                            _ => 0,
                        },
                        // stdio fd (already validated above) or any other valid fd: 0.
                        None => 0,
                    };
                    write_packed(&mut *cx.memory, arg, &available.to_le_bytes())
                }
                LINUX_FIONBIO => {
                    let Ok(bytes) = cx.memory.read_bytes(arg, 4) else {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    };
                    let enable = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0;
                    if let Some(open_file) = this.open_file(fd.0) {
                        let mut open = open_file.description.write();
                        let mut status_flags = open.status_flags();
                        if enable {
                            status_flags |= LINUX_O_NONBLOCK;
                        } else {
                            status_flags &= !LINUX_O_NONBLOCK;
                        }
                        open.set_status_flags(status_flags);
                        let host_fd = match &*open {
                            OpenDescription::HostPipe { host_fd, .. }
                            | OpenDescription::HostSocket { host_fd, .. }
                            | OpenDescription::HostFile { host_fd, .. } => Some(host_fd.raw()),
                            _ => None,
                        };
                        if let Some(host_fd) = host_fd {
                            crate::dispatch::net::set_host_nonblocking(host_fd);
                        }
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_TIOCNOTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCGIFNAME => match this.open_file(fd.0).as_ref() {
                    Some(open_file) => match &*open_file.description.read() {
                        OpenDescription::HostSocket { .. } => {
                            let Ok(bytes) = cx.memory.read_bytes(arg + 16, 4) else {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            };
                            let ifindex =
                                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                            if ifindex <= 0 {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            } else if let Some(name) = linux_if_indextoname(ifindex) {
                                let mut ifreq_name = [0u8; LINUX_IFNAMSIZ];
                                let len = name.len().min(ifreq_name.len().saturating_sub(1));
                                ifreq_name[..len].copy_from_slice(&name.as_bytes()[..len]);
                                write_packed(&mut *cx.memory, arg, &ifreq_name)
                            } else {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            }
                        }
                        _ => DispatchOutcome::errno(LINUX_ENOTTY),
                    },
                    None => DispatchOutcome::errno(LINUX_ENOTTY),
                },
                LINUX_SIOCGIFINDEX => match this.open_file(fd.0).as_ref() {
                    Some(open_file) => match &*open_file.description.read() {
                        OpenDescription::HostSocket { .. } => {
                            let Ok(bytes) = cx.memory.read_bytes(arg, 16) else {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            };
                            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                            if end == 0 {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            } else {
                                let name = String::from_utf8_lossy(&bytes[..end]);
                                if let Some(ifindex) = linux_if_nametoindex(&name) {
                                    write_packed(
                                        &mut *cx.memory,
                                        arg + LINUX_IFNAMSIZ as u64,
                                        &ifindex.to_le_bytes(),
                                    )
                                } else {
                                    DispatchOutcome::errno(LINUX_ENODEV)
                                }
                            }
                        }
                        _ => DispatchOutcome::errno(LINUX_ENOTTY),
                    },
                    None => DispatchOutcome::errno(LINUX_ENOTTY),
                },
                LINUX_SIOCATMARK => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // SIOCATMARK reports whether the next read sits at the
                        // out-of-band mark. It is a STREAM-only op: Linux returns
                        // ENOTTY on a datagram socket (sockioctl01 "ATMARK on UDP"
                        // resets the expected errno to ENOTTY). A NULL arg faults
                        // (sockioctl01 "invalid option buffer"). carrick keeps no
                        // OOB queue, so a valid stream socket reports atmark = 0
                        // (man sockatmark: 0 ⇒ not at the mark), which is the true
                        // state for any socket with no urgent data pending.
                        if this.socket_guest_type(fd.0) != Some(LINUX_SOCK_STREAM) {
                            DispatchOutcome::errno(LINUX_ENOTTY)
                        } else if arg == 0 {
                            DispatchOutcome::errno(LINUX_EFAULT)
                        } else {
                            write_packed(&mut *cx.memory, arg, &0i32.to_le_bytes())
                        }
                    }
                    // A non-socket fd (e.g. a FIFO): Linux's vfs_ioctl returns
                    // ENOTTY for SIOCATMARK, not ENOTSOCK (sockioctl01 "not a
                    // socket" resets the expected errno to ENOTTY).
                    Err(_) => DispatchOutcome::errno(LINUX_ENOTTY),
                },
                LINUX_SIOCGIFCONF => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // struct ifconf: ifc_len (off 0, i32), ifc_buf (off 8, ptr).
                        if arg == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let conf: LinuxIfconf = match cx.memory.read_struct(arg) {
                            Ok(c) => c,
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        };
                        let ifc_len = conf.ifc_len.max(0) as usize;
                        let ifc_buf = conf.ifc_buf;
                        let ifaces = host_inet4_interfaces();
                        // Linux convention: a NULL ifc_buf is a size query that
                        // reports the bytes required without writing entries.
                        let cap = if ifc_buf == 0 {
                            usize::MAX
                        } else {
                            ifc_len / std::mem::size_of::<LinuxIfreq>()
                        };
                        let mut written = 0usize;
                        let mut blob: Vec<u8> = Vec::new();
                        for iface in ifaces.iter() {
                            if written >= cap {
                                break;
                            }
                            let req = linux_ifreq_inet4(&iface.name, iface.addr_be);
                            blob.extend_from_slice(req.as_bytes());
                            written += 1;
                        }
                        if ifc_buf != 0
                            && !blob.is_empty()
                            && cx.memory.write_bytes(ifc_buf, &blob).is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let new_len = (written * std::mem::size_of::<LinuxIfreq>()) as i32;
                        write_packed(&mut *cx.memory, arg, &new_len.to_le_bytes())
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCGIFFLAGS
                | LINUX_SIOCGIFADDR
                | LINUX_SIOCGIFBRDADDR
                | LINUX_SIOCGIFNETMASK
                | LINUX_SIOCGIFMTU => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // ifr_name occupies the first IFNAMSIZ bytes; a NULL arg
                        // faults (sockioctl01 "SIOCGIFFLAGS with invalid ifr").
                        if arg == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let Ok(name_bytes) = cx.memory.read_bytes(arg, LINUX_IFNAMSIZ) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        let end = name_bytes
                            .iter()
                            .position(|b| *b == 0)
                            .unwrap_or(name_bytes.len());
                        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
                        let ifaces = host_inet4_interfaces();
                        let Some(iface) = ifaces.iter().find(|i| i.name == name) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENODEV));
                        };
                        match ioctl_request {
                            LINUX_SIOCGIFFLAGS => {
                                // ifr_flags is a `short` at offset IFNAMSIZ.
                                let flags = host_iff_to_linux(iface.flags_host);
                                write_packed(
                                    &mut *cx.memory,
                                    arg + LINUX_IFNAMSIZ as u64,
                                    &flags.to_le_bytes(),
                                )
                            }
                            LINUX_SIOCGIFADDR | LINUX_SIOCGIFNETMASK | LINUX_SIOCGIFBRDADDR => {
                                // ifr_addr (sockaddr_in) at offset IFNAMSIZ.
                                let mut sa = [0u8; 16];
                                sa[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
                                // Address: the interface IPv4 for SIOCGIFADDR; a
                                // /32 mask / broadcast best-effort for the others.
                                if ioctl_request == LINUX_SIOCGIFNETMASK {
                                    sa[4..8].copy_from_slice(&[255, 255, 255, 255]);
                                } else {
                                    sa[4..8].copy_from_slice(&iface.addr_be);
                                }
                                write_packed(&mut *cx.memory, arg + LINUX_IFNAMSIZ as u64, &sa)
                            }
                            // SIOCGIFMTU: ifr_mtu (i32) at offset IFNAMSIZ.
                            _ => write_packed(
                                &mut *cx.memory,
                                arg + LINUX_IFNAMSIZ as u64,
                                &1500i32.to_le_bytes(),
                            ),
                        }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCSIFFLAGS => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // Setting interface flags needs CAP_NET_ADMIN; a NULL arg
                        // faults first (sockioctl01 "SIOCSIFFLAGS with invalid
                        // ifr"). carrick never mutates host interface state.
                        if arg == 0 {
                            DispatchOutcome::errno(LINUX_EFAULT)
                        } else {
                            DispatchOutcome::errno(LINUX_EPERM)
                        }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGSID => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        // Under `-t` stdio is a real pty slave. Ask Darwin for
                        // the controlling session instead of returning Carrick's
                        // bootstrap fallback, so interactive job-control probes
                        // see the host pty state when it exists.
                        if crate::host_tty::host_isatty(fd.0) {
                            match crate::host_tty::host_tty_tcgetsid(fd.0) {
                                Ok(sid) => write_packed(&mut *cx.memory, arg, &sid.to_le_bytes()),
                                Err(raw_errno) => DispatchOutcome::errno(
                                    crate::host_to_linux_errno(raw_errno),
                                ),
                            }
                        } else {
                            write_packed(&mut *cx.memory, arg, &LINUX_BOOTSTRAP_SID.to_le_bytes())
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                _ => {
                    cx.reporter
                        .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                    DispatchOutcome::errno(LINUX_ENOTTY)
                }
            })

        }

        fn flock(this, cx, fd: Fd, operation: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            let lock_operation = operation & !LINUX_LOCK_NB;
            if !matches!(
                lock_operation,
                LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Host-backed fd: forward to the macOS kernel's flock(2) so that
            // cross-process lock conflicts are real — a forked guest shares the
            // same host fd, so the parent's lock blocks the child's conflicting
            // LOCK_NB attempt (flock04/06). macOS LOCK_SH/EX/UN/NB are
            // numerically identical to Linux's, so `operation` passes straight
            // through; EWOULDBLOCK maps to Linux EAGAIN via host_syscall_errno.
            // A non-host fd (in-memory backend) keeps the single-tenant no-op.
            if let Some(host_fd) = this.regular_host_file_fd(fd.0) {
                // flock(2): "EINTR — while waiting to acquire a lock, the call
                // was interrupted by delivery of a signal caught by a handler."
                // A bare blocking host flock cannot honour that: the thread
                // parks inside the macOS kernel where carrick can observe
                // nothing, so no guest signal — not even SIGKILL — ends it, and
                // LTP flock07 (child blocks on LOCK_EX, parent signals it after
                // 1 s, test asserts EINTR) wedged to the harness timeout.
                //
                // Always ask the host NON-blocking and own the waiting here, so
                // the interrupt check is reachable between attempts. LOCK_UN and
                // an uncontended acquire still complete on the first pass.
                let guest_nonblock = operation & LINUX_LOCK_NB != 0;
                let host_operation = (operation as i32) | libc::LOCK_NB;
                let tid = cx.tid();
                loop {
                    let rc = unsafe { libc::flock(host_fd.get(), host_operation) };
                    match rc.host_syscall_errno() {
                        Ok(_) => return Ok(DispatchOutcome::Returned { value: 0 }),
                        // The guest asked for LOCK_NB itself: report the
                        // would-block verbatim rather than waiting on its
                        // behalf.
                        Err(errno) if errno == LINUX_EAGAIN && guest_nonblock => {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        Err(errno) if errno == LINUX_EAGAIN => {
                            let non_interrupting =
                                this.non_interrupting_signal_mask(cx.kernel, tid);
                            if this.signal_wait_should_eintr(
                                cx.kernel,
                                tid,
                                carrick_abi::SigSet::EMPTY,
                                carrick_abi::SigBlockMask::blocking_all_of(non_interrupting),
                            ) {
                                return Ok(DispatchOutcome::errno(LINUX_EINTR));
                            }
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fallocate(this, cx, fd: Fd, mode: u64, offset: u64, len: u64) {

            let fd: Fd = fd;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            let length = i64::from_ne_bytes(len.to_ne_bytes());
            if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length <= 0 || offset < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The resulting file size (offset + len) must fit the off_t maximum;
            // overflowing the max LFS file size is EFBIG on Linux, not the EINVAL
            // a too-large host ftruncate would yield (fallocate02 cases 7-8 pass
            // offset/len ≈ LLONG_MAX so offset+len overflows i64).
            if offset.checked_add(length).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
            }
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // Only mode-0 (default allocation) is implemented as a real grow;
            // FALLOC_FL_KEEP_SIZE preallocates without changing the apparent
            // size, which on a tmpfs/host-backed file is a no-op success.
            let grow = mode & LINUX_FALLOC_FL_KEEP_SIZE == 0;
            let new_size = (offset as u64).saturating_add(length as u64);
            // Snapshot the writeback path/contents in a scope so the borrow
            // drops before we touch this.fs.rootfs_vfs.overlay (mirrors ftruncate).
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::File {
                        base,
                        path,
                        contents,
                        metadata,
                        writable,
                        ..
                    } if grow => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // memfd seals: an allocating (non-KEEP_SIZE) fallocate is
                        // blocked only by F_SEAL_GROW when it extends the file —
                        // F_SEAL_WRITE does NOT block a pure grow (memfd_create01
                        // seals WRITE then grows via fallocate successfully).
                        if matches!(
                            base.seals().and_then(carrick_abi::LinuxMemfdSeals::from_bits),
                            Some(s) if s.contains(carrick_abi::LinuxMemfdSeals::GROW)
                        ) && new_size as usize > contents.len()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        }
                        // In-memory model (--fs memory): grow the cached bytes.
                        if new_size > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        if new_size as usize > contents.len() {
                            contents.resize(new_size as usize);
                            metadata.size = contents.len();
                        }
                        // Sync the grown contents to the overlay backing so a
                        // later fstat (which resolves the memfd's path) agrees
                        // (memfd_create01 CHECK_MFD_GROWABLE fstats the new size).
                        writeback = Some((path.clone(), contents.to_vec()));
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::File { base, writable, .. } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // A hole punch modifies content, so F_SEAL_WRITE blocks it
                        // (memfd_create01 check_mfd_non_writeable). A plain
                        // KEEP_SIZE preallocate changes nothing and is unaffected.
                        if mode & LINUX_FALLOC_FL_PUNCH_HOLE != 0
                            && let Err(errno) = memfd_seal_write_check(base.seals(), 0, 0, 0)
                        {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        // KEEP_SIZE: don't change apparent size.
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // Real fd into the cap-std scratch: grow with ftruncate
                        // (the change is visible across fork). KEEP_SIZE → no-op.
                        if grow {
                            let mut st: libc::stat = unsafe { core::mem::zeroed() };
                            if let Err(errno) =
                                (unsafe { libc::fstat(host_fd.raw(), &mut st) }).host_syscall_errno()
                            {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            if new_size > st.st_size as u64
                                && let Err(errno) = (unsafe {
                                    libc::ftruncate(host_fd.raw(), new_size as libc::off_t)
                                })
                                .host_syscall_errno()
                                {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                        }
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EROFS));
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                    }
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

        fn ftruncate(this, cx, fd: Fd, length: u64) {

            let fd: Fd = fd;
            let length = i64::from_ne_bytes(length.to_ne_bytes());
            if length < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // RLIMIT_FSIZE caps the resulting file size — see
            // `rlimit_fsize_errno`. Checked after EBADF so an invalid fd still
            // reports EBADF, matching Linux's argument-validation order.
            if let Some(errno) = this.rlimit_fsize_errno(length) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Snapshot the path + new contents in a scope so the borrow drops
            // before we touch this.fs.rootfs_vfs.overlay.
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let mut open = open_file.description.write();
                match &mut *open {
                    OpenDescription::File {
                        base,
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            // RO fd is a valid fd opened the wrong way → EINVAL,
                            // not EBADF (ftruncate03). EBADF is for an invalid fd
                            // (handled by open_file→None above).
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        if length as u64 > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        let new_len = length as usize;
                        // memfd resize seals: F_SEAL_SHRINK blocks shrink,
                        // F_SEAL_GROW blocks grow (memfd_create01).
                        if let Err(errno) =
                            memfd_seal_resize_check(base.seals(), new_len, contents.len())
                        {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        if new_len > contents.len() {
                            contents.resize(new_len);
                        } else {
                            contents.truncate(new_len);
                            if *offset > new_len {
                                *offset = new_len;
                            }
                        }
                        metadata.size = contents.len();
                        writeback = Some((path.clone(), contents.to_vec()));
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            // RO fd → EINVAL (ftruncate03), not EBADF.
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        // Real fd: ftruncate the kernel file directly (the
                        // change is visible across fork).
                        if let Err(errno) =
                            (unsafe { libc::ftruncate(host_fd.raw(), length as libc::off_t) })
                                .host_syscall_errno()
                        {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                    }
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .overlay
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

        fn openat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mode: u64) {

            let pathname = pathname.0;
            this.open_at_path(cx, dirfd, pathname, flags, mode)

        }

        fn openat2(this, cx, dirfd: u64, pathname: GuestPtr, how: GuestPtr, size: u64) {

            let how_address = how.0;
            let arg0 = dirfd;
            let arg1 = pathname.0;
            // copy_struct_from_user semantics for `open_how`:
            //  - size < sizeof(open_how) (incl. 0) → EINVAL (openat203 invalid-size-zero);
            //  - size > sizeof: the trailing bytes are forward-compat padding —
            //    they must be readable (else EFAULT, openat203 invalid-size-big)
            //    and all zero (else E2BIG, invalid-size-big-with-pad); zero pad
            //    is accepted (openat201 case 15 uses sizeof+8 with zero pad).
            if size < LINUX_OPEN_HOW_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if size > LINUX_OPEN_HOW_SIZE {
                let pad_len = (size - LINUX_OPEN_HOW_SIZE) as usize;
                match (*cx.memory).read_bytes(how_address + LINUX_OPEN_HOW_SIZE, pad_len) {
                    Ok(pad) => {
                        if pad.iter().any(|&b| b != 0) {
                            return Ok(DispatchOutcome::errno(LINUX_E2BIG));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            }
            let how = read_open_how(&*cx.memory, how_address)?;
            // open_how validation, matching the kernel's build_open_how():
            //  - mode must be within 0o7777 (openat203 invalid-mode: mode=-1);
            //  - mode may be nonzero only when creating (openat203 invalid-flags:
            //    mode set without O_CREAT/O_TMPFILE → EINVAL);
            //  - resolve may carry only known RESOLVE_* bits (openat203
            //    invalid-resolve: resolve=-1 → EINVAL).
            let mode = how.mode;
            let flags = how.flags;
            let resolve = how.resolve;
            if mode & !0o7777 != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if mode != 0 && flags & (LINUX_O_CREAT | crate::linux_abi::LINUX_O_TMPFILE) == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // RESOLVE_{NO_XDEV,NO_MAGICLINKS,NO_SYMLINKS,BENEATH,IN_ROOT,CACHED}.
            const VALID_RESOLVE: u64 = 0x3f;
            if resolve & !VALID_RESOLVE != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, arg1)?;
            let path = match this.openat2_checked_path(arg0, &path, resolve) {
                Ok(path) => path,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            this.open_at_path_string(
                cx.kernel,
                cx.thread.as_ref().map(|thread| thread.registry),
                arg0,
                path.as_ref(),
                flags,
                mode,
                cx.reporter,
            )

        }

        fn close(this, cx, fd: Fd) {

            let fd: Fd = fd;
            // Closing a stdio number (0/1/2) frees it for reuse by the
            // lowest-free-descriptor allocator (a later open()/dup can land there).
            if fd.0 >= 0 && fd.0 < 3 {
                this.captured_file_table().lock_closed_stdio()[fd.0 as usize] = true;
            }
            this.discard_splice_pushback_if_final(fd.0);
            this.dnotify_close_fd(fd.0);
            // inotify IN_CLOSE_WRITE/IN_CLOSE_NOWRITE for a watched regular file
            // or directory — emitted while the fd is still in the table so its
            // description (writability) and recorded path are still readable.
            this.inotify_close_for_fd(fd.0);
            // fanotify FAN_CLOSE_WRITE/FAN_CLOSE_NOWRITE, emitted here for the
            // same reason: the description's writability and recorded path are
            // only readable while the fd is still in the table.
            this.fanotify_close_for_fd(cx.kernel, fd.0);
            // Auto-remove this fd from every epoll interest set BEFORE freeing
            // the fd number from open_files. ORDER IS LOAD-BEARING: the instant
            // the fd leaves open_files another thread's open/pipe/dup can recycle
            // that number and `epoll_ctl(ADD)` it; if the detach ran AFTER the
            // free it would rip out the NEW owner's freshly-added interest, whose
            // EPOLLET edge then never re-fires (the Go-netpoller hang reproduced
            // by epoll_et_pipe_eof_not_lost — a worker's close raced a sibling's
            // reuse+ADD of the same fd number). While the fd is still in the table
            // the allocator cannot hand it out, so detaching first scopes the
            // removal to THIS registration. detach takes only a read lock, so it
            // does not deadlock with the separate write below.
            this.detach_fd_from_epolls(fd.0);
            let removed = this.captured_file_table().write_open_files().remove(&fd.0);
            Ok(
                if let Some(open_file) = removed {
                    this.record_fd_close_owner(fd.0, cx.tid().raw(), &open_file);
                    this.release_hvpatch_classic_record_locks(
                        cx.kernel.task().key(),
                        &open_file,
                    );
                    crate::event_ring::rec(
                        crate::event_ring::FDCLOSE,
                        fd.0,
                        fd_helpers::event_ring_host_fd(&open_file),
                        0,
                    );
                    // Centralised close: frees the host fd and, for pty masters,
                    // removes the /dev/pts/N entry from the PtyTable so it becomes
                    // ENOENT — mirroring Linux devpts semantics. The same helper is
                    // used by close_range and close_cloexec_fds so every close path
                    // stays in sync.
                    this.close_open_file_and_free_pty(&open_file);
                    this.note_fd_closed(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                } else if is_stdio_fd(fd.0) {
                    // Guest closing its own stdio at exit: there's nothing for
                    // us to do (host fd stays open under stream_stdio so
                    // sibling processes keep working), but reporting EBADF
                    // here makes glibc print "write error: Bad file descriptor"
                    // after the program's real output. Return success.
                    this.note_fd_closed(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_EBADF)
                },
            )

        }

        fn close_range(this, cx, first: u64, last: u64, flags: u64) {
            let Some(flags) = carrick_abi::LinuxCloseRangeFlags::from_bits(flags as u32) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if first > last {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let cloexec_only = flags.contains(carrick_abi::LinuxCloseRangeFlags::CLOEXEC);
            // Drain matching fds out of the table so we don't iterate a
            // gigantic [first, last] (callers commonly pass last=u32::MAX).
            let fds: Vec<i32> = this
                .captured_file_table()
                .read_open_files()
                .keys()
                .copied()
                .filter(|fd| (*fd as u64) >= first && (*fd as u64) <= last)
                .collect();
            if cloexec_only {
                let files = this.captured_file_table();
                let mut table = files.write_open_files();
                for fd in fds {
                    if let Some(open_file) = table.get_mut(&fd) {
                        open_file.fd_flags |= LINUX_FD_CLOEXEC;
                    }
                }
            } else {
                // Detach BEFORE freeing each fd number — same ordering rule as
                // `close` (a freed number is instantly reusable, and a
                // detach-after-free would rip out a sibling's reused-fd interest;
                // see `close`). Detach (read lock) and remove (write lock) are
                // separate per fd, so the fd is still in the table — hence not
                // reallocatable — across its own detach.
                for fd in fds {
                    this.discard_splice_pushback_if_final(fd);
                    this.detach_fd_from_epolls(fd);
                    if let Some(open_file) = this.captured_file_table().write_open_files().remove(&fd) {
                        this.record_fd_close_owner(fd, cx.tid().raw(), &open_file);
                        this.release_hvpatch_classic_record_locks(
                            cx.kernel.task().key(),
                            &open_file,
                        );
                        crate::event_ring::rec(
                            crate::event_ring::FDCLOSE,
                            fd,
                            fd_helpers::event_ring_host_fd(&open_file),
                            0,
                        );
                        // Centralised close so pty masters freed via close_range
                        // also drop their /dev/pts/N entry. open_files and pty_table
                        // are independent locks (no nesting), so deadlock-free.
                        this.close_open_file_and_free_pty(&open_file);
                        this.note_fd_closed(fd);
                    }
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn getdents64(this, cx, fd: Fd, dirp: GuestPtr, count: u64) {

            let fd: Fd = fd;
            let address = dirp.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let mut open = open_file.description.write();
            let OpenDescription::Directory {
                entries,
                offset,
                path,
                trusted_host_dir,
                ..
            } = &mut *open
            else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            // Trusted lane: materialize entries LAZILY on the first read —
            // streamed off the host dirfd (d_type/d_ino straight from the
            // kernel, zero per-child stats) when nothing interferes, the
            // exact layered merge otherwise. Directory opens that never call
            // getdents (walk anchors) pay nothing.
            if let Some(trusted) = trusted_host_dir
                && !trusted.entries_loaded
            {
                this.materialize_trusted_dir_entries(path, trusted, entries);
            }

            // Real Linux getdents64 always returns `.` (self) and `..` (parent)
            // first. Synthesize them on the READ path only — NOT in
            // layered_directory_entries, which also backs the rmdir/unlinkat
            // emptiness check (two synthetic dot entries there made every empty
            // dir look non-empty → ENOTEMPTY broke `rm -rf`). Idempotent: prepend
            // once if absent.
            if entries.first().map(|e| e.name.as_str()) != Some(".") {
                let parent = std::path::Path::new(path.as_str())
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/".to_string());
                let dir_path = path.clone();
                let dot_entry = |name: &str, p: String| RootFsDirEntry {
                    name: name.to_string(),
                    metadata: RootFsMetadata {
                        path: std::path::PathBuf::from(p),
                        kind: RootFsEntryKind::Directory,
                        mode: 0o755,
                        size: 0,
                    },
                    // "."/".." are skipped by scandir; ino unused → hash fallback.
                    ino: 0,
                };
                entries.insert(0, dot_entry("..", parent));
                entries.insert(0, dot_entry(".", dir_path));
            }

            let mut out = Vec::new();
            while *offset < entries.len() {
                let record = dirent64_record(&entries[*offset], *offset + 1);
                if record.len() > length {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if out.len() + record.len() > length {
                    break;
                }
                out.extend_from_slice(&record);
                *offset += 1;
            }

            memory.write_bytes(address, &out)?;

            Ok(DispatchOutcome::Returned {
                value: out.len() as i64,
            })

        }

        fn lseek(this, cx, fd: Fd, offset: u64, whence: u64) {

            let fd: Fd = fd;
            let offset = offset as i64;
            let Some(open_file) = this.open_file(fd.0) else {
                // lseek on stdio with no OpenDescription is, on Linux, a
                // valid call on an unseekable pipe/tty — kernel returns
                // ESPIPE, not EBADF. Returning EBADF confuses glibc's
                // ftell/fclose path into reporting "write error: Bad
                // file descriptor" after every successful write. BUT a
                // stdio fd the guest explicitly closed is genuinely closed:
                // lseek on it is EBADF, not ESPIPE.
                if is_stdio_fd(fd.0) && !this.stdio_is_closed(fd.0) {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let mut open = open_file.description.write();

            // HostFile: the kernel owns the offset — delegate straight to
            // libc::lseek on the real fd.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let host_whence = match whence {
                    LINUX_SEEK_SET => libc::SEEK_SET,
                    LINUX_SEEK_CUR => libc::SEEK_CUR,
                    LINUX_SEEK_END => libc::SEEK_END,
                    // SEEK_DATA/SEEK_HOLE: macOS supports them but SWAPS the
                    // numbers (Linux DATA=3/HOLE=4, macOS DATA=4/HOLE=3), so
                    // translate for sparse-file hole queries (test_fs_holes).
                    3 => 4, // LINUX_SEEK_DATA -> macOS SEEK_DATA
                    4 => 3, // LINUX_SEEK_HOLE -> macOS SEEK_HOLE
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                };
                let r =
                    (unsafe { libc::lseek(host_fd.raw(), offset as libc::off_t, host_whence) })
                        .host_syscall_errno()?;
                return Ok(DispatchOutcome::Returned { value: r as i64 });
            }

            // A CHARACTER device (/dev/null, /dev/zero, /dev/full, /dev/random,
            // /dev/urandom) is backed by a host fd but lands here as a HostPipe
            // (the open path keeps devices as streams). Such devices ARE
            // seekable on Linux — lseek returns 0/the offset, never ESPIPE — and
            // Python's io.open("/dev/null","r+") requires seekable(). Delegate to
            // the host lseek when the backing fd is a char device; genuine
            // pipes/fifos (S_IFIFO) fall through to the ESPIPE branch below.
            if let OpenDescription::HostPipe { host_fd, .. } = &*open {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
                {
                    let host_whence = match whence {
                        LINUX_SEEK_SET => libc::SEEK_SET,
                        LINUX_SEEK_CUR => libc::SEEK_CUR,
                        LINUX_SEEK_END => libc::SEEK_END,
                        _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };
                    let r = (unsafe {
                        libc::lseek(host_fd.raw(), offset as libc::off_t, host_whence)
                    })
                    .host_syscall_errno()?;
                    return Ok(DispatchOutcome::Returned { value: r as i64 });
                }
            }

            // A trusted directory materializes lazily; a SEEK_END that needs
            // the entry count must see the real entries first.
            if whence == LINUX_SEEK_END
                && let OpenDescription::Directory {
                    entries,
                    path,
                    trusted_host_dir: Some(trusted),
                    ..
                } = &mut *open
                && !trusted.entries_loaded
            {
                this.materialize_trusted_dir_entries(path, trusted, entries);
            }

            let (current, end) = match &*open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents, offset, ..
                } => (*offset as i64, contents.len() as i64),
                OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => (*offset as i64, contents.len() as i64),
                OpenDescription::Directory {
                    entries, offset, ..
                } => (*offset as i64, entries.len() as i64),
                // Linux returns ESPIPE for lseek on a pipe / socket / tty
                // (the kernel's POSIX answer for "unseekable stream") and
                // EINVAL only for nonsensical arg combinations. Returning
                // EINVAL here made dpkg-query's ftell() retry-loop spin
                // forever because POSIX says "EINVAL is recoverable" while
                // ESPIPE means "give up, it's a stream".
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                // HostFile is handled by the early libc::lseek above.
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            let next = match whence {
                LINUX_SEEK_SET => offset,
                LINUX_SEEK_CUR => current.saturating_add(offset),
                LINUX_SEEK_END => end.saturating_add(offset),
                _ => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            if next < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { offset, .. }
                | OpenDescription::Directory { offset, .. }
                | OpenDescription::SyntheticFile { offset, .. } => *offset = next as usize,
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {}
            }
            // A rewind of a trusted directory drops the materialized snapshot
            // so the next getdents64 streams a FRESH view (Linux re-reads the
            // directory after rewinddir; untrusted descriptions keep their
            // historical open-time snapshot).
            if next == 0
                && let OpenDescription::Directory {
                    entries,
                    trusted_host_dir: Some(trusted),
                    ..
                } = &mut *open
                && trusted.entries_loaded
            {
                entries.clear();
                trusted.entries_loaded = false;
            }
            Ok(DispatchOutcome::Returned { value: next })

        }

        fn read(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if this.io_uring_description(fd.0).is_some() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            // Calling thread id (for signalfd drain). Taken before borrowing
            // cx.memory mutably below.
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;
            // Guest's intended blocking mode for this fd; passed to the host-fd
            // read helper so a blocking-mode fd hands off to the lockless kqueue
            // wait on EAGAIN instead of blocking under the dispatcher lock. (read has no
            // per-call non-blocking flag.) Computed before the open_files borrow.
            let nonblocking = this.io_is_nonblocking(fd.0, 0);
            // inotify IN_ACCESS: a read(2) against a watched regular file emits
            // IN_ACCESS on that file. The kernel reports it per read syscall,
            // independent of bytes returned. Fast-exits when nothing is watched.
            this.inotify_emit_for_fd(fd.0, carrick_abi::LINUX_IN_ACCESS);
            // fanotify FAN_ACCESS: same operation, one event. fanotify has no
            // self/child split — the registry decides whether an inode mark or
            // an FAN_EVENT_ON_CHILD directory mark receives it.
            this.fanotify_emit_for_fd(
                cx.kernel,
                fd.0,
                carrick_abi::LinuxFanotifyEvents::ACCESS,
            );
            // A stdio fd the guest explicitly closed (and did not reopen) is a
            // genuinely closed descriptor: read is EBADF, not a host-stdin read.
            if this.stdio_is_closed(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // fd 0 with no explicit OpenDescription: read from host stdin.
            // This is what makes `read` against the guest's stdin pick up
            // input from the user's terminal (or whatever the carrick host
            // process's stdin is — file, pipe, or terminal).
            if fd.0 == 0 && !this.fd_table_contains(0) {
                crate::dispatch::net::set_host_nonblocking(0);
                return Ok(read_host_pipe(
                    memory,
                    address,
                    length,
                    0,
                    None,
                    nonblocking,
                ));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let mut open = open_file.description.write();
            // read() on a regular file opened write-only (O_WRONLY) → EBADF
            // (open09/creat01 read a creat()'d write-only fd). Only regular-file
            // descriptions carry O_ACCMODE semantics; pipes/sockets/eventfds and
            // the like have their own readability rules handled per-branch.
            if matches!(
                &*open,
                OpenDescription::File { .. }
                    | OpenDescription::SyntheticFile { .. }
                    | OpenDescription::HostFile { .. }
            ) && open.status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let (read_len, bytes) = match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents, offset, ..
                } => {
                    let bytes = contents.read_at(*offset, length);
                    let read_len = bytes.len();
                    *offset += read_len;
                    (read_len, bytes)
                }
                OpenDescription::SyntheticFile {
                    path,
                    contents,
                    offset,
                    ..
                } => {
                    // `/proc/<pid>/mem` for the guest's own process is a synthetic
                    // file whose reads translate the file offset as a GUEST VIRTUAL
                    // ADDRESS and return that process's memory there (debuggers +
                    // LTP read their own mappings this way). An unmapped VA is EIO,
                    // like Linux. Every OTHER synthetic file serves its precomputed
                    // byte blob.
                    //
                    // `memory` is the CALLER's address space, so the predicate
                    // must reject a peer's pid — otherwise this arm answers
                    // `/proc/<peer>/mem` with the reader's own bytes. The open
                    // side refuses a peer first; this is the second gate on the
                    // same invariant, kept because the two are reached
                    // independently (an fd can outlive the check that made it).
                    let self_pid = crate::vfs::proc::self_linux_pid(
                        this.synthetic_proc_identity(cx.kernel),
                    );
                    if crate::vfs::proc::is_proc_self_mem_path(path, self_pid) {
                        let va = *offset as u64;
                        match memory.read_bytes(va, length) {
                            Ok(bytes) => {
                                let read_len = bytes.len();
                                *offset += read_len;
                                (read_len, bytes)
                            }
                            Err(_) => {
                                drop(open);
                                return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                            }
                        }
                    } else if crate::vfs::proc::is_proc_self_pagemap_path(path, self_pid) {
                        let present = (1u64 << 63).to_le_bytes();
                        let mut bytes = vec![0u8; length];
                        for (i, byte) in bytes.iter_mut().enumerate() {
                            *byte = present[(*offset + i) % present.len()];
                        }
                        *offset += bytes.len();
                        (bytes.len(), bytes)
                    } else {
                        let remaining: &[u8] = contents.get(*offset..).unwrap_or(&[]);
                        let read_len = remaining.len().min(length);
                        let bytes = remaining[..read_len].to_vec();
                        *offset += read_len;
                        (read_len, bytes)
                    }
                }
                OpenDescription::EventFd {
                    base,
                    state,
                    semaphore,
                } => {
                    let state = Arc::clone(state);
                    let semaphore = *semaphore;
                    let nonblocking = base.is_nonblocking();
                    drop(open);
                    return Ok(read_eventfd(
                        memory,
                        address,
                        length,
                        &state,
                        semaphore,
                        nonblocking,
                    ));
                }
                OpenDescription::TimerFd { base, state } => {
                    let state = Arc::clone(state);
                    let nonblocking = base.status_flags() & LINUX_TFD_NONBLOCK != 0;
                    drop(open);
                    return Ok(read_timerfd(memory, address, length, &state, nonblocking));
                }
                OpenDescription::Inotify { state, .. } => {
                    let state = Arc::clone(state);
                    drop(open);
                    // Drain queued inotify_event records into the guest buffer.
                    // An empty queue is EAGAIN (inotify fds are overwhelmingly
                    // used non-blocking + epoll; a true blocking wait on the
                    // backing kqueue fd is a tracked follow-up).
                    //
                    // NOTE: a blocking-mode read cannot be reliably satisfied on
                    // macOS for a CROSS-PROCESS transient-event flood (inotify11:
                    // a forked child create+unlinks 9999 files). kqueue only
                    // reports "the directory vnode changed", and carrick's
                    // dir-snapshot diff misses any file both created AND deleted
                    // between two coalesced scans — so parking on the kqueue would
                    // hang rather than deliver the IN_DELETE names. That needs a
                    // cross-process inotify event mirror, out of scope here.
                    return Ok(match state.read_records(length) {
                        Ok(bytes) if bytes.is_empty() => DispatchOutcome::errno(LINUX_EAGAIN),
                        Ok(bytes) => {
                            if memory.write_bytes(address, &bytes).is_err() {
                                DispatchOutcome::errno(LINUX_EFAULT)
                            } else {
                                DispatchOutcome::Returned {
                                    value: bytes.len() as i64,
                                }
                            }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    });
                }
                OpenDescription::Fanotify { base, group } => {
                    let group = Arc::clone(group);
                    // FAN_NONBLOCK (init) and O_NONBLOCK (a later fcntl) are
                    // independent switches; either one makes the read
                    // non-blocking.
                    let nonblocking = group.init_nonblocking()
                        || base.status_flags() & LINUX_O_NONBLOCK != 0;
                    drop(open);
                    return read_fanotify(
                        this,
                        cx.kernel,
                        cx.thread.as_ref().map(|thread| thread.registry),
                        cx.reporter,
                        memory,
                        address,
                        length,
                        &group,
                        nonblocking,
                    );
                }
                OpenDescription::PipeReader { base, pipe } => {
                    return Ok(read_pipe(memory, address, length, pipe, base.status_flags()));
                }
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    pty,
                    bidirectional,
                    ..
                } => {
                    // pty ends and O_RDWR FIFOs are bidirectional; only real
                    // one-way pipe ends are gated by is_read_end.
                    if !*is_read_end && pty.is_none() && !*bidirectional {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let host_fd_raw = host_fd.raw();
                    let host_fd_owner = host_fd.clone();
                    drop(open);
                    let staged = this.take_staged_splice_pipe_bytes(fd.0, length)?;
                    if !staged.is_empty() {
                        if memory.write_bytes(address, &staged).is_err() {
                            this.restore_splice_pipe_bytes(fd.0, &staged);
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: staged.len() as i64,
                        });
                    }
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd_raw,
                        Some(host_fd_owner),
                        nonblocking,
                    ));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::SignalFd { mask, .. } => {
                    let mask = *mask;
                    drop(open);
                    // Drain pending signals matching the fd's mask into
                    // signalfd_siginfo records (empty → EAGAIN, like inotify).
                    return Ok(this.read_signalfd(cx.kernel, memory, address, length, mask, tid));
                }
                // read() on an fs context (the kernel's fsconfig error-log
                // channel) is unimplemented — EINVAL, documented in
                // `dispatch/mount_api.rs`.
                OpenDescription::FsContext { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::PipeWriter { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::HostSocket { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd.raw(),
                        Some(host_fd.clone()),
                        nonblocking,
                    ));
                }
                // Netlink: drain whatever a prior dump request queued. A bare
                // read(2) is rare on netlink sockets (recvmsg is the norm), but
                // model it as draining the synthetic response so it doesn't
                // wedge a caller.
                OpenDescription::Netlink { recv_queue, .. } => {
                    return Ok(net::drain_netlink_queue(
                        memory, address, length, recv_queue,
                    ));
                }
                // Real host file: libc::read advances the kernel offset
                // (shared across fork). read_host_pipe is just a
                // memory-into-guest read(2) wrapper.
                OpenDescription::HostFile { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd.raw(),
                        Some(host_fd.clone()),
                        nonblocking,
                    ));
                }
            };
            memory.write_bytes(address, &bytes)?;
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn readv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let nonblocking = this.io_is_nonblocking(fd.0, 0);
            let mut open = open_file.description.write();
            // Real host file: readv via the kernel fd (advances the shared
            // offset). Fill each iovec sequentially.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = host_fd.raw();
                if let Some(targets) = prepare_readv_targets(memory, &iovecs)? {
                    if targets.host_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(targets.host_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = {
                        let _host_write = carrick_guest_mem::HostWriteGuard::new(
                            memory,
                            &targets.guest_ranges,
                        );
                        unsafe { libc::readv(hfd, targets.host_iovecs.as_ptr(), iovcnt) }
                    };
                    let n = n.host_syscall_errno()?;
                    return Ok(DispatchOutcome::Returned { value: n as i64 });
                }
                let mut total = 0i64;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    match read_host_pipe(
                        memory,
                        iov.iov_base,
                        len,
                        hfd,
                        None,
                        /*nonblocking=*/ false,
                    ) {
                        DispatchOutcome::Returned { value } => {
                            total += value;
                            if (value as usize) < len {
                                break;
                            }
                        }
                        other => return Ok(other),
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            match &*open {
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    pty,
                    bidirectional,
                    ..
                } => {
                    if !*is_read_end && pty.is_none() && !*bidirectional {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let hfd = host_fd.raw();
                    let owner = Some(host_fd.clone());
                    drop(open);
                    let staged_capacity = iovecs.iter().try_fold(0usize, |total, iovec| {
                        usize::try_from(iovec.iov_len)
                            .ok()
                            .and_then(|length| total.checked_add(length))
                    });
                    let Some(staged_capacity) = staged_capacity else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let staged = this.take_staged_splice_pipe_bytes(
                        fd.0,
                        staged_capacity.min(crate::dispatch::MAX_RW_COUNT),
                    )?;
                    if !staged.is_empty() {
                        let read_len = read_from_contents_at(memory, &staged, 0, &iovecs)?;
                        if read_len < staged.len() {
                            this.restore_splice_pipe_bytes(fd.0, &staged[read_len..]);
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: read_len as i64,
                        });
                    }
                    return Ok(Self::read_host_pipe_iovecs(
                        memory,
                        &iovecs,
                        hfd,
                        owner,
                        nonblocking,
                    ));
                }
                OpenDescription::HostSocket { host_fd, .. } => {
                    let hfd = host_fd.raw();
                    let owner = Some(host_fd.clone());
                    drop(open);
                    return Ok(Self::read_host_pipe_iovecs(
                        memory,
                        &iovecs,
                        hfd,
                        owner,
                        nonblocking,
                    ));
                }
                _ => {}
            }
            let read_len = match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents, offset, ..
                } => {
                    let read_len = read_from_file_contents_at(memory, contents, *offset, &iovecs)?;
                    *offset += read_len;
                    read_len
                }
                OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => {
                    let read_len = read_from_contents_at(memory, contents, *offset, &iovecs)?;
                    *offset += read_len;
                    read_len
                }
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // readv on a directory is EISDIR (readv02). Other non-regular
                // fds keep EINVAL here (readv on a pipe/socket reading at the
                // current offset is a separate, untested path).
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn pread64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let buffer = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset =
                usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            // Real host file: positional read via libc::pread (doesn't
            // disturb the shared kernel offset).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let length = length.min(crate::dispatch::MAX_RW_COUNT);
                let mut buf = vec![0u8; length];
                let n = unsafe {
                    libc::pread(
                        host_fd.raw(),
                        buf.as_mut_ptr() as *mut _,
                        length,
                        offset as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                if n > 0 && memory.write_bytes(buffer, &buf[..n]).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: n as i64 });
            }
            let bytes = match &*open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { contents, .. } => contents.read_at(offset, length),
                OpenDescription::SyntheticFile { contents, .. } => contents
                    .get(offset..)
                    .unwrap_or_default()
                    .iter()
                    .take(length)
                    .copied()
                    .collect(),
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    // Positional read on a non-seekable fd (pipe/socket/anon) is
                    // ESPIPE on Linux; a directory is EISDIR (above). pread02.
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            };
            let read_len = bytes.len();
            if read_len > 0 {
                memory.write_bytes(buffer, &bytes)?;
            }
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn preadv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64, rwf: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset =
                usize::try_from(pos_l).map_err(|_| DispatchError::LengthTooLarge(pos_l))?;
            // preadv2 (canonical 286) treats offset == -1 as "use (and advance)
            // the current file offset" — readv semantics. Plain preadv (69) has
            // no such case, and would hand -1 straight to the host preadv → EINVAL
            // (the preadv201 failure). The trailing RWF_* flags arg (raw_args[5])
            // is advisory for our host-file backing; RWF_HIPRI is a priority hint
            // here, so preadv2(off, RWF_HIPRI) reads like preadv.
            let is_preadv2 = cx.number() == 286;
            let read_at_current = is_preadv2 && (pos_l as i64) == -1;
            // preadv2's RWF_* flags: any bit outside RWF_SUPPORTED is rejected by
            // Linux's kiocb_set_rw_flags() with EOPNOTSUPP (preadv202 passes
            // flag=-1 and expects EOPNOTSUPP, NOT EINVAL). RWF_NOWAIT on our
            // buffered host backing likewise cannot be honored → EOPNOTSUPP. The
            // known-but-advisory bits (HIPRI/DSYNC/SYNC/APPEND) are accepted.
            if is_preadv2
                && rwf
                    & !(crate::linux_abi::LINUX_RWF_SUPPORTED
                        & !crate::linux_abi::LINUX_RWF_NOWAIT)
                    != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            // preadv reads the fd, so a descriptor not open for reading
            // (O_WRONLY) is EBADF (preadv02 "not open for reading" case), exactly
            // as the kernel rejects it before touching the data.
            if open.status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Real host file: positional readv via libc::pread per iovec
            // (kernel offset untouched).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = host_fd.raw();
                if let Some(targets) = prepare_readv_targets(memory, &iovecs)? {
                    if targets.host_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(targets.host_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = {
                        let _host_write = carrick_guest_mem::HostWriteGuard::new(
                            memory,
                            &targets.guest_ranges,
                        );
                        unsafe {
                            if read_at_current {
                                libc::readv(hfd, targets.host_iovecs.as_ptr(), iovcnt)
                            } else {
                                libc::preadv(
                                    hfd,
                                    targets.host_iovecs.as_ptr(),
                                    iovcnt,
                                    offset as libc::off_t,
                                )
                            }
                        }
                    };
                    let n = n.host_syscall_errno()?;
                    return Ok(DispatchOutcome::Returned { value: n as i64 });
                }
                let mut total = 0i64;
                let mut cur = offset;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    let mut buf = vec![0u8; len];
                    // BLOCKING-IO-OK: hfd is an OpenDescription::HostFile (the
                    // `if let HostFile` arm above; stdio returned ESPIPE earlier) —
                    // a regular host file, never a pipe/socket/tty — so this read
                    // cannot block the vCPU waiting on a peer.
                    let n = unsafe {
                        if read_at_current {
                            libc::read(hfd, buf.as_mut_ptr() as *mut _, len)
                        } else {
                            libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, cur as libc::off_t)
                        }
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(value) => value as usize,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    if n > 0 && memory.write_bytes(iov.iov_base, &buf[..n]).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    total += n as i64;
                    cur += n;
                    if n < len {
                        break;
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let read_len = match &*open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { contents, .. } => {
                    read_from_file_contents_at(memory, contents, offset, &iovecs)?
                }
                OpenDescription::SyntheticFile { contents, .. } => {
                    read_from_contents_at(memory, contents, offset, &iovecs)?
                }
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    // Positional read on a non-seekable fd → ESPIPE; directory →
                    // EISDIR (above). preadv02.
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            };
            Ok(DispatchOutcome::Returned {
                value: read_len as i64,
            })

        }

        fn pwrite64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            if offset < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A zero-length write never accesses the buffer — `pwrite(fd, NULL,
            // 0)` returns 0, NOT EFAULT (Linux checks count before touching the
            // buffer; LTP pwrite03). Only read guest memory when count > 0.
            let bytes = if length == 0 {
                Vec::new()
            } else {
                match (*cx.memory).read_bytes(address, length) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            // An O_APPEND fd forces EVERY write to EOF, ignoring the supplied
            // offset (pwrite04). macOS pwrite() on an O_APPEND fd returns EINVAL,
            // so seek-to-end then write() instead (matching the plain write()
            // append path).
            let is_append = open.is_append();
            // Real host file: positional write via libc::pwrite (visible
            // across fork; kernel offset untouched).
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let n = unsafe {
                    if is_append {
                        // O_APPEND writes at EOF regardless of the offset, but
                        // pwrite MUST leave the file offset untouched (pwrite04
                        // checks lseek(SEEK_CUR) is unchanged). Save the offset,
                        // seek to EOF, write, then restore. (The write goes
                        // through write(), not pwrite(), which macOS rejects with
                        // EINVAL on an O_APPEND fd.)
                        let saved = libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR);
                        libc::lseek(host_fd.raw(), 0, libc::SEEK_END);
                        // BLOCKING-IO-OK: HostFile fds are adopted O_NONBLOCK;
                        // regular-file writes do not park on pipe/socket wait.
                        let w = libc::write(host_fd.raw(), bytes.as_ptr() as *const _, length);
                        if saved >= 0 {
                            libc::lseek(host_fd.raw(), saved, libc::SEEK_SET);
                        }
                        w
                    } else {
                        libc::pwrite(
                            host_fd.raw(),
                            bytes.as_ptr() as *const _,
                            length,
                            offset as libc::off_t,
                        )
                    }
                };
                let n = n.host_syscall_errno()?;
                return Ok(DispatchOutcome::Returned { value: n as i64 });
            }
            // In-memory File (memfd / O_TMPFILE fallback): positional write into
            // the cached contents, honoring memfd write/grow seals. Previously an
            // unconditional EBADF (memfd_create01 CHECK_MFD_*_BY_WRITE pwrites).
            let is_inmem_file = matches!(&*open, OpenDescription::File { .. });
            drop(open);
            if is_inmem_file {
                let mut open = open_file.description.write();
                if let OpenDescription::File {
                    base,
                    path,
                    contents,
                    writable,
                    metadata,
                    ..
                } = &mut *open
                {
                    if !*writable {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let write_at = if is_append {
                        contents.len()
                    } else {
                        offset as usize
                    };
                    if let Err(errno) = memfd_seal_write_check(
                        base.seals(),
                        write_at,
                        bytes.len(),
                        contents.len(),
                    ) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let mut off = write_at;
                    if let Err(errno) = write_into_file_contents(contents, &mut off, &bytes) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    metadata.size = contents.len();
                    let writeback = (path.clone(), contents.to_vec());
                    drop(open);
                    let _ = this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .set_file_contents(&writeback.0, writeback.1);
                    return Ok(DispatchOutcome::Returned {
                        value: bytes.len() as i64,
                    });
                }
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let open = open_file.description.read();
            let errno = match &*open {
                OpenDescription::Closed { .. }
                | OpenDescription::File { .. }
                | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. } => LINUX_ESPIPE,
            };
            Ok(DispatchOutcome::errno(errno))

        }

        fn pwritev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64, rwf: u64) {

            let fd: Fd = fd;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset = i64::from_ne_bytes(pos_l.to_ne_bytes());
            // pwritev2 (canonical 287) treats offset == -1 as "use (and advance)
            // the current file offset" — writev semantics. Plain pwritev (70) has
            // no such case. The trailing RWF_* flags arg is advisory for our
            // host-file backing; RWF_HIPRI writes like pwritev.
            let is_pwritev2 = cx.number() == 287;
            let write_at_current = is_pwritev2 && offset == -1;
            // pwritev2's RWF_* flags: any bit outside RWF_SUPPORTED is rejected by
            // Linux's kiocb_set_rw_flags() with EOPNOTSUPP (pwritev202 passes
            // flag=-1 and expects EOPNOTSUPP, NOT EINVAL). RWF_NOWAIT on our
            // buffered host backing likewise cannot be honored → EOPNOTSUPP. The
            // known-but-advisory bits (HIPRI/DSYNC/SYNC/APPEND) are accepted.
            if is_pwritev2
                && rwf
                    & !(crate::linux_abi::LINUX_RWF_SUPPORTED
                        & !crate::linux_abi::LINUX_RWF_NOWAIT)
                    != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            let memory = &*cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            if offset < 0 && !write_at_current {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payloads = match prepare_pwritev_payloads(memory, &iovecs) {
                Ok(payloads) => payloads,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            // An O_APPEND fd writes at EOF regardless of the offset, but pwritev
            // (like pwrite) MUST leave the file offset untouched. Save the
            // offset, seek to EOF, then write via writev()/write() (macOS rejects
            // pwritev() on an O_APPEND fd with EINVAL), and restore the offset
            // afterward.
            let is_append = open.is_append();
            // Real host file: positional writev via libc::pwrite per iovec.
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let hfd = host_fd.raw();
                let saved_offset =
                    is_append.then(|| unsafe { libc::lseek(hfd, 0, libc::SEEK_CUR) });
                if is_append {
                    unsafe { libc::lseek(hfd, 0, libc::SEEK_END) };
                }
                let restore_offset = |saved: Option<i64>| {
                    if let Some(s) = saved
                        && s >= 0
                    {
                        unsafe { libc::lseek(hfd, s, libc::SEEK_SET) };
                    }
                };
                let at_current = write_at_current || is_append;
                if let PwritevPayloads::Borrowed(borrowed_iovecs) = &payloads {
                    if borrowed_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(borrowed_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = unsafe {
                        if at_current {
                            libc::writev(hfd, borrowed_iovecs.as_ptr(), iovcnt)
                        } else {
                            libc::pwritev(
                                hfd,
                                borrowed_iovecs.as_ptr(),
                                iovcnt,
                                offset as libc::off_t,
                            )
                        }
                    };
                    restore_offset(saved_offset);
                    let n = n.host_syscall_errno()?;
                    return Ok(DispatchOutcome::Returned { value: n as i64 });
                }
                let mut total = 0i64;
                let mut cur = offset;
                let PwritevPayloads::Staged(staged_iovecs) = &payloads else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                for buf in staged_iovecs {
                    if buf.is_empty() {
                        continue;
                    }
                    let len = buf.len();
                    // BLOCKING-IO-OK: hfd is an OpenDescription::HostFile (the
                    // `if let HostFile` arm above; stdio returned ESPIPE earlier) —
                    // a regular host file, never a pipe/socket/tty — so this write
                    // cannot block the vCPU waiting on a peer.
                    let n = unsafe {
                        if at_current {
                            libc::write(hfd, buf.as_ptr() as *const _, len)
                        } else {
                            libc::pwrite(hfd, buf.as_ptr() as *const _, len, cur as libc::off_t)
                        }
                    };
                    let n = n.host_syscall_errno()?;
                    total += n as i64;
                    cur += n as i64;
                    if (n as usize) < len {
                        break;
                    }
                }
                restore_offset(saved_offset);
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let errno = match &*open {
                OpenDescription::Closed { .. }
                | OpenDescription::File { .. }
                | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. } => LINUX_ESPIPE,
            };
            Ok(DispatchOutcome::errno(errno))

        }

        fn sendfile(this, cx, out_fd: Fd, in_fd: Fd, offset: GuestPtr, count: u64) {
            let tid = cx.tid();

            let out_fd: Fd = out_fd;
            let in_fd: Fd = in_fd;
            let offset_address = offset.0;
            let count =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // in_fd must be READABLE — sendfile reads the source from it. An
            // O_WRONLY in_fd → EBADF (LTP sendfile03 case 4). A bad in_fd is
            // caught as EBADF by sendfile_offset below; out_fd writability is
            // enforced on the write path (sendfile03 case 2 already passes).
            if let Some(in_file) = this.open_file(in_fd.0)
                && in_file.description.read().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            let mut offset = this.sendfile_offset(in_fd.0, offset_address, memory)??;

            // Darwin-native fast path: a regular file -> socket uses macOS
            // sendfile(2) (BSD-style, in-kernel, zero-copy). It honors socket
            // backpressure by returning a partial `len` + EAGAIN, which Go's
            // netpoller drives via EPOLLOUT — so a large transfer does NOT hang
            // the way a userspace read-into-buffer-then-write does. Non-socket
            // destinations and in-memory file sources fall through to the buffer
            // path below.
            if let (Some(file_fd), Some(sock_fd)) =
                (this.regular_host_file_fd(in_fd.0), this.host_socket_fd(out_fd.0))
            {
                // SAFETY: both are live host fds owned by these guest fds. The
                // portable wrapper hides the Darwin (6-arg, in/out len) vs Linux
                // (4-arg, swapped fds) signature: returns bytes sent, or -1
                // (errno set), so `host_syscall_errno()` below still works.
                let rc = unsafe {
                    carrick_portable::sendfile_to_socket(
                        file_fd.get(),
                        sock_fd.get(),
                        offset as i64,
                        count,
                    )
                };
                let sent = rc.max(0) as usize;
                let advance_and_return = |offset: usize,
                                          sent: usize,
                                          memory: &mut dyn GuestMemory|
                 -> Result<DispatchOutcome, DispatchError> {
                    let new_off = offset.saturating_add(sent);
                    if offset_address == 0 {
                        // macOS sendfile takes an explicit `offset` and does NOT
                        // advance the file's kernel offset; do it so a follow-up
                        // read/sendfile (no explicit offset) continues correctly.
                        unsafe { libc::lseek(file_fd.get(), new_off as libc::off_t, libc::SEEK_SET) };
                    } else if memory
                        .write_bytes(offset_address, &(new_off as u64).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::Returned { value: sent as i64 })
                };
                match (rc as i64).host_syscall_errno() {
                    Ok(_) => return advance_and_return(offset, sent, memory),
                    Err(e) if e == LINUX_EAGAIN => {
                        if sent > 0 {
                            // Partial transfer before the socket filled: report it
                            // (Go advances and loops).
                            return advance_and_return(offset, sent, memory);
                        }
                        return Ok(if this.io_is_nonblocking(out_fd.0, 0) {
                            DispatchOutcome::errno(LINUX_EAGAIN)
                        } else {
                            DispatchOutcome::WaitOnFds {
                                fds: WaitFds::raw_one(sock_fd.get(), libc::POLLOUT),
                                timeout: None,
                                on_timeout: LINUX_EAGAIN.guest_retval(),
                                sig_mask: carrick_abi::WaitSigMask::NONE,
                            }
                        });
                    }
                    // FreeBSD sendfile(2) only supports STREAM sockets; an AF_UNIX
                    // (especially DGRAM) out_fd is rejected with EINVAL. Linux
                    // sendfile handles any socket destination, so fall through to the
                    // buffer path below (read in_fd, then write_output_fd, which
                    // honours the socket's EAGAIN/ENOBUFS backpressure) when the host
                    // sendfile rejects the destination outright with nothing sent
                    // (LTP sendfile07 sendfiles to a full non-blocking AF_UNIX fd).
                    Err(e) if e == LINUX_EINVAL && sent == 0 => {}
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                }
            }

            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = this.write_output_fd(out_fd.0, &bytes, tid);
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if offset_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0) {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        // HostFile reads via `pread` (sendfile_bytes), which does
                        // NOT advance the kernel offset; advance it explicitly so a
                        // follow-up sendfile/read with no explicit offset continues
                        // past what we just sent. Without this, busybox `cat` —
                        // which copies a file with `sendfile(out, file, NULL, n)` in
                        // a `while (n > 0)` loop — re-sends offset 0 forever.
                        OpenDescription::HostFile { host_fd, .. } => {
                            // SAFETY: host_fd is a live regular-file fd owned by
                            // this guest fd; lseek to an absolute position is benign.
                            unsafe {
                                libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET);
                            }
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn copy_file_range(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_addr = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_addr = off_out.0;
            // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
            // so cap each call to a bounded chunk rather than trying to allocate
            // a multi-exabyte buffer. A short return is legal for copy_file_range.
            let requested = usize::try_from(len).unwrap_or(usize::MAX);
            let memory = &mut *cx.memory;
            let count = requested.min(8 * 1024 * 1024);
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let in_offset = this.sendfile_offset(in_fd.0, off_in_addr, memory)??;
            // copy_file_range onto the SAME file with OVERLAPPING ranges must fail
            // EINVAL (Linux). Go's io.Copy(f, f) self-copy hits exactly this: fd_in
            // == fd_out, NULL/NULL offsets → identical (thus overlapping) ranges.
            // Without this carrick copied the bytes and returned a success count, so
            // Go's zero-copy hook recorded handled=true and skipped its generic
            // doubling fallback (TestCopyFile/CopyFileItself). Reject ONLY when the
            // fds are the same file AND the per-round ranges overlap — distinct
            // files and non-overlapping self-copies are untouched. Resolve the out
            // offset only in this branch to avoid touching the out fd on the common
            // cross-file path. Sits above the Darwin clone fast path so it can't
            // mis-handle an overlapping self-copy either.
            if this.copy_same_file(in_fd.0, out_fd.0) {
                let out_offset = this.sendfile_offset(out_fd.0, off_out_addr, memory)??;
                let in_end = in_offset.saturating_add(count);
                let out_end = out_offset.saturating_add(count);
                if in_offset < out_end && out_offset < in_end {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(outcome) = this.try_darwin_copyfile_range_fast_path(
                in_fd.0,
                in_offset,
                off_in_addr,
                out_fd.0,
                off_out_addr,
                count,
            )? {
                return Ok(outcome);
            }
            let bytes = this.sendfile_bytes(in_fd.0, in_offset, count)?;
            if bytes.is_empty() {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // Write side. off_out == NULL → write at out_fd's current position
            // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
            // given offset on a real host fd and advance *off_out.
            let written = if off_out_addr == 0 {
                let outcome = this.write_output_fd(out_fd.0, &bytes, tid);
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                usize::try_from(value).unwrap_or(0)
            } else {
                let out_off = read_u64(memory, off_out_addr)?;
                let host_fd = match this.open_file(out_fd.0).as_ref() {
                    Some(of) => match &*of.description.read() {
                        OpenDescription::HostFile {
                            host_fd,
                            writable: true,
                            ..
                        } => host_fd.raw(),
                        OpenDescription::HostFile { .. } => {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        _ => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                };
                let n = unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                        out_off as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                if memory
                    .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                n
            };

            // Advance the input offset (pointer or the fd's own position).
            let new_in = in_offset.saturating_add(written);
            if off_in_addr == 0 {
                if let Some(of) = this.open_file(in_fd.0).as_ref() {
                    let mut open = of.description.write();
                    match &mut *open {
                        OpenDescription::File { offset, .. }
                        | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                        OpenDescription::HostFile { host_fd, .. } => {
                            unsafe {
                                libc::lseek(host_fd.raw(), new_in as libc::off_t, libc::SEEK_SET)
                            };
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned {
                value: written as i64,
            })

        }

        fn tee(this, cx, fd_in: Fd, fd_out: Fd, len: u64, flags: u64) {

            // tee(2) duplicates up to `len` bytes of pipe data from fd_in to
            // fd_out WITHOUT consuming the source. carrick's pipes are real host
            // kernel pipes (HostPipe), so on Linux we pass straight through to
            // the host tee(2) — exact, fork-coherent semantics with no userspace
            // ring to peek. macOS has no tee(2): it stays ENOSYS (as before).
            let _ = cx;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // Both fds must be pipes — fd_in a READ end, fd_out a WRITE end —
            // else EINVAL (tee01 setup). The read and write end of the SAME pipe
            // object is also EINVAL (tee02), detected via the shared pipe_id.
            let Some((in_fd, in_pipe)) = this.host_pipe_end(fd_in.0, true) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let Some((out_fd, out_pipe)) = this.host_pipe_end(fd_out.0, false) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if in_pipe != 0 && in_pipe == out_pipe {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let count = usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            this.host_tee(in_fd, in_pipe, out_fd, count, splice_flags)

        }

        fn splice(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_address = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_address = off_out.0;
            let count =
                usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
            let memory = &mut *cx.memory;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // A closed/negative fd_in is EBADF before any routing — the
            // file→pipe fallthrough otherwise read an empty byte stream from
            // the dead fd and "spliced" 0 bytes (LTP splice03 badfd case).
            if in_fd.0 < 0 || (in_fd.0 > 2 && this.open_file(in_fd.0).is_none()) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) reads from fd_in, so a source not open for reading — an
            // O_PATH descriptor, a write-only file, or the write end of a pipe —
            // is EBADF, decided ahead of the pipe-vs-pipe routing (splice03's
            // write-only fd_in, splice07's O_PATH / pipe-write-end sources).
            if this.splice_source_not_readable(in_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) requires at least ONE end to be a genuine pipe; a
            // char-device HostPipe (e.g. /dev/zero) does NOT count. When neither
            // fd is a genuine pipe the call is EINVAL, resolved BEFORE any read so
            // a char-device or socket source is never drained (splice07
            // /dev/zero->file & socket->file/socket, splice03 file->file).
            if !this.is_genuine_pipe(in_fd.0) && !this.is_genuine_pipe(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // An `io_uring` ring is an anonymous inode with no splice file
            // operations, so Linux answers EINVAL for either end. carrick backs
            // the ring fd with a plain `SyntheticFile`, which
            // `splice_source_not_readable` accepts: the call fell through to the
            // file->pipe path, `sendfile_bytes` read the description's empty
            // `contents`, and splice reported a successful 0-byte transfer
            // (splice07 "splice() on io uring -> pipe write end succeeded").
            if this.io_uring_description(in_fd.0).is_some()
                || this.io_uring_description(out_fd.0).is_some()
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A guest that did not ask for SPLICE_F_NONBLOCK still gets
            // non-blocking behaviour when the DESTINATION fd is O_NONBLOCK,
            // exactly like write(2) on the same fd.
            let out_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(out_fd.0);
            // Never hand the destination more than it can take in one go. The
            // write path returns a SHORT count rather than parking (splice(2)'s
            // own contract), and bounding the SOURCE read by the same figure
            // keeps the undelivered tail out of carrick's hands entirely.
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(0) => return Ok(this.splice_output_would_block(out_fd.0, out_nonblocking)),
                Some(room) => count.min(room),
                None => count,
            };

            if let Some((pipe, status_flags)) = this.pipe_reader(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let bytes = take_pipe_bytes(&pipe, count, status_flags)?;
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &bytes, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    Self::restore_pipe_bytes(&pipe, &bytes);
                    return Ok(outcome);
                };
                let written = usize::try_from(value).unwrap_or(0).min(bytes.len());
                if written < bytes.len() {
                    Self::restore_pipe_bytes(&pipe, &bytes[written..]);
                }
                return Ok(DispatchOutcome::Returned { value: written as i64 });
            }

            // Splice OUT of a real host pipe's read end (the fork-safe pipe model;
            // `pipe2`/`fcntl` now hand back HostPipe descriptions, so splice must
            // recognise them just like the legacy in-memory PipeReader above).
            if let Some(host_fd) = this.host_pipe_read_fd(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                // A source read that finds nothing waits (or reports EAGAIN)
                // like every other blocking-mode host read; the guest's own
                // O_NONBLOCK on fd_in counts alongside SPLICE_F_NONBLOCK.
                let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    || this.fd_is_nonblocking(in_fd.0);
                let host_fd_owner = this.open_file(in_fd.0).and_then(|file| {
                    let open = file.description.read();
                    match &*open {
                        OpenDescription::HostPipe { host_fd, .. } => Some(host_fd.clone()),
                        _ => None,
                    }
                });
                let buf = match this.take_splice_pipe_bytes(
                    in_fd.0,
                    host_fd,
                    host_fd_owner,
                    count,
                    in_nonblocking,
                )? {
                    Ok(buf) => buf,
                    Err(outcome) => return Ok(outcome),
                };
                if buf.is_empty() {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf);
                    return Ok(outcome);
                };
                let written = if value <= 0 {
                    0
                } else {
                    usize::try_from(value).unwrap_or(buf.len()).min(buf.len())
                };
                if written < buf.len() {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf[written..]);
                }
                return Ok(DispatchOutcome::Returned {
                    value: written as i64,
                });
            }

            // Splice OUT of a host socket (socket -> pipe, and socket -> socket).
            // This is the path Go's `io.Copy(pipe, conn)` takes; without it a
            // socket source fell through to the sendfile path below, which treats
            // `in_fd` as a regular file and fails. The host socket fd is
            // non-blocking, so an empty socket yields EAGAIN — which is exactly
            // what a non-blocking guest (the Go netpoller) expects; a true
            // blocking-wait for an empty socket is the same tracked follow-up as
            // the host-pipe branch above.
            if let Some(host_fd) = this.host_socket_fd(in_fd.0) {
                // A pipe/socket source has no seekable offset → off_in must be
                // NULL. off_out IS allowed (honored below) when fd_out is a
                // regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if off_out_address == 0
                    && splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    && let Some((pipe_read_fd, room)) =
                        this.host_pipe_splice_staging_target(out_fd.0)
                {
                    if room == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    let want = count.min(room).min(1 << 20);
                    let mut buf = vec![0u8; want];
                    let n = unsafe {
                        // BLOCKING-IO-OK: MSG_DONTWAIT is passed on this recv.
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr() as *mut _,
                            want,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(v) => v,
                        // A socket that STRUCTURALLY cannot serve as a splice
                        // source — unconnected (ENOTCONN) or a family without a
                        // splice_read op (EOPNOTSUPP) — is EINVAL, matching
                        // Linux's structural check (splice07). Every OTHER recv
                        // error is a genuine transport/nonblocking condition —
                        // EAGAIN (netpoller), ECONNRESET, EPIPE, … — which Linux
                        // propagates verbatim, so surface the real errno.
                        Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        Err(e) => return Ok(DispatchOutcome::errno(e)),
                    };
                    if n == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    buf.truncate(n as usize);
                    let consumed = buf.len();
                    this.stage_splice_pipe_bytes_owned(pipe_read_fd, buf);
                    return Ok(DispatchOutcome::Returned {
                        value: consumed as i64,
                    });
                }
                // PEEK first, then consume EXACTLY what the destination accepts.
                // The destination is typically Go's O_NONBLOCK splice pipe (64 KiB
                // on macOS — F_SETPIPE_SZ is bookkeeping-only here). A plain
                // consuming recv() pulls up to `count` (~RCVBUF) off the socket,
                // but splice_write_out does a single non-blocking write to the
                // pipe; when recv > the pipe's free space the un-written tail —
                // ALREADY removed from the socket — is silently DROPPED and
                // unrecoverable (TestLargeCopyViaNetwork: server saw ~1.9MB of a
                // 10MB sendfile). MSG_PEEK leaves the bytes in the socket; we
                // remove only the prefix that actually reached the destination, so
                // the guest's Go splice loop just makes another pass for the rest.
                let want = count.min(1 << 20);
                let mut buf = vec![0u8; want];
                // Non-blocking peek (MSG_PEEK | MSG_DONTWAIT below): never blocks
                // under the dispatcher lock; EAGAIN is surfaced, not awaited here.
                let n = unsafe {
                    libc::recv(
                        host_fd.get(),
                        buf.as_mut_ptr() as *mut _,
                        want,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(v) => v,
                    // A socket that STRUCTURALLY cannot serve as a splice source —
                    // unconnected (ENOTCONN) or a family without a splice_read op
                    // (EOPNOTSUPP) — is EINVAL, matching Linux's structural check
                    // (splice07 socket-source cases). Every OTHER recv error is a
                    // genuine transport/nonblocking condition — EAGAIN (Go
                    // netpoller), ECONNRESET, EPIPE, … — which Linux propagates
                    // verbatim, so surface the real errno.
                    Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                };
                if n == 0 {
                    // EOF: the writer closed; splice reports 0 (Go stops the loop).
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                buf.truncate(n as usize);
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    // EAGAIN / WaitOnFds / Errno on the destination — propagate
                    // WITHOUT consuming any socket bytes (the peek left them).
                    return Ok(outcome);
                };
                let written = usize::try_from(value).unwrap_or(0);
                // Now drain EXACTLY `written` bytes from the socket — they are safely
                // in the destination. recv on a stream socket may return short, so
                // loop until `written` are consumed (a single recv could leave a
                // remainder that the next PEEK re-delivers → duplicated bytes).
                let mut consumed = 0usize;
                while consumed < written {
                    // Non-blocking drain (MSG_DONTWAIT below): the bytes are known
                    // to be present (we just peeked them), so this never blocks
                    // under the dispatcher lock.
                    let cn = unsafe {
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr().add(consumed) as *mut _,
                            written - consumed,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    match cn.host_syscall_errno() {
                        Ok(c) if c > 0 => consumed += c as usize,
                        // 0 (peer gone) or EAGAIN: the peeked bytes should be
                        // present, but never spin — stop draining to avoid a hang.
                        _ => break,
                    }
                }
                // `consumed == written` in every normal case (the peeked bytes are
                // present). Report the bytes moved into the destination; the drain
                // above keeps the socket position in lockstep so nothing is lost.
                return Ok(DispatchOutcome::Returned {
                    value: written as i64,
                });
            }

            match this.fd_is_pipe_writer(out_fd.0) {
                Ok(true) => {}
                // Neither side is a pipe → EINVAL (splice(2)); the pipe-source
                // shapes were all handled above.
                Ok(false) => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
            // fd_out IS a pipe here, so a non-NULL off_out is ESPIPE.
            if off_out_address != 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }

            // splice(2) into a pipe moves at most what the pipe can hold and
            // returns a SHORT count; the caller loops. `write_output_fd` below
            // implements write(2) semantics instead — deliver every byte, parking
            // on POLLOUT when the pipe fills — so handing it more than the
            // destination's room deadlocks whenever the only reader is the same
            // single-threaded guest. coreutils `cat` drains its bounce pipe only
            // AFTER this splice returns, so `cat` of any file larger than one
            // pipe-full parked forever. Bound the read window by the room the
            // write path itself accounts for (`host_pipe_write_room`).
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(room) if room > 0 => count.min(room),
                // Full pipe (or not a plain one-way host pipe): leave `count`
                // alone. A genuinely full pipe is exactly the case blocking
                // splice(2) is specified to wait out, and the write path's own
                // staging handles it.
                _ => count,
            };
            let mut offset = this.sendfile_offset(in_fd.0, off_in_address, memory)??;
            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = match this.write_output_fd_partial(out_fd.0, &bytes, tid) {
                // Nothing moved: the destination pipe is full. SPLICE_F_NONBLOCK
                // reports EAGAIN; a blocking splice(2) must wait for room. Waiting
                // is safe in exactly this case — a full pipe can only be drained by
                // a DIFFERENT thread, so the write(2)-semantics path cannot
                // self-deadlock the way it does on a partially-filled pipe.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN => {
                    if splice_flags.contains(LinuxSpliceFlags::NONBLOCK) {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    this.write_output_fd(out_fd.0, &bytes, tid)
                }
                other => other,
            };
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if off_in_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0) {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        // Same contract as `sendfile`: HostFile reads via `pread`
                        // (sendfile_bytes), which does NOT advance the kernel
                        // offset, and `sendfile_offset` reads that offset back
                        // with `lseek(SEEK_CUR)`. Advance it explicitly or the
                        // next iteration re-reads the same window. Without this,
                        // coreutils `cat` — which drains a file through a pipe
                        // with `splice(file, NULL, pipe, NULL, n)` in a loop —
                        // re-sends offset 0 forever and never reaches EOF.
                        OpenDescription::HostFile { host_fd, .. } => {
                            // SAFETY: host_fd is a live regular-file fd owned by
                            // this guest fd; lseek to an absolute position is benign.
                            unsafe {
                                libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET);
                            }
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn vmsplice(this, cx, fd: Fd, iov: GuestPtr, nr_segs: u64, flags: u64) {

            // vmsplice(2): fd must be a pipe; the pipe END selects the direction —
            // the WRITE end gathers user pages into the pipe, the READ end extracts
            // pipe bytes into user pages. SPLICE_F_GIFT/MOVE/MORE are advisory hints
            // for our copy-based path (no zero-copy page stealing); SPLICE_F_NONBLOCK
            // forces EAGAIN rather than blocking. A valid non-pipe fd is EINVAL; a
            // bad fd is EBADF.
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let tid = cx.tid();
            let nr =
                usize::try_from(nr_segs).map_err(|_| DispatchError::LengthTooLarge(nr_segs))?;
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov.0, nr)?;
            // SPLICE_F_NONBLOCK *or* an O_NONBLOCK pipe: vmsplice(2) blocks
            // only when both say it may.
            let nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(fd.0);

            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            enum VmDir {
                Write,
                /// Borrowed [`HostFd`] view + the owned handle keeping it live
                /// across the wait (mirrors the blocking-read plumbing).
                ReadHost(HostFd, Option<HostFdRef>),
                ReadMem,
            }
            let dir = {
                let open = open_file.description.read();
                match &*open {
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        if *is_read_end {
                            VmDir::ReadHost(host_fd.view(), Some(host_fd.clone()))
                        } else {
                            VmDir::Write
                        }
                    }
                    OpenDescription::PipeWriter { .. } => VmDir::Write,
                    OpenDescription::PipeReader { .. } => VmDir::ReadMem,
                    // vmsplice(2): a valid fd that does not refer to a pipe is
                    // EBADF ("fd either not valid, or doesn't refer to a
                    // pipe"), NOT EINVAL — LTP vmsplice02's file-fd case.
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            };

            match dir {
                VmDir::Write => {
                    // vmsplice(2) into a pipe moves AT MOST what the pipe can
                    // hold and reports a SHORT count; the caller loops. Bound
                    // the gather by the destination's room so the transfer is
                    // a single non-blocking write. Without the bound, LTP
                    // `vmsplice01` handed 128 KiB to a 64 KiB pipe, the
                    // full-delivery write path parked on POLLOUT for the
                    // remainder, and the only reader could not run until this
                    // call returned — a hang until the 30 s test timeout.
                    let room = this.splice_pipe_write_room(fd.0);
                    if room == Some(0) {
                        return Ok(this.splice_output_would_block(fd.0, nonblocking));
                    }
                    let bytes = match gather_bounded_iovec_bytes(memory, &iovecs) {
                        Ok(Some(bytes)) => bytes,
                        Ok(None) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    if bytes.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let bytes = &bytes[..room.map_or(bytes.len(), |room| bytes.len().min(room))];
                    Ok(this.splice_write_out(fd.0, 0, bytes, memory, tid, nonblocking))
                }
                VmDir::ReadHost(hfd, owner) => Ok(Self::read_host_pipe_iovecs(
                    memory,
                    &iovecs,
                    hfd.get(),
                    owner,
                    nonblocking,
                )),
                VmDir::ReadMem => {
                    let Some((pipe, status_flags)) = this.pipe_reader(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let want: usize = iovecs
                        .iter()
                        .map(|v| usize::try_from(v.iov_len).unwrap_or(0))
                        .sum();
                    if want == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let bytes = take_pipe_bytes(&pipe, want, status_flags)?;
                    let mut off = 0usize;
                    for v in &iovecs {
                        if off >= bytes.len() {
                            break;
                        }
                        let len =
                            usize::try_from(v.iov_len).unwrap_or(0).min(bytes.len() - off);
                        if len == 0 {
                            continue;
                        }
                        if memory
                            .write_bytes(v.iov_base, &bytes[off..off + len])
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        off += len;
                    }
                    Ok(DispatchOutcome::Returned { value: off as i64 })
                }
            }
        }

        fn inotify_init1(this, cx, flags: u64) {
            let known = crate::inotify::IN_NONBLOCK as u64 | crate::inotify::IN_CLOEXEC as u64;
            if flags & !known != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(state) = crate::inotify::InotifyState::new() else {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE));
            };
            let description = OpenDescription::Inotify {
                base: OpenDescriptionBase::new(flags & LINUX_O_NONBLOCK),
                state: Arc::new(state),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
        }

        fn inotify_add_watch(this, cx, fd: Fd, pathname: GuestPtr, mask: u64) {
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            let mask = mask as u32;
            // Try the per-instance backend first (kqueue host-vnode watch on
            // macOS/BSD, native inotify on Linux) so cross-process directory
            // changes — a forked guest child mutating a watched dir — still
            // wake the parent. Whatever wd results (a real backend watch, or a
            // virtual dispatch-only one when the backend declines) is recorded
            // in the dispatch registry so the fs handlers can synthesize the
            // precise same-process events the coarse kqueue NOTE_* set misses.
            let wd = if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                match m.vfs.watch_fds(&m.full_path) {
                    Ok(watch_fds) => match state.add_watch_fds(watch_fds, mask) {
                        Ok(wd) => wd,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    // Backend can't hand back a host vnode: fall back to a
                    // dispatch-only watch iff the path exists.
                    Err(errno) if errno == LINUX_ENOSYS => {
                        if !this.path_exists(&path) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ENOENT));
                        }
                        state.add_virtual_watch(mask)
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            } else {
                match this.fs.rootfs_vfs.watch_fds(&path) {
                    Ok(watch_fds) => match state.add_watch_fds(watch_fds, mask) {
                        Ok(wd) => wd,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    Err(errno) if errno == LINUX_ENOSYS => {
                        // The legacy host-file open path can still yield a real
                        // host vnode (writable backend with no snapshot path).
                        match this
                            .fs
                            .rootfs_vfs
                            .open_for_dispatch(&path, false, false, false, false)
                        {
                            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. }) => {
                                match state.add_watch(host_fd, mask) {
                                    Ok(wd) => wd,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                }
                            }
                            // No host vnode (in-memory overlay): dispatch-only.
                            Ok(_) => state.add_virtual_watch(mask),
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        }
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            this.fs.inotify_registry.register(&path, &state, wd, mask);
            // The dispatch registry now owns same-process event generation for
            // this instance; suppress the kqueue backend's duplicate synthesis
            // (it stays a poll_fd readiness source only).
            state.mark_dispatch_authoritative();
            Ok(DispatchOutcome::Returned { value: wd as i64 })
        }

        fn inotify_rm_watch(this, cx, fd: Fd, wd: u64) {
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let wd = wd as i32;
            // rm_watch removes the per-instance watch (virtual watches live in
            // the same `watches` table with no host fds, so it finds them too).
            // Drop the dispatch-registry entry to match.
            let result = state.rm_watch(wd);
            this.fs.inotify_registry.unregister(&state, wd);
            Ok(match result {
                Ok(()) => DispatchOutcome::Returned { value: 0 },
                Err(errno) => DispatchOutcome::errno(errno),
            })
        }

        fn fanotify_init(this, cx, flags: u64, event_f_flags: u64) {
            // fanotify_init(2) requires CAP_SYS_ADMIN. Carrick has no capability
            // model finer than the credential snapshot, so gate on effective
            // root — the same answer Linux gives an unprivileged caller, and
            // NOT a fabricated success that would let a non-root guest believe
            // it is monitoring a filesystem it cannot.
            if !this.cred_snapshot().euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LinuxFanotifyInitFlags::KNOWN_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let init_flags = LinuxFanotifyInitFlags::from_bits_retain(flags);
            // The class is a 2-bit FIELD, not a bit — `flags & FAN_CLASS_NOTIF`
            // is always false because FAN_CLASS_NOTIF is 0. Only the reserved
            // fourth encoding (both class bits set) is invalid.
            //
            // All THREE classes are accepted, including the permission classes
            // carrick cannot serve verdicts for. That is not a fudge — it is
            // what a kernel built without CONFIG_FANOTIFY_ACCESS_PERMISSIONS
            // does: `fanotify_init(FAN_CLASS_CONTENT, ...)` SUCCEEDS there, and
            // it is the later `fanotify_mark` carrying FAN_ACCESS_PERM /
            // FAN_OPEN_PERM that returns EINVAL. `fanotify_mark` below enforces
            // exactly that, so a permission-class group can still receive the
            // ordinary notification events it asks for and can never block
            // waiting for a verdict nothing will deliver.
            //
            // Failing the init instead is what LTP's
            // `require_fanotify_access_permissions_supported_on_fs` cannot
            // survive: it wraps the init in SAFE_FANOTIFY_INIT, so an EINVAL
            // there is a hard TBROK, where the real kernel's success followed
            // by a mark EINVAL is the intended TCONF (fanotify07).
            if init_flags.class().is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The FID/PIDFD reporting families need file handles
            // (`name_to_handle_at`) and pidfd info records, neither of which
            // carrick has. Refusing them here is what makes the corresponding
            // event bits refusable at `fanotify_mark` below.
            const UNSUPPORTED_INIT: LinuxFanotifyInitFlags = LinuxFanotifyInitFlags::from_bits_retain(
                carrick_abi::LINUX_FAN_REPORT_FID
                    | carrick_abi::LINUX_FAN_REPORT_DIR_FID
                    | carrick_abi::LINUX_FAN_REPORT_NAME
                    | carrick_abi::LINUX_FAN_REPORT_TARGET_FID
                    | carrick_abi::LINUX_FAN_REPORT_FD_ERROR
                    | carrick_abi::LINUX_FAN_REPORT_PIDFD
                    | carrick_abi::LINUX_FAN_ENABLE_AUDIT,
            );
            if init_flags.intersects(UNSUPPORTED_INIT) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `event_f_flags` are the open flags for the descriptors delivered
            // with each event; only the access mode is constrained.
            let access = event_f_flags & LINUX_O_ACCMODE;
            if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let group = Arc::new(crate::fanotify::FanotifyGroup::new(init_flags, event_f_flags));
            // Linux mirrors FAN_NONBLOCK into the description's O_NONBLOCK, so
            // fcntl(F_GETFL) reports it and a later F_SETFL can clear it.
            let status_flags = if init_flags.contains(LinuxFanotifyInitFlags::NONBLOCK) {
                LINUX_O_NONBLOCK
            } else {
                0
            };
            let description = OpenDescription::Fanotify {
                base: OpenDescriptionBase::new(status_flags),
                group,
            };
            // FAN_CLOEXEC is bit 0, NOT O_CLOEXEC — the generic
            // `linux_fd_flags_from_open_flags` would silently map the wrong bit
            // and fanotify08 asserts exactly this FD_CLOEXEC round-trip.
            let fd_flags = if init_flags.contains(LinuxFanotifyInitFlags::CLOEXEC) {
                carrick_abi::LinuxFdFlags::CLOEXEC.bits()
            } else {
                0
            };
            Ok(this.install_fd(description, fd_flags))
        }

        fn fanotify_mark(this, cx, fanotify_fd: Fd, flags: u64, mask: u64, dirfd: Fd, pathname: GuestPtr) {
            let Some(group) = this.fanotify_group(fanotify_fd.0) else {
                // A live fd that is not a fanotify group is EINVAL, not EBADF
                // (fanotify_mark(2): "fanotify_fd was not an fanotify file
                // descriptor"); only an absent fd is EBADF.
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(fanotify_fd.0) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            if flags & !LinuxFanotifyMarkFlags::KNOWN_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mark_flags = LinuxFanotifyMarkFlags::from_bits_retain(flags);
            // Exactly one of ADD / REMOVE / FLUSH, and at most one object type.
            let (Some(command), Some(mark_type)) = (mark_flags.command(), mark_flags.mark_type())
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // FAN_MARK_FLUSH ignores `mask` AND `pathname` entirely — it drops
            // every mark of one class from this group. Resolving the path here
            // would wrongly ENOENT a flush aimed at an already-deleted dir.
            if command == LinuxFanotifyMarkFlags::FLUSH {
                this.fs.fanotify_registry.flush(&group, mark_type);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // ADD and REMOVE both require a non-empty mask.
            if mask == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let events = LinuxFanotifyEvents::from_bits_retain(mask);
            // Everything outside NOTIF_MARKABLE needs a class or a reporting
            // mode carrick refused at `fanotify_init`: permission events need
            // FAN_CLASS_CONTENT; the dirent / inode-identity events
            // (FAN_CREATE, FAN_ATTRIB, FAN_MOVE, FAN_DELETE_SELF, ...) need
            // FAN_REPORT_FID. `fanotify_mark(2)` specifies EINVAL for both.
            if !LinuxFanotifyEvents::NOTIF_MARKABLE.contains(events) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // Resolve intermediates but not the final component; that IS the
            // FAN_MARK_DONT_FOLLOW behaviour. Without the flag the final
            // symlink is followed too, so a mark placed through a symlink lands
            // on the target — fanotify04 marks the same symlink both ways and
            // asserts opening the TARGET fires only in the following case.
            let resolved = this.resolve_at_path(dirfd.0 as u64, &path)?;
            let resolved = if mark_flags.contains(LinuxFanotifyMarkFlags::DONT_FOLLOW) {
                resolved
            } else {
                match this.canonicalize_following(&resolved) {
                    Ok(target) => target,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            let Some(is_dir) = this.inotify_path_kind(&resolved) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            };
            if mark_flags.contains(LinuxFanotifyMarkFlags::ONLYDIR) && !is_dir {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            // FAN_MARK_IGNORED_MASK / FAN_MARK_IGNORE update the mark's IGNORE
            // mask instead of its event mask; both live on one mark, so an
            // ignore mark added after a normal mark filters it.
            let ignored = mark_flags
                .intersects(LinuxFanotifyMarkFlags::IGNORED_MASK | LinuxFanotifyMarkFlags::IGNORE);
            if command == LinuxFanotifyMarkFlags::ADD {
                this.fs
                    .fanotify_registry
                    .add_mark(&resolved, mark_type, &group, events, ignored);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // REMOVE from an object this group never marked is ENOENT.
            if this
                .fs
                .fanotify_registry
                .remove_mark(&resolved, mark_type, &group, events, ignored)
            {
                Ok(DispatchOutcome::Returned { value: 0 })
            } else {
                Ok(DispatchOutcome::errno(LINUX_ENOENT))
            }
        }

        fn sync(this, cx) {

            unsafe {
                libc::sync();
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn syncfs(this, cx, fd: Fd) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let host_fd = this.host_file_fd_for_flush(fd.0)?;
            if let Some(host_fd) = host_fd
                && let Err(errno) = flush_host_fd(host_fd) {
                    return Ok(DispatchOutcome::errno(errno));
                }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sys_setxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            this.setxattr(cx.memory, XattrTarget::Path { path, follow: true }, name, value, size, flags)

        }

        fn sys_lsetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            this.setxattr(cx.memory, XattrTarget::Path { path, follow: false }, name, value, size, flags)

        }

        fn sys_setxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            // An O_PATH descriptor is not open for I/O — fd-based xattr ops on it
            // are EBADF (LTP open13 issues fgetxattr on an O_PATH fd).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.setxattr(cx.memory, XattrTarget::Fd(fd), name, value, size, flags)

        }

        fn sys_getxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {

            this.getxattr(cx.memory, XattrTarget::Path { path, follow: true }, name, value, size)

        }

        fn sys_lgetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {

            this.getxattr(cx.memory, XattrTarget::Path { path, follow: false }, name, value, size)

        }

        fn sys_getxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.getxattr(cx.memory, XattrTarget::Fd(fd), name, value, size)

        }

        fn sys_listxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {

            this.listxattr(cx.memory, XattrTarget::Path { path, follow: true }, list, size)

        }

        fn sys_llistxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {

            this.listxattr(cx.memory, XattrTarget::Path { path, follow: false }, list, size)

        }

        fn sys_listxattr_fd(this, cx, fd: Fd, list: GuestPtr, size: u64) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.listxattr(cx.memory, XattrTarget::Fd(fd), list, size)

        }

        fn sys_removexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {

            this.removexattr(cx.memory, XattrTarget::Path { path, follow: true }, name)

        }

        fn sys_lremovexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {

            this.removexattr(cx.memory, XattrTarget::Path { path, follow: false }, name)

        }

        fn sys_removexattr_fd(this, cx, fd: Fd, name: GuestPtr) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.removexattr(cx.memory, XattrTarget::Fd(fd), name)

        }

        fn sys_statfs(this, cx, path: GuestPtr, buf: GuestPtr) {

            this.statfs(path, buf, cx.memory)

        }

        fn sys_fstatfs(this, cx, fd: Fd, buf: GuestPtr) {

            Ok(this.fstatfs(fd, buf, cx.memory))

        }

        fn sys_truncate(this, cx, path: GuestPtr, length: u64) {

            this.truncate(cx.kernel, path, length, &*cx.memory)

        }

        fn fsync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            match this.host_file_fd_for_flush(fd.0) {
                Ok(Some(host_fd)) => {
                    if let Err(errno) = flush_host_fd(host_fd) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // Non-HostFile: a pipe/socket/char device has no ->fsync op
                // (EINVAL); a directory / synthetic / in-memory file is a no-op.
                Ok(None) if this.fd_lacks_fsync(fd.0) => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                Ok(None) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        /// `sync_file_range(fd, offset, nbytes, flags)` (advisory range flush).
        /// macOS has no equivalent, so it's a validating best-effort flush.
        /// Validation order matches Linux (LTP sync_file_range01): unknown
        /// flags / negative offset / negative nbytes (or offset+nbytes
        /// overflow) → EINVAL; bad fd → EBADF; a pipe/socket/anon fd (no page
        /// cache range) → ESPIPE; a regular file → best-effort fsync, return 0.
        fn sync_file_range(this, cx, fd: Fd, offset: u64, nbytes: u64, flags: u64) {
            let fd: Fd = fd;
            // SYNC_FILE_RANGE_WAIT_BEFORE(1) | WRITE(2) | WAIT_AFTER(4).
            const VALID_FLAGS: u64 = 0x1 | 0x2 | 0x4;
            if flags & !VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let offset_i = offset as i64;
            let nbytes_i = nbytes as i64;
            if offset_i < 0 || nbytes_i < 0 || offset_i.checked_add(nbytes_i).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // A pipe/socket/eventfd/timerfd/epoll/pidfd/inotify/signalfd/netlink
            // fd has no page-cache range to sync → ESPIPE.
            let is_special = matches!(
                &*open_file.description.read(),
                OpenDescription::HostPipe { .. }
                    | OpenDescription::HostSocket { .. }
                    | OpenDescription::PipeReader { .. }
                    | OpenDescription::PipeWriter { .. }
                    | OpenDescription::EventFd { .. }
                    | OpenDescription::TimerFd { .. }
                    | OpenDescription::Epoll { .. }
                    | OpenDescription::Pidfd { .. }
                    | OpenDescription::Inotify { .. }
                    | OpenDescription::Fanotify { .. }
                    | OpenDescription::SignalFd { .. }
                | OpenDescription::FsContext { .. }
                    | OpenDescription::Mqueue { .. }
                    | OpenDescription::BpfMap { .. }
                    | OpenDescription::BpfProg { .. }
                    | OpenDescription::Netlink { .. }
            );
            if is_special {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            // Regular / synthetic / in-memory file: best-effort flush a real
            // host fd; otherwise a no-op (the range-cache effect isn't observable).
            if let Ok(Some(host_fd)) = this.host_file_fd_for_flush(fd.0) {
                let _ = flush_host_fd(host_fd);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `cachestat(fd, cstat_range, cstat, flags)`: page-cache stats for a
        /// file range. macOS exposes no per-page cache map, so carrick reports
        /// every in-range, in-file page as cached (nr_cache) and nothing
        /// evicted/dirty/in-writeback — which for a populated file matches
        /// Linux's observable result and the LTP cachestat02 invariant
        /// `nr_cache + nr_evicted == num_pages`. flags!=0 → EINVAL; bad/
        /// non-cache-backed fd → EBADF; bad pointers → EFAULT. Was ENOSYS.
        fn cachestat(this, cx, fd: Fd, cstat_range: GuestPtr, cstat: GuestPtr, flags: u64) {
            let fd: Fd = fd;
            if flags != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let file_size: u64 = {
                let open = open_file.description.read();
                match &*open {
                    OpenDescription::HostFile { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        st.st_size.max(0) as u64
                    }
                    OpenDescription::File { contents, .. } => contents.len() as u64,
                    OpenDescription::SyntheticFile { contents, .. } => contents.len() as u64,
                    // cachestat needs a page-cache-backed fd (regular file /
                    // shmem); anything else has no cache → EBADF.
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            };
            let memory = &mut *cx.memory;
            let range = memory.read_bytes(cstat_range.0, 16)?;
            let off = u64::from_le_bytes(range[0..8].try_into().unwrap_or([0; 8]));
            let len = u64::from_le_bytes(range[8..16].try_into().unwrap_or([0; 8]));
            let page = crate::linux_abi::LINUX_PAGE_SIZE;
            let end = off.saturating_add(len).min(file_size);
            let nr_cache = if off >= end {
                0u64
            } else {
                end.div_ceil(page) - off / page
            };
            // struct cachestat: nr_cache, nr_dirty, nr_writeback, nr_evicted,
            // nr_recently_evicted (5 × u64). Only nr_cache is non-zero.
            let mut cs = [0u8; 40];
            cs[0..8].copy_from_slice(&nr_cache.to_le_bytes());
            memory.write_bytes(cstat.0, &cs)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fdatasync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            match this.host_file_fd_for_flush(fd.0) {
                Ok(Some(host_fd)) => {
                    if let Err(errno) = flush_host_fd(host_fd) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // fdatasync02: /dev/null (a char device) → EINVAL; regular files
                // flush, directories / synthetic files no-op.
                Ok(None) if this.fd_lacks_fsync(fd.0) => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                Ok(None) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn write(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd = fd.0;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if this.io_uring_description(fd).is_some() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            // A zero-length write never accesses the buffer (write(fd, NULL, 0)
            // returns 0, not EFAULT) — only read guest memory when count > 0.
            let bytes = if length == 0 {
                Vec::new()
            } else {
                match (*cx.memory).read_bytes(address, length) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };

            let nonblocking = this.io_is_nonblocking(fd, 0);

            // inotify IN_MODIFY: a non-empty write(2) to a watched regular file
            // emits IN_MODIFY on it. A zero-length write touches nothing and
            // generates no event, matching Linux. Fast-exits when unwatched.
            if length > 0 {
                this.inotify_emit_for_fd(fd, carrick_abi::LINUX_IN_MODIFY);
                this.fanotify_emit_for_fd(
                    cx.kernel,
                    fd,
                    carrick_abi::LinuxFanotifyEvents::MODIFY,
                );
            }

            #[cfg(feature = "trace-io")]
            if !bytes.is_empty() {
                let has = this.open_file(fd).is_some();
                eprintln!(
                    "[WRDBG] guest_fd={fd} in_table={has} n={} bytes={:02x?}",
                    bytes.len(),
                    &bytes[..bytes.len().min(48)]
                );
            }

            // Check open_files FIRST: dup3 may have redirected fd 1/2 to
            // a pipe, an eventfd, or some other resource. Only after we've
            // confirmed there's no open description do we fall back to the
            // dispatcher's built-in stdout/stderr buffers.
            if let Some(open_file) = this.open_file(fd) {
                // Take an inner scope so the borrow on the description ends
                // before we touch this.fs.rootfs_vfs.overlay (writable File path below).
                enum FileWriteback {
                    Range {
                        path: String,
                        offset: usize,
                        bytes: Vec<u8>,
                        final_size: usize,
                    },
                }
                let outcome: DispatchOutcome;
                let writeback: Option<FileWriteback>;
                {
                    let mut open = open_file.description.write();
                    match &mut *open {
                        OpenDescription::EventFd { state, .. } => {
                            return Ok(write_eventfd(this, &bytes, state));
                        }
                        OpenDescription::PipeWriter { pipe, .. } => {
                            return Ok(write_pipe(&bytes, pipe));
                        }
                        OpenDescription::HostPipe {
                            base,
                            host_fd,
                            is_read_end,
                            pipe_id,
                            pty,
                            bidirectional,
                            write_kind,
                            ..
                        } => {
                            // pty ends and O_RDWR FIFOs are bidirectional; only
                            // real one-way pipe ends are gated by is_read_end.
                            #[cfg(feature = "trace-tty")]
                            if bytes.contains(&0x0a) {
                                let hf = host_fd.raw();
                                let tt = unsafe { libc::isatty(hf) };
                                eprintln!(
                                    "[PTYWRDBG] guest_fd={fd} desc_host_fd={hf} isatty={tt} pty={:?} is_read_end={is_read_end} bidir={bidirectional}",
                                    pty.as_ref().map(|r| r.is_master)
                                );
                            }
                            if *is_read_end && pty.is_none() && !*bidirectional {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            // A broken pipe (read end closed) → EPIPE AND a
                            // SIGPIPE on the writer (write05).
                            let out = write_host_pipe_owned(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: *write_kind,
                                    pipe_state: this.host_pipe_capacity_state(
                                        base,
                                        *pipe_id,
                                        *is_read_end,
                                        *bidirectional,
                                        host_fd.raw(),
                                    ),
                                    tid: cx.tid(),
                                    sigpipe_on_epipe: true,
                                },
                            );
                            // Signal-driven I/O: a write that added bytes makes the
                            // pipe's read end readable — the FASYNC readiness edge.
                            // Deliver the read end's owner signal (default SIGIO)
                            // via the fork-coherent registry (LTP fcntl31).
                            let written = match &out {
                                DispatchOutcome::Returned { value } => *value,
                                _ => 0,
                            };
                            let key_fd = fd;
                            drop(open);
                            this.fasync_notify_after_write(cx.kernel, key_fd, written);
                            return Ok(this.raise_sigpipe_on_epipe(cx, out));
                        }
                        OpenDescription::HostSocket { host_fd, .. } => {
                            // write(2) on a connected socket maps directly to a
                            // host write(2). Unconnected sockets will surface
                            // their own ENOTCONN via the host.
                            let out = write_host_pipe_owned(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: HostWriteKind::SocketLike,
                                    pipe_state: None,
                                    tid: cx.tid(),
                                    sigpipe_on_epipe: false,
                                },
                            );
                            // Signal-driven I/O readiness edge on the socket peer.
                            let written = match &out {
                                DispatchOutcome::Returned { value } => *value,
                                _ => 0,
                            };
                            let key_fd = fd;
                            drop(open);
                            this.fasync_notify_after_write(cx.kernel, key_fd, written);
                            return Ok(out);
                        }
                        OpenDescription::HostFile {
                            base,
                            host_fd,
                            writable,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            // O_APPEND: seek to EOF before writing so `>>` and
                            // log appends don't overwrite from offset 0. (The
                            // host fd isn't opened O_APPEND, so we emulate the
                            // seek-then-write; single-writer, which covers the
                            // shell/dpkg append cases.)
                            if base.is_append() {
                                unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_END) };
                            }
                            // RLIMIT_FSIZE: a write starting past the guest's
                            // soft file-size cap is EFBIG + SIGXFSZ (llseek01).
                            // The offset lives in the host kernel; read it back
                            // (post-append reposition) only when a cap is set.
                            if this.fsize_soft_limit().is_some() {
                                let pos = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
                                if pos >= 0
                                    && let Some(errno) =
                                        this.fsize_write_guard(cx, pos as u64, bytes.len())
                                {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                            }
                            // libc::write to the real fd: advances the
                            // kernel offset and is visible across fork.
                            return Ok(write_host_pipe_owned(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: HostWriteKind::RegularFile,
                                    pipe_state: None,
                                    tid: cx.tid(),
                                    sigpipe_on_epipe: false,
                                },
                            ));
                        }
                        OpenDescription::File {
                            base,
                            path,
                            contents,
                            offset,
                            writable,
                            metadata,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            // memfd write seals: F_SEAL_WRITE → EPERM; F_SEAL_GROW
                            // → EPERM when the write would extend the file.
                            if let Err(errno) = memfd_seal_write_check(
                                base.seals(),
                                *offset,
                                bytes.len(),
                                contents.len(),
                            ) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            // RLIMIT_FSIZE: a write starting past the guest's
                            // soft file-size cap is EFBIG + SIGXFSZ (llseek01).
                            if let Some(errno) =
                                this.fsize_write_guard(cx, *offset as u64, bytes.len())
                            {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            let write_offset = *offset;
                            if let Err(errno) = write_into_file_contents(contents, offset, &bytes) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            let written = bytes.len();
                            metadata.size = contents.len();
                            outcome = DispatchOutcome::Returned {
                                value: written as i64,
                            };
                            writeback = Some(FileWriteback::Range {
                                path: path.clone(),
                                offset: write_offset,
                                bytes,
                                final_size: contents.len(),
                            });
                        }
                        OpenDescription::SyntheticFile { path, .. }
                            if crate::vfs::proc::is_userns_map_path(path) =>
                        {
                            // Writing /proc/self/{uid_map,gid_map,setgroups}:
                            // the user-namespace map writers enforce the
                            // write-once / setgroups-gate / ≤5-line rules
                            // (docs/namespaces-design.md §4.3).
                            // The map named by /proc/self/uid_map is the
                            // CALLER's own, and the privilege verdict is read
                            // from the caller's own capability set — both off
                            // its task, so one guest process cannot rewrite
                            // another's maps.
                            let task = cx.kernel.task();
                            let privileged = task.caps().is_map_write_privileged();
                            let result = task.with_user_ns(|ns| {
                                crate::vfs::proc::write_userns_map(ns, privileged, path, &bytes)
                            });
                            return Ok(match result {
                                Ok(n) => DispatchOutcome::Returned { value: n as i64 },
                                Err(errno) => DispatchOutcome::errno(errno),
                            });
                        }
                        OpenDescription::SyntheticFile { path, .. }
                            if crate::vfs::proc::is_writable_tunable_path(path) =>
                        {
                            // oom_score_adj PERSISTS the value (per-process,
                            // fork-inherited): tst_test's OOM protection
                            // (tst_memutils.c) writes -1000 to /proc/<pid>/oom_score_adj
                            // then reads it back, and every test that enables it TBROKs
                            // in setup otherwise. The rest (oom_adj/loginuid/
                            // timerslack_ns) carrick has no live state for, so
                            // accept-and-ignore.
                            //
                            // The VFS parses and validates; applying it is the
                            // dispatcher's job because only here is it known
                            // which backend owns per-process state. The write
                            // may name ANOTHER process, so it cannot be routed
                            // to "the current one" — LTP writes the library
                            // process's file from the test child.
                            let written = bytes.len() as i64;
                            let parsed =
                                crate::vfs::proc::parse_tunable_write(path, &bytes);
                            return Ok(match parsed {
                                Err(errno) => DispatchOutcome::errno(errno),
                                Ok(crate::vfs::proc::TunableWrite::Ignored) => {
                                    DispatchOutcome::Returned { value: written }
                                }
                                Ok(crate::vfs::proc::TunableWrite::OomScoreAdj {
                                    pid,
                                    value,
                                }) => {
                                    let target = pid.unwrap_or_else(|| {
                                        cx.kernel.task().key().id.raw() as u32
                                    });
                                    match this.hvpatch_process() {
                                        Some(process) => {
                                            if process
                                                .kernel_graph()
                                                .registry()
                                                .set_oom_score_adj(target, value)
                                            {
                                                DispatchOutcome::Returned { value: written }
                                            } else {
                                                // The process exited between
                                                // open(2) and write(2).
                                                DispatchOutcome::errno(LINUX_ESRCH)
                                            }
                                        }
                                        None => {
                                            crate::vfs::proc::set_single_process_oom_score_adj(
                                                value,
                                            );
                                            DispatchOutcome::Returned { value: written }
                                        }
                                    }
                                }
                            });
                        }
                        _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    }
                }
                if let Some(FileWriteback::Range {
                    path,
                    offset,
                    bytes,
                    final_size,
                }) = writeback
                {
                    let _ = this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .write_file_range(&path, offset, &bytes, final_size);
                }
                return Ok(outcome);
            }
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: write is EBADF, not a host-stream/buffer write.
            if this.stdio_is_closed(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if *this.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
                // Stream bare stdio to the inherited stdout/stderr (the user's
                // tty/pipe) exactly like writev does — do NOT buffer it. Buffering
                // delays interactive output until process exit: busybox ash writes
                // its post-Enter newline to fd 2 via write(2), so buffering left the
                // newline stuck and the next command's output ran onto the prompt.
                return Ok(Self::write_all_stdio(fd, &bytes));
            }
            match fd {
                1 => this.io.stdout.lock().extend_from_slice(&bytes),
                2 => this.io.stderr.lock().extend_from_slice(&bytes),
                _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
            }

            Ok(DispatchOutcome::Returned {
                value: length as i64,
            })

        }

        fn writev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd = fd.0;
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let memory = &*cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: writev is EBADF, not a host-stream/buffer write.
            if this.stdio_is_closed(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let nonblocking = this.io_is_nonblocking(fd, 0);

            struct HostWritevTarget {
                host_fd: i32,
                host_fd_owner: Option<HostFdRef>,
                write_kind: HostWriteKind,
                pipe_state: Option<(i64, usize)>,
                sigpipe_on_epipe: bool,
                append: bool,
            }

            let host_target = if let Some(open_file) = this.open_file(fd) {
                let open = open_file.description.read();
                match &*open {
                    OpenDescription::HostPipe {
                        base,
                        host_fd,
                        is_read_end,
                        pipe_id,
                        pty,
                        bidirectional,
                        write_kind,
                        ..
                    } => {
                        // pty ends and O_RDWR FIFOs are bidirectional; only
                        // real one-way pipe ends gate on is_read_end.
                        if *is_read_end && pty.is_none() && !*bidirectional {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        Some(HostWritevTarget {
                            host_fd: host_fd.raw(),
                            host_fd_owner: Some(host_fd.clone()),
                            write_kind: *write_kind,
                            pipe_state: this.host_pipe_capacity_state(
                                base,
                                *pipe_id,
                                *is_read_end,
                                *bidirectional,
                                host_fd.raw(),
                            ),
                            sigpipe_on_epipe: true,
                            append: false,
                        })
                    }
                    OpenDescription::HostSocket { host_fd, .. } => Some(HostWritevTarget {
                        host_fd: host_fd.raw(),
                        host_fd_owner: Some(host_fd.clone()),
                        write_kind: HostWriteKind::SocketLike,
                        pipe_state: None,
                        sigpipe_on_epipe: false,
                        append: false,
                    }),
                    OpenDescription::HostFile {
                        base,
                        host_fd,
                        writable,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        Some(HostWritevTarget {
                            host_fd: host_fd.raw(),
                            host_fd_owner: Some(host_fd.clone()),
                            write_kind: HostWriteKind::RegularFile,
                            pipe_state: None,
                            sigpipe_on_epipe: false,
                            append: base.is_append(),
                        })
                    }
                    _ => None,
                }
            } else {
                None
            };

            if let Some(target) = host_target
                && let Some(bytes) = gather_bounded_iovec_bytes(memory, &iovecs)?
            {
                if bytes.is_empty() {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if target.append {
                    unsafe { libc::lseek(target.host_fd, 0, libc::SEEK_END) };
                }
                let outcome = write_host_pipe_owned(
                    bytes,
                    HostPipeWriteTarget {
                        host_fd: target.host_fd,
                        host_fd_owner: target.host_fd_owner.clone(),
                        nonblocking,
                        write_kind: target.write_kind,
                        pipe_state: target.pipe_state,
                        tid: cx.tid(),
                        sigpipe_on_epipe: target.sigpipe_on_epipe,
                    },
                );
                return if target.sigpipe_on_epipe {
                    Ok(this.raise_sigpipe_on_epipe(cx, outcome))
                } else {
                    Ok(outcome)
                };
            }

            let mut total = 0usize;
            for iovec in iovecs {
                let iov_base = iovec.iov_base;
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                // A zero-length iovec is a no-op regardless of its base — Linux
                // never dereferences it, so a {NULL, 0} entry must be skipped,
                // not EFAULTed (LTP writev01 "NULL and zero length iovec").
                if iov_len == 0 {
                    continue;
                }
                let bytes = match memory.read_bytes(iov_base, iov_len) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                // Mirror `write`: check open_files FIRST so post-dup3
                // redirects (eg `dup3(pipe_write, 1)`) actually plumb
                // through the redirected description rather than the
                // built-in stdout buffer.
                if let Some(open_file) = this.open_file(fd) {
                    enum FileWriteback {
                        Range {
                            path: String,
                            offset: usize,
                            bytes: Vec<u8>,
                            final_size: usize,
                        },
                    }
                    let outcome: DispatchOutcome;
                    let writeback: Option<FileWriteback>;
                    {
                        let mut open = open_file.description.write();
                        match &mut *open {
                            OpenDescription::PipeWriter { pipe, .. } => {
                                outcome = write_pipe(&bytes, pipe);
                                writeback = None;
                            }
                            OpenDescription::HostPipe {
                                base,
                                host_fd,
                                is_read_end,
                                pipe_id,
                                pty,
                                bidirectional,
                                write_kind,
                                ..
                            } => {
                                // pty ends and O_RDWR FIFOs are bidirectional;
                                // only real one-way pipe ends gate on is_read_end.
                                if *is_read_end && pty.is_none() && !*bidirectional {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                outcome = write_host_pipe_owned(
                                    bytes,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: *write_kind,
                                        pipe_state: this.host_pipe_capacity_state(
                                            base,
                                            *pipe_id,
                                            *is_read_end,
                                            *bidirectional,
                                            host_fd.raw(),
                                        ),
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: true,
                                    },
                                );
                                writeback = None;
                            }
                            OpenDescription::HostSocket { host_fd, .. } => {
                                outcome = write_host_pipe_owned(
                                    bytes,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: HostWriteKind::SocketLike,
                                        pipe_state: None,
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: false,
                                    },
                                );
                                writeback = None;
                            }
                            OpenDescription::HostFile {
                                base,
                                host_fd,
                                writable,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                // Mirror `write`(64): O_APPEND seeks to EOF, then
                                // libc::write to the real fd advances the shared
                                // kernel offset (visible across fork and to the
                                // readv that follows).
                                if base.is_append() {
                                    unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_END) };
                                }
                                outcome = write_host_pipe_owned(
                                    bytes,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: HostWriteKind::RegularFile,
                                        pipe_state: None,
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: false,
                                    },
                                );
                                writeback = None;
                            }
                            OpenDescription::File {
                                base,
                                path,
                                contents,
                                offset,
                                writable,
                                metadata,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                if let Err(errno) = memfd_seal_write_check(
                                    base.seals(),
                                    *offset,
                                    bytes.len(),
                                    contents.len(),
                                ) {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                                let write_offset = *offset;
                                if let Err(errno) = write_into_file_contents(contents, offset, &bytes) {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                                let written = bytes.len();
                                metadata.size = contents.len();
                                outcome = DispatchOutcome::Returned {
                                    value: written as i64,
                                };
                                writeback = Some(FileWriteback::Range {
                                    path: path.clone(),
                                    offset: write_offset,
                                    bytes,
                                    final_size: contents.len(),
                                });
                            }
                            _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                        }
                    }
                    if let Some(FileWriteback::Range {
                        path,
                        offset,
                        bytes,
                        final_size,
                    }) = writeback
                    {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .write_file_range(&path, offset, &bytes, final_size);
                    }
                    let DispatchOutcome::Returned { value } = outcome else {
                        // EAGAIN/EPIPE on this iovec. writev(2) is atomic across
                        // iovecs: if EARLIER iovecs were already written (total >
                        // 0), return that short count — NOT the error, which
                        // would discard bytes already sent and make the caller
                        // re-send from offset 0 (libuv's stream flow control then
                        // never completes a write: ipc_heavy_traffic_deadlock_bug,
                        // bw stuck at 0). Only surface the error when nothing has
                        // been written yet.
                        //
                        // For EPIPE specifically with nothing written: a broken
                        // pipe/socket (read end closed) → EPIPE AND a SIGPIPE on
                        // the writer, same as write(2) (busybox `yes | head`
                        // wants exit 141, write05).
                        if total > 0 {
                            return Ok(DispatchOutcome::Returned {
                                value: total as i64,
                            });
                        }
                        return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                    };
                    total = total
                        .checked_add(value as usize)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    // A SHORT write on this iovec (host send buffer full) ends the
                    // writev: the rest of this iovec and all later iovecs are
                    // unsent. Returning the partial `total` is correct writev(2)
                    // semantics; continuing would write a later iovec AFTER an
                    // unfilled earlier one — a gap/reorder in the byte stream.
                    if (value as usize) < iov_len {
                        return Ok(DispatchOutcome::Returned {
                            value: total as i64,
                        });
                    }
                    continue;
                }
                if *this.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
                    // BLOCKING-IO-OK: streamed writev to the inherited stdout/
                    // stderr (the user's tty/pipe); blocking is correct backpressure.
                    // Full write loop — never drop the tail on an O_NONBLOCK slave.
                    match Self::write_all_stdio(fd, &bytes) {
                        DispatchOutcome::Returned { value } => {
                            total = total
                                .checked_add(value as usize)
                                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                            continue;
                        }
                        other => return Ok(other),
                    }
                }
                match fd {
                    1 => this.io.stdout.lock().extend_from_slice(&bytes),
                    2 => this.io.stderr.lock().extend_from_slice(&bytes),
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
                total = total
                    .checked_add(bytes.len())
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            }

            Ok(DispatchOutcome::Returned {
                value: total as i64,
            })

        }

        fn readlinkat(this, cx, dirfd: u64, pathname: GuestPtr, buf: GuestPtr, bufsiz: u64) {

            let pathname = pathname.0;
            let buffer = buf.0;
            let buffer_size =
                usize::try_from(bufsiz).map_err(|_| DispatchError::LengthTooLarge(bufsiz))?;
            if buffer_size == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let path = read_guest_c_string(&*cx.memory, pathname)?;
            // An empty pathname with an O_PATH|O_NOFOLLOW dirfd naming a SYMLINK
            // reads that link — readlinkat implicitly treats "" as AT_EMPTY_PATH
            // for such an fd (readlinkat(2) since 2.6.39; readlinkat01 case 6).
            // Rewrite to the fd's recorded symlink path so the readlink below runs.
            let path = if path.is_empty() {
                let dfd = (dirfd as i32) as i64 as u64 as i32;
                match this.lookup_recorded_fd_open_path(dfd).filter(|p| {
                    this.fd_is_o_path(dfd)
                        && matches!(this.layered_lstat(p), Ok(md) if md.kind == RootFsEntryKind::Symlink)
                }) {
                    Some(p) => p,
                    // A plain empty readlink (AT_FDCWD / non-symlink fd) is ENOENT
                    // on modern Linux (readlink03), not the EINVAL a lookup raises.
                    None => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                }
            } else {
                this.resolve_at_path(dirfd, &path)?
            };

            let target = if let Some(kind) = proc_self_magic_link(&path) {
                match kind {
                    // /proc/self/exe is the REAL running binary. If the entrypoint
                    // was a symlink (e.g. /usr/bin/readlink -> /bin/busybox), resolve
                    // the chain like Docker/Linux do; a non-symlink path is returned
                    // unchanged, and a resolution failure falls back to the raw path.
                    "exe" => {
                        let exe = this.proc.lock().executable_path.clone();
                        this.canonicalize_following(&exe).unwrap_or(exe)
                    }
                    // /proc/self/cwd → the guest working dir; /proc/self/root → the
                    // guest root. Both come from the captured Kernel FsContext.
                    "cwd" => this.cwd(),
                    _ => "/".to_string(),
                }
            } else if let Some(t) = this.proc_self_fd_tty_link(&path) {
                // /proc/this/fd/{0,1,2} → /dev/pts/N when the guest's stdio is the
                // `carrick run -t` controlling pty. This is what glibc `ttyname(3)`
                // reads, so `tty(1)` and tty-name lookups resolve.
                t
            } else if let Some(t) = proc_self_fd_number(&path).and_then(|n| {
                this.lookup_recorded_fd_open_path(n).or_else(|| {
                    this.open_file(n)
                        .and_then(|f| f.description.read().open_path().map(str::to_owned))
                })
            }) {
                // /proc/self/fd/N → the path fd N was opened at. Rosetta readlinks
                // its main-binary fd this way to recover the binary's path.
                t
            } else if let Some(t) = proc_self_fd_number(&path).and_then(|n| {
                this.open_file(n)
                    .and_then(|f| f.description.read().readlink_target())
            }) {
                // /proc/self/fd/N for an fd with NO backing path (pipe/socket/
                // eventfd/…) → the synthetic pipe:[ino]/socket:[ino]/anon_inode:[…]
                // target Linux shows, so fd-introspection and 'are we piped?'
                // checks see a real target instead of an empty string.
                t
            } else if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                match m.vfs.readlink(&m.full_path) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            } else if let Some(t) = this.fs.rootfs_vfs.overlay.read_link(&path) {
                // Symlink created in the writable backend (cap-std on --fs host).
                t
            } else {
                use crate::vfs::Vfs as _;
                match this.fs.rootfs_vfs.readlink(&path) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };

            // `target` is in the VFS layer's reversible escape form; decode it
            // back to the opaque link-target BYTES so readlink hands the guest
            // exactly what was stored (an undecodable target round-trips).
            let decoded = crate::pathcodec::decode_to_bytes(&target);
            let written = decoded.len().min(buffer_size);
            cx.memory.write_bytes(buffer, &decoded[..written])?;
            Ok(DispatchOutcome::Returned {
                value: written as i64,
            })

        }

        fn mknodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, dev: u64) {

            let pathname = pathname.0;
            let mode = mode as u32;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved = this.resolve_at_path(dirfd, &path)?;
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context(cx.kernel)) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // Existence check must consult the layered view (overlay/disk
            // first, then rootfs) — a rootfs-direct lookup would miss a file
            // the guest already created in the overlay and wrongly report
            // EROFS instead of EEXIST. Mirrors the linkat EEXIST check.
            if this.layered_metadata(&resolved).is_ok() {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // mknod(2) does NOT create intermediate directories: a missing
            // parent is ENOENT (LTP mknod06). An intermediate path component
            // that is a non-directory already surfaced as ENOTDIR from
            // resolve_at_path above. Mirrors the open(O_CREAT) parent check.
            //
            // Follow a contained symlink-to-dir parent leaf exactly like Linux:
            // `mkfifo /link/f` where `/link -> /realdir` must land the node at
            // /realdir/f. We resolve the PARENT through canonicalize_following
            // (LINUX_ELOOP-bounded; the one-level leaf-of-parent case is what
            // the probe and LTP require) and rebuild the materialisation path
            // from the resolved parent + the final component. This (a) makes
            // the path_is_directory check see the followed directory instead of
            // misclassifying the symlink as a File → spurious ENOENT, and (b)
            // hands the backend a symlink-FREE path so its cap-std confinement
            // never has to follow an absolute in-rootfs symlink (which cap-std
            // refuses as a sandbox escape).
            let mut materialize_path = resolved.clone();
            if let Some(parent) = Path::new(&resolved).parent() {
                let parent_str = display_rootfs_path(parent);
                if !parent_str.is_empty() && parent_str != "/" {
                    let resolved_parent = this
                        .canonicalize_following(&parent_str)
                        .unwrap_or_else(|_| parent_str.clone());
                    if !this.path_is_directory(&resolved_parent) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    }
                    if resolved_parent != parent_str
                        && let Some(name) = Path::new(&resolved).file_name()
                    {
                        materialize_path =
                            display_rootfs_path(&Path::new(&resolved_parent).join(name));
                    }
                }
            }
            // Linux mknod(2) type dispatch. A zero type field means S_IFREG.
            // An ambiguous/invalid type (e.g. S_IFMT, multiple type bits) is
            // EINVAL (LTP mknod09); a valid device/socket type carrick can't
            // back on the cap-std scratch is EPERM (the unprivileged-mknod
            // errno); FIFO and regular files are materialised below.
            let type_bits = mode & LINUX_S_IFMT;
            match type_bits {
                // FIFO: create a real named pipe on the host backend
                // (mkfifoat). Opened later as a non-blocking HostPipe so a
                // writer-less open can't wedge the dispatcher. The
                // MemoryBackend can't back a real pipe → Unsupported → EPERM.
                t if t == LINUX_S_IFIFO => {
                    // mknod(2) applies the umask to the permission bits (the
                    // suid/sgid/sticky bits are NOT masked).
                    let umask = this.cred_snapshot().umask & 0o777;
                    let fifo_mode = (mode & 0o7777) & !umask;
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .create_fifo(&materialize_path, fifo_mode)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, fifo_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // Character/block device nodes: macOS/cap-std can't mknod a real
                // device as a non-root process, so materialise a MARKER regular
                // file tagged with the device xattrs (full mode + raw dev_t,
                // fork-coherent on the scratch). The stat reconstruction reads
                // them back and reports S_IFCHR/S_IFBLK with the right st_rdev.
                // mknod(2) applies the umask to the permission bits only; the
                // type bits are preserved. The MemoryBackend has no host inode to
                // tag → Unsupported → EPERM (unprivileged-mknod errno).
                t if t == LINUX_S_IFCHR || t == LINUX_S_IFBLK => {
                    let umask = this.cred_snapshot().umask & 0o777;
                    let full_mode = t | ((mode & 0o7777) & !umask);
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .create_device(&materialize_path, full_mode, dev)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, full_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // AF_UNIX socket node via mknod is bind(2) territory (out of
                // scope here); report EPERM as before.
                // mknod(S_IFSOCK) creates a socket INODE (a filesystem node,
                // distinct from a bound AF_UNIX socket). Reuse the socket-node
                // marker the bind path uses — stat then reports it as S_IFSOCK
                // via RootFsEntryKind::Socket, so no device-override is needed.
                // (A later bind(2) to this path is EADDRINUSE, matching Linux.)
                t if t == LINUX_S_IFSOCK => {
                    let umask = this.cred_snapshot().umask & 0o777;
                    let sock_mode = (mode & 0o7777) & !umask;
                    return Ok(
                        match this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .create_socket(&materialize_path, sock_mode)
                        {
                            Ok(()) => {
                                this.stamp_new_node_owner(&materialize_path, sock_mode);
                                this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(crate::fs_backend::BackendError::Unsupported) => {
                                DispatchOutcome::errno(LINUX_EPERM)
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                        },
                    );
                }
                // Regular file (0 or S_IFREG): materialised below.
                0 => {}
                t if t == LINUX_S_IFREG => {}
                // Anything else (S_IFMT, S_IFDIR, multiple type bits) is an
                // invalid mknod type → EINVAL.
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
            // Create an empty regular file in the writable backend (cap-std).
            // MemoryBackend's create_file works in-memory too. After this the
            // path exists in the layered view.
            match this.fs.rootfs_vfs.overlay.create_file(&materialize_path) {
                Ok(()) => {
                    if mode & 0o7777 != 0 {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_mode(&materialize_path, mode & 0o7777);
                    }
                    this.stamp_new_node_owner(&materialize_path, mode & 0o7777);
                    this.dnotify_child(cx.kernel, &materialize_path, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
                Err(_) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
            }

        }

        fn mkdirat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {

            let pathname = pathname.0;
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved = this.resolve_at_path(dirfd, &path)?;
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context(cx.kernel)) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                let creds = this.cred_snapshot();
                let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                return match m.vfs.mkdir(&m.full_path, create_mode) {
                    Ok(()) => {
                        let _ = m.vfs.chown(
                            &m.full_path,
                            Some(creds.euid),
                            Some(creds.egid),
                            false,
                        );
                        // inotify IN_CREATE|IN_ISDIR on the parent dir watch.
                        this.inotify_child(&resolved, carrick_abi::LINUX_IN_CREATE, true);
                        this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::CREATE);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // DAC: creating a new entry needs write+search on the parent dir
            // (mkdir04). Only when the target doesn't already exist — an
            // existing target is EEXIST (returned by mkdir below), which the
            // kernel reports before the permission error.
            if this.layered_metadata(&resolved).is_err()
                && let Some(parent) = Path::new(&resolved).parent()
                && !this.guest_can_modify_dir(&display_rootfs_path(parent))
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }
            // Layered existence + parent-exists checks live inside
            // RootFsVfs::mkdir; the dispatcher only handles synthetic
            // path shadowing.
            use crate::vfs::Vfs as _;
            match this.fs.rootfs_vfs.mkdir(&resolved, 0) {
                Ok(()) => {
                    // Apply the requested mode (umask-masked, like the kernel) and
                    // stamp the creating process's owner — mkdir previously dropped
                    // both, so DAC checks against the new dir were wrong.
                    let creds = this.cred_snapshot();
                    let mut create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                    let mut owner_gid = creds.egid;
                    // setgid-directory inheritance (LTP mkdir02/04): a new dir in
                    // a parent with S_ISGID inherits the parent's GID *and* gets
                    // S_ISGID itself (so a shared-group subtree propagates).
                    // Otherwise the new dir's group is the creator's egid.
                    let mut inherited_gid = false;
                    const S_ISGID: u32 = 0o2000;
                    if let Some(parent) = Path::new(&resolved).parent() {
                        let parent_str = display_rootfs_path(parent);
                        if let Ok(pmd) = this.layered_metadata(&parent_str)
                            && pmd.mode & S_ISGID != 0
                        {
                            create_mode |= S_ISGID;
                            if let Some((_, pgid)) =
                                this.fs.rootfs_vfs.overlay.get_owner(&parent_str)
                            {
                                owner_gid = pgid;
                                inherited_gid = true;
                            }
                        }
                    }
                    let _ = this.fs.rootfs_vfs.overlay.set_mode(&resolved, create_mode);
                    // Stamp the owner when it's non-root OR the gid was inherited
                    // from a setgid parent (so a root-created dir still records the
                    // inherited group).
                    if !creds.euid.is_root() || !owner_gid.is_root() || inherited_gid {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .overlay
                            .set_owner(&resolved, Some(creds.euid), Some(owner_gid));
                    }
                    // inotify IN_CREATE|IN_ISDIR on the parent dir watch.
                    this.inotify_child(&resolved, carrick_abi::LINUX_IN_CREATE, true);
                    this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn fchmod(this, cx, fd: Fd, mode: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let mode = (mode & 0o7777) as u32;
            // Resolve the fd to its path and route through the backend's set_mode,
            // so the guest-visible mode lands in the carrick mode xattr (what
            // fstat reports) — not just the real fd's mode, which could be the
            // forced-owner-accessible value. Previously this called libc::fchmod
            // directly, so fstat kept reporting the stale creation-time mode.
            let path = this
                .open_file(fd.0)
                .and_then(|of| match &*of.description.read() {
                    OpenDescription::HostFile { metadata, .. }
                    | OpenDescription::File { metadata, .. }
                    | OpenDescription::Directory { metadata, .. } => {
                        Some(metadata.path.to_string_lossy().into_owned())
                    }
                    _ => None,
                });
            if let Some(path) = path {
                if let Some(errno) = this.chmod_permission_errno(&path) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mode = this.maybe_clear_setgid(&path, mode);
                if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                    if let Err(errno) = m.vfs.chmod(&m.full_path, mode) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                } else {
                    let _ = this.fs.rootfs_vfs.overlay.set_mode(&path, mode);
                }
                // Refresh THIS fd's cached metadata so a subsequent fstat on it
                // sees the new mode. A Directory/File fstat reads the cached
                // metadata (only HostFile re-reads the live xattr), so without
                // this an fchmod(dirfd)+fstat(dirfd) reported the stale
                // open-time mode (LTP fchmod04/05). metadata.mode holds the
                // permission bits; the type comes from `kind`.
                if let Some(of) = this.open_file(fd.0) {
                    match &mut *of.description.write() {
                        OpenDescription::Directory { metadata, .. }
                        | OpenDescription::File { metadata, .. }
                        | OpenDescription::HostFile { metadata, .. } => {
                            metadata.mode = mode;
                        }
                        _ => {}
                    }
                }
                // inotify IN_ATTRIB (chmod is a metadata change).
                this.inotify_attrib(&path);
                this.dnotify_attrib_for_tid(cx.kernel, &path, Some(cx.tid()));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchown(this, cx, fd: Fd, owner: u64, group: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            Ok(this.fchown_by_fd(cx.kernel, fd.0, uid, gid))

        }

        fn fchownat(this, cx, dirfd: u64, pathname: GuestPtr, owner: u64, group: u64, flags: u64) {

            let pathname = pathname.0;
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                if !at_flags.contains(carrick_abi::LinuxAtFlags::EMPTY_PATH) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if !this.fd_is_valid(dirfd as i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                // AT_EMPTY_PATH operates on the fd ITSELF — record the owner like
                // fchown (was a silent no-op success that never set_owner'd).
                let uid = Self::chown_uid_arg(owner);
                let gid = Self::chown_gid_arg(group);
                return Ok(this.fchown_by_fd(cx.kernel, dirfd as i32, uid, gid));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            let resolved = this.resolve_at_path(dirfd, &path)?;
            let nofollow = at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW);
            if this.fs.vfs_mounts.resolve(&resolved).is_some() {
                let lookup = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        if nofollow {
                            m.vfs.lookup_nofollow(&m.full_path)
                        } else {
                            m.vfs.lookup(&m.full_path)
                        }
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                if let Err(errno) = lookup {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if let Some(errno) = this.chown_permission_errno(uid, gid) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let result = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        m.vfs.chown(&m.full_path, uid, gid, nofollow)
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                return match result {
                    Ok(()) => {
                        this.clear_setid_on_chown(&resolved);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Layered presence check: overlay first (tombstones become ENOENT),
            // synthetic /proc and /sys are no-op success, rootfs is no-op
            // success (tmpfs semantics). Record the guest-visible owner on the
            // backend (durably, via xattr on --fs host) so a later stat reports it.
            match this.layered_metadata(&resolved) {
                Ok(_) => {
                    if let Some(errno) = this.chown_permission_errno(uid, gid) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let _ = this.fs.rootfs_vfs.overlay.set_owner(
                        &resolved,
                        uid,
                        gid,
                    );
                    this.clear_setid_on_chown(&resolved);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => {
                    if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context(cx.kernel))
                    {
                        Ok(DispatchOutcome::Returned { value: 0 })
                    } else {
                        Ok(DispatchOutcome::errno(errno))
                    }
                }
            }

        }

        fn fchmodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux: it takes
            // only (dirfd, path, mode) and IGNORES the 4th register. glibc's
            // AT_SYMLINK_NOFOLLOW path still leaves the flag in that register —
            // `apt-get update` issues fchmodat(AT_FDCWD, path, 0644, 0x100) on
            // every downloaded index — and the real kernel silently ignores it.
            // Rejecting non-zero flags here made every apt download chmod fail
            // ("chmod 0644 of file … failed - 201::URIDone"). Only fchmodat2 (452)
            // validates the flags.
            let _ = flags;
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)

        }

        fn fchmodat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            // fchmodat2 (nr 452) carries a REAL flags argument: only
            // AT_SYMLINK_NOFOLLOW is valid (fchmodat2_02 passes -1 → EINVAL). On
            // the disk-authoritative host backend the flag itself stays advisory.
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)

        }

        fn linkat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {

            let oldpath = oldpath.0;
            let newpath = newpath.0;
            // linkat accepts AT_SYMLINK_FOLLOW + AT_EMPTY_PATH (NOT
            // AT_SYMLINK_NOFOLLOW — that is a *at-stat/chmod flag); reject any
            // other bit with EINVAL, before path faults. (audit M4; probe linkatflag)
            if flags & !(LINUX_AT_SYMLINK_FOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let old = read_guest_c_string(&*cx.memory, oldpath)?;
            let new_path = read_guest_c_string(&*cx.memory, newpath)?;
            if new_path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            if old.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // O_TMPFILE / memfd materialization candidate. The source can name an
            // ANONYMOUS inode (an O_TMPFILE/memfd fd with no directory entry) two
            // ways:
            //   - linkat(AT_FDCWD, "/proc/self/fd/<n>", ..., AT_SYMLINK_FOLLOW)
            //     — the magic symlink FOLLOWED to the unnamed inode (open14,
            //     openat03). AT_SYMLINK_FOLLOW must be set, else linkat would
            //     hard-link the symlink itself.
            //   - linkat(fd, "", ..., AT_EMPTY_PATH) — link the fd's inode
            //     directly.
            // Resolved here BEFORE the ordinary source-existence check, because
            // the anon inode has no namespace path that check would find.
            let anon_fd_candidate = if old.is_empty() {
                Some(olddirfd as i32)
            } else if flags & LINUX_AT_SYMLINK_FOLLOW != 0 {
                proc_self_fd_number(&old)
            } else {
                None
            };
            let resolved_old = if old.is_empty() {
                if !this.fd_is_valid(olddirfd as i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                None
            } else {
                let resolved = this.resolve_at_path(olddirfd, &old)?;
                let exists =
                    crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context(cx.kernel))
                        || this.layered_metadata(&resolved).is_ok()
                        // An anon fd's magic symlink has no layered metadata; its
                        // existence is the live fd, validated below in the
                        // materialize branch.
                        || anon_fd_candidate
                            .is_some_and(|n| this.fd_table_contains(n) || is_stdio_fd(n));
                if !exists {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                Some(resolved)
            };
            let resolved_new = this.resolve_at_path(newdirfd, &new_path)?;
            if crate::vfs::is_synthetic_virtual_file(&resolved_new, &this.synthetic_proc_context(cx.kernel))
                || this.layered_metadata(&resolved_new).is_ok()
            {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // The new-path's parent directory must exist, be a directory, and be
            // writable by the caller — creating a hard link writes an entry into
            // it (link04: a missing parent component -> ENOENT, a non-directory
            // component -> ENOTDIR, an unwritable parent under a dropped euid ->
            // EACCES). VFS-mount targets own their own checks below.
            if this.fs.vfs_mounts.resolve(&resolved_new).is_none() {
                let new_parent = std::path::Path::new(&resolved_new)
                    .parent()
                    .map(|p| {
                        let s = p.to_string_lossy().into_owned();
                        if s.is_empty() { "/".to_string() } else { s }
                    })
                    .unwrap_or_else(|| "/".to_string());
                match this.layered_metadata(&new_parent) {
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                    Ok(md) if md.kind != RootFsEntryKind::Directory => {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                    }
                    Ok(_) => {}
                }
                if let Some(errno) = this.may_write(&new_parent) {
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            // Linux gives the unnamed inode a name in place (same inode); carrick
            // has no shared-inode primitive for the overlay, so it materializes a
            // fresh entry from the fd's live bytes + creation mode. The O_TMPFILE
            // tests only stat size + mode, so a content+mode copy is
            // observationally exact. `materialize_anon_fd_to` returns None when
            // the fd is NOT an anon file (a real /proc/self/fd/<n> to a named
            // file), so the ordinary hard-link path below still handles those.
            if let Some(n) = anon_fd_candidate
                && let Some(result) = this.materialize_anon_fd_to(n, &resolved_new)
            {
                return Ok(match result {
                    Ok(()) => {
                        this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                });
            }
            // Create a real hard link in the writable backend (cap-std
            // hard_link). dpkg link()s e.g. /var/lib/dpkg/status -> status-old.
            // AT_EMPTY_PATH (link by fd) isn't supported. MemoryBackend can't
            // hard-link an in-memory file, so it falls back to a content copy.
            let Some(src) = resolved_old else {
                return Ok(DispatchOutcome::errno(LINUX_EROFS));
            };
            // Hard-linking a DIRECTORY is forbidden: Linux's vfs_link returns
            // EPERM for S_ISDIR (only a privileged FS-specific path could, which
            // carrick never offers). Check before the overlay hard_link, which
            // would otherwise surface EROFS (linkat01 case 21 links ".").
            if matches!(
                this.layered_metadata(&src).map(|md| md.kind),
                Ok(RootFsEntryKind::Directory)
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // A hard link whose source lives on a synthetic pseudo-filesystem
            // (/proc, /sys) crosses a device boundary into the rootfs overlay →
            // EXDEV, not the EROFS a failed overlay hard_link would yield
            // (linkat01 case 20 links /proc/cpuinfo into a real dir).
            if crate::vfs::is_synthetic_virtual_file(&src, &this.synthetic_proc_context(cx.kernel))
                && this.fs.vfs_mounts.resolve(&resolved_new).is_none()
            {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));
            }
            // Route a hard link whose NEW path is under a VFS mount (e.g.
            // /dev/shm, a BindVfs) to that mount's link() — the rootfs overlay
            // can't hard-link mount-backed paths and would wrongly return EROFS.
            // glibc sem_open does openat(temp) -> linkat(temp,final) ->
            // unlink(temp), so without this the whole multiprocessing SemLock
            // path fails EROFS and every multiprocessing/concurrent_futures
            // module SKIPS ("broken multiprocessing SemLock"). open already
            // routes through the mounts (try_mount_open); linkat must mirror it.
            // BindVfs::to_host rejects a `src` outside the mount, so a cross-fs
            // link returns ENOENT (not a corrupt link).
            if let Some(mnew) = this.fs.vfs_mounts.resolve(&resolved_new) {
                return Ok(match mnew.vfs.link(&src, &resolved_new) {
                    Ok(()) => {
                        this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                });
            }
            match this.fs.rootfs_vfs.overlay.hard_link(&src, &resolved_new) {
                Ok(()) => {
                    this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => {
                    // In-memory backend: emulate with a content copy (callers
                    // like dpkg only need the data, not shared inodes).
                    let contents = this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .file_contents(&src)
                        .or_else(|| {
                            this.fs
                                .rootfs_vfs
                                .rootfs
                                .as_ref()
                                .and_then(|r| r.read(&src).ok())
                        })
                        .unwrap_or_default();
                    match this
                        .fs
                        .rootfs_vfs
                        .overlay
                        .set_file_contents(&resolved_new, contents)
                    {
                        Ok(()) => {
                            this.dnotify_child(cx.kernel, &resolved_new, LinuxDnotifyMask::CREATE);
                            Ok(DispatchOutcome::Returned { value: 0 })
                        }
                        Err(_) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
                    }
                }
                Err(_) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
            }

        }

        fn symlinkat(this, cx, target: GuestPtr, newdirfd: u64, linkpath: GuestPtr) {

            let target = target.0;
            let linkpath = linkpath.0;
            let target_path = read_guest_c_string(&*cx.memory, target)?;
            if target_path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let link = read_guest_c_string(&*cx.memory, linkpath)?;
            if link.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved_link = this.resolve_at_path(newdirfd, &link)?;
            if crate::vfs::is_synthetic_virtual_file(&resolved_link, &this.synthetic_proc_context(cx.kernel)) {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // If the link path already exists (anywhere in the layered
            // view), report EEXIST. Otherwise the overlay can't create
            // symlinks today, so we return EROFS.
            if this.layered_metadata(&resolved_link).is_ok() {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved_link) {
                return match m.vfs.symlink(&target_path, &m.full_path) {
                    Ok(()) => {
                        this.dnotify_child(cx.kernel, &resolved_link, LinuxDnotifyMask::CREATE);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // DAC: creating the symlink entry needs write+search on the parent
            // directory (symlink03 case 1 → EACCES). Root bypasses.
            if let Some(parent) = Path::new(&resolved_link).parent()
                && !this.guest_can_modify_dir(&display_rootfs_path(parent))
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }
            // Create a real symlink in the writable backend (cap-std). The
            // target is stored verbatim, matching symlinkat(2). MemoryBackend
            // returns Unsupported → EROFS.
            match this
                .fs
                .rootfs_vfs
                .overlay
                .symlink(&target_path, &resolved_link)
            {
                Ok(()) => {
                    this.dnotify_child(cx.kernel, &resolved_link, LinuxDnotifyMask::CREATE);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
                Err(_) => Ok(DispatchOutcome::errno(LINUX_EROFS)),
            }

        }

        fn renameat(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr) {

            this.do_renameat(
                cx.kernel,
                RenameAtRequest {
                olddirfd,
                    oldpath: oldpath.0,
                newdirfd,
                    newpath: newpath.0,
                    flags: 0,
                    target_tid: Some(cx.tid()),
                },
                &*cx.memory,
            )

        }

        fn renameat2(this, cx, olddirfd: u64, oldpath: GuestPtr, newdirfd: u64, newpath: GuestPtr, flags: u64) {
            let Some(rf) = LinuxRenameat2Flags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if rf.contains(LinuxRenameat2Flags::EXCHANGE)
                && (rf.contains(LinuxRenameat2Flags::NOREPLACE)
                    || rf.contains(LinuxRenameat2Flags::WHITEOUT))
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if rf.contains(LinuxRenameat2Flags::WHITEOUT) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            this.do_renameat(
                cx.kernel,
                RenameAtRequest {
                    olddirfd,
                    oldpath: oldpath.0,
                    newdirfd,
                    newpath: newpath.0,
                    flags,
                    target_tid: Some(cx.tid()),
                },
                &*cx.memory,
            )
        }

        fn memfd_create(this, cx, name: GuestPtr, flags: u64) {
            // memfd_create(name, flags): an anonymous in-memory file. macOS has
            // no memfd, so model it as an unlinked, writable in-memory File
            // (same shape as O_TMPFILE). MFD_CLOEXEC → FD_CLOEXEC;
            // MFD_ALLOW_SEALING is accepted (fcntl F_ADD_SEALS sealing itself is
            // a separate follow-up — that's what gates memfd_create01).
            let allowed = if flags & LINUX_MFD_HUGETLB != 0 {
                LinuxMemfdFlags::KNOWN_MASK | LinuxMemfdFlags::HUGE_BITS
            } else {
                LinuxMemfdFlags::KNOWN_MASK
            };
            // Linux validates the flags BEFORE the name (LTP memfd_create02
            // passes a valid name with bad flags and still expects EINVAL).
            if flags & !allowed != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The name is bounded by MFD_NAME_MAX_LEN (256 − len("memfd:") − 1 =
            // 249): a NULL/unmapped pointer → EFAULT; no NUL within 250 bytes →
            // EINVAL (name too long). read_guest_c_string can't be reused — it
            // caps at PATH_MAX and returns ENAMETOOLONG, not the memfd EINVAL.
            const MFD_NAME_MAX_LEN: usize = 249;
            let memory = &*cx.memory;
            let mut name_bytes = Vec::new();
            let mut terminated = false;
            for off in 0..=MFD_NAME_MAX_LEN {
                let Some(addr) = name.0.checked_add(off as u64) else {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                };
                let byte = match memory.read_bytes(addr, 1) {
                    Ok(b) => b[0],
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                if byte == 0 {
                    terminated = true;
                    break;
                }
                name_bytes.push(byte);
            }
            if !terminated {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            let path = format!("/memfd:{name}");
            // Every memfd supports the sealing API. With MFD_ALLOW_SEALING the
            // initial seal set is empty; without it F_SEAL_SEAL is preset so no
            // seals can ever be added (F_ADD_SEALS → EPERM) while F_GET_SEALS
            // still succeeds. (memfd_create01)
            let Some(memfd_flags) =
                LinuxMemfdFlags::from_bits(flags & LinuxMemfdFlags::KNOWN_MASK)
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let initial_seals = if memfd_flags.contains(LinuxMemfdFlags::ALLOW_SEALING) {
                carrick_abi::LinuxMemfdSeals::empty().bits()
            } else {
                carrick_abi::LinuxMemfdSeals::SEAL.bits()
            };
            // A memfd is opened O_RDWR (memfd_create(2)); F_ADD_SEALS requires
            // the description carry write access (FMODE_WRITE).
            let mut base = OpenDescriptionBase::new(LINUX_O_RDWR);
            base.set_seals(Some(initial_seals));
            let description = OpenDescription::File {
                metadata: RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o777,
                    size: 0,
                },
                path,
                contents: FileContents::dense(Vec::new()),
                offset: 0,
                base,
                writable: true,
            };
            let fd_flags = if memfd_flags.contains(LinuxMemfdFlags::CLOEXEC) {
                LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd(description, fd_flags))
        }

        fn unlinkat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64) {

            let pathname = pathname.0;
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if at_flags.bits() & !LINUX_AT_REMOVEDIR != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let resolved = this.resolve_at_path(dirfd, &path)?;
            let remove_dir = at_flags.contains(carrick_abi::LinuxAtFlags::REMOVEDIR);
            // Synthetic /proc /sys paths can't be unlinked.
            if crate::vfs::is_synthetic_virtual_file(&resolved, &this.synthetic_proc_context(cx.kernel)) {
                return Ok(DispatchOutcome::errno(LINUX_EROFS));
            }
            use crate::vfs::Vfs as _;
            // DAC: removing an entry needs write+search on the parent dir
            // (unlink08: 0555 lacks write, 0666 lacks search — both → EACCES).
            // A sticky parent (S_ISVTX) additionally requires owning the entry
            // or the dir (rmdir03 case 2 → EPERM). Only when the target exists
            // (a missing one is ENOENT) and on the rootfs path (not the
            // carrick-internal bind-mount IPC paths).
            if this.fs.vfs_mounts.resolve(&resolved).is_none()
                && this.layered_metadata(&resolved).is_ok()
                && let Some(parent) = Path::new(&resolved).parent()
            {
                let parent_str = display_rootfs_path(parent);
                if !this.guest_can_modify_dir(&parent_str) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                if !this.guest_sticky_delete_ok(&parent_str, &resolved) {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
            }
            // Route through bind mounts (e.g. /dev/shm → host-tmp) so a file
            // CREATED via the openat mount path can also be unlinkat'd. The
            // open path resolves mounts first then falls through to rootfs;
            // unlinkat must mirror that or LTP's SAFE_UNLINK(shm_path) — which
            // creates the IPC region then immediately unlinks it (the mapping
            // outlives the name) — fails ENOENT and TBROKs setup_ipc.
            // An OVERRIDABLE single-file injection (/etc/services, /etc/resolv.conf)
            // is just a default the guest may replace: unlinking it must DETACH
            // the injection rather than EROFS from the read-only synthetic mount
            // (kaniko's image-unpack unlinks /etc/services to lay down the base
            // image's copy). Record the override so the path falls through to the
            // overlay everywhere thereafter; the injection isn't a real overlay
            // file, so "unlink" just means stop injecting. If the overlay DOES
            // happen to carry the path, also run the normal overlay delete.
            if let Some(m) = this.fs.vfs_mounts.resolve(&resolved)
                && m.vfs.overridable()
            {
                this.fs.vfs_mounts.override_path(&resolved);
                let overlay_result = if remove_dir {
                    this.fs.rootfs_vfs.rmdir(&resolved)
                } else {
                    this.fs.rootfs_vfs.unlink(&resolved)
                };
                // A missing overlay file is expected (the injection had no real
                // backing) — that's still a successful detach. Only a non-ENOENT
                // error from a real overlay file should surface.
                return match overlay_result {
                    Ok(()) | Err(LINUX_ENOENT) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Capture the target kind and (for a file) its pre-delete link count
            // BEFORE the delete, only when something is watching (the lookups are
            // otherwise wasted work). The link count distinguishes "a link was
            // removed but the inode survives" (IN_ATTRIB only) from "the last link
            // is gone, the file is removed" (IN_ATTRIB → IN_DELETE_SELF →
            // IN_IGNORED) — see inotify04 and inotify(7).
            let watching = !this.fs.inotify_registry.is_empty();
            let unlinked_is_dir = if watching {
                this.inotify_path_kind(&resolved).unwrap_or(remove_dir)
            } else {
                false
            };
            // nlink only matters for the file (non-dir) self-watch sequence.
            let nlink_before = if watching && !unlinked_is_dir {
                this.path_stat_record(cx.kernel, dirfd, &path, 0)
                    .map(|r| r.nlink)
                    .unwrap_or(1)
            } else {
                0
            };
            let result = if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                if remove_dir { m.vfs.rmdir(&m.full_path) } else { m.vfs.unlink(&m.full_path) }
            } else if remove_dir {
                this.fs.rootfs_vfs.rmdir(&resolved)
            } else {
                this.fs.rootfs_vfs.unlink(&resolved)
            };
            match result {
                Ok(()) => {
                    // inotify: IN_DELETE (name) to a watch on the parent dir.
                    this.inotify_child(
                        &resolved,
                        carrick_abi::LINUX_IN_DELETE,
                        unlinked_is_dir,
                    );
                    this.dnotify_child(cx.kernel, &resolved, LinuxDnotifyMask::DELETE);
                    // To a watch ON the entry itself:
                    // - A directory (rmdir) has no link-count subtlety:
                    //   IN_DELETE_SELF → IN_IGNORED.
                    // - A file whose link count just dropped to 0 (the last link):
                    //   IN_ATTRIB (link count changed) → IN_DELETE_SELF → IN_IGNORED.
                    // - A file with surviving hardlinks (link count was > 1): the
                    //   inode lives on, so only IN_ATTRIB — no self-delete/ignore.
                    if unlinked_is_dir {
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_DELETE_SELF);
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_IGNORED);
                        this.fs.inotify_registry.unregister_path(&resolved);
                    } else {
                        // The unlinked name changes the inode's link count → IN_ATTRIB.
                        this.inotify_self(&resolved, carrick_abi::LINUX_IN_ATTRIB);
                        if nlink_before <= 1 {
                            // Last link gone: the watched object is destroyed.
                            this.inotify_self(&resolved, carrick_abi::LINUX_IN_DELETE_SELF);
                            this.inotify_self(&resolved, carrick_abi::LINUX_IN_IGNORED);
                            this.fs.inotify_registry.unregister_path(&resolved);
                        }
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn utimensat(this, cx, dirfd: u64, pathname: GuestPtr, times: GuestPtr, flags: u64) {

            let pathname = pathname.0;
            let times = times.0;
            let memory = &*cx.memory;
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `times == NULL` means "set both to now"; otherwise read the two
            // timespecs and resolve UTIME_NOW/UTIME_OMIT into concrete
            // (sec, nsec) pairs or `None` (omit) for the backend.
            #[allow(clippy::type_complexity)]
            let (atime_set, mtime_set): (Option<(i64, i64)>, Option<(i64, i64)>);
            if times != 0 {
                let atime = read_timespec(memory, times)?;
                let mtime_address = times
                    .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                    .ok_or(DispatchError::LengthTooLarge(times))?;
                let mtime = read_timespec(memory, mtime_address)?;
                if !linux_utimensat_timespec_is_valid(atime)
                    || !linux_utimensat_timespec_is_valid(mtime)
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                atime_set = resolve_utimensat_timespec(atime);
                mtime_set = resolve_utimensat_timespec(mtime);
            } else {
                // NULL → set both to the current wall-clock time.
                let now = now_realtime_timespec();
                atime_set = Some(now);
                mtime_set = Some(now);
            }

            if pathname == 0 {
                // `futimens(fd, times)` lowers to `utimensat(fd, NULL, times, 0)`
                // in musl/glibc: set the times of the *open fd itself*. (This is
                // distinct from the AT_EMPTY_PATH form, which carries an empty —
                // not NULL — path.)
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if atime_set.is_none() && mtime_set.is_none() {
                    // Both UTIME_OMIT: nothing to persist; just validate the fd.
                    if !this.fd_is_valid(dirfd as i32) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(this.set_fd_times(dirfd as i32, atime_set, mtime_set));
            }

            let path = read_guest_c_string(memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => {
                    crate::probes::fs_op("utimensat:resolve_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            };
            // Without AT_SYMLINK_NOFOLLOW, utime()/utimensat FOLLOWS a trailing
            // symlink to its target and updates THAT file's times: a dangling
            // target is ENOENT and a symlink cycle is ELOOP (utime07). Only when
            // the final component is genuinely a symlink — plain paths and
            // synthetic /proc entries are left untouched for the checks below,
            // and resolve_at_path already leaves the final component unfollowed.
            let path = if flags & LINUX_AT_SYMLINK_NOFOLLOW == 0
                && matches!(
                    this.layered_lstat(&path),
                    Ok(md) if md.kind == RootFsEntryKind::Symlink
                ) {
                match this.canonicalize_following(&path) {
                    Ok(resolved) => resolved,
                    Err(errno) => {
                        crate::probes::fs_op("utimensat:follow_err", &path, errno.get());
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
            } else {
                path
            };
            // The path must exist in the layered view, else NotFound (or a
            // no-op success for synthetic /proc paths whose times we can't
            // back).
            match this.layered_metadata(&path) {
                Ok(_) => {}
                Err(errno) => {
                    if crate::vfs::is_synthetic_virtual_file(&path, &this.synthetic_proc_context(cx.kernel)) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::probes::fs_op("utimensat:meta_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            if atime_set.is_none() && mtime_set.is_none() {
                // Both UTIME_OMIT: nothing to persist.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                return match m.vfs.set_times(
                    &m.full_path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                ) {
                    Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Persist atime/mtime to the materialised host file (disk-backed
            // overlay). A subsequent stat reads real disk metadata via
            // real_stat and will report the set mtime. MemoryBackend returns
            // Unsupported; accept as a no-op so in-memory guests don't fail.
            match this
                .fs
                .rootfs_vfs
                .overlay
                .set_times(
                    &path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                )
            {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(crate::fs_backend::BackendError::Unsupported) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // Best-effort timestamps: a successful set above persists real
                // mtime (apt's pkgcache x-ref relies on that), but a FAILURE to
                // set times must NOT abort the caller. Linux tools like dpkg treat
                // utimensat failure on a file they just wrote as fatal ("error
                // setting timestamps … Read-only file system"); returning EROFS
                // there breaks `dpkg --unpack` of any package with shared libs.
                // The file content is already correct; timestamps are cosmetic.
                Err(e) => {
                    crate::probes::fs_op("utimensat:set_times_err_besteffort", &path, 0);
                    let _ = e;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }

        }

        fn newfstatat(this, cx, dirfd: u64, pathname: GuestPtr, statbuf: GuestPtr, flags: u64) {
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // Only AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT and AT_EMPTY_PATH are
            // valid; any other bit is EINVAL (fstatat01 case 4 passes flags=9999).
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_NO_AUTOMOUNT | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, dirfd, &path, flags) {
                Ok(record) => Ok(write_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_stat(this, cx, pathname: GuestPtr, statbuf: GuestPtr) {

            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, LINUX_AT_FDCWD, &path, 0) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_fstat(this, cx, fd: Fd, statbuf: GuestPtr) {

            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            match this.fd_stat_record(fd.0) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_lstat(this, cx, pathname: GuestPtr, statbuf: GuestPtr) {

            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(
                cx.kernel,
                LINUX_AT_FDCWD,
                &path,
                LINUX_AT_SYMLINK_NOFOLLOW,
            ) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn x86_newfstatat(this, cx, dirfd: u64, pathname: GuestPtr, statbuf: GuestPtr, flags: u64) {

            // Only AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT and AT_EMPTY_PATH are
            // valid; any other bit is EINVAL (fstatat01 case 4 passes flags=9999).
            if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_NO_AUTOMOUNT | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let pathname = pathname.0;
            let statbuf = statbuf.0;
            let memory = &mut *cx.memory;
            let path = read_guest_c_string(memory, pathname)?;
            match this.path_stat_record(cx.kernel, dirfd, &path, flags) {
                Ok(record) => Ok(write_x8664_stat_record(memory, statbuf, &record)),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn statx(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mask: u64, statxbuf: GuestPtr) {

            let pathname = pathname.0;
            let statxbuf = statxbuf.0;
            let memory = &mut *cx.memory;

            if !linux_statx_flags_are_supported(flags) || mask & LINUX_STATX_RESERVED != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let path = read_guest_c_string(memory, pathname)?;

            if path.is_empty() {
                if flags & LINUX_AT_EMPTY_PATH == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                return Ok(this.write_fd_statx(dirfd as i32, statxbuf, memory));
            }

            // A trailing "/" or "/." forces directory semantics: follow the final
            // symlink even under AT_SYMLINK_NOFOLLOW, and a non-directory final →
            // ENOTDIR (matches newfstatat; man path_resolution(7)).
            let requires_dir = path.ends_with('/') || path.ends_with("/.");

            // Dispatch-level stat-cache fast path — see the twin block in
            // `newfstatat` for the gating rationale. write_statx_real's `path`
            // only feeds the type bits, so a hit is byte-identical.
            if !requires_dir
                && dirfd == LINUX_AT_FDCWD
                && path.starts_with('/')
                && !path.starts_with("/proc")
                && !path.starts_with("/sys")
                && !path.split('/').any(|c| c == "..")
                && let Some(real) = this.fs.rootfs_vfs.overlay.stat_cache_lookup(&path)
            {
                return Ok(this.write_statx_real_with_device(memory, statxbuf, &path, &real));
            }

            let path = this.resolve_at_path(dirfd, &path)?;
            {
                // One context assembly for both consults — see the twin block
                // in `path_stat_record`, including why the kernel task graph is
                // the only thing that can settle a peer's `/proc/<pid>`.
                let proc_ctx = this.synthetic_proc_context(cx.kernel);
                if let Some(contents) = crate::vfs::proc::synthetic_file(&path, &proc_ctx) {
                    return Ok(write_synthetic_statx(
                        memory,
                        statxbuf,
                        &path,
                        contents.len(),
                    ));
                }
                if crate::vfs::proc::synthetic_dir_entries(&path, &proc_ctx).is_some() {
                    return Ok(write_synthetic_statx_mode(
                        memory,
                        statxbuf,
                        &path,
                        0,
                        LINUX_S_IFDIR | 0o555,
                    ));
                }
            }
            if let Some(contents) = crate::vfs::sys::synthetic_file(&path) {
                return Ok(write_synthetic_statx(
                    memory,
                    statxbuf,
                    &path,
                    contents.len(),
                ));
            }
            // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
            // (S_IFLNK + true st_nlink). `AT_SYMLINK_NOFOLLOW` selects lstat
            // (the link) vs stat (the target).
            let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0 || requires_dir;
            if let Some(real) = this.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
                if requires_dir && real.kind != RootFsEntryKind::Directory {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                return Ok(this.write_statx_real_with_device(memory, statxbuf, &path, &real));
            }
            // DANGLING SYMLINK: following statx of a symlink whose target does
            // not exist is ENOENT on Linux (mirrors the newfstatat path above).
            if follow
                && let Some(link) = this.fs.rootfs_vfs.overlay.real_stat(&path, false)
                && link.kind == RootFsEntryKind::Symlink
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            use crate::vfs::Vfs as _;
            // VFS mounts (/dev, /dev/pts, /proc, /sys): stat their nodes so e.g.
            // /dev/ptmx, /dev/pts/N, /dev/tty resolve (mirrors the open path).
            if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                if let Some(real) = m.vfs.real_stat(&m.full_path, follow) {
                    return Ok(write_statx_real(memory, statxbuf, &path, &real));
                }
                if let Ok(md) = if follow {
                    m.vfs.lookup(&m.full_path)
                } else {
                    m.vfs.lookup_nofollow(&m.full_path)
                } {
                    return Ok(write_statx(
                        memory,
                        statxbuf,
                        &vfs_md_to_rootfs_md(&path, &md),
                    ));
                }
            }
            // Fallback for backends without real_stat (e.g. the in-memory
            // overlay): honour AT_SYMLINK_NOFOLLOW by reporting the link itself
            // rather than its target.
            let lookup = if follow {
                this.fs.rootfs_vfs.lookup(&path)
            } else {
                this.fs.rootfs_vfs.lookup_nofollow(&path)
            };
            match lookup {
                Ok(md) => {
                    // Same identity reconciliation newfstatat performs, so
                    // statx and stat cannot report different inodes for one
                    // immutable-lower file.
                    let record = this.layered_identity_record(
                        &path,
                        follow,
                        &vfs_md_to_rootfs_md(&path, &md),
                    );
                    Ok(write_statx_record(memory, statxbuf, &record))
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn fstat(this, cx, fd: Fd, statbuf: GuestPtr) {

            let fd: Fd = fd;
            let statbuf = statbuf.0;
            Ok(this.write_fd_stat(fd.0, statbuf, &mut *cx.memory))

        }

    }
}

/// One streamed readdir batch of a TRUSTED host dirfd, translated to the
/// `RootFsDirEntry` shape `getdents64`'s `dirent64_record` encoder consumes —
/// `d_name`/`d_type`/`d_ino` straight off the kernel, zero per-child stats.
/// `dup` + `fdopendir` so the `DIR*` lifecycle (its own buffer, `closedir`)
/// never touches the description fd's state. Skips "."/".." (the getdents
/// handler synthesizes deterministic dot entries) and carrick's internal
/// sidecar names. `None` on any surprise (`DT_UNKNOWN`, an unmappable type,
/// `fdopendir` failure) ⇒ the caller takes the exact layered path.
#[cfg(target_os = "macos")]
fn read_host_dir_entries(host_dir_fd: i32, dir_path: &str) -> Option<Vec<RootFsDirEntry>> {
    struct Dirp(*mut libc::DIR);
    impl Drop for Dirp {
        fn drop(&mut self) {
            // SAFETY: closes the DIR* (and its adopted dup'd fd) exactly once.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    // SAFETY: dup a private fd for the DIR* to adopt; the description's own
    // fd (and its seek state) stays untouched.
    let dup = unsafe { libc::dup(host_dir_fd) };
    if dup < 0 {
        return None;
    }
    let raw_dirp = unsafe { libc::fdopendir(dup) };
    if raw_dirp.is_null() {
        // SAFETY: fdopendir did not adopt the fd, so it is still ours.
        unsafe {
            libc::close(dup);
        }
        return None;
    }
    let dirp = Dirp(raw_dirp);
    // fdopendir adopts the fd's CURRENT offset; the dup shares the
    // original's, so rewind to read the whole directory.
    unsafe { libc::rewinddir(dirp.0) };
    let mut out = Vec::new();
    loop {
        // SAFETY: dirp.0 is a live DIR*; readdir returns null at end.
        let ent = unsafe { libc::readdir(dirp.0) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` points at the DIR*'s current record; d_name is
        // NUL-terminated within the struct.
        let (d_type, d_ino, name_bytes) = unsafe {
            let e = &*ent;
            (
                e.d_type,
                e.d_ino,
                std::ffi::CStr::from_ptr(e.d_name.as_ptr()).to_bytes(),
            )
        };
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        // On-disk names are valid UTF-8 by construction (APFS rejects raw
        // non-UTF-8; undecodable guest names live in the reversible escape
        // form — see `fs_backend::normalize`), so this lossy read matches
        // `child_names` byte-for-byte.
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        if crate::fs_backend::is_internal_sidecar_name(&name) {
            continue;
        }
        let kind = match d_type {
            libc::DT_DIR => RootFsEntryKind::Directory,
            libc::DT_REG => RootFsEntryKind::File,
            libc::DT_LNK => RootFsEntryKind::Symlink,
            libc::DT_FIFO => RootFsEntryKind::Fifo,
            libc::DT_SOCK => RootFsEntryKind::Socket,
            libc::DT_CHR => RootFsEntryKind::CharDevice,
            // DT_UNKNOWN / DT_BLK / anything else: the stream cannot answer
            // d_type faithfully — layered path for the WHOLE directory.
            _ => return None,
        };
        let path = if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        };
        out.push(RootFsDirEntry {
            name,
            metadata: RootFsMetadata {
                path: std::path::PathBuf::from(path),
                kind,
                // getdents64 consumes only `kind` (→ d_type), the name and
                // the ino; mode/size mirror the layered merge's defaults for
                // entries it does not open.
                mode: if kind == RootFsEntryKind::Directory {
                    0o755
                } else {
                    0o644
                },
                size: 0,
            },
            ino: d_ino,
        });
    }
    Some(out)
}

/// Trusted host dirfds are only ever minted by the macOS `--fs host` fast
/// path; the streaming reader is unreachable elsewhere.
#[cfg(not(target_os = "macos"))]
fn read_host_dir_entries(_host_dir_fd: i32, _dir_path: &str) -> Option<Vec<RootFsDirEntry>> {
    None
}

/// `read(2)` on a fanotify group fd: drain queued events into the guest buffer
/// as `struct fanotify_event_metadata` records.
///
/// The subtle part is the per-event descriptor. Linux allocates it in the
/// READING process's file-descriptor table at read time, not in the table of
/// whatever process generated the event — a forked child that triggers an event
/// must not burn an fd of its own, and the reader must get a descriptor it can
/// `fstat` and `close` (LTP `fanotify04` does exactly that, and asserts the fd
/// refers to an object of the expected type). So the queue stores PATHS and the
/// open happens here, with the group's `event_f_flags`.
///
/// Partial-record protection: only whole 24-byte records are ever written, and
/// a copyout fault un-does the whole call — the descriptors just opened are
/// closed and the events are pushed back on the front of the queue, so the
/// guest's `EFAULT` leaves nothing consumed and no fd leaked.
#[allow(clippy::too_many_arguments)]
fn read_fanotify<M: GuestMemory>(
    this: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    registry: Option<&crate::thread::ThreadRegistry>,
    reporter: &CompatReporter,
    memory: &mut M,
    address: u64,
    length: usize,
    group: &Arc<crate::fanotify::FanotifyGroup>,
    nonblocking: bool,
) -> Result<DispatchOutcome, DispatchError> {
    // A buffer too small for even one record can never make progress.
    if length < carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    let capacity = length / carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN;
    let events = group.take(capacity);
    if events.is_empty() {
        // Park on the group's readiness pipe rather than returning EAGAIN to a
        // blocking fd: `fanotify11` starts a worker thread and reads
        // immediately, so the queue is legitimately empty at read time and the
        // read must sleep until the worker's open lands.
        return Ok(super::would_block_outcome(
            group.poll_fd(),
            libc::POLLIN,
            nonblocking,
            None,
        ));
    }
    let mut bytes =
        Vec::with_capacity(events.len() * carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN);
    let mut opened: Vec<i32> = Vec::with_capacity(events.len());
    // Every open below is carrick's own; without this the FAN_OPEN it would
    // emit lands right back on the queue this read is draining.
    let _internal = crate::fanotify::InternalOpenGuard::enter();
    for event in &events {
        // An object that has since been unlinked (or that this process cannot
        // open) still yields a record — with FAN_NOFD, exactly as Linux does
        // when it cannot open the object for the reader.
        let fd = match this.open_at_path_string(
            context,
            registry,
            LINUX_AT_FDCWD,
            &event.path,
            group.event_f_flags(),
            0,
            reporter,
        ) {
            Ok(DispatchOutcome::Returned { value }) if value >= 0 => {
                let fd = value as i32;
                opened.push(fd);
                fd
            }
            _ => crate::fanotify::NOFD,
        };
        bytes.extend_from_slice(&crate::fanotify::encode_event(event.mask, fd, event.pid));
    }
    if memory.write_bytes(address, &bytes).is_err() {
        // Roll the whole call back: close the descriptors we just handed out
        // and restore the events, so a faulting read consumes nothing.
        for fd in opened {
            this.close_fd_for_internal_rollback(fd);
        }
        group.requeue_front(events);
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    Ok(DispatchOutcome::Returned {
        value: bytes.len() as i64,
    })
}

#[cfg(test)]
#[path = "fs/tests.rs"]
mod tests;
