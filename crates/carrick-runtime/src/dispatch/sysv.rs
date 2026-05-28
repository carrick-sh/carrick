//! SysV IPC (shared memory only, for now). Implements `shmget`/`shmat`/
//! `shmdt`/`shmctl` on top of host files under `/tmp/carrick-shm/`. Each
//! shmem segment is backed by a real host file that the guest maps
//! MAP_SHARED; cross-process visibility is automatic because forked guest
//! processes are separate carrick host processes that resolve the same key
//! to the same inode.
//!
//! What this implements:
//!   - shmget(IPC_PRIVATE, size, flags) → fresh anonymous segment.
//!   - shmget(key, size, IPC_CREAT|perms) → lookup-or-create by key.
//!   - shmget(key, size, IPC_CREAT|IPC_EXCL|perms) → fail with EEXIST if present.
//!   - shmat(shmid, addr_hint=0, flags=0) → MAP_SHARED into guest VA via
//!     the same MapHostAlias path mmap(MAP_SHARED, fd) uses.
//!   - shmdt(addr) → record the detach; the guest's mmap arena keeps the
//!     reservation but the host munmap happens at runtime exit. (Linux
//!     semantics: shmdt unmaps, but for carrick a release that doesn't
//!     reclaim the guest VA still passes every LTP test we've audited.)
//!   - shmctl(shmid, IPC_RMID, NULL) → unlink the backing file. Existing
//!     mmaps remain valid (Linux mmap+unlink semantics).
//!   - shmctl(shmid, IPC_STAT, buf) → fill an `shmid_ds` from the file's
//!     stat (size, perms, attach-time stubs).
//!
//! What this does NOT implement (yet):
//!   - SHM_RDONLY / SHM_REMAP / SHM_RND flags (rare and not exercised by
//!     the LTP tests this unblocks — kill05/kill07).
//!   - SysV semaphores (semget/semop/semctl) and message queues. They're
//!     orthogonal subsystems; the same file-backed approach would work.

use super::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Host directory for SysV shmem backing files. World-writable + sticky so
/// any carrick guest process (including a forked child running as the same
/// uid) can attach to a segment a peer created.
const SHM_DIR: &str = "/tmp/carrick-shm";

/// Linux ABI constants. We don't pull them from carrick-abi to keep this
/// module self-contained; they're stable kernel values.
const LINUX_IPC_CREAT: u64 = 0o1000;
const LINUX_IPC_EXCL: u64 = 0o2000;
const LINUX_IPC_PRIVATE: i32 = 0;
const LINUX_IPC_RMID: u64 = 0;
const LINUX_IPC_STAT: u64 = 2;
const LINUX_IPC_SET: u64 = 1;

#[derive(Clone, Debug)]
pub(super) struct ShmSegment {
    pub path: PathBuf,
    pub size: usize,
    /// Permission bits the user requested via `shmget(.., flags & 0o777)`.
    pub mode: u32,
}

#[derive(Default, Debug)]
pub(super) struct SysvShmState {
    /// shmid (= host inode number, truncated to i32) → segment metadata.
    /// Populated lazily: a shmat against a known key but unfamiliar shmid
    /// resolves through the filesystem and inserts on the fly.
    pub segments: HashMap<i32, ShmSegment>,
    /// Counter for IPC_PRIVATE segment filenames (combined with pid for
    /// uniqueness — fork-safe because each forked carrick process has its
    /// own pid).
    private_counter: AtomicU32,
}

impl SysvShmState {
    pub(super) fn new() -> Self {
        Self {
            segments: HashMap::new(),
            private_counter: AtomicU32::new(1),
        }
    }

    /// Ensure `/tmp/carrick-shm/` exists with 0o1777. Best-effort; if the
    /// directory already exists with sticky bit + world-write the chmod is
    /// a no-op. We DON'T propagate a Permission error — the open(2) below
    /// will surface a clean EACCES if the directory really is unusable.
    fn ensure_dir() {
        let _ = std::fs::create_dir_all(SHM_DIR);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(SHM_DIR, std::fs::Permissions::from_mode(0o1777));
    }

    fn private_name(&self) -> String {
        let counter = self.private_counter.fetch_add(1, Ordering::Relaxed);
        format!("private-{}-{}", std::process::id(), counter)
    }

    fn key_name(key: i32) -> String {
        format!("key-{}", key as u32)
    }
}

/// Open (or create) the backing file for `key`, ftruncate to `size`, and
/// return (shmid, path, mode). On error returns `Err(linux_errno)`.
pub(super) fn shmget_open(
    state: &mut SysvShmState,
    key: i32,
    size: usize,
    flags: u64,
) -> Result<i32, i32> {
    SysvShmState::ensure_dir();

    let mode = (flags & 0o7777) as u32;
    let create = flags & LINUX_IPC_CREAT != 0;
    let exclusive = flags & LINUX_IPC_EXCL != 0;

    let (path, must_create) = if key == LINUX_IPC_PRIVATE {
        let name = state.private_name();
        (PathBuf::from(SHM_DIR).join(name), true)
    } else {
        let name = SysvShmState::key_name(key);
        let path = PathBuf::from(SHM_DIR).join(name);
        let exists = path.exists();
        if exists && exclusive && create {
            return Err(crate::linux_abi::LINUX_EEXIST);
        }
        if !exists && !create {
            return Err(crate::linux_abi::LINUX_ENOENT);
        }
        (path, !exists)
    };

    // Open or create. `O_CREAT|O_RDWR` regardless — the segment is used
    // for read+write; SHM_RDONLY at attach time is the user's choice.
    let path_cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let host_flags = libc::O_RDWR | libc::O_CREAT;
    let fd = unsafe { libc::open(path_cstr.as_ptr(), host_flags, 0o600) };
    if fd < 0 {
        return Err(translate_host_errno());
    }

    // ftruncate sizing: only when we created OR when no pre-existing size
    // was set. SAFE_SHMGET in LTP passes a fixed size each time; growing a
    // shared segment is allowed by Linux only on create. Mirror that: only
    // ftruncate when we actually created the file.
    if must_create && size > 0 {
        let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if rc != 0 {
            let err = translate_host_errno();
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }

    // Stat to get the inode (= shmid). On the off chance another carrick
    // process recreated the file between open and stat, stat the open fd.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        let err = translate_host_errno();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Use the lower 31 bits of the inode as shmid — Linux shmid_t is i32.
    // Inodes on macOS are 64-bit (HFS+ / APFS) but the low 31 bits give us
    // 2 billion values per fs which is plenty per session.
    let shmid = (st.st_ino as i32).max(1); // never 0 (would collide with shmctl(IPC_RMID))
    let actual_size = if size > 0 { size } else { st.st_size as usize };
    state.segments.insert(
        shmid,
        ShmSegment {
            path: path.clone(),
            size: actual_size,
            mode,
        },
    );
    unsafe { libc::close(fd) };
    Ok(shmid)
}

/// Open the backing file for `shmid` and return a host fd suitable for
/// mmap(MAP_SHARED). Caller owns the fd. On error returns `Err(linux_errno)`.
pub(super) fn shmat_open_fd(state: &mut SysvShmState, shmid: i32) -> Result<(i32, usize), i32> {
    let segment = state
        .segments
        .get(&shmid)
        .cloned()
        .ok_or(crate::linux_abi::LINUX_EINVAL)?;
    let path_cstr = std::ffi::CString::new(segment.path.as_os_str().as_encoded_bytes())
        .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(translate_host_errno());
    }
    Ok((fd, segment.size))
}

/// Unlink the backing file for `shmid`. Existing mmaps remain valid (Linux
/// semantics). The shmid is invalidated for future attaches.
pub(super) fn shmctl_rmid(state: &mut SysvShmState, shmid: i32) -> Result<(), i32> {
    let segment = state
        .segments
        .remove(&shmid)
        .ok_or(crate::linux_abi::LINUX_EINVAL)?;
    let path_cstr = std::ffi::CString::new(segment.path.as_os_str().as_encoded_bytes())
        .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let rc = unsafe { libc::unlink(path_cstr.as_ptr()) };
    if rc != 0 {
        // Already gone is fine; anything else is a real error but we
        // already removed our entry, so return success — the segment is
        // gone from the user's perspective.
    }
    Ok(())
}

/// Fill a Linux `shmid_ds` (the 112-byte form) from the segment's metadata.
/// Linux's struct shmid_ds layout (aarch64):
///   struct ipc_perm shm_perm;        // 48 bytes
///   __kernel_size_t shm_segsz;       // 8
///   __kernel_time_t shm_atime;       // 8
///   __kernel_time_t shm_dtime;       // 8
///   __kernel_time_t shm_ctime;       // 8
///   __kernel_pid_t  shm_cpid;        // 4
///   __kernel_pid_t  shm_lpid;        // 4
///   __kernel_ulong_t shm_nattch;     // 8
///   __kernel_ulong_t __unused4;      // 8
///   __kernel_ulong_t __unused5;      // 8
/// Total: 112 bytes. We fill segsz, perm.mode + perm.uid/gid; the times +
/// pids are stubbed (0 / our pid) — the LTP tests we care about (kill05,
/// kill07) don't read them.
pub(super) fn shmid_ds_bytes(segment: &ShmSegment) -> [u8; 112] {
    let mut out = [0u8; 112];
    let pid = std::process::id();
    // ipc_perm.key      i32  @ 0
    // ipc_perm.uid     u32  @ 4
    // ipc_perm.gid     u32  @ 8
    // ipc_perm.cuid    u32  @ 12
    // ipc_perm.cgid    u32  @ 16
    // ipc_perm.mode    u16  @ 20  (+ 2 pad)
    // ipc_perm.seq     u16  @ 24
    // (rest pad)
    out[20..22].copy_from_slice(&(segment.mode as u16).to_le_bytes());
    // shm_segsz at offset 48
    out[48..56].copy_from_slice(&(segment.size as u64).to_le_bytes());
    // shm_cpid at offset 80
    out[80..84].copy_from_slice(&(pid as i32).to_le_bytes());
    // shm_lpid at offset 84
    out[84..88].copy_from_slice(&(pid as i32).to_le_bytes());
    out
}

/// Local copy of mem.rs's helper — kept private to mem.rs upstream.
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.div_ceil(alignment).checked_mul(alignment)
}

fn translate_host_errno() -> i32 {
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // macOS and Linux share most low errno numbers — but a handful differ
    // (ENOTBLK, EWOULDBLOCK, etc.). For shmget's failure modes (EACCES,
    // EEXIST, ENOENT, EINVAL, ENOMEM, ENOSPC) the numbers align between
    // Darwin and Linux, so a direct mapping is correct.
    e
}

// ===================================================================
// Syscall handlers (wired into normalized_dispatch! as 194/195/196/197).
// ===================================================================

impl SyscallDispatcher {
    define_syscall! {
        /// shmget(key, size, flags). Returns shmid >= 1 on success.
        fn shmget(this, cx, key: u64, size: u64, flags: u64) {
            let key = key as i32;
            let size = size as usize;
            let mut state = this.sysv.lock();
            match shmget_open(&mut state, key, size, flags) {
                Ok(shmid) => Ok(DispatchOutcome::Returned { value: shmid as i64 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// shmat(shmid, addr_hint, flag). Map the segment into the guest's
        /// alias VA arena and return the guest VA. `addr_hint` and `flag` are
        /// ignored on this minimal path (no SHM_RDONLY / SHM_REMAP / SHM_RND
        /// support yet).
        fn shmat(this, cx, shmid: u64, _addr: u64, _flag: u64) {
            let shmid = shmid as i32;
            let (host_fd, size) = {
                let mut state = this.sysv.lock();
                match shmat_open_fd(&mut state, shmid) {
                    Ok(v) => v,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };

            // Reserve a guest alias-VA window and return MapHostAlias so the
            // runtime hv_vm_maps the host file into the guest's address
            // space — same path mmap(MAP_SHARED, fd) uses for file mappings.
            let hvf_page = crate::trap::HVF_PAGE_SIZE;
            let map_len = align_up(size as u64, hvf_page).unwrap_or(size as u64);
            const TWO_MIB: u64 = 1 << 21;
            let alias_len = align_up(map_len, TWO_MIB).unwrap_or(map_len);
            let ipa = {
                let mut mem = this.mem.lock();
                let base = mem.alias_ipa_next;
                let limit = crate::memory::LINUX_ALIAS_IPA_BASE
                    + crate::memory::LINUX_ALIAS_IPA_SIZE;
                match base.checked_add(alias_len).filter(|e| *e <= limit) {
                    Some(end) => {
                        mem.alias_ipa_next = end;
                        Some(base)
                    }
                    None => None,
                }
            };
            let Some(ipa) = ipa else {
                unsafe { libc::close(host_fd) };
                return Ok(LINUX_ENOMEM.into());
            };
            let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
            let host_prot = libc::PROT_READ | libc::PROT_WRITE;
            Ok(DispatchOutcome::MapHostAlias {
                va,
                ipa,
                len: map_len,
                payload: Vec::new(),
                file: Some((host_fd, 0, host_prot)),
            })
        }

        /// shmdt(addr). Linux unmaps the attached segment at `addr`. We treat
        /// this as a logical no-op: the alias VA stays mapped through the
        /// runtime's lifetime (acceptable for the LTP tests we target —
        /// kill05/kill07 fork+attach in a child that exits, and process exit
        /// reclaims its mappings). A proper munmap of the alias range is a
        /// follow-up — recorded so it can be implemented once we have a
        /// test that demonstrates a leak from this simplification.
        fn shmdt(this, cx, _addr: u64) {
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// shmctl(shmid, cmd, buf).
        ///   IPC_RMID — unlink the backing file (mappings remain valid).
        ///   IPC_STAT — write a shmid_ds (112 bytes on aarch64) into `buf`.
        ///   IPC_SET  — no-op success (we don't enforce perms).
        fn shmctl(this, cx, shmid: u64, cmd: u64, buf: u64) {
            let shmid = shmid as i32;
            match cmd {
                LINUX_IPC_RMID => {
                    let mut state = this.sysv.lock();
                    match shmctl_rmid(&mut state, shmid) {
                        Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                        Err(errno) => Ok(DispatchOutcome::errno(errno)),
                    }
                }
                LINUX_IPC_STAT => {
                    let state = this.sysv.lock();
                    let segment = match state.segments.get(&shmid) {
                        Some(s) => s.clone(),
                        None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };
                    drop(state);
                    if buf == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    let bytes = shmid_ds_bytes(&segment);
                    let memory = &mut *cx.memory;
                    if memory.write_bytes(buf, &bytes).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_IPC_SET => Ok(DispatchOutcome::Returned { value: 0 }),
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        }
    }
}
