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
//!   - addr_hint placement / SHM_REMAP / SHM_RND — carrick owns the alias VA
//!     arena and picks the placement, so a caller-supplied address can't be
//!     honored. Documented arch gap. (SHM_RDONLY *is* honored — the alias is
//!     mapped read-only so a guest store faults SIGSEGV like Linux.)
//!   - SysV semaphores (semget/semop/semctl) and message queues. They're
//!     orthogonal subsystems; the same file-backed approach would work.

use super::*;

// The `libc` crate exposes the SysV semaphore family on macOS but NOT the
// message-queue family, so declare those externs ourselves. Signatures per
// macOS <sys/msg.h>.
unsafe extern "C" {
    fn msgget(key: libc::key_t, msgflg: libc::c_int) -> libc::c_int;
    fn msgsnd(
        msqid: libc::c_int,
        msgp: *const libc::c_void,
        msgsz: libc::size_t,
        msgflg: libc::c_int,
    ) -> libc::c_int;
    fn msgrcv(
        msqid: libc::c_int,
        msgp: *mut libc::c_void,
        msgsz: libc::size_t,
        msgtyp: libc::c_long,
        msgflg: libc::c_int,
    ) -> libc::ssize_t;
    fn msgctl(msqid: libc::c_int, cmd: libc::c_int, buf: *mut libc::c_void) -> libc::c_int;
}

/// macOS `struct msqid_ds` field offsets (measured via offsetof). Used to
/// translate IPC_STAT into the Linux aarch64 `msqid64_ds` layout.
const MACOS_MSQID_DS_SIZE: usize = 116;
const MAC_MSG_CBYTES: usize = 32; // u64
const MAC_MSG_QNUM: usize = 40; // u64
const MAC_MSG_QBYTES: usize = 48; // u64
const MAC_MSG_LSPID: usize = 56; // i32
const MAC_MSG_LRPID: usize = 60; // i32
const MAC_MSG_STIME: usize = 64; // time_t (read low 8)
const MAC_MSG_RTIME: usize = 76; // time_t
const MAC_MSG_CTIME: usize = 88; // time_t

// Linux aarch64 `struct msqid64_ds` field offsets (asm-generic/msgbuf.h):
// ipc64_perm(48), msg_stime@48, msg_rtime@56, msg_ctime@64, msg_cbytes@72,
// msg_qnum@80, msg_qbytes@88, msg_lspid@96, msg_lrpid@100. Total 120.
const LIN_MSG_STIME: usize = 48;
const LIN_MSG_RTIME: usize = 56;
const LIN_MSG_CTIME: usize = 64;
const LIN_MSG_CBYTES: usize = 72;
const LIN_MSG_QNUM: usize = 80;
const LIN_MSG_QBYTES: usize = 88;
const LIN_MSG_LSPID: usize = 96;
const LIN_MSG_LRPID: usize = 100;
const LINUX_MSQID_DS_SIZE: usize = 120;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Linux aarch64 `struct ipc64_perm` (UAPI, `include/uapi/asm-generic/ipcbuf.h`).
/// 48 bytes; embedded in shmid_ds. `mode` is `__kernel_mode_t` which is
/// `unsigned int` on 64-bit kernels (so 4 bytes, NOT 2 — the old `ipc_perm`
/// form). `__unused1` is u64-aligned via a 4-byte pad following `pad2`.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Default)]
pub(super) struct LinuxIpcPerm {
    pub key: i32,       // @0
    pub uid: u32,       // @4
    pub gid: u32,       // @8
    pub cuid: u32,      // @12
    pub cgid: u32,      // @16
    pub mode: u32,      // @20
    pub seq: u16,       // @24
    pub __pad2: u16,    // @26
    pub __pad3: u32,    // @28 — aligns __unused1 to 8
    pub __unused1: u64, // @32
    pub __unused2: u64, // @40 → end @48
}

/// Linux aarch64 `struct shmid_ds` (UAPI). 112 bytes. Verified against the
/// kernel's `arch/arm64/include/uapi/asm/shmbuf.h` (which falls back to the
/// generic asm-generic/shmbuf.h for 64-bit). LTP shmctl01 reads each field.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Default)]
pub(super) struct LinuxShmidDs {
    pub shm_perm: LinuxIpcPerm, // 48
    pub shm_segsz: u64,         // 8
    pub shm_atime: u64,         // 8 — last attach time
    pub shm_dtime: u64,         // 8 — last detach time
    pub shm_ctime: u64,         // 8 — creation/last-IPC_SET time
    pub shm_cpid: i32,          // 4 — pid of creator
    pub shm_lpid: i32,          // 4 — pid of last shmop
    pub shm_nattch: u64,        // 8 — current attaches
    pub __unused4: u64,         // 8
    pub __unused5: u64,         // 8
}

const _: () = assert!(core::mem::size_of::<LinuxShmidDs>() == 112);
const _: () = assert!(core::mem::size_of::<LinuxIpcPerm>() == 48);

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
const LINUX_IPC_SET: u64 = 1;
const LINUX_IPC_STAT: u64 = 2;
const LINUX_IPC_INFO: u64 = 3;
const LINUX_SHM_STAT: u64 = 13;
const LINUX_SHM_INFO: u64 = 14;
const LINUX_SHM_STAT_ANY: u64 = 15;
const LINUX_SHM_RDONLY: u64 = 0o10000;

#[derive(Clone, Debug)]
pub(super) struct ShmSegment {
    pub path: PathBuf,
    pub size: usize,
    /// Permission bits the user requested via `shmget(.., flags & 0o777)`.
    pub mode: u32,
    /// Number of live attaches in THIS process. Linux's `shm_nattch` is a
    /// PROCESS-AGGREGATED counter — shmat across siblings each increments
    /// it. Since carrick guests fork into separate host processes that
    /// don't share dispatcher state, we track this per-process only;
    /// LTP `shmat01` exercises the single-process attach-count semantics
    /// (4 sub-tests, each verifies the count after a shmat/shmdt pair).
    pub nattch: u64,
    /// shm_ctime — Unix time (seconds) the segment was created. Linux
    /// writes this on shmget and IPC_SET; shmctl01 verifies it's within a
    /// reasonable window of "now".
    pub ctime: u64,
    /// shm_atime — last attach time. Updated on shmat.
    pub atime: u64,
    /// shm_dtime — last detach time. Updated on shmdt.
    pub dtime: u64,
}

#[derive(Default, Debug)]
pub(super) struct SysvShmState {
    /// shmid (= host inode number, truncated to i32) → segment metadata.
    /// Populated lazily: a shmat against a known key but unfamiliar shmid
    /// resolves through the filesystem and inserts on the fly.
    pub segments: HashMap<i32, ShmSegment>,
    /// Map guest VA (returned from shmat) → shmid so shmdt can find which
    /// segment to decrement when given just an address.
    pub attachments: HashMap<u64, i32>,
    /// Counter for IPC_PRIVATE segment filenames (combined with pid for
    /// uniqueness — fork-safe because each forked carrick process has its
    /// own pid).
    private_counter: AtomicU32,
}

impl SysvShmState {
    pub(super) fn new() -> Self {
        Self {
            segments: HashMap::new(),
            attachments: HashMap::new(),
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
    let fd = unsafe { libc::open(path_cstr.as_ptr(), host_flags, 0o600) }.host_syscall_errno()?;

    // ftruncate sizing: only when we created OR when no pre-existing size
    // was set. SAFE_SHMGET in LTP passes a fixed size each time; growing a
    // shared segment is allowed by Linux only on create. Mirror that: only
    // ftruncate when we actually created the file.
    if must_create && size > 0 {
        let truncated = unsafe { libc::ftruncate(fd, size as libc::off_t) }.host_syscall_errno();
        if let Err(err) = truncated {
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }

    // Stat to get the inode (= shmid). On the off chance another carrick
    // process recreated the file between open and stat, stat the open fd.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if let Err(err) = unsafe { libc::fstat(fd, &mut st) }.host_syscall_errno() {
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Use the lower 31 bits of the inode as shmid — Linux shmid_t is i32.
    // Inodes on macOS are 64-bit (HFS+ / APFS) but the low 31 bits give us
    // 2 billion values per fs which is plenty per session.
    let shmid = (st.st_ino as i32).max(1); // never 0 (would collide with shmctl(IPC_RMID))
    let actual_size = if size > 0 { size } else { st.st_size as usize };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    state
        .segments
        .entry(shmid)
        .and_modify(|s| {
            // Pre-existing key (lookup-by-key hit): refresh ctime per Linux
            // shmget when called with IPC_CREAT on an existing segment? No
            // — Linux only updates ctime on IPC_SET/RMID. Leave ctime alone.
            s.size = actual_size;
        })
        .or_insert(ShmSegment {
            path: path.clone(),
            size: actual_size,
            mode,
            nattch: 0,
            ctime: now,
            atime: 0,
            dtime: 0,
        });
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
    let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_RDWR) }.host_syscall_errno()?;
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

/// Fill a Linux `shmid_ds` (the 112-byte aarch64 UAPI form) from the
/// segment's metadata. LTP shmctl01 reads every populated field.
pub(super) fn shmid_ds_bytes(segment: &ShmSegment) -> [u8; 112] {
    let pid = std::process::id() as i32;
    let ds = LinuxShmidDs {
        shm_perm: LinuxIpcPerm {
            mode: segment.mode,
            ..Default::default()
        },
        shm_segsz: segment.size as u64,
        shm_atime: segment.atime,
        shm_dtime: segment.dtime,
        shm_ctime: segment.ctime,
        shm_cpid: pid,
        shm_lpid: pid,
        shm_nattch: segment.nattch,
        __unused4: 0,
        __unused5: 0,
    };
    // `LinuxShmidDs` is exactly 112 bytes (static-asserted above), so its
    // `as_bytes()` view is infallibly 112 bytes — copy it into the array.
    let mut out = [0u8; 112];
    out.copy_from_slice(ds.as_bytes());
    out
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
        /// alias VA arena and return the guest VA. SHM_RDONLY is honored: the
        /// alias is mapped read-only so a guest STORE faults SIGSEGV, matching
        /// Linux. `addr_hint`, SHM_REMAP and SHM_RND remain a documented arch
        /// gap — carrick owns the alias VA arena and picks the placement, so it
        /// cannot honor a caller-supplied address. Unknown shmflg bits are
        /// silently ignored (Linux do_shmat acts only on the known bits).
        fn shmat(this, cx, shmid: u64, _addr: u64, flag: u64) {
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
            let map_len = align_up_u64(size as u64, hvf_page).unwrap_or(size as u64);
            const TWO_MIB: u64 = 1 << 21;
            let alias_len = align_up_u64(map_len, TWO_MIB).unwrap_or(map_len);
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
            // SHM_RDONLY → map the alias read-only. STEP 1 (host PROT_READ)
            // makes the syscall write-path return EFAULT; STEP 2 (the alias
            // leaf built AP=RO via map_aliased) makes a DIRECT guest store
            // fault SIGSEGV — together matching Linux do_shmat.
            let host_prot = if flag & LINUX_SHM_RDONLY != 0 {
                libc::PROT_READ
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            };

            // Track the attach so shmdt can find the shmid and the
            // shm_nattch counter (read by LTP shmat01 via IPC_STAT) is
            // accurate.
            {
                let mut state = this.sysv.lock();
                state.attachments.insert(va, shmid);
                if let Some(seg) = state.segments.get_mut(&shmid) {
                    seg.nattch = seg.nattch.saturating_add(1);
                }
            }

            Ok(DispatchOutcome::MapHostAlias {
                va,
                ipa,
                len: map_len,
                payload: Vec::new(),
                file: Some((host_fd, 0, host_prot)),
            })
        }

        /// shmdt(addr). Decrement the segment's nattch and drop the
        /// addr→shmid mapping so LTP shmat01's IPC_STAT-after-shmdt sees
        /// the right count. The alias VA stays mapped in the guest until
        /// process exit (proper munmap of the alias range is a follow-up;
        /// the LTP tests we target don't observe the leak).
        fn shmdt(this, cx, addr: u64) {
            let mut state = this.sysv.lock();
            let shmid = match state.attachments.remove(&addr) {
                Some(id) => id,
                None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            if let Some(seg) = state.segments.get_mut(&shmid) {
                seg.nattch = seg.nattch.saturating_sub(1);
            }
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
                LINUX_SHM_STAT | LINUX_SHM_STAT_ANY => {
                    // SHM_STAT takes an INDEX into the kernel's segment
                    // table (NOT a shmid). It writes the shmid_ds for the
                    // segment at that index into `buf` and returns the
                    // shmid. LTP shmctl01 builds an index→shmid mapping by
                    // iterating SHM_STAT(0..N).
                    let state = this.sysv.lock();
                    let mut ids: Vec<i32> = state.segments.keys().copied().collect();
                    ids.sort();
                    let idx = shmid as usize; // SHM_STAT uses the first arg as idx
                    let target_id = match ids.get(idx) {
                        Some(id) => *id,
                        None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };
                    let segment = state.segments.get(&target_id).cloned();
                    drop(state);
                    let Some(segment) = segment else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    if buf != 0 {
                        let bytes = shmid_ds_bytes(&segment);
                        let memory = &mut *cx.memory;
                        if memory.write_bytes(buf, &bytes).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }
                    Ok(DispatchOutcome::Returned { value: target_id as i64 })
                }
                LINUX_IPC_INFO | LINUX_SHM_INFO => {
                    // Aggregate info. Linux fills `struct shminfo`
                    // (IPC_INFO) or `struct shm_info` (SHM_INFO). Return
                    // values: max shmid INDEX currently in use (Linux).
                    let state = this.sysv.lock();
                    let used_ids = state.segments.len() as i64;
                    if buf != 0 {
                        let bytes = [0u8; 112];
                        let memory = &mut *cx.memory;
                        if memory.write_bytes(buf, &bytes).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }
                    Ok(DispatchOutcome::Returned {
                        value: (used_ids - 1).max(0),
                    })
                }
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        }

        /// msgget(key, msgflg): allocate/look up a SysV message queue.
        /// Forwarded to the host (macOS has SysV message queues; IPC_CREAT/
        /// IPC_EXCL share Linux's values). Cross-process for free.
        fn msgget(this, cx, key: u64, msgflg: u64) {
            let _ = (this, cx);
            let rc = unsafe { msgget(key as i32 as libc::key_t, msgflg as i32) };
            match rc.host_syscall_errno() {
                Ok(id) => Ok(DispatchOutcome::Returned { value: id as i64 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// msgsnd(msqid, msgp, msgsz, msgflg): send a message. The msgbuf
        /// layout (`long mtype; char mtext[msgsz]`) is identical Linux↔macOS,
        /// so the buffer forwards verbatim (8-byte mtype + msgsz payload).
        fn msgsnd(this, cx, msqid: u64, msgp: GuestPtr, msgsz: u64, msgflg: u64) {
            let _ = this;
            let sz = msgsz as usize;
            // Guard the 8+sz add: an overflow would wrap to a tiny read while the
            // original huge msgsz is forwarded to the host. Linux EINVALs an
            // oversized msgsz. Probe: msgoverflow.
            let total = match sz.checked_add(8) {
                Some(t) if t <= crate::dispatch::MAX_RW_COUNT => t,
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            // Read mtype (8) + payload (sz).
            let buf = match cx.memory.read_bytes(msgp.0, total) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            let rc = unsafe {
                msgsnd(
                    msqid as i32,
                    buf.as_ptr() as *const libc::c_void,
                    sz,
                    msgflg as i32,
                )
            };
            match rc.host_syscall_errno() {
                Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg): receive a message into
        /// `msgp` (`long mtype; char mtext[msgsz]`). Returns the payload byte
        /// count received.
        fn msgrcv(this, cx, msqid: u64, msgp: GuestPtr, msgsz: u64, msgtyp: u64, msgflg: u64) {
            let _ = this;
            let sz = msgsz as usize;
            // Bound the eager allocation and guard the 8+sz add (a huge msgsz
            // would otherwise OOM-abort or wrap). Linux EINVALs oversized msgsz.
            let total = match sz.checked_add(8) {
                Some(t) if t <= crate::dispatch::MAX_RW_COUNT => t,
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            let mut buf = vec![0u8; total];
            let rc = unsafe {
                msgrcv(
                    msqid as i32,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    sz,
                    msgtyp as libc::c_long,
                    msgflg as i32,
                )
            };
            match rc.host_syscall_errno() {
                Ok(received) => {
                    let received = received as usize;
                    // Write back mtype (8) + the received payload.
                    if cx
                        .memory
                        .write_bytes(msgp.0, &buf[..8 + received])
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::Returned { value: received as i64 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// msgctl(msqid, cmd, buf). IPC_RMID forwards; IPC_STAT fills a
        /// best-effort msqid_ds (msg_qnum + msg_qbytes, the fields LTP reads);
        /// IPC_SET is a no-op success.
        fn msgctl(this, cx, msqid: u64, cmd: u64, buf: u64) {
            let _ = this;
            match cmd {
                LINUX_IPC_RMID => {
                    let rc = unsafe { msgctl(msqid as i32, libc::IPC_RMID, core::ptr::null_mut()) };
                    match rc.host_syscall_errno() {
                        Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
                        Err(errno) => Ok(DispatchOutcome::errno(errno)),
                    }
                }
                LINUX_IPC_SET => Ok(DispatchOutcome::Returned { value: 0 }),
                LINUX_IPC_STAT => {
                    // Stat into a raw macOS msqid_ds buffer (libc lacks the
                    // type on macOS); extract msg_qnum/msg_qbytes from the
                    // measured offsets.
                    let mut ds = [0u8; MACOS_MSQID_DS_SIZE];
                    let rc = unsafe {
                        msgctl(msqid as i32, libc::IPC_STAT, ds.as_mut_ptr() as *mut libc::c_void)
                    };
                    if let Err(errno) = rc.host_syscall_errno() {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let rd8 = |o: usize| {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(&ds[o..o + 8]);
                        u64::from_le_bytes(a)
                    };
                    let rd4 = |o: usize| {
                        let mut a = [0u8; 4];
                        a.copy_from_slice(&ds[o..o + 4]);
                        i32::from_le_bytes(a)
                    };
                    if buf != 0 {
                        let mut out = [0u8; LINUX_MSQID_DS_SIZE];
                        let put8 = |out: &mut [u8], o: usize, v: u64| {
                            out[o..o + 8].copy_from_slice(&v.to_le_bytes())
                        };
                        let put4 = |out: &mut [u8], o: usize, v: i32| {
                            out[o..o + 4].copy_from_slice(&v.to_le_bytes())
                        };
                        put8(&mut out, LIN_MSG_STIME, rd8(MAC_MSG_STIME));
                        put8(&mut out, LIN_MSG_RTIME, rd8(MAC_MSG_RTIME));
                        put8(&mut out, LIN_MSG_CTIME, rd8(MAC_MSG_CTIME));
                        put8(&mut out, LIN_MSG_CBYTES, rd8(MAC_MSG_CBYTES));
                        put8(&mut out, LIN_MSG_QNUM, rd8(MAC_MSG_QNUM));
                        put8(&mut out, LIN_MSG_QBYTES, rd8(MAC_MSG_QBYTES));
                        put4(&mut out, LIN_MSG_LSPID, rd4(MAC_MSG_LSPID));
                        put4(&mut out, LIN_MSG_LRPID, rd4(MAC_MSG_LRPID));
                        // ipc64_perm (bytes 0..28): the macOS msg_perm sits at
                        // offset 0 of msqid_ds — uid@0,gid@4,cuid@8,cgid@12,
                        // mode@16(u16),_seq@18(u16),_key@20(i32). Map into the
                        // Linux ipc64_perm — key@0,uid@4,gid@8,cuid@12,cgid@16,
                        // mode@20(u32),seq@24(u16). key/mode/seq come from the
                        // host stat; the owner/creator ids come from the GUEST
                        // creds (carrick's macOS process is not the guest uid).
                        // (msgctl01 reads msg_perm.key + msg_perm.mode.)
                        let rd2 = |o: usize| {
                            let mut a = [0u8; 2];
                            a.copy_from_slice(&ds[o..o + 2]);
                            u16::from_le_bytes(a)
                        };
                        let creds = this.cred_snapshot();
                        put4(&mut out, 0, rd4(20)); // key
                        put4(&mut out, 4, creds.euid as i32); // uid
                        put4(&mut out, 8, creds.egid as i32); // gid
                        put4(&mut out, 12, creds.euid as i32); // cuid
                        put4(&mut out, 16, creds.egid as i32); // cgid
                        out[20..24].copy_from_slice(&(rd2(16) as u32).to_le_bytes()); // mode
                        out[24..26].copy_from_slice(&rd2(18).to_le_bytes()); // seq
                        let memory = &mut *cx.memory;
                        if memory.write_bytes(buf, &out).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        }

        /// semget(key, nsems, semflg): allocate/look up a SysV semaphore set.
        /// Forwarded to the host (macOS has SysV semaphores); IPC_CREAT/IPC_EXCL
        /// share their values with Linux, and carrick guest processes are
        /// separate host processes, so the host kernel gives cross-process
        /// semaphore coherence for free. The host semid is returned to the
        /// guest and accepted back verbatim.
        fn semget(this, cx, key: u64, nsems: u64, semflg: u64) {
            let _ = (this, cx);
            // Linux caps nsems at SEMMSL (default 32000): nsems > SEMMSL → EINVAL
            // (LTP semget02). macOS has a much smaller limit and returns ENOSPC
            // for the same over-large request, so validate against the Linux
            // limit before forwarding to the host.
            const LINUX_SEMMSL: i32 = 32000;
            if (nsems as i32) > LINUX_SEMMSL {
                return Ok(LINUX_EINVAL.into());
            }
            let rc = unsafe {
                libc::semget(key as i32 as libc::key_t, nsems as i32, semflg as i32)
            };
            match rc.host_syscall_errno() {
                Ok(id) => Ok(DispatchOutcome::Returned { value: id as i64 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// semop(semid, sops, nsops): apply an array of `struct sembuf`. The
        /// Linux and macOS `sembuf` layouts are identical (sem_num:u16@0,
        /// sem_op:i16@2, sem_flg:i16@4 = 6 bytes), so the array forwards
        /// without translation. Blocking ops (no IPC_NOWAIT) block the host
        /// thread in `semop` — acceptable for the single-guest model.
        ///
        /// SEM_UNDO (audit M10): the flag is carried verbatim in `sem_flg` to
        /// the host `semop`, and carrick runs each guest process as a real host
        /// child, so the macOS kernel tracks the per-process undo adjustments and
        /// applies them when the guest process exits — the undo-on-exit contract
        /// is satisfied by the host for the common case. carrick keeps no
        /// separate undo list. The residual divergence is the narrow case where
        /// a guest `exit_group`/thread teardown does NOT coincide with host
        /// process death; a carrick-managed undo replay for that case is a
        /// tracked follow-up (it needs the multiprocess LTP semaphore harness to
        /// verify), not an accepted limitation of the primitive.
        fn semop(this, cx, semid: u64, sops: GuestPtr, nsops: u64) {
            sysv_semop(cx, semid as i32, sops.0, nsops as usize, None)
        }

        /// semtimedop(semid, sops, nsops, timeout): semop with a relative
        /// timeout (struct timespec). macOS lacks semtimedop, so we emulate
        /// the bounded wait by retrying IPC_NOWAIT semop until the deadline.
        fn semtimedop(this, cx, semid: u64, sops: GuestPtr, nsops: u64, timeout: GuestPtr) {
            let to = if timeout.0 == 0 {
                None
            } else {
                match read_timespec(&*cx.memory, timeout.0) {
                    Ok(ts) => Some(ts),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            sysv_semop(cx, semid as i32, sops.0, nsops as usize, to)
        }

        /// semctl(semid, semnum, cmd, arg). The command constants differ
        /// between Linux and macOS and are translated; the union `arg` is
        /// interpreted per command (int for SETVAL, u16[] for GET/SETALL,
        /// semid_ds* for IPC_STAT/SET).
        fn semctl(this, cx, semid: u64, semnum: u64, cmd: u64, arg: u64) {
            let _ = this;
            sysv_semctl(cx, semid as i32, semnum as i32, cmd, arg)
        }
    }
}

// Linux SysV semaphore command constants (linux/sem.h + ipc.h).
const LINUX_GETPID: u64 = 11;
const LINUX_GETVAL: u64 = 12;
const LINUX_GETALL: u64 = 13;
const LINUX_GETNCNT: u64 = 14;
const LINUX_GETZCNT: u64 = 15;
const LINUX_SETVAL: u64 = 16;
const LINUX_SETALL: u64 = 17;
const LINUX_SEM_IPC_NOWAIT: i16 = 0o4000; // IPC_NOWAIT in sem_flg

/// Shared semop / semtimedop core. Reads the `nsops` sembuf entries (Linux ==
/// macOS layout) and forwards to host `semop`. For a timed wait (macOS has no
/// semtimedop) it retries an IPC_NOWAIT variant until the deadline, mapping a
/// would-block to ETIMEDOUT/EAGAIN per the deadline.
fn sysv_semop<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    semid: i32,
    sops_addr: u64,
    nsops: usize,
    timeout: Option<LinuxTimespec>,
) -> Result<DispatchOutcome, DispatchError> {
    if nsops == 0 || nsops > 1024 {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    // sembuf is 6 bytes; read the whole array.
    let bytes = match cx.memory.read_bytes(sops_addr, nsops * 6) {
        Ok(b) => b,
        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
    };
    let mut sops: Vec<libc::sembuf> = Vec::with_capacity(nsops);
    for i in 0..nsops {
        let o = i * 6;
        sops.push(libc::sembuf {
            sem_num: u16::from_le_bytes([bytes[o], bytes[o + 1]]),
            sem_op: i16::from_le_bytes([bytes[o + 2], bytes[o + 3]]),
            sem_flg: i16::from_le_bytes([bytes[o + 4], bytes[o + 5]]),
        });
    }

    if timeout.is_none() {
        let rc = unsafe { libc::semop(semid, sops.as_mut_ptr(), nsops) };
        return match rc.host_syscall_errno() {
            Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::errno(errno)),
        };
    }

    // Timed: poll with IPC_NOWAIT until the relative deadline. Force NOWAIT on
    // every op so the host call returns EAGAIN instead of blocking past the
    // timeout; on EAGAIN we sleep briefly and retry until the deadline, then
    // surface EAGAIN (Linux semtimedop returns EAGAIN on timeout).
    // `timeout.is_none()` returned above, so this is always Some; the else arm
    // is unreachable but keeps us off `unwrap()` (workspace denies it).
    let Some(ts) = timeout else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    let total_ns = (ts.tv_sec.max(0) as u128) * 1_000_000_000 + ts.tv_nsec.max(0) as u128;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_nanos(total_ns.min(u64::MAX as u128) as u64);
    let mut nowait = sops.clone();
    for s in &mut nowait {
        s.sem_flg |= LINUX_SEM_IPC_NOWAIT;
    }
    loop {
        let mut attempt = nowait.clone();
        let rc = unsafe { libc::semop(semid, attempt.as_mut_ptr(), nsops) };
        match rc.host_syscall_errno() {
            Ok(_) => return Ok(DispatchOutcome::Returned { value: 0 }),
            Err(e) if e == LINUX_EAGAIN => {
                if std::time::Instant::now() >= deadline {
                    return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        }
    }
}

/// Translate a Linux semctl command to the macOS value. Returns `None` for a
/// command macOS doesn't have (SEM_STAT/SEM_INFO).
fn linux_semctl_cmd_to_host(cmd: u64) -> Option<i32> {
    Some(match cmd {
        LINUX_IPC_RMID => libc::IPC_RMID,
        LINUX_IPC_SET => libc::IPC_SET,
        LINUX_IPC_STAT => libc::IPC_STAT,
        LINUX_GETPID => libc::GETPID,
        LINUX_GETVAL => libc::GETVAL,
        LINUX_GETALL => libc::GETALL,
        LINUX_GETNCNT => libc::GETNCNT,
        LINUX_GETZCNT => libc::GETZCNT,
        LINUX_SETVAL => libc::SETVAL,
        LINUX_SETALL => libc::SETALL,
        _ => return None,
    })
}

fn sysv_semctl<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    semid: i32,
    semnum: i32,
    cmd: u64,
    arg: u64,
) -> Result<DispatchOutcome, DispatchError> {
    let Some(host_cmd) = linux_semctl_cmd_to_host(cmd) else {
        // SEM_STAT/SEM_INFO and friends: not supported on macOS.
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };

    // Commands that take NO arg or return a value directly.
    match cmd {
        LINUX_IPC_RMID | LINUX_GETPID | LINUX_GETVAL | LINUX_GETNCNT | LINUX_GETZCNT => {
            let rc = unsafe { libc::semctl(semid, semnum, host_cmd) };
            match rc.host_syscall_errno() {
                Ok(v) => Ok(DispatchOutcome::Returned { value: v as i64 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }
        LINUX_SETVAL => {
            // arg is `union semun { int val }`. Linux requires the value be in
            // [0, SEMVMX(32767)]; out of range → ERANGE (semctl05). macOS does
            // not enforce the Linux bound, so validate before forwarding.
            const SEMVMX: i32 = 32767;
            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ERANGE));
            }
            let rc = unsafe { libc::semctl(semid, semnum, host_cmd, val) };
            match rc.host_syscall_errno() {
                Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }
        LINUX_GETALL | LINUX_SETALL => {
            // arg is `unsigned short *array`. Find nsems via IPC_STAT.
            let nsems = match host_sem_nsems(semid) {
                Ok(n) => n,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let mut vals: Vec<u16> = vec![0; nsems];
            if cmd == LINUX_SETALL {
                let bytes = match cx.memory.read_bytes(arg, nsems * 2) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                for (i, v) in vals.iter_mut().enumerate() {
                    *v = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
                }
                // SETALL: every value must be <= SEMVMX(32767) → else ERANGE
                // (semctl05; macOS doesn't enforce the Linux bound).
                if vals.iter().any(|&v| v > 32767) {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ERANGE));
                }
            }
            let rc = unsafe { libc::semctl(semid, 0, host_cmd, vals.as_mut_ptr()) };
            match rc.host_syscall_errno() {
                Ok(_) => {
                    if cmd == LINUX_GETALL {
                        let mut out = Vec::with_capacity(nsems * 2);
                        for v in &vals {
                            out.extend_from_slice(&v.to_le_bytes());
                        }
                        if cx.memory.write_bytes(arg, &out).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }
        LINUX_IPC_STAT | LINUX_IPC_SET => {
            // semid_ds translation. LTP's sem tests mostly read sem_nsems +
            // sem_perm; fill those from the host. Full IPC_SET (writing perms)
            // is a best-effort no-op success for now.
            if cmd == LINUX_IPC_SET {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let nsems = match host_sem_nsems(semid) {
                Ok(n) => n,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            // Linux semid_ds: ipc_perm(48) then sem_otime(8) sem_ctime(8)
            // sem_nsems(8)... Write a zeroed buffer with sem_nsems filled at
            // the Linux offset (ipc_perm 48 + otime 8 + ctime 8 = 64).
            if arg != 0 {
                let mut buf = [0u8; 104];
                buf[64..72].copy_from_slice(&(nsems as u64).to_le_bytes());
                if cx.memory.write_bytes(arg, &buf).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }
        _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
    }
}

/// Number of semaphores in the set, via host IPC_STAT.
fn host_sem_nsems(semid: i32) -> Result<usize, i32> {
    let mut ds: libc::semid_ds = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::semctl(semid, 0, libc::IPC_STAT, &mut ds as *mut libc::semid_ds) };
    rc.host_syscall_errno().map(|_| ds.sem_nsems as usize)
}
