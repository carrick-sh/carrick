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
//!   - shmdt(addr) → invalidate the alias mapping, retire its complete VMA
//!     metadata, and then remove the attachment/decrement `nattch`. Ambiguous
//!     backend teardown failure is fail-stop rather than exposing split ownership.
//!   - shmctl(shmid, IPC_RMID, NULL) → unlink the backing file. Existing
//!     mmaps remain valid (Linux mmap+unlink semantics).
//!   - shmctl(shmid, IPC_STAT, buf) → fill an `shmid_ds` from carrick's
//!     segment metadata (size, permissions, attach/detach bookkeeping).
//!
//! What this does NOT implement (yet):
//!   - SHM_REMAP.
//!   - Complete SysV semaphore parity; this module still forwards semaphores to
//!     host SysV semaphores with Carrick-owned guest metadata layered above.

use super::*;
use crate::linux_abi::{LINUX_EIO, LINUX_ENOMSG, LINUX_ENOSPC, LinuxErrno};
use carrick_abi::{NsGid, NsUid};

syscall_table! {
    /// Per-module syscall routing for the `sysv` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `sysv` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_sysv;
    186 => msgget,
    187 => msgctl,
    188 => msgrcv,
    189 => msgsnd,
    190 => semget,
    191 => semctl,
    192 => semtimedop,
    193 => semop,
    194 => shmget,
    195 => shmctl,
    196 => shmat,
    197 => shmdt,
}

// Linux aarch64 `struct msqid64_ds` field offsets (asm-generic/msgbuf.h):
// ipc64_perm(48), msg_stime@48, msg_rtime@56, msg_ctime@64, msg_cbytes@72,
// msg_qnum@80, msg_qbytes@88, msg_lspid@96, msg_lrpid@100. Total 120.
const LIN_MSG_QBYTES: usize = 88;
const LINUX_MSQID_DS_SIZE: usize = 120;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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

/// Linux aarch64 `struct semid64_ds` (UAPI, `include/uapi/asm-generic/sembuf.h`
/// — 64-bit time_t form). 88 bytes: ipc64_perm(48), sem_otime@48, sem_ctime@56,
/// sem_nsems@64, then two reserved u64. (On a 64-bit-time_t arch the kernel's
/// legacy otime/ctime-high split words read as zero, so the reserved tail is 0.)
/// LTP semctl01 reads sem_perm.mode, the owner ids, sem_nsems and sem_otime/
/// sem_ctime.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Default)]
pub(super) struct LinuxSemidDs {
    pub sem_perm: LinuxIpcPerm, // 48
    pub sem_otime: u64,         // 8 — last semop time
    pub sem_ctime: u64,         // 8 — creation/last-IPC_SET time
    pub sem_nsems: u64,         // 8 — number of semaphores in the set
    pub __unused3: u64,         // 8
    pub __unused4: u64,         // 8
}

const _: () = assert!(core::mem::size_of::<LinuxSemidDs>() == 88);

/// Linux aarch64 `struct msqid64_ds` (UAPI). 120 bytes: ipc64_perm(48), three
/// 64-bit timestamps, cbytes/qnum/qbytes, last sender/receiver pids, and two
/// reserved u64 slots. Carrick owns SysV message queue state, so `IPC_STAT`
/// serializes directly from this metadata instead of translating a host
/// `msqid_ds`.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Default)]
pub(super) struct LinuxMsqidDs {
    pub msg_perm: LinuxIpcPerm, // 48
    pub msg_stime: u64,         // 8
    pub msg_rtime: u64,         // 8
    pub msg_ctime: u64,         // 8
    pub msg_cbytes: u64,        // 8
    pub msg_qnum: u64,          // 8
    pub msg_qbytes: u64,        // 8
    pub msg_lspid: i32,         // 4
    pub msg_lrpid: i32,         // 4
    pub __unused4: u64,         // 8
    pub __unused5: u64,         // 8
}

const _: () = assert!(core::mem::size_of::<LinuxMsqidDs>() == LINUX_MSQID_DS_SIZE);

/// Host directory for SysV shmem backing files. World-writable + sticky so
/// any carrick guest process (including a forked child running as the same
/// uid) can attach to a segment a peer created.
const SHM_DIR: &str = "/tmp/carrick-shm";

/// Linux SysV IPC command numbers and limits. Flag domains below use typed
/// wrappers instead of reusing these raw command values.
const LINUX_IPC_PRIVATE: i32 = 0;
const LINUX_IPC_RMID: u64 = 0;
const LINUX_IPC_SET: u64 = 1;
const LINUX_IPC_STAT: u64 = 2;
const LINUX_IPC_INFO: u64 = 3;
const LINUX_SHM_STAT: u64 = 13;
const LINUX_SHM_INFO: u64 = 14;
const LINUX_SHM_STAT_ANY: u64 = 15;
const LINUX_SHMMNI: usize = 4096;
const LINUX_SHM_LOCK: u64 = 11;
const LINUX_SHM_UNLOCK: u64 = 12;
const LINUX_SEM_STAT: u64 = 18;
const LINUX_SEM_INFO: u64 = 19;
const LINUX_SEM_STAT_ANY: u64 = 20;
const LINUX_SEMMSL: usize = 32000;
const LINUX_SEMMNI: usize = 32000;
const LINUX_SEMOPM: u32 = 500;
const LINUX_SEMVMX: u32 = 32767;
const LINUX_MSGMNI: usize = 8;
const LINUX_MSGMNB: u64 = 16384;
const LINUX_MSGMAX: usize = 8192;
const LINUX_MSG_STAT: u64 = 11;
const LINUX_MSG_INFO: u64 = 12;
const LINUX_MSG_STAT_ANY: u64 = 13;

const MSG_QUEUE_MAGIC: u32 = 0x5356_4d51; // "SVMQ"
const MSG_QUEUE_VERSION: u32 = 1;
const MSG_QUEUE_HEADER_SIZE: usize = 128;
const MSG_RECORD_HEADER_SIZE: usize = 16;
const MSG_QUEUE_COMPACT_HEAD_THRESHOLD: usize = 64 * 1024;
const MSG_QUEUE_WAIT_WORD_BYTES: usize = std::mem::size_of::<std::sync::atomic::AtomicU32>();

const MSG_OFF_MAGIC: usize = 0;
const MSG_OFF_VERSION: usize = 4;
const MSG_OFF_KEY: usize = 8;
const MSG_OFF_ID: usize = 12;
const MSG_OFF_MODE: usize = 16;
const MSG_OFF_UID: usize = 20;
const MSG_OFF_GID: usize = 24;
const MSG_OFF_CUID: usize = 28;
const MSG_OFF_CGID: usize = 32;
const MSG_OFF_QBYTES: usize = 40;
const MSG_OFF_CBYTES: usize = 48;
const MSG_OFF_QNUM: usize = 56;
const MSG_OFF_STIME: usize = 64;
const MSG_OFF_RTIME: usize = 72;
const MSG_OFF_CTIME: usize = 80;
const MSG_OFF_LSPID: usize = 88;
const MSG_OFF_LRPID: usize = 92;
const MSG_OFF_HEAD: usize = 96;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct IpcCreateFlags: u64 {
        const CREAT = 0o1000;
        const EXCL = 0o2000;
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct ShmAttachFlags: u64 {
        const RDONLY = 0o10000;
        const RND = 0o20000;
        const REMAP = 0o40000;
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct ShmModeFlags: u32 {
        const LOCKED = 0o2000;
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct SemOpFlags: u16 {
        const NOWAIT = 0o4000;
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct MsgOpFlags: u64 {
        const NOWAIT = 0o4000;
        const NOERROR = 0o10000;
        const EXCEPT = 0o20000;
        const COPY = 0o40000;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ShmPermMode {
    bits: u32,
}

impl ShmPermMode {
    const PERMS_MASK: u32 = 0o777;

    fn requested(flags: u64) -> Self {
        Self {
            bits: (flags as u32) & Self::PERMS_MASK,
        }
    }

    fn from_ipc_set(raw: u32, current: Self) -> Self {
        Self {
            bits: (current.bits & ShmModeFlags::LOCKED.bits()) | (raw & Self::PERMS_MASK),
        }
    }

    fn raw(self) -> u32 {
        self.bits
    }

    fn perms(self) -> u32 {
        self.bits & Self::PERMS_MASK
    }

    fn is_empty_perms(self) -> bool {
        self.perms() == 0
    }

    fn set_locked(&mut self, locked: bool) {
        if locked {
            self.bits |= ShmModeFlags::LOCKED.bits();
        } else {
            self.bits &= !ShmModeFlags::LOCKED.bits();
        }
    }

    fn owner_readable(self) -> bool {
        self.bits & 0o400 != 0
    }

    fn other_readable(self) -> bool {
        self.bits & 0o004 != 0
    }

    fn owner_writable(self) -> bool {
        self.bits & 0o200 != 0
    }

    fn other_writable(self) -> bool {
        self.bits & 0o002 != 0
    }
}

#[derive(Clone, Debug)]
pub(super) struct ShmSegment {
    pub path: PathBuf,
    pub key: i32,
    pub size: usize,
    /// Guest-visible SysV shm permission/mode bits.
    pub mode: ShmPermMode,
    pub uid: NsUid,
    pub gid: NsGid,
    pub cuid: NsUid,
    pub cgid: NsGid,
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
    /// Guest namespace pid of the creator.
    pub cpid: i32,
    /// Guest namespace pid of the last shmat/shmdt operator.
    pub lpid: i32,
}

impl ShmSegment {
    fn can_read(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_readable()
            } else {
                self.mode.other_readable()
            }
    }

    fn can_write(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_writable()
            } else {
                self.mode.other_writable()
            }
    }
}

#[derive(Clone, Debug)]
struct SemSet {
    key: i32,
    scan_index: SemScanIndex,
    nsems: usize,
    mode: ShmPermMode,
    uid: NsUid,
    gid: NsGid,
    cuid: NsUid,
    cgid: NsGid,
    ctime: u64,
    otime: u64,
    values: Arc<Mutex<Vec<u16>>>,
    /// Linux `sempid` per semaphore.
    logical_last_operators: Arc<Mutex<Vec<Option<i32>>>>,
    /// Linux `semncnt`/`semzcnt` per semaphore.
    logical_wait_counts: SemWaitCounters,
    changed: Arc<parking_lot::Condvar>,
}

/// Linux sembuf ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinuxSembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

/// Which Linux blocked-waiter counter a `semop` operation feeds while parked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemWaitKind {
    /// `sem_op < 0` — waiting for the value to INCREASE (semctl `GETNCNT`).
    Increase,
    /// `sem_op == 0` — waiting for the value to reach ZERO (semctl `GETZCNT`).
    Zero,
}

impl SemWaitKind {
    /// The counter a single `sembuf` feeds, or `None` for `sem_op > 0` — an
    /// increment always completes, so it never parks a waiter.
    fn for_op(sem_op: i16) -> Option<Self> {
        match sem_op.cmp(&0) {
            std::cmp::Ordering::Less => Some(Self::Increase),
            std::cmp::Ordering::Equal => Some(Self::Zero),
            std::cmp::Ordering::Greater => None,
        }
    }
}

/// One semaphore set's blocked-waiter counters, shared by `Arc` so every
/// in-process fork clone of the dispatcher reads and writes the same authority.
type SemWaitCounters = Arc<Mutex<Vec<SemWaitCounts>>>;

/// Carrick's own blocked-waiter counts for one semaphore of a set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SemWaitCounts {
    increase: u32,
    zero: u32,
}

impl SemWaitCounts {
    fn get(self, kind: SemWaitKind) -> u32 {
        match kind {
            SemWaitKind::Increase => self.increase,
            SemWaitKind::Zero => self.zero,
        }
    }

    fn slot_mut(&mut self, kind: SemWaitKind) -> &mut u32 {
        match kind {
            SemWaitKind::Increase => &mut self.increase,
            SemWaitKind::Zero => &mut self.zero,
        }
    }

    fn enter_wait(&mut self, kind: SemWaitKind) {
        let slot = self.slot_mut(kind);
        *slot = slot.saturating_add(1);
    }

    fn leave_wait(&mut self, kind: SemWaitKind) {
        let slot = self.slot_mut(kind);
        *slot = slot.saturating_sub(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GuestSemId(i32);

impl GuestSemId {
    fn from_syscall_arg(value: i32) -> Result<Self, LinuxErrno> {
        if value < 0 {
            Err(LINUX_EINVAL)
        } else {
            Ok(GuestSemId(value))
        }
    }

    fn as_i64(self) -> i64 {
        i64::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct MsgQueueId(i32);

impl MsgQueueId {
    fn from_syscall_arg(value: u64) -> Result<Self, LinuxErrno> {
        let raw = i32::try_from(value).map_err(|_| LINUX_EINVAL)?;
        if raw < 0 {
            Err(LINUX_EINVAL)
        } else {
            Ok(Self(raw))
        }
    }

    fn raw(self) -> i32 {
        self.0
    }

    fn as_i64(self) -> i64 {
        i64::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MsgKey(i32);

impl MsgKey {
    const PRIVATE: Self = Self(LINUX_IPC_PRIVATE);

    fn from_syscall_arg(value: u64) -> Result<Self, LinuxErrno> {
        i32::try_from(value).map(Self).map_err(|_| LINUX_EINVAL)
    }

    fn raw(self) -> i32 {
        self.0
    }

    fn is_private(self) -> bool {
        self == Self::PRIVATE
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MsgType(i64);

impl MsgType {
    fn from_msgbuf(value: i64) -> Result<Self, LinuxErrno> {
        if value <= 0 {
            Err(LINUX_EINVAL)
        } else {
            Ok(Self(value))
        }
    }

    fn from_syscall_arg(value: u64) -> Self {
        Self(value as i64)
    }

    fn raw(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug)]
struct MsgRecord {
    msg_type: MsgType,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MsgQueueMetrics {
    queues: usize,
    messages: usize,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemStatSelector {
    StatIndex(SemScanIndex),
    AnyIndex(SemScanIndex),
}

impl SemStatSelector {
    fn scan_index(self) -> SemScanIndex {
        match self {
            SemStatSelector::StatIndex(index) | SemStatSelector::AnyIndex(index) => index,
        }
    }

    fn enforces_read_permission(self) -> bool {
        matches!(self, SemStatSelector::StatIndex(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SemScanIndex(u32);

impl SemScanIndex {
    fn from_semctl_arg(value: i32) -> Result<Self, LinuxErrno> {
        u32::try_from(value)
            .map(SemScanIndex)
            .map_err(|_| LINUX_EINVAL)
    }

    fn as_i64(self) -> i64 {
        i64::from(self.0)
    }
}

impl SemSet {
    fn can_admin(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root() || creds.euid == self.uid || creds.euid == self.cuid
    }

    fn can_read(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_readable()
            } else {
                self.mode.other_readable()
            }
    }

    fn can_write(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_writable()
            } else {
                self.mode.other_writable()
            }
    }

    fn record_logical_semop(&self, pid: i32, sops: &[LinuxSembuf]) {
        let mut operators = self.logical_last_operators.lock();
        for sop in sops {
            if let Some(operator) = operators.get_mut(usize::from(sop.sem_num)) {
                *operator = Some(pid);
            }
        }
    }

    fn record_logical_setval(&self, pid: i32, semnum: i32) {
        let Ok(index) = usize::try_from(semnum) else {
            return;
        };
        if let Some(operator) = self.logical_last_operators.lock().get_mut(index) {
            *operator = Some(pid);
        }
    }

    fn record_logical_setall(&self, pid: i32) {
        self.logical_last_operators.lock().fill(Some(pid));
    }

    fn logical_last_operator(&self, semnum: i32) -> Option<i32> {
        let index = usize::try_from(semnum).ok()?;
        self.logical_last_operators
            .lock()
            .get(index)
            .copied()
            .flatten()
    }

    /// Carrick's blocked-waiter count for one semaphore, the value semctl
    /// `GETNCNT`/`GETZCNT` must report.
    fn logical_wait_count(&self, semnum: i32, kind: SemWaitKind) -> Option<u32> {
        let index = usize::try_from(semnum).ok()?;
        self.logical_wait_counts
            .lock()
            .get(index)
            .map(|counts| counts.get(kind))
    }
}

pub(crate) struct HostAliasShmatCommit {
    pub(super) va: u64,
    pub(super) shmid: i32,
    pub(super) atime: u64,
    pub(super) lpid: i32,
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
    /// SysV attachment starts that have been passed to remap_file_pages(2).
    /// Linux no longer accepts those addresses as shmdt(2) segment starts; LTP
    /// shmctl05 depends on that EINVAL path while racing IPC_RMID.
    pub remapped_attachments: HashSet<u64>,
    /// Counter for IPC_PRIVATE segment filenames (combined with pid for
    /// uniqueness — fork-safe because each forked carrick process has its
    /// own pid).
    private_counter: AtomicU32,
    /// Carrick-owned SysV message queues created by this dispatcher. The queue
    /// contents and metadata live in files under [`SHM_DIR`] so forked guest
    /// processes see one Linux IPC namespace instead of per-process maps or
    /// Darwin's host-global SysV queue pool.
    message_queues: HashSet<MsgQueueId>,
    /// Host SysV semaphore sets observed through guest `semget`, with guest
    /// ownership/mode metadata layered over the host primitive.
    semaphores: HashMap<GuestSemId, SemSet>,
    sem_keys: HashMap<i32, GuestSemId>,
    next_sem_scan_index: u32,
}

impl SysvShmState {
    pub(super) fn new() -> Self {
        Self {
            segments: HashMap::new(),
            attachments: HashMap::new(),
            remapped_attachments: HashSet::new(),
            private_counter: AtomicU32::new(1),
            message_queues: HashSet::new(),
            semaphores: HashMap::new(),
            sem_keys: HashMap::new(),
            next_sem_scan_index: 0,
        }
    }

    pub(super) fn fork_clone(&self) -> Self {
        Self {
            segments: self.segments.clone(),
            attachments: self.attachments.clone(),
            remapped_attachments: self.remapped_attachments.clone(),
            private_counter: AtomicU32::new(self.private_counter.load(Ordering::Relaxed)),
            message_queues: self.message_queues.clone(),
            semaphores: self.semaphores.clone(),
            sem_keys: self.sem_keys.clone(),
            next_sem_scan_index: self.next_sem_scan_index,
        }
    }

    fn allocate_sem_id(&mut self) -> Result<(GuestSemId, SemScanIndex), LinuxErrno> {
        let raw = i32::try_from(self.next_sem_scan_index).map_err(|_| LINUX_ENOSPC)?;
        let index = SemScanIndex(self.next_sem_scan_index);
        self.next_sem_scan_index = self.next_sem_scan_index.saturating_add(1);
        Ok((GuestSemId(raw), index))
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
        format!(
            "{}-private-{}-{}",
            sysv_run_scope(),
            std::process::id(),
            counter
        )
    }

    fn key_name(key: i32) -> String {
        format!("{}-key-{}", sysv_run_scope(), key as u32)
    }
}

struct SysvIpcService;

impl SysvIpcService {
    fn after_fork_child() {
        MSG_QUEUE_FD_CACHE.with(|cache| cache.borrow_mut().refresh_for_current_process());
    }

    fn cleanup_process_exit(state: &mut SysvShmState) {
        state.message_queues.clear();
        cleanup_msg_queue_files_for_scope();
    }

    fn msg_table() -> String {
        sysvipc_msg_table_from_files()
    }

    fn msgget(
        state: &mut SysvShmState,
        creds: &crate::kernel::Credentials,
        key: MsgKey,
        flags: u64,
    ) -> Result<MsgQueueId, LinuxErrno> {
        msgget_open(state, creds, key, flags)
    }

    fn msgsnd(
        id: MsgQueueId,
        creds: &crate::kernel::Credentials,
        msg_type: MsgType,
        payload: &[u8],
        operator: i32,
    ) -> Result<bool, LinuxErrno> {
        msg_queue_try_send(id, creds, msg_type, payload, operator)
    }

    #[allow(clippy::too_many_arguments)]
    fn msgrcv<M: GuestMemory>(
        cx: &mut SyscallCtx<M>,
        id: MsgQueueId,
        creds: &crate::kernel::Credentials,
        msgp: u64,
        msgsz: usize,
        wanted: MsgType,
        flags: MsgOpFlags,
        operator: i32,
    ) -> Result<Option<usize>, LinuxErrno> {
        msg_queue_receive(cx, id, creds, msgp, msgsz, wanted, flags, operator)
    }

    fn msgctl<M: GuestMemory>(
        dispatcher: &SyscallDispatcher,
        cx: &mut SyscallCtx<M>,
        msqid: u64,
        cmd: u64,
        buf: u64,
    ) -> Result<DispatchOutcome, LinuxErrno> {
        sysv_msgctl(dispatcher, cx, msqid, cmd, buf)
    }
}

static SYSV_FALLBACK_ROOT_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Freeze the no-run-id SysV IPC scope before creating the first guest
/// process. Descendants must keep using the top-level runtime pid: recomputing
/// `pid-{getpid()}` after a host fork splits one guest IPC namespace into one
/// directory namespace per process.
#[allow(dead_code)]
pub(crate) fn init_sysv_run_scope() {
    let _ = SYSV_FALLBACK_ROOT_PID.compare_exchange(
        0,
        std::process::id(),
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    );
}

fn sysv_run_scope() -> String {
    let raw = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        std::env::var("CARRICK_CONTAINER_ID").unwrap_or_else(|_| {
            let frozen = SYSV_FALLBACK_ROOT_PID.load(std::sync::atomic::Ordering::Acquire);
            let root_pid = if frozen == 0 {
                std::process::id()
            } else {
                frozen
            };
            format!("pid-{root_pid}")
        })
    });
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
fn scoped_host_sem_key(key: i32) -> libc::key_t {
    if key == LINUX_IPC_PRIVATE {
        return LINUX_IPC_PRIVATE as libc::key_t;
    }
    scoped_host_sem_key_for_scope(&sysv_run_scope(), key)
}

#[cfg(test)]
fn scoped_host_sem_key_for_scope(scope: &str, key: i32) -> libc::key_t {
    // Darwin SysV semaphore keys live in one host-global pool. Linux containers
    // get an IPC namespace, so mix Carrick's run scope into the host key while
    // preserving the guest-visible key in Carrick metadata.
    let mut hash = 0x811c_9dc5u32;
    for byte in scope.as_bytes().iter().copied().chain(key.to_le_bytes()) {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let raw = (hash & 0x7fff_ffff) as i32;
    let scoped = if raw == LINUX_IPC_PRIVATE { 1 } else { raw };
    // The scoped key is computed in the non-negative i32 hash domain above;
    // it escapes into the host's `key_t` only at this libc return boundary
    // (a lossless widen where `key_t` is i64, as on FreeBSD; identity where
    // it is i32 — same escape as `scoped_host_sem_key`'s IPC_PRIVATE arm).
    scoped as libc::key_t
}

fn shm_nattch_path(path: &std::path::Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".nattch");
    PathBuf::from(out)
}

fn rd_u32(buf: &[u8], off: usize) -> u32 {
    match buf.get(off..off + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

fn rd_i32(buf: &[u8], off: usize) -> i32 {
    match buf.get(off..off + 4) {
        Some(b) => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

fn rd_u64(buf: &[u8], off: usize) -> u64 {
    match buf.get(off..off + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

fn rd_i64(buf: &[u8], off: usize) -> i64 {
    match buf.get(off..off + 8) {
        Some(b) => i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

fn wr_u32(buf: &mut [u8], off: usize, value: u32) {
    if let Some(dst) = buf.get_mut(off..off + 4) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

fn wr_i32(buf: &mut [u8], off: usize, value: i32) {
    if let Some(dst) = buf.get_mut(off..off + 4) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

fn wr_u64(buf: &mut [u8], off: usize, value: u64) {
    if let Some(dst) = buf.get_mut(off..off + 8) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

fn wr_i64(buf: &mut [u8], off: usize, value: i64) {
    if let Some(dst) = buf.get_mut(off..off + 8) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

#[derive(Clone, Debug)]
struct MsgQueueFile {
    id: MsgQueueId,
    key: i32,
    mode: ShmPermMode,
    uid: NsUid,
    gid: NsGid,
    cuid: NsUid,
    cgid: NsGid,
    qbytes: u64,
    cbytes: u64,
    stime: u64,
    rtime: u64,
    ctime: u64,
    lspid: i32,
    lrpid: i32,
    qnum: u64,
    messages: Vec<MsgRecord>,
}

impl MsgQueueFile {
    fn new(
        id: MsgQueueId,
        key: i32,
        mode: ShmPermMode,
        creds: &crate::kernel::Credentials,
    ) -> Self {
        let now = unix_now_secs();
        Self {
            id,
            key,
            mode,
            uid: creds.euid,
            gid: creds.egid,
            cuid: creds.euid,
            cgid: creds.egid,
            qbytes: LINUX_MSGMNB,
            cbytes: 0,
            stime: 0,
            rtime: 0,
            ctime: now,
            lspid: 0,
            lrpid: 0,
            qnum: 0,
            messages: Vec::new(),
        }
    }

    fn can_admin(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root() || creds.euid == self.uid || creds.euid == self.cuid
    }

    fn can_read(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_readable()
            } else {
                self.mode.other_readable()
            }
    }

    fn can_write(&self, creds: &crate::kernel::Credentials) -> bool {
        creds.euid.is_root()
            || if creds.euid == self.uid {
                self.mode.owner_writable()
            } else {
                self.mode.other_writable()
            }
    }

    fn parse(buf: &[u8]) -> Result<Self, LinuxErrno> {
        if buf.len() < MSG_QUEUE_HEADER_SIZE
            || rd_u32(buf, MSG_OFF_MAGIC) != MSG_QUEUE_MAGIC
            || rd_u32(buf, MSG_OFF_VERSION) != MSG_QUEUE_VERSION
        {
            return Err(LINUX_EINVAL);
        }
        let header_qnum = rd_u64(buf, MSG_OFF_QNUM);
        let stored_head = rd_u64(buf, MSG_OFF_HEAD);
        let mut messages = Vec::new();
        let mut off = usize::try_from(stored_head)
            .ok()
            .filter(|head| *head >= MSG_QUEUE_HEADER_SIZE && *head <= buf.len())
            .unwrap_or(MSG_QUEUE_HEADER_SIZE);
        while off < buf.len()
            && u64::try_from(messages.len())
                .map(|len| len < header_qnum)
                .unwrap_or(false)
        {
            let Some(header) = buf.get(off..off + MSG_RECORD_HEADER_SIZE) else {
                return Err(LINUX_EINVAL);
            };
            let msg_type = MsgType::from_msgbuf(rd_i64(header, 0))?;
            let len = rd_u32(header, 8) as usize;
            let data_off = off + MSG_RECORD_HEADER_SIZE;
            let Some(payload) = buf.get(data_off..data_off + len) else {
                return Err(LINUX_EINVAL);
            };
            messages.push(MsgRecord {
                msg_type,
                payload: payload.to_vec(),
            });
            off = data_off + len;
        }
        Ok(Self {
            id: MsgQueueId(rd_i32(buf, MSG_OFF_ID)),
            key: rd_i32(buf, MSG_OFF_KEY),
            mode: ShmPermMode {
                bits: rd_u32(buf, MSG_OFF_MODE),
            },
            uid: NsUid::new(rd_u32(buf, MSG_OFF_UID)),
            gid: NsGid::new(rd_u32(buf, MSG_OFF_GID)),
            cuid: NsUid::new(rd_u32(buf, MSG_OFF_CUID)),
            cgid: NsGid::new(rd_u32(buf, MSG_OFF_CGID)),
            qbytes: rd_u64(buf, MSG_OFF_QBYTES),
            cbytes: rd_u64(buf, MSG_OFF_CBYTES),
            stime: rd_u64(buf, MSG_OFF_STIME),
            rtime: rd_u64(buf, MSG_OFF_RTIME),
            ctime: rd_u64(buf, MSG_OFF_CTIME),
            lspid: rd_i32(buf, MSG_OFF_LSPID),
            lrpid: rd_i32(buf, MSG_OFF_LRPID),
            qnum: messages.len() as u64,
            messages,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let payload_len = self
            .messages
            .iter()
            .map(|message| MSG_RECORD_HEADER_SIZE + message.payload.len())
            .sum::<usize>();
        let mut buf = vec![0u8; MSG_QUEUE_HEADER_SIZE + payload_len];
        wr_u32(&mut buf, MSG_OFF_MAGIC, MSG_QUEUE_MAGIC);
        wr_u32(&mut buf, MSG_OFF_VERSION, MSG_QUEUE_VERSION);
        wr_i32(&mut buf, MSG_OFF_KEY, self.key);
        wr_i32(&mut buf, MSG_OFF_ID, self.id.raw());
        wr_u32(&mut buf, MSG_OFF_MODE, self.mode.raw());
        wr_u32(&mut buf, MSG_OFF_UID, self.uid.raw());
        wr_u32(&mut buf, MSG_OFF_GID, self.gid.raw());
        wr_u32(&mut buf, MSG_OFF_CUID, self.cuid.raw());
        wr_u32(&mut buf, MSG_OFF_CGID, self.cgid.raw());
        wr_u64(&mut buf, MSG_OFF_QBYTES, self.qbytes);
        wr_u64(&mut buf, MSG_OFF_CBYTES, self.cbytes);
        wr_u64(&mut buf, MSG_OFF_QNUM, self.messages.len() as u64);
        wr_u64(&mut buf, MSG_OFF_STIME, self.stime);
        wr_u64(&mut buf, MSG_OFF_RTIME, self.rtime);
        wr_u64(&mut buf, MSG_OFF_CTIME, self.ctime);
        wr_i32(&mut buf, MSG_OFF_LSPID, self.lspid);
        wr_i32(&mut buf, MSG_OFF_LRPID, self.lrpid);
        wr_u64(&mut buf, MSG_OFF_HEAD, MSG_QUEUE_HEADER_SIZE as u64);
        let mut off = MSG_QUEUE_HEADER_SIZE;
        for message in &self.messages {
            wr_i64(&mut buf, off, message.msg_type.raw());
            wr_u32(&mut buf, off + 8, message.payload.len() as u32);
            let data_off = off + MSG_RECORD_HEADER_SIZE;
            buf[data_off..data_off + message.payload.len()].copy_from_slice(&message.payload);
            off = data_off + message.payload.len();
        }
        buf
    }

    fn stat_bytes(&self) -> [u8; LINUX_MSQID_DS_SIZE] {
        let ds = LinuxMsqidDs {
            msg_perm: LinuxIpcPerm {
                key: self.key,
                uid: self.uid.raw(),
                gid: self.gid.raw(),
                cuid: self.cuid.raw(),
                cgid: self.cgid.raw(),
                mode: self.mode.raw(),
                ..Default::default()
            },
            msg_stime: self.stime,
            msg_rtime: self.rtime,
            msg_ctime: self.ctime,
            msg_cbytes: self.cbytes,
            msg_qnum: self.qnum,
            msg_qbytes: self.qbytes,
            msg_lspid: self.lspid,
            msg_lrpid: self.lrpid,
            ..Default::default()
        };
        let mut out = [0u8; LINUX_MSQID_DS_SIZE];
        out.copy_from_slice(zerocopy::IntoBytes::as_bytes(&ds));
        out
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn msg_queue_path_for_private(state: &SysvShmState) -> PathBuf {
    PathBuf::from(SHM_DIR).join(format!(
        "{}-msg-private-{}",
        sysv_run_scope(),
        state.private_name()
    ))
}

fn msg_queue_path_for_key(key: i32) -> PathBuf {
    PathBuf::from(SHM_DIR).join(format!("{}-msg-key-{}", sysv_run_scope(), key as u32))
}

fn msg_queue_path_for_id(id: MsgQueueId) -> PathBuf {
    PathBuf::from(SHM_DIR).join(format!("{}-msg-id-{}", sysv_run_scope(), id.raw() as u32))
}

fn msg_queue_wait_path(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".wait");
    PathBuf::from(out)
}

fn msg_queue_id_from_stat(st: &libc::stat) -> MsgQueueId {
    MsgQueueId((st.st_ino as i32).max(1))
}

fn msg_queue_id_for_fd(fd: i32) -> Result<MsgQueueId, LinuxErrno> {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) }
        .host_syscall_errno()
        .map(|_| msg_queue_id_from_stat(&st))
}

fn msg_queue_scope_prefix() -> String {
    format!("{}-msg-", sysv_run_scope())
}

fn is_msg_queue_path(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(&msg_queue_scope_prefix()) && !name.ends_with(".wait"))
}

fn is_msg_queue_artifact_path(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(&msg_queue_scope_prefix()))
}

fn is_msg_queue_id_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(&msg_queue_scope_prefix())
                && name.contains("-id-")
                && !name.ends_with(".wait")
        })
}

fn read_exact_at_fd(fd: i32, buf: &mut [u8], offset: libc::off_t) -> Result<(), LinuxErrno> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe {
            libc::pread(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - done,
                offset + done as libc::off_t,
            )
        }
        .host_syscall_errno()?;
        if n == 0 {
            return Err(LINUX_EINVAL);
        }
        done += n as usize;
    }
    Ok(())
}

fn write_all_at_fd(fd: i32, buf: &[u8], offset: libc::off_t) -> Result<(), LinuxErrno> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe {
            libc::pwrite(
                fd,
                buf[done..].as_ptr() as *const libc::c_void,
                buf.len() - done,
                offset + done as libc::off_t,
            )
        }
        .host_syscall_errno()?;
        if n == 0 {
            return Err(LINUX_EIO);
        }
        done += n as usize;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_msg_queue_progress(
    fd: i32,
    cbytes: u64,
    qnum: u64,
    stime: u64,
    rtime: u64,
    ctime: u64,
    lspid: i32,
    lrpid: i32,
    head: usize,
) -> Result<(), LinuxErrno> {
    let mut buf = [0u8; MSG_OFF_HEAD + 8 - MSG_OFF_CBYTES];
    wr_u64(&mut buf, 0, cbytes);
    wr_u64(&mut buf, MSG_OFF_QNUM - MSG_OFF_CBYTES, qnum);
    wr_u64(&mut buf, MSG_OFF_STIME - MSG_OFF_CBYTES, stime);
    wr_u64(&mut buf, MSG_OFF_RTIME - MSG_OFF_CBYTES, rtime);
    wr_u64(&mut buf, MSG_OFF_CTIME - MSG_OFF_CBYTES, ctime);
    wr_i32(&mut buf, MSG_OFF_LSPID - MSG_OFF_CBYTES, lspid);
    wr_i32(&mut buf, MSG_OFF_LRPID - MSG_OFF_CBYTES, lrpid);
    wr_u64(&mut buf, MSG_OFF_HEAD - MSG_OFF_CBYTES, head as u64);
    write_all_at_fd(fd, &buf, MSG_OFF_CBYTES as libc::off_t)
}

fn lookup_msg_queue_path(id: MsgQueueId) -> Result<PathBuf, LinuxErrno> {
    SysvShmState::ensure_dir();
    let direct = msg_queue_path_for_id(id);
    if direct.exists() {
        return Ok(direct);
    }
    let entries = std::fs::read_dir(SHM_DIR).map_err(|_| LINUX_EINVAL)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_msg_queue_path(&path) {
            continue;
        }
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            continue;
        }
        let candidate = msg_queue_id_for_fd(fd);
        unsafe { libc::close(fd) };
        if candidate.ok() == Some(id) {
            return Ok(path);
        }
    }
    Err(LINUX_EINVAL)
}

fn cleanup_msg_queue_files_for_scope() {
    if let Ok(entries) = std::fs::read_dir(SHM_DIR) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_msg_queue_artifact_path(&path) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedMsgQueueIdentity {
    dev: libc::dev_t,
    ino: libc::ino_t,
}

#[derive(Debug)]
struct CachedMsgQueueFd {
    fd: i32,
    identity: CachedMsgQueueIdentity,
}

#[derive(Debug)]
struct MsgQueueFdCache {
    host_pid: libc::pid_t,
    entries: HashMap<PathBuf, CachedMsgQueueFd>,
}

impl MsgQueueFdCache {
    fn new() -> Self {
        Self {
            host_pid: unsafe { libc::getpid() },
            entries: HashMap::new(),
        }
    }

    fn refresh_for_current_process(&mut self) {
        let host_pid = unsafe { libc::getpid() };
        if self.host_pid == host_pid {
            return;
        }
        for (_, entry) in self.entries.drain() {
            unsafe { libc::close(entry.fd) };
        }
        self.host_pid = host_pid;
    }
}

impl Drop for MsgQueueFdCache {
    fn drop(&mut self) {
        for (_, entry) in self.entries.drain() {
            unsafe { libc::close(entry.fd) };
        }
    }
}

thread_local! {
    static MSG_QUEUE_FD_CACHE: RefCell<MsgQueueFdCache> =
        RefCell::new(MsgQueueFdCache::new());
}

impl SyscallDispatcher {
    /// Clear the host-fd cache before an executor pthread changes task
    /// identity. Wait-word mappings and blocked queue ids are owned by
    /// `SysvWaitState` inside the Kernel continuation and never live in TLS.
    pub(crate) fn reset_sysv_executor_boundary_state() -> bool {
        MSG_QUEUE_FD_CACHE.with(|cache| {
            for (_, entry) in cache.borrow_mut().entries.drain() {
                unsafe { libc::close(entry.fd) };
            }
        });
        MSG_QUEUE_FD_CACHE.with(|cache| cache.borrow().entries.is_empty())
    }

    #[cfg(test)]
    pub(crate) fn dirty_sysv_executor_boundary_state_for_test() -> (i32, i32) {
        fn pipe_read_end() -> i32 {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            unsafe { libc::close(fds[1]) };
            fds[0]
        }

        let cached_fd = pipe_read_end();
        let wait_word_fd = pipe_read_end();
        let identity = CachedMsgQueueIdentity { dev: 0, ino: 0 };
        MSG_QUEUE_FD_CACHE.with(|cache| {
            cache.borrow_mut().entries.insert(
                PathBuf::from("executor-boundary-fd-test"),
                CachedMsgQueueFd {
                    fd: cached_fd,
                    identity,
                },
            );
        });
        MSG_QUEUE_FD_CACHE.with(|cache| {
            cache.borrow_mut().entries.insert(
                PathBuf::from("executor-boundary-second-fd-test"),
                CachedMsgQueueFd {
                    fd: wait_word_fd,
                    identity,
                },
            );
        });
        (cached_fd, wait_word_fd)
    }

    #[cfg(test)]
    pub(crate) fn sysv_executor_boundary_state_is_clear_for_test() -> bool {
        MSG_QUEUE_FD_CACHE.with(|cache| cache.borrow().entries.is_empty())
    }
}

fn msg_queue_identity(path: &Path) -> Result<CachedMsgQueueIdentity, LinuxErrno> {
    let cpath =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| LINUX_EINVAL)?;
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    unsafe { libc::stat(cpath.as_ptr(), &mut st) }.host_syscall_errno()?;
    Ok(CachedMsgQueueIdentity {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

fn cached_msg_queue_fd(path: &Path) -> Result<i32, LinuxErrno> {
    MSG_QUEUE_FD_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache.refresh_for_current_process();
        if is_msg_queue_id_path(path)
            && let Some(entry) = cache.entries.get(path)
        {
            return Ok(entry.fd);
        }
        let identity = msg_queue_identity(path)?;
        if let Some(entry) = cache.entries.get(path)
            && entry.identity == identity
        {
            return Ok(entry.fd);
        }
        if let Some(entry) = cache.entries.remove(path) {
            unsafe { libc::close(entry.fd) };
        }
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) }.host_syscall_errno()?;
        cache
            .entries
            .insert(path.to_path_buf(), CachedMsgQueueFd { fd, identity });
        Ok(fd)
    })
}

struct MsgQueueLock {
    fd: i32,
    close_on_drop: bool,
}

impl MsgQueueLock {
    fn acquire(path: &Path) -> Result<Self, LinuxErrno> {
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) }.host_syscall_errno()?;
        Self::acquire_fd(fd, true)
    }

    fn acquire_cached(path: &Path) -> Result<Self, LinuxErrno> {
        let fd = cached_msg_queue_fd(path)?;
        Self::acquire_fd(fd, false)
    }

    fn acquire_fd(fd: i32, close_on_drop: bool) -> Result<Self, LinuxErrno> {
        let mut fl: libc::flock = unsafe { core::mem::zeroed() };
        #[allow(clippy::unnecessary_cast)]
        {
            fl.l_type = libc::F_WRLCK as i16;
            fl.l_whence = libc::SEEK_SET as i16;
        }
        fl.l_start = 0;
        fl.l_len = 0;
        let rc = unsafe {
            libc::fcntl(
                fd,
                carrick_portable::F_OFD_SETLKW,
                &mut fl as *mut libc::flock,
            )
        };
        if let Err(errno) = rc.host_syscall_errno() {
            if close_on_drop {
                unsafe { libc::close(fd) };
            }
            return Err(errno);
        }
        Ok(Self { fd, close_on_drop })
    }

    fn read_queue(&self) -> Result<MsgQueueFile, LinuxErrno> {
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        unsafe { libc::fstat(self.fd, &mut st) }.host_syscall_errno()?;
        let size = usize::try_from(st.st_size).map_err(|_| LINUX_EINVAL)?;
        let mut buf = vec![0u8; size.max(MSG_QUEUE_HEADER_SIZE)];
        let mut done = 0usize;
        while done < size {
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf[done..size].as_mut_ptr() as *mut libc::c_void,
                    size - done,
                    done as libc::off_t,
                )
            }
            .host_syscall_errno()?;
            if n == 0 {
                break;
            }
            done += n as usize;
        }
        MsgQueueFile::parse(&buf[..size])
    }

    fn read_header(&self) -> Result<(MsgQueueFile, usize, usize), LinuxErrno> {
        let mut buf = [0u8; MSG_QUEUE_HEADER_SIZE];
        let mut done = 0usize;
        while done < buf.len() {
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf[done..].as_mut_ptr() as *mut libc::c_void,
                    buf.len() - done,
                    done as libc::off_t,
                )
            }
            .host_syscall_errno()?;
            if n == 0 {
                break;
            }
            done += n as usize;
        }
        if done < MSG_QUEUE_HEADER_SIZE {
            return Err(LINUX_EINVAL);
        }
        if rd_u32(&buf, MSG_OFF_MAGIC) != MSG_QUEUE_MAGIC
            || rd_u32(&buf, MSG_OFF_VERSION) != MSG_QUEUE_VERSION
        {
            return Err(LINUX_EINVAL);
        }
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        unsafe { libc::fstat(self.fd, &mut st) }.host_syscall_errno()?;
        let size = usize::try_from(st.st_size).map_err(|_| LINUX_EINVAL)?;
        let head = usize::try_from(rd_u64(&buf, MSG_OFF_HEAD))
            .ok()
            .filter(|head| *head >= MSG_QUEUE_HEADER_SIZE && *head <= size)
            .unwrap_or(MSG_QUEUE_HEADER_SIZE);
        Ok((
            MsgQueueFile {
                id: MsgQueueId(rd_i32(&buf, MSG_OFF_ID)),
                key: rd_i32(&buf, MSG_OFF_KEY),
                mode: ShmPermMode {
                    bits: rd_u32(&buf, MSG_OFF_MODE),
                },
                uid: NsUid::new(rd_u32(&buf, MSG_OFF_UID)),
                gid: NsGid::new(rd_u32(&buf, MSG_OFF_GID)),
                cuid: NsUid::new(rd_u32(&buf, MSG_OFF_CUID)),
                cgid: NsGid::new(rd_u32(&buf, MSG_OFF_CGID)),
                qbytes: rd_u64(&buf, MSG_OFF_QBYTES),
                cbytes: rd_u64(&buf, MSG_OFF_CBYTES),
                stime: rd_u64(&buf, MSG_OFF_STIME),
                rtime: rd_u64(&buf, MSG_OFF_RTIME),
                ctime: rd_u64(&buf, MSG_OFF_CTIME),
                lspid: rd_i32(&buf, MSG_OFF_LSPID),
                lrpid: rd_i32(&buf, MSG_OFF_LRPID),
                qnum: rd_u64(&buf, MSG_OFF_QNUM),
                messages: Vec::new(),
            },
            head,
            size,
        ))
    }

    fn write_queue(&self, queue: &MsgQueueFile) -> Result<(), LinuxErrno> {
        let buf = queue.serialize();
        unsafe { libc::ftruncate(self.fd, buf.len() as libc::off_t) }.host_syscall_errno()?;
        let mut done = 0usize;
        while done < buf.len() {
            let n = unsafe {
                libc::pwrite(
                    self.fd,
                    buf[done..].as_ptr() as *const libc::c_void,
                    buf.len() - done,
                    done as libc::off_t,
                )
            }
            .host_syscall_errno()?;
            if n == 0 {
                return Err(LINUX_EIO);
            }
            done += n as usize;
        }
        Ok(())
    }

    /// `operator` is the SENDING Linux process's own pid, recorded as
    /// `msg_lspid`. It is threaded in from the dispatch boundary rather than
    /// read from the host: under HVPatch every logical process shares the VM
    /// carrier's host pid, so `self_ns_pid()` would stamp one value for all of
    /// them (LTP msgsnd01 "PID of last msgsnd(2) mismatched").
    fn append_message(
        &self,
        queue: &MsgQueueFile,
        head: usize,
        file_size: usize,
        msg_type: MsgType,
        payload: &[u8],
        operator: i32,
    ) -> Result<(), LinuxErrno> {
        let append_offset = if queue.qnum == 0 {
            MSG_QUEUE_HEADER_SIZE
        } else {
            file_size
        };
        if queue.qnum == 0 {
            unsafe { libc::ftruncate(self.fd, MSG_QUEUE_HEADER_SIZE as libc::off_t) }
                .host_syscall_errno()?;
        }
        let mut rec = vec![0u8; MSG_RECORD_HEADER_SIZE + payload.len()];
        wr_i64(&mut rec, 0, msg_type.raw());
        wr_u32(&mut rec, 8, payload.len() as u32);
        rec[MSG_RECORD_HEADER_SIZE..].copy_from_slice(payload);
        write_all_at_fd(self.fd, &rec, append_offset as libc::off_t)?;
        write_msg_queue_progress(
            self.fd,
            queue.cbytes.saturating_add(payload.len() as u64),
            queue.qnum.saturating_add(1),
            unix_now_secs(),
            queue.rtime,
            queue.ctime,
            operator,
            queue.lrpid,
            if queue.qnum == 0 {
                MSG_QUEUE_HEADER_SIZE
            } else {
                head
            },
        )
    }

    fn read_record_at(&self, off: usize) -> Result<(MsgRecord, usize), LinuxErrno> {
        let mut header = [0u8; MSG_RECORD_HEADER_SIZE];
        read_exact_at_fd(self.fd, &mut header, off as libc::off_t)?;
        let msg_type = MsgType::from_msgbuf(rd_i64(&header, 0))?;
        let len = rd_u32(&header, 8) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_exact_at_fd(
                self.fd,
                &mut payload,
                (off + MSG_RECORD_HEADER_SIZE) as libc::off_t,
            )?;
        }
        Ok((
            MsgRecord { msg_type, payload },
            off + MSG_RECORD_HEADER_SIZE + len,
        ))
    }

    /// `operator` is the RECEIVING Linux process's own pid, recorded as
    /// `msg_lrpid`; see [`MsgQueueLock::append_message`] for why it is threaded
    /// in rather than read from the host (LTP msgrcv01).
    fn consume_head_message(
        &self,
        queue: &MsgQueueFile,
        next_head: usize,
        payload_len: usize,
        operator: i32,
    ) -> Result<(), LinuxErrno> {
        let next_qnum = queue.qnum.saturating_sub(1);
        let next_cbytes = queue.cbytes.saturating_sub(payload_len as u64);
        if next_qnum == 0 {
            unsafe { libc::ftruncate(self.fd, MSG_QUEUE_HEADER_SIZE as libc::off_t) }
                .host_syscall_errno()?;
            write_msg_queue_progress(
                self.fd,
                next_cbytes,
                next_qnum,
                queue.stime,
                unix_now_secs(),
                queue.ctime,
                queue.lspid,
                operator,
                MSG_QUEUE_HEADER_SIZE,
            )?;
        } else {
            write_msg_queue_progress(
                self.fd,
                next_cbytes,
                next_qnum,
                queue.stime,
                unix_now_secs(),
                queue.ctime,
                queue.lspid,
                operator,
                next_head,
            )?;
        }
        if next_qnum > 0 && next_head >= MSG_QUEUE_COMPACT_HEAD_THRESHOLD {
            let queue = self.read_queue()?;
            self.write_queue(&queue)?;
        }
        Ok(())
    }
}

impl Drop for MsgQueueLock {
    fn drop(&mut self) {
        let mut fl: libc::flock = unsafe { core::mem::zeroed() };
        #[allow(clippy::unnecessary_cast)]
        {
            fl.l_type = libc::F_UNLCK as i16;
            fl.l_whence = libc::SEEK_SET as i16;
        }
        fl.l_start = 0;
        fl.l_len = 0;
        let _ = unsafe {
            libc::fcntl(
                self.fd,
                carrick_portable::F_OFD_SETLK,
                &mut fl as *mut libc::flock,
            )
        };
        if self.close_on_drop {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[derive(Debug)]
struct MsgQueueWaitWord {
    ptr: std::ptr::NonNull<std::sync::atomic::AtomicU32>,
    len: usize,
    fd: i32,
    queue_identity: CachedMsgQueueIdentity,
}

// The mapping is owned until the last Arc drops, the pointed-to object is an
// AtomicU32, and every access uses atomic ordering. Moving the owner between
// executor pthreads therefore cannot race unmap or a non-atomic access.
unsafe impl Send for MsgQueueWaitWord {}
unsafe impl Sync for MsgQueueWaitWord {}

impl MsgQueueWaitWord {
    fn open(queue_path: &Path) -> Result<Self, LinuxErrno> {
        let queue_identity = msg_queue_identity(queue_path)?;
        let wait_path = msg_queue_wait_path(queue_path);
        let cpath = std::ffi::CString::new(wait_path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) }
            .host_syscall_errno()?;
        if let Err(errno) = unsafe { libc::ftruncate(fd, MSG_QUEUE_WAIT_WORD_BYTES as libc::off_t) }
            .host_syscall_errno()
        {
            unsafe { libc::close(fd) };
            return Err(errno);
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MSG_QUEUE_WAIT_WORD_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(LINUX_EINVAL);
        }
        let Some(ptr) = std::ptr::NonNull::new(mapped.cast::<std::sync::atomic::AtomicU32>())
        else {
            unsafe {
                libc::munmap(mapped, MSG_QUEUE_WAIT_WORD_BYTES);
                libc::close(fd);
            }
            return Err(LINUX_EINVAL);
        };
        Ok(Self {
            ptr,
            len: MSG_QUEUE_WAIT_WORD_BYTES,
            fd,
            queue_identity,
        })
    }

    fn addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }

    fn load(&self) -> u32 {
        unsafe { self.ptr.as_ref() }.load(std::sync::atomic::Ordering::Acquire)
    }

    fn wake_all(&self) {
        unsafe { self.ptr.as_ref() }.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let _ = carrick_host::shared_word::wake(self.addr(), true);
    }
}

impl Drop for MsgQueueWaitWord {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
            libc::close(self.fd);
        }
    }
}

#[derive(Clone, serde::Serialize)]
pub struct SysvWaitState {
    blocked_id: i32,
    queue_path: PathBuf,
    #[serde(skip_serializing)]
    word: Arc<MsgQueueWaitWord>,
}

impl std::fmt::Debug for SysvWaitState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SysvWaitState")
            .field("blocked_id", &self.blocked_id)
            .field("queue_path", &self.queue_path)
            .field("waiter_key", &(self.blocked_id as usize))
            .finish_non_exhaustive()
    }
}

impl PartialEq for SysvWaitState {
    fn eq(&self, other: &Self) -> bool {
        self.blocked_id == other.blocked_id
            && self.queue_path == other.queue_path
            && self.word.queue_identity == other.word.queue_identity
    }
}

impl Eq for SysvWaitState {}

impl SysvWaitState {
    fn for_queue(id: MsgQueueId) -> Result<Self, LinuxErrno> {
        let queue_path = lookup_msg_queue_path(id)?;
        let word = Arc::new(MsgQueueWaitWord::open(&queue_path)?);
        Ok(Self {
            blocked_id: id.raw(),
            queue_path,
            word,
        })
    }

    pub(crate) const fn blocked_id(&self) -> i32 {
        self.blocked_id
    }

    pub(crate) fn wait_word_fd(&self) -> i32 {
        self.word.fd
    }

    pub(crate) fn completion_after_wake(&self) -> Option<DispatchOutcome> {
        match msg_queue_identity(&self.queue_path) {
            Ok(identity) if identity == self.word.queue_identity => None,
            Ok(_) | Err(_) => Some(DispatchOutcome::errno(crate::linux_abi::LINUX_EIDRM)),
        }
    }

    fn wait_outcome(self) -> DispatchOutcome {
        let waiter_key = self.blocked_id as usize;
        DispatchOutcome::WaitOnSharedWord {
            location: carrick_guest_mem::SharedFutexLocation::Direct {
                word: carrick_guest_mem::HostVa(self.word.addr()),
                waiter_key,
            },
            waiter_key,
            generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                .prepare_wait(waiter_key as u64),
            value: self.word.load(),
            sysv: Some(self),
        }
    }

    #[cfg(test)]
    fn for_tests(blocked_id: i32) -> Result<Self, LinuxErrno> {
        let file = tempfile::NamedTempFile::new().map_err(|_| LINUX_EINVAL)?;
        let queue_path = file.path().to_path_buf();
        std::fs::write(&queue_path, vec![0u8; MSG_QUEUE_HEADER_SIZE]).map_err(|_| LINUX_EINVAL)?;
        let word = Arc::new(MsgQueueWaitWord::open(&queue_path)?);
        Ok(Self {
            blocked_id,
            queue_path,
            word,
        })
    }
}

/// Wake everything blocked on this queue.
///
/// TWO wakes, because the waiter's park and this word live in different worlds.
///
/// The word bump is what a waiter re-validates, and it propagates on its own:
/// the wait word is a `MAP_SHARED` file mapping, so every thread's mapping sees
/// the same physical page even though each owned `SysvWaitState` maps it at a
/// potentially different host VA.
///
/// The WAKE does not propagate that way. A blocked `msgrcv`/`msgsnd` parks via
/// `DispatchOutcome::WaitOnSharedWord`, which since `a1bd418d8` lands in the
/// carrier-wide in-process `FutexTable` keyed on `waiter_key` — the queue id.
/// The Darwin `os_sync_wait_on_address` path it replaced keyed on the PHYSICAL
/// PAGE, which is exactly what made a host `shared_word::wake` from another
/// thread's mapping reach the waiter. That keying is gone, so the host wake now
/// signals a primitive nobody waits on, and the waiter sleeps until its own
/// timeout.
///
/// Measured: the `sysvmsgwake` probe's `rmid_wakes_receiver` leg printed
/// `Alarm clock` — its own 20 s alarm — under both libcs, where Linux prints
/// `rmid_wakes_receiver=true`. It is also the mechanism behind `ltp-msgsnd06`
/// hanging.
///
/// The host wake is kept for the DSR native lanes, which really do run separate
/// host processes and still rendezvous on the physical page.
fn wake_msg_queue_waiters(path: &Path, id: MsgQueueId) {
    if let Ok(word) = MsgQueueWaitWord::open(path) {
        word.wake_all();
    }
    carrick_thread::platform_futex::carrier_shared_futex_table().wake(id.raw() as u64, u32::MAX);
}

fn with_shm_nattch_file<R>(
    segment: &ShmSegment,
    f: impl FnOnce(&mut std::fs::File, u64) -> std::io::Result<R>,
) -> std::io::Result<R> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;

    let path = shm_nattch_path(&segment.path);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_EX);
    }
    let result = (|| {
        file.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let count = text.trim().parse::<u64>().unwrap_or(segment.nattch);
        f(&mut file, count)
    })();
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
    result
}

fn read_shm_nattch(segment: &ShmSegment) -> u64 {
    with_shm_nattch_file(segment, |_file, count| Ok(count)).unwrap_or(segment.nattch)
}

fn adjust_shm_nattch(segment: &ShmSegment, delta: i64) -> u64 {
    use std::io::{Seek, SeekFrom, Write};

    with_shm_nattch_file(segment, |file, count| {
        let next = if delta.is_negative() {
            count.saturating_sub(delta.unsigned_abs())
        } else {
            count.saturating_add(delta as u64)
        };
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{next}")?;
        Ok(next)
    })
    .unwrap_or_else(|_| {
        if delta.is_negative() {
            segment.nattch.saturating_sub(delta.unsigned_abs())
        } else {
            segment.nattch.saturating_add(delta as u64)
        }
    })
}

/// Open (or create) the backing file for `key`, ftruncate to `size`, and
/// return (shmid, path, mode). On error returns `Err(linux_errno)`.
///
/// `creator` is the CALLING Linux process's own pid, recorded as `shm_cpid`.
/// It is threaded in from the dispatch boundary because under HVPatch every
/// logical process shares the VM carrier's host pid, so a host-derived value
/// would name the carrier rather than the creator.
pub(super) fn shmget_open(
    state: &mut SysvShmState,
    creds: &crate::kernel::Credentials,
    key: i32,
    size: usize,
    flags: u64,
    creator: i32,
) -> Result<i32, LinuxErrno> {
    SysvShmState::ensure_dir();

    let mode = ShmPermMode::requested(flags);
    let create_flags = IpcCreateFlags::from_bits_retain(flags);
    let create = create_flags.contains(IpcCreateFlags::CREAT);
    let exclusive = create_flags.contains(IpcCreateFlags::EXCL);

    let (path, must_create) = if key == LINUX_IPC_PRIVATE {
        let name = state.private_name();
        (PathBuf::from(SHM_DIR).join(name), true)
    } else {
        let name = SysvShmState::key_name(key);
        let path = PathBuf::from(SHM_DIR).join(name);
        let exists = path.exists();
        if !exists && !create {
            return Err(crate::linux_abi::LINUX_ENOENT);
        }
        if exists {
            if exclusive && create {
                return Err(crate::linux_abi::LINUX_EEXIST);
            }
            if let Some(existing) = state.segments.values().find(|segment| segment.path == path) {
                let wants_read = flags & 0o400 != 0;
                let wants_write = flags & 0o200 != 0;
                if (wants_read && !existing.can_read(creds))
                    || (wants_write && !existing.can_write(creds))
                {
                    return Err(crate::linux_abi::LINUX_EACCES);
                }
            }
        }
        (path, !exists)
    };
    if must_create && state.segments.len() >= LINUX_SHMMNI {
        return Err(crate::linux_abi::LINUX_ENOSPC);
    }

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
            key,
            size: actual_size,
            mode,
            uid: creds.euid,
            gid: creds.egid,
            cuid: creds.euid,
            cgid: creds.egid,
            nattch: 0,
            ctime: now,
            atime: 0,
            dtime: 0,
            cpid: creator,
            lpid: 0,
        });
    unsafe { libc::close(fd) };
    Ok(shmid)
}

/// Open the backing file for `shmid` and return a host fd suitable for
/// mmap(MAP_SHARED). Caller owns the fd. On error returns `Err(linux_errno)`.
pub(super) fn shmat_open_fd(
    state: &mut SysvShmState,
    shmid: i32,
) -> Result<(i32, usize), LinuxErrno> {
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
pub(super) fn shmctl_rmid(state: &mut SysvShmState, shmid: i32) -> Result<(), LinuxErrno> {
    let segment = state
        .segments
        .remove(&shmid)
        .ok_or(crate::linux_abi::LINUX_EINVAL)?;
    let path_cstr = std::ffi::CString::new(segment.path.as_os_str().as_encoded_bytes())
        .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let rc = unsafe { libc::unlink(path_cstr.as_ptr()) };
    let _ = std::fs::remove_file(shm_nattch_path(&segment.path));
    if rc != 0 {
        // Already gone is fine; anything else is a real error but we
        // already removed our entry, so return success — the segment is
        // gone from the user's perspective.
    }
    Ok(())
}

/// Fill a Linux `shmid_ds` (the 112-byte aarch64 UAPI form) from the
/// segment's metadata. LTP shmctl01 reads every populated field, including the
/// owner/creator ids in `shm_perm` — those come from the GUEST creds (carrick's
/// host process is not the guest uid), not the host stat.
pub(super) fn shmid_ds_bytes(
    segment: &ShmSegment,
    _creds: &crate::kernel::Credentials,
) -> [u8; 112] {
    let ds = LinuxShmidDs {
        shm_perm: LinuxIpcPerm {
            uid: segment.uid.raw(),
            gid: segment.gid.raw(),
            cuid: segment.cuid.raw(),
            cgid: segment.cgid.raw(),
            mode: segment.mode.raw(),
            ..Default::default()
        },
        shm_segsz: segment.size as u64,
        shm_atime: segment.atime,
        shm_dtime: segment.dtime,
        shm_ctime: segment.ctime,
        shm_cpid: segment.cpid,
        shm_lpid: segment.lpid,
        shm_nattch: read_shm_nattch(segment),
        __unused4: 0,
        __unused5: 0,
    };
    // `LinuxShmidDs` is exactly 112 bytes (static-asserted above), so its
    // `as_bytes()` view is infallibly 112 bytes — copy it into the array.
    let mut out = [0u8; 112];
    out.copy_from_slice(ds.as_bytes());
    out
}

fn sysvipc_msg_table_from_files() -> String {
    let mut rows = String::from(
        "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
    );
    for id in sorted_msg_queue_ids() {
        let Ok(path) = lookup_msg_queue_path(id) else {
            continue;
        };
        let Ok(lock) = MsgQueueLock::acquire(&path) else {
            continue;
        };
        let Ok(queue) = lock.read_queue() else {
            continue;
        };
        rows.push_str(&format!(
            "{:10} {:10} {:5o} {:11} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
            queue.key,
            queue.id.raw(),
            queue.mode.perms(),
            queue.cbytes,
            queue.qnum,
            queue.lspid,
            queue.lrpid,
            queue.uid,
            queue.gid,
            queue.cuid,
            queue.cgid,
            queue.stime,
            queue.rtime,
            queue.ctime,
        ));
    }
    rows
}

// ===================================================================
// Syscall handlers (wired into dispatch_sysv as 194/195/196/197).
// ===================================================================

impl SyscallDispatcher {
    pub(super) fn commit_host_alias_shmat(&self, commit: HostAliasShmatCommit) {
        let mut state = self.sysv.lock();
        if state.attachments.contains_key(&commit.va) || !state.segments.contains_key(&commit.shmid)
        {
            // The host mapping is already installed. Alias exclusion proves no
            // legitimate shmat/shmdt/shmctl mutation can intervene here, so an
            // occupied VA or vanished segment is irrecoverable corruption.
            std::process::abort();
        }
        state.attachments.insert(commit.va, commit.shmid);
        let Some(segment) = state.segments.get_mut(&commit.shmid) else {
            std::process::abort();
        };
        segment.nattch = adjust_shm_nattch(segment, 1);
        segment.atime = commit.atime;
        segment.lpid = commit.lpid;
    }

    #[allow(dead_code)]
    pub(crate) fn init_sysv_run_scope(&self) {
        init_sysv_run_scope();
    }

    pub(crate) fn sysv_after_fork_child(&self) {
        // `self` is already the CHILD's dispatcher clone, so `identity_pid()`
        // is the child's own Linux pid — the value Linux records in `shm_lpid`
        // for the attachments the child inherited. Resolved BEFORE the sysv
        // lock: identity takes the proc lock, and proc-then-sysv is the order
        // the /proc renderers use (see `cleanup_sysv_shm_attachments_on_
        // process_exit` for the deadlock this prevents).
        let lpid = self.identity_pid() as i32;
        let mut state = self.sysv.lock();
        SysvIpcService::after_fork_child();
        let ids = state.attachments.values().copied().collect::<Vec<_>>();
        for shmid in ids {
            if let Some(seg) = state.segments.get_mut(&shmid) {
                seg.nattch = adjust_shm_nattch(seg, 1);
                seg.lpid = lpid;
            }
        }
    }

    pub(crate) fn sysvipc_shm_table(&self) -> String {
        let state = self.sysv.lock();
        let mut rows = String::from(
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
        );
        let mut segments = state.segments.iter().collect::<Vec<_>>();
        segments.sort_by_key(|(shmid, _)| **shmid);
        for (shmid, segment) in segments {
            let nattch = read_shm_nattch(segment);
            let rss = segment.size.div_ceil(LINUX_PAGE_SIZE as usize);
            rows.push_str(&format!(
                "{:10} {:10} {:5o} {:21} {:5} {:5} {:6} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} {:21}\n",
                segment.key,
                shmid,
                segment.mode.perms(),
                segment.size,
                segment.cpid,
                segment.lpid,
                nattch,
                segment.uid,
                segment.gid,
                segment.cuid,
                segment.cgid,
                segment.atime,
                segment.dtime,
                segment.ctime,
                rss,
                0,
            ));
        }
        rows
    }

    pub(crate) fn sysvipc_sem_table(&self) -> String {
        let state = self.sysv.lock();
        let mut rows = String::from(
            "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
        );
        let mut semaphores = state.semaphores.iter().collect::<Vec<_>>();
        semaphores.sort_by_key(|(semid, _)| semid.0);
        for (semid, meta) in semaphores {
            rows.push_str(&format!(
                "{:10} {:10} {:5o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}\n",
                meta.key,
                semid.0,
                meta.mode.perms(),
                meta.nsems,
                meta.uid,
                meta.gid,
                meta.cuid,
                meta.cgid,
                meta.otime,
                meta.ctime,
            ));
        }
        rows
    }

    pub(crate) fn sysvipc_msg_table(&self) -> String {
        SysvIpcService::msg_table()
    }

    pub(crate) fn note_sysv_remap_file_pages(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<bool, LinuxErrno> {
        let mut state = self.sysv.lock();
        for (attached, shmid) in state.attachments.clone() {
            let Some(segment) = state.segments.get(&shmid) else {
                return Err(crate::linux_abi::LINUX_EIDRM);
            };
            let Some(attached_end) = attached.checked_add(segment.size as u64) else {
                continue;
            };
            if addr >= attached && end <= attached_end {
                state.remapped_attachments.insert(attached);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn cleanup_sysv_shm_attachments_on_process_exit(&self) {
        // Lock ORDER: `identity_pid()` takes the proc lock, and the /proc
        // renderers (`synthetic_proc_context` -> `/proc/sysvipc/shm`) take
        // proc THEN sysv — so taking sysv first here and proc second is the
        // ABBA half of a real deadlock. Observed live (multiprocessing
        // forkserver, shared_memory tests): an exiting leader held sysv here
        // wanting proc, while a sibling's `newfstatat("/proc/...")` held proc
        // wanting sysv, and a third thread wedged behind them delivering
        // SIGTERM. Resolve identity BEFORE touching the sysv lock.
        let lpid = self.identity_pid() as i32;
        let mut state = self.sysv.lock();
        let ids = state
            .attachments
            .drain()
            .map(|(_, shmid)| shmid)
            .collect::<Vec<_>>();
        for shmid in ids {
            if let Some(seg) = state.segments.get_mut(&shmid) {
                seg.nattch = adjust_shm_nattch(seg, -1);
                seg.lpid = lpid;
            }
        }
    }

    pub(crate) fn cleanup_sysv_ipc_on_process_exit(&self) {
        self.cleanup_sysv_shm_attachments_on_process_exit();
        if self.is_forked_guest_process() {
            return;
        }
        let shm_segments = {
            let mut state = self.sysv.lock();
            SysvIpcService::cleanup_process_exit(&mut state);
            state.semaphores.clear();
            state.sem_keys.clear();
            state
                .segments
                .drain()
                .map(|(_, segment)| segment)
                .collect::<Vec<_>>()
        };
        for segment in shm_segments {
            let _ = std::fs::remove_file(&segment.path);
            let _ = std::fs::remove_file(shm_nattch_path(&segment.path));
        }
    }

    define_syscall! {
        /// shmget(key, size, flags). Returns shmid >= 1 on success.
        fn shmget(this, cx, key: u64, size: u64, flags: u64) {
            let key = key as i32;
            let size = size as usize;
            let creds = this.cred_snapshot();
            let mut state = this.sysv.lock();
            match shmget_open(&mut state, &creds, key, size, flags, this.identity_pid() as i32) {
                Ok(shmid) => Ok(DispatchOutcome::Returned { value: shmid as i64 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// shmat(shmid, addr_hint, flag). Map the segment into the guest's
        /// alias VA arena and return the guest VA. SHM_RDONLY is honored by
        /// mapping the alias read-only so a guest STORE faults SIGSEGV, and
        /// SHM_RND rounds an unaligned requested address down to a page
        /// boundary. SHM_REMAP remains unsupported.
        fn shmat(this, cx, shmid: u64, addr: u64, flag: u64) {
            let host_alias_dispatch = this.begin_host_alias_dispatch();
            let shmid = shmid as i32;
            let attach_flags = ShmAttachFlags::from_bits_retain(flag);
            let linux_page_size = this.linux_page_size();
            if attach_flags.contains(ShmAttachFlags::REMAP) {
                // SHM_REMAP is not implemented. Never start a fixed replacement
                // while the transaction is deliberately non-destructive.
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let (host_fd, size) = {
                let mut state = this.sysv.lock();
                match shmat_open_fd(&mut state, shmid) {
                    Ok(v) => v,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            let creds = this.cred_snapshot();
            if let Some(segment) = this.sysv.lock().segments.get(&shmid).cloned() {
                let needs_write = !attach_flags.contains(ShmAttachFlags::RDONLY);
                if !segment.can_read(&creds) || (needs_write && !segment.can_write(&creds)) {
                    unsafe { libc::close(host_fd) };
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
            }

            // mmap_min_addr floor (default 64 KiB): a process may not place a
            // mapping in the first 64 KiB of the address space. do_shmat sets
            // MAP_FIXED for a non-NULL shmaddr, so a too-low address — even
            // after SHM_RND rounds it down to a page boundary — is rejected
            // outright rather than relocated. shmat03 attaches at a low address
            // and asserts nothing maps within the first 64 KiB.
            const MMAP_MIN_ADDR: u64 = 0x10000;
            if addr != 0 && (addr & !(linux_page_size - 1)) < MMAP_MIN_ADDR {
                unsafe { libc::close(host_fd) };
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            // Reserve a guest alias-VA window and return MapHostAlias so the
            // runtime hv_vm_maps the host file into the guest's address
            // space — same path mmap(MAP_SHARED, fd) uses for file mappings.
            let hvf_page = crate::trap::HVF_PAGE_SIZE;
            let map_len = align_up_u64(size as u64, hvf_page).unwrap_or(size as u64);
            if addr == 0 && !attach_flags.contains(ShmAttachFlags::RDONLY) {
                let mut state = this.sysv.lock();
                if let Some(va) = state.remapped_attachments.iter().next().copied() {
                    let old_shmid = state.attachments.insert(va, shmid);
                    if old_shmid != Some(shmid) {
                        if let Some(old) = old_shmid.and_then(|old| state.segments.get_mut(&old)) {
                            old.nattch = adjust_shm_nattch(old, -1);
                        }
                        if let Some(seg) = state.segments.get_mut(&shmid) {
                            seg.nattch = adjust_shm_nattch(seg, 1);
                            seg.atime = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            seg.lpid = this.identity_pid() as i32;
                        }
                    }
                    unsafe { libc::close(host_fd) };
                    return Ok(DispatchOutcome::Returned { value: va as i64 });
                }
            }
            if addr != 0
                && !addr.is_multiple_of(linux_page_size)
                && !attach_flags.contains(ShmAttachFlags::RND)
            {
                unsafe { libc::close(host_fd) };
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let requested_va = (addr != 0).then_some(addr & !(linux_page_size - 1));
            if let Some(va) = requested_va
                && (this.guest_vma_overlaps(va, map_len)
                    || this.sysv.lock().attachments.contains_key(&va))
            {
                // Without SHM_REMAP Linux refuses to replace any existing VMA.
                // Check before consuming a monotonic alias IPA or touching a host
                // mapping; the unsupported replacement is never destructive.
                unsafe { libc::close(host_fd) };
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // When the caller selected the VA, HVPatch's reusable backend lease
            // is the only real IPA authority. A hint-less attach still consumes
            // the legacy cursor because its offset selects a fresh guest VA.
            let Some(ipa) = crate::dispatch::mem::alloc_alias_ipa_for_publication(
                this.execution_backend(),
                map_len,
                requested_va.is_some(),
            ) else {
                unsafe { libc::close(host_fd) };
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let va = requested_va.unwrap_or_else(|| {
                crate::memory::LINUX_HIGH_VA_THRESHOLD
                    + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE)
            });
            if this.sysv.lock().attachments.contains_key(&va) {
                unsafe { libc::close(host_fd) };
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // SHM_RDONLY → map the alias read-only. STEP 1 (host PROT_READ)
            // makes the syscall write-path return EFAULT; STEP 2 (the alias
            // leaf built AP=RO via map_aliased) makes a DIRECT guest store
            // fault SIGSEGV — together matching Linux do_shmat.
            let host_prot = if attach_flags.contains(ShmAttachFlags::RDONLY) {
                libc::PROT_READ
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            };

            let guest_prot = if attach_flags.contains(ShmAttachFlags::RDONLY) {
                crate::linux_abi::LinuxProtFlags::READ
            } else {
                crate::linux_abi::LinuxProtFlags::READ
                    | crate::linux_abi::LinuxProtFlags::WRITE
            };
            let transaction = host_alias_dispatch.publish(HostAliasCommit::shmat(
                crate::dispatch::mem::HostAliasMmapCommit {
                    start: va,
                    len: map_len,
                    prot: guest_prot,
                    sharing: ProcMapSharing::Shared,
                    path: String::new(),
                    file_page_offset: None,
                    locked: None,
                    resident: true,
                    bus_fault: None,
                    write_sealed_shared: false,
                    read_only_shared_file: false,
                    secretmem: false,
                    writable_memfd: None,
                    shared_file_alias: None,
                },
                HostAliasShmatCommit {
                    va,
                    shmid,
                    atime: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    lpid: this.identity_pid() as i32,
                },
            ));

            Ok(DispatchOutcome::MapHostAlias {
                success_retval: va as i64,
                transaction,
                va: GuestVa(va),
                ipa: Gpa(ipa),
                len: map_len,
                payload: Vec::new(),
                file: Some((
                    // SAFETY: `shmat_open_fd` returned a fresh descriptor whose
                    // ownership transfers into this non-cloneable outcome.
                    unsafe { HostAliasOwnedFd::from_raw_fd(host_fd) },
                    0,
                    host_prot,
                )),
                shared: true,
                prot: if attach_flags.contains(ShmAttachFlags::RDONLY) {
                    crate::linux_abi::LINUX_PROT_READ
                } else {
                    crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE
                },
                // shmat is always at least readable (SHM_RDONLY or RW).
                prot_none: false,
            })
        }

        /// shmdt(addr). Decrement the segment's nattch, drop the addr→shmid
        /// mapping, and tear down the dynamic alias leaves so repeated SysV shm
        /// attach/detach cycles reclaim the backend's per-alias page-table pool.
        fn shmdt(this, cx, addr: u64) {
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch();
            let (shmid, len) = {
                let state = this.sysv.lock();
                if state.remapped_attachments.contains(&addr) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let Some(shmid) = state.attachments.get(&addr).copied() else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let Some(segment) = state.segments.get(&shmid) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let Some(aligned_len) =
                    align_up_u64(segment.size as u64, crate::trap::HVF_PAGE_SIZE)
                else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let Ok(len) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                (shmid, len)
            };
            if cx.memory.unmap_alias_range(addr, len).is_err() {
                // A backend error may follow a partial page-table/stage-2
                // mutation. Returning ENOMEM would let the guest continue with
                // attachment and backend ownership in an unknowable split state.
                std::process::abort();
            }
            cx.memory.set_unmapped(addr, len, true);
            this.remove_mapping_metadata(addr, len as u64);
            let dtime = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let lpid = this.identity_pid() as i32;
            let mut state = this.sysv.lock();
            if state.remapped_attachments.contains(&addr)
                || state.attachments.get(&addr).copied() != Some(shmid)
            {
                // Alias exclusion makes this impossible unless bookkeeping was
                // mutated outside the contract. The backend unmap has already
                // succeeded, so continuing with stale attachment metadata would
                // leave two irreconcilable owners.
                std::process::abort();
            }
            let Some(seg) = state.segments.get_mut(&shmid) else {
                // The backend alias is gone and the attachment still names this
                // segment, so there is no recoverable bookkeeping state.
                std::process::abort();
            };
            seg.nattch = adjust_shm_nattch(seg, -1);
            seg.dtime = dtime;
            seg.lpid = lpid;
            state.attachments.remove(&addr);
            drop(state);
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// shmctl(shmid, cmd, buf).
        ///   IPC_RMID — unlink the backing file (mappings remain valid).
        ///   IPC_STAT — write a shmid_ds (112 bytes on aarch64) into `buf`.
        ///   IPC_SET  — apply the requested permission bits (and refresh
        ///              shm_ctime) in carrick's owned segment bookkeeping so a
        ///              following IPC_STAT reads them back.
        fn shmctl(this, cx, shmid: u64, cmd: u64, buf: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let shmid = shmid as i32;
            let creds = this.cred_snapshot();
            match cmd {
                LINUX_IPC_RMID => {
                    let mut state = this.sysv.lock();
                    if let Some(segment) = state.segments.get(&shmid)
                        && !segment.can_write(&creds)
                    {
                        if segment.mode.is_empty_perms() {
                            let _ = shmctl_rmid(&mut state, shmid);
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
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
                    if !segment.can_read(&creds) {
                        return Ok(DispatchOutcome::errno(LINUX_EACCES));
                    }
                    drop(state);
                    if buf == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    let bytes = shmid_ds_bytes(&segment, &this.cred_snapshot());
                    let memory = &mut *cx.memory;
                    if memory.write_bytes(buf, &bytes).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_IPC_SET => {
                    // IPC_SET applies the permission bits from the guest's
                    // shmid_ds (the low 0o777 of shm_perm.mode) to carrick's
                    // OWNED segment metadata and refreshes shm_ctime, mirroring
                    // Linux `ipc_update_perm`. carrick runs as a single host
                    // identity so it can't reassign the owner uid/gid, but it CAN
                    // store the mode — a SysV shm segment here is carrick's own
                    // /tmp backing file plus this bookkeeping, NOT a host SysV
                    // object, so the store lands in `state.segments` and a
                    // following IPC_STAT (which reads `segment.mode` via
                    // `shmid_ds_bytes`) reads it back. It was previously a silent
                    // no-op, dropping the mode change on every lane (the semctl/
                    // msgctl IPC_SET twins already apply their fields).
                    if buf == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    // shm_perm.mode lives at offset 20 in the shmid_ds
                    // (LinuxIpcPerm.mode), the same offset semctl IPC_SET reads.
                    let Some(mode_addr) = buf.checked_add(20) else {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    };
                    let new_mode = match cx.memory.read_bytes(mode_addr, 4) {
                        Ok(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let mut state = this.sysv.lock();
                    match state.segments.get_mut(&shmid) {
                        Some(seg) => {
                            if !seg.can_write(&creds) {
                                return Ok(DispatchOutcome::errno(LINUX_EPERM));
                            }
                            seg.mode = ShmPermMode::from_ipc_set(new_mode, seg.mode);
                            seg.ctime = now;
                            Ok(DispatchOutcome::Returned { value: 0 })
                        }
                        None => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    }
                }
                LINUX_SHM_LOCK | LINUX_SHM_UNLOCK => {
                    let mut state = this.sysv.lock();
                    match state.segments.get_mut(&shmid) {
                        Some(segment) if !segment.can_write(&creds) => {
                            Ok(DispatchOutcome::errno(LINUX_EPERM))
                        }
                        Some(segment) => {
                            segment.mode.set_locked(cmd == LINUX_SHM_LOCK);
                            Ok(DispatchOutcome::Returned { value: 0 })
                        }
                        None => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    }
                }
                LINUX_SHM_STAT | LINUX_SHM_STAT_ANY => {
                    // SHM_STAT takes an INDEX into the kernel's segment
                    // table (NOT a shmid). It writes the shmid_ds for the
                    // segment at that index into `buf` and returns the
                    // shmid. LTP shmctl01 builds an index→shmid mapping by
                    // iterating SHM_STAT(0..N).
                    let state = this.sysv.lock();
                    let mut ids: Vec<i32> = state.segments.keys().copied().collect();
                    ids.sort();
                    let target_id = if cmd == LINUX_SHM_STAT_ANY && state.segments.contains_key(&shmid) {
                        shmid
                    } else {
                        let idx = shmid as usize; // SHM_STAT uses the first arg as idx
                        match ids.get(idx) {
                            Some(id) => *id,
                            None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                        }
                    };
                    let segment = state.segments.get(&target_id).cloned();
                    drop(state);
                    let Some(segment) = segment else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    if buf != 0 {
                        let bytes = shmid_ds_bytes(&segment, &this.cred_snapshot());
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
                        let mut bytes = [0u8; 72];
                        let put = |bytes: &mut [u8], idx: usize, value: u64| {
                            bytes[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_le_bytes());
                        };
                        if cmd == LINUX_IPC_INFO {
                            put(&mut bytes, 0, 18_446_744_073_692_774_399);
                            put(&mut bytes, 1, 1);
                            put(&mut bytes, 2, LINUX_SHMMNI as u64);
                            put(&mut bytes, 3, LINUX_SHMMNI as u64);
                            put(&mut bytes, 4, 18_446_744_073_692_774_399);
                        } else {
                            put(&mut bytes, 0, used_ids.max(0) as u64);
                            put(&mut bytes, 1, used_ids.max(0) as u64);
                        }
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

        /// msgget(key, msgflg): allocate/look up a Carrick-owned Linux SysV
        /// message queue in this run's IPC namespace.
        fn msgget(this, cx, key: u64, msgflg: u64) {
            let _ = cx;
            let creds = this.cred_snapshot();
            let key = match MsgKey::from_syscall_arg(key) {
                Ok(key) => key,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let mut state = this.sysv.lock();
            match SysvIpcService::msgget(&mut state, &creds, key, msgflg) {
                Ok(id) => Ok(DispatchOutcome::Returned { value: id.as_i64() }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// msgsnd(msqid, msgp, msgsz, msgflg): append one typed message.
        fn msgsnd(this, cx, msqid: u64, msgp: GuestPtr, msgsz: u64, msgflg: u64) {
            let msqid = match MsgQueueId::from_syscall_arg(msqid) {
                Ok(msqid) => msqid,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let Ok(sz) = usize::try_from(msgsz) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if sz > LINUX_MSGMAX {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let total = match sz.checked_add(8) {
                Some(t) if t <= crate::dispatch::MAX_RW_COUNT => t,
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            let buf = match cx.memory.read_bytes(msgp.0, total) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            let mut type_bytes = [0u8; 8];
            type_bytes.copy_from_slice(&buf[..8]);
            let msg_type = match MsgType::from_msgbuf(i64::from_le_bytes(type_bytes)) {
                Ok(msg_type) => msg_type,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let payload = buf[8..].to_vec();
            let flags = MsgOpFlags::from_bits_retain(msgflg);
            let creds = this.cred_snapshot();
            let operator = this.identity_pid() as i32;
            let tid = cx.tid();
            let _block_state = (!flags.contains(MsgOpFlags::NOWAIT))
                .then(|| SysvSemBlockStateGuard::new(sysv_run_state_task_pid(this, cx.kernel), tid));
            let mut saw_would_block = false;
            loop {
                match SysvIpcService::msgsnd(msqid, &creds, msg_type, &payload, operator) {
                    Ok(true) => {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Ok(false) => {
                        saw_would_block = true;
                        if flags.contains(MsgOpFlags::NOWAIT) {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        if sysv_msg_wait_interrupted(this, cx.kernel, tid) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        if let Ok(token) = SysvWaitState::for_queue(msqid) {
                            match SysvIpcService::msgsnd(msqid, &creds, msg_type, &payload, operator) {
                                Ok(true) => {
                                    return Ok(DispatchOutcome::Returned { value: 0 });
                                }
                                Ok(false) => {
                                    if sysv_msg_wait_interrupted(this, cx.kernel, tid) {
                                        return Ok(DispatchOutcome::errno(LINUX_EINTR));
                                    }
                                    return Ok(token.wait_outcome());
                                }
                                Err(errno) if errno == LINUX_EINVAL && saw_would_block => {
                                    return Ok(DispatchOutcome::errno(
                                        crate::linux_abi::LINUX_EIDRM,
                                    ));
                                }
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                        } else {
                            std::thread::yield_now();
                        }
                    }
                    Err(errno) if errno == LINUX_EINVAL && saw_would_block => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIDRM));
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
        }

        /// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg): receive by Linux SysV
        /// message-selection rules, including MSG_EXCEPT/MSG_COPY.
        fn msgrcv(this, cx, msqid: u64, msgp: GuestPtr, msgsz: u64, msgtyp: u64, msgflg: u64) {
            let msqid = match MsgQueueId::from_syscall_arg(msqid) {
                Ok(msqid) => msqid,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let Ok(sz) = usize::try_from(msgsz) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let Some(total) = sz.checked_add(8) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if total > crate::dispatch::MAX_RW_COUNT {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let flags = MsgOpFlags::from_bits_retain(msgflg);
            if flags.contains(MsgOpFlags::COPY) {
                if !flags.contains(MsgOpFlags::NOWAIT) || flags.contains(MsgOpFlags::EXCEPT) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            let msgtyp = MsgType::from_syscall_arg(msgtyp);
            let creds = this.cred_snapshot();
            let operator = this.identity_pid() as i32;
            let tid = cx.tid();
            let _block_state = (!flags.contains(MsgOpFlags::NOWAIT))
                .then(|| SysvSemBlockStateGuard::new(sysv_run_state_task_pid(this, cx.kernel), tid));
            let mut saw_would_block = false;
            loop {
                match SysvIpcService::msgrcv(cx, msqid, &creds, msgp.0, sz, msgtyp, flags, operator) {
                    Ok(Some(received)) => {
                        return Ok(DispatchOutcome::Returned { value: received as i64 });
                    }
                    Ok(None) => {
                        saw_would_block = true;
                        if flags.contains(MsgOpFlags::NOWAIT) {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMSG));
                        }
                        if sysv_msg_wait_interrupted(this, cx.kernel, tid) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        if let Ok(token) = SysvWaitState::for_queue(msqid) {
                            match SysvIpcService::msgrcv(cx, msqid, &creds, msgp.0, sz, msgtyp, flags, operator)
                            {
                                Ok(Some(received)) => {
                                    return Ok(DispatchOutcome::Returned {
                                        value: received as i64,
                                    });
                                }
                                Ok(None) => {
                                    if sysv_msg_wait_interrupted(this, cx.kernel, tid) {
                                        return Ok(DispatchOutcome::errno(LINUX_EINTR));
                                    }
                                    return Ok(token.wait_outcome());
                                }
                                Err(errno) if errno == LINUX_EINVAL && saw_would_block => {
                                    return Ok(DispatchOutcome::errno(
                                        crate::linux_abi::LINUX_EIDRM,
                                    ));
                                }
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                        } else {
                            std::thread::yield_now();
                        }
                    }
                    Err(errno) if errno == LINUX_EINVAL && saw_would_block => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIDRM));
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
        }

        /// msgctl(msqid, cmd, buf): operate on Carrick-owned Linux queue
        /// metadata and serialized message contents.
        fn msgctl(this, cx, msqid: u64, cmd: u64, buf: u64) {
            match SysvIpcService::msgctl(this, cx, msqid, cmd, buf) {
                Ok(outcome) => Ok(outcome),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }
        }

        /// semget(key, nsems, semflg): allocate/look up a SysV semaphore set.
        /// Forwarded to the host (macOS has SysV semaphores); IPC_CREAT/IPC_EXCL
        /// share their values with Linux, and carrick guest processes are
        /// separate host processes, so the host kernel gives cross-process
        /// semaphore coherence for free. Carrick returns a Linux-shaped guest
        /// semid and keeps the host semid private at the libc boundary.
        fn semget(this, cx, key: u64, nsems: u64, semflg: u64) {
            let _ = cx;
            // Linux caps nsems at SEMMSL (default 32000): nsems > SEMMSL → EINVAL
            // (LTP semget02). macOS has a much smaller limit and returns ENOSPC
            // for the same over-large request, so validate against the Linux
            // limit before forwarding to the host.
            let Ok(nsems_usize) = usize::try_from(nsems) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if nsems_usize > LINUX_SEMMSL {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let key = key as i32;
            let create_flags = IpcCreateFlags::from_bits_retain(semflg);
            let create = create_flags.contains(IpcCreateFlags::CREAT);
            let exclusive = create_flags.contains(IpcCreateFlags::EXCL);
            let creds = this.cred_snapshot();
            {
                let state = this.sysv.lock();
                if key != LINUX_IPC_PRIVATE
                    && let Some(guest_semid) = state.sem_keys.get(&key).copied()
                    && let Some(existing) = state.semaphores.get(&guest_semid)
                {
                    if create && exclusive {
                        return Ok(DispatchOutcome::errno(LINUX_EEXIST));
                    }
                    if nsems_usize > existing.nsems {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let wants_read = semflg & 0o400 != 0;
                    let wants_write = semflg & 0o200 != 0;
                    if (wants_read && !existing.can_read(&creds))
                        || (wants_write && !existing.can_write(&creds))
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EACCES));
                    }
                    return Ok(DispatchOutcome::Returned {
                        value: guest_semid.as_i64(),
                    });
                }
            }
            if !create && key != LINUX_IPC_PRIVATE {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            if nsems_usize == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut state = this.sysv.lock();
            let Ok((guest_semid, scan_index)) = state.allocate_sem_id() else {
                return Ok(DispatchOutcome::errno(LINUX_ENOSPC));
            };
            state.semaphores.insert(
                guest_semid,
                SemSet {
                    key,
                    scan_index,
                    nsems: nsems_usize,
                    mode: ShmPermMode::requested(semflg),
                    uid: creds.euid,
                    gid: creds.egid,
                    cuid: creds.euid,
                    cgid: creds.egid,
                    ctime: now,
                    otime: 0,
                    values: Arc::new(Mutex::new(vec![0u16; nsems_usize])),
                    logical_last_operators: Arc::new(Mutex::new(vec![None; nsems_usize])),
                    logical_wait_counts: Arc::new(Mutex::new(vec![
                        SemWaitCounts::default();
                        nsems_usize
                    ])),
                    changed: Arc::new(parking_lot::Condvar::new()),
                },
            );
            if key != LINUX_IPC_PRIVATE {
                state.sem_keys.insert(key, guest_semid);
            }
            Ok(DispatchOutcome::Returned {
                value: guest_semid.as_i64(),
            })
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
            this.sysv_semop(cx, semid as i32, sops.0, nsops as usize, None)
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
            this.sysv_semop(cx, semid as i32, sops.0, nsops as usize, to)
        }

        /// semctl(semid, semnum, cmd, arg). The command constants differ
        /// between Linux and macOS and are translated; the union `arg` is
        /// interpreted per command (int for SETVAL, u16[] for GET/SETALL,
        /// semid_ds* for IPC_STAT/SET).
        fn semctl(this, cx, semid: u64, semnum: u64, cmd: u64, arg: u64) {
            // IPC_STAT needs the GUEST creds for the owner ids (carrick's host
            // process is not the guest uid); snapshot them here where `this` is
            // in scope and hand them to the free fn.
            let creds = this.cred_snapshot();
            this.sysv_semctl(cx, semid as i32, semnum as i32, cmd, arg, &creds)
        }
    }
}

fn msgget_open(
    state: &mut SysvShmState,
    creds: &crate::kernel::Credentials,
    key: MsgKey,
    flags: u64,
) -> Result<MsgQueueId, LinuxErrno> {
    SysvShmState::ensure_dir();
    let mode = ShmPermMode::requested(flags);
    let create_flags = IpcCreateFlags::from_bits_retain(flags);
    let create = create_flags.contains(IpcCreateFlags::CREAT);
    let exclusive = create_flags.contains(IpcCreateFlags::EXCL);
    let path = if key.is_private() {
        msg_queue_path_for_private(state)
    } else {
        msg_queue_path_for_key(key.raw())
    };
    let exists = path.exists();
    if !key.is_private() && !exists && !create {
        return Err(LINUX_ENOENT);
    }
    if !key.is_private() && exists && create && exclusive {
        return Err(LINUX_EEXIST);
    }
    let must_create = key.is_private() || !exists;
    if must_create && state.message_queues.len() >= LINUX_MSGMNI {
        return Err(LINUX_ENOSPC);
    }

    if must_create {
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        }
        .host_syscall_errno()?;
        let id = msg_queue_id_for_fd(fd);
        unsafe { libc::close(fd) };
        let id = id?;
        let path = if key.is_private() {
            let id_path = msg_queue_path_for_id(id);
            std::fs::rename(&path, &id_path).map_err(|_| LINUX_EIO)?;
            id_path
        } else {
            path
        };
        let lock = MsgQueueLock::acquire(&path)?;
        let queue = MsgQueueFile::new(id, key.raw(), mode, creds);
        lock.write_queue(&queue)?;
        state.message_queues.insert(id);
        return Ok(id);
    }

    let lock = MsgQueueLock::acquire(&path)?;
    let queue = lock.read_queue()?;
    let wants_read = flags & 0o400 != 0;
    let wants_write = flags & 0o200 != 0;
    if (wants_read && !queue.can_read(creds)) || (wants_write && !queue.can_write(creds)) {
        return Err(LINUX_EACCES);
    }
    state.message_queues.insert(queue.id);
    Ok(queue.id)
}

fn msg_queue_try_send(
    id: MsgQueueId,
    creds: &crate::kernel::Credentials,
    msg_type: MsgType,
    payload: &[u8],
    operator: i32,
) -> Result<bool, LinuxErrno> {
    let path = lookup_msg_queue_path(id)?;
    let lock = MsgQueueLock::acquire_cached(&path)?;
    let (queue, head, file_size) = lock.read_header()?;
    if !queue.can_write(creds) {
        return Err(LINUX_EACCES);
    }
    let payload_len = payload.len() as u64;
    let full_by_bytes = queue.cbytes.saturating_add(payload_len) > queue.qbytes;
    let full_by_count = queue.qnum.saturating_add(1) > queue.qbytes;
    if full_by_bytes || full_by_count {
        return Ok(false);
    }
    lock.append_message(&queue, head, file_size, msg_type, payload, operator)?;
    wake_msg_queue_waiters(&path, id);
    Ok(true)
}

fn selected_msg_index(messages: &[MsgRecord], wanted: MsgType, flags: MsgOpFlags) -> Option<usize> {
    if flags.contains(MsgOpFlags::COPY) {
        return usize::try_from(wanted.raw())
            .ok()
            .filter(|idx| *idx < messages.len());
    }
    let wanted_raw = wanted.raw();
    if wanted_raw == 0 {
        return (!messages.is_empty()).then_some(0);
    }
    if wanted_raw > 0 {
        if flags.contains(MsgOpFlags::EXCEPT) {
            return messages
                .iter()
                .position(|message| message.msg_type.raw() != wanted_raw);
        }
        return messages
            .iter()
            .position(|message| message.msg_type.raw() == wanted_raw);
    }

    let limit = wanted_raw.checked_abs().unwrap_or(i64::MAX);
    let mut best: Option<(usize, MsgType)> = None;
    for (idx, message) in messages.iter().enumerate() {
        if message.msg_type.raw() > limit {
            continue;
        }
        let take = match best {
            Some((_, best_type)) => message.msg_type < best_type,
            None => true,
        };
        if take {
            best = Some((idx, message.msg_type));
        }
    }
    best.map(|(idx, _)| idx)
}

#[allow(clippy::too_many_arguments)]
fn msg_queue_receive<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    id: MsgQueueId,
    creds: &crate::kernel::Credentials,
    msgp: u64,
    msgsz: usize,
    wanted: MsgType,
    flags: MsgOpFlags,
    operator: i32,
) -> Result<Option<usize>, LinuxErrno> {
    let path = lookup_msg_queue_path(id)?;
    let lock = MsgQueueLock::acquire_cached(&path)?;
    let (queue_header, head, _) = lock.read_header()?;
    if !queue_header.can_read(creds) {
        return Err(LINUX_EACCES);
    }
    if queue_header.qnum == 0 {
        return Ok(None);
    }
    let (head_message, next_head) = lock.read_record_at(head)?;
    if selected_msg_index(std::slice::from_ref(&head_message), wanted, flags) == Some(0) {
        if head_message.payload.len() > msgsz && !flags.contains(MsgOpFlags::NOERROR) {
            return Err(LINUX_E2BIG);
        }
        let copy_len = head_message.payload.len().min(msgsz);
        let text_addr = msgp.checked_add(8).ok_or(LINUX_EFAULT)?;
        if cx
            .memory
            .write_bytes(msgp, &head_message.msg_type.raw().to_le_bytes())
            .is_err()
        {
            return Err(LINUX_EFAULT);
        }
        if copy_len > 0
            && cx
                .memory
                .write_bytes(text_addr, &head_message.payload[..copy_len])
                .is_err()
        {
            return Err(LINUX_EFAULT);
        }
        if !flags.contains(MsgOpFlags::COPY) {
            lock.consume_head_message(
                &queue_header,
                next_head,
                head_message.payload.len(),
                operator,
            )?;
            wake_msg_queue_waiters(&path, id);
        }
        return Ok(Some(copy_len));
    }

    let mut queue = lock.read_queue()?;
    if !queue.can_read(creds) {
        return Err(LINUX_EACCES);
    }
    let Some(idx) = selected_msg_index(&queue.messages, wanted, flags) else {
        return Ok(None);
    };
    let message = queue.messages[idx].clone();
    if message.payload.len() > msgsz && !flags.contains(MsgOpFlags::NOERROR) {
        return Err(LINUX_E2BIG);
    }
    let copy_len = message.payload.len().min(msgsz);
    let text_addr = msgp.checked_add(8).ok_or(LINUX_EFAULT)?;
    if cx
        .memory
        .write_bytes(msgp, &message.msg_type.raw().to_le_bytes())
        .is_err()
    {
        return Err(LINUX_EFAULT);
    }
    if copy_len > 0
        && cx
            .memory
            .write_bytes(text_addr, &message.payload[..copy_len])
            .is_err()
    {
        return Err(LINUX_EFAULT);
    }
    if !flags.contains(MsgOpFlags::COPY) {
        let removed = queue.messages.remove(idx);
        queue.cbytes = queue.cbytes.saturating_sub(removed.payload.len() as u64);
        queue.qnum = queue.messages.len() as u64;
        queue.rtime = unix_now_secs();
        queue.lrpid = operator;
        lock.write_queue(&queue)?;
        wake_msg_queue_waiters(&path, id);
    }
    Ok(Some(copy_len))
}

fn sorted_msg_queue_ids() -> Vec<MsgQueueId> {
    let mut ids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(SHM_DIR) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_msg_queue_path(&path) {
                continue;
            }
            let cpath = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
                Ok(cpath) => cpath,
                Err(_) => continue,
            };
            let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
            if fd < 0 {
                continue;
            }
            if let Ok(id) = msg_queue_id_for_fd(fd) {
                ids.push(id);
            }
            unsafe { libc::close(fd) };
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn msg_queue_metrics() -> MsgQueueMetrics {
    let mut metrics = MsgQueueMetrics::default();
    for id in sorted_msg_queue_ids() {
        let Ok(path) = lookup_msg_queue_path(id) else {
            continue;
        };
        let Ok(lock) = MsgQueueLock::acquire(&path) else {
            continue;
        };
        let Ok(queue) = lock.read_queue() else {
            continue;
        };
        metrics.queues = metrics.queues.saturating_add(1);
        metrics.messages = metrics
            .messages
            .saturating_add(usize::try_from(queue.qnum).unwrap_or(usize::MAX));
        metrics.bytes = metrics.bytes.saturating_add(queue.cbytes);
    }
    metrics
}

fn write_msginfo<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    addr: u64,
    metrics: MsgQueueMetrics,
    cmd: u64,
) -> Result<(), LinuxErrno> {
    if addr == 0 {
        return Ok(());
    }
    let mut out = [0u8; 36];
    let put = |out: &mut [u8], idx: usize, value: i32| {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut out, 2, LINUX_MSGMAX as i32);
    put(&mut out, 3, LINUX_MSGMNB as i32);
    put(&mut out, 4, LINUX_MSGMNI as i32);
    put(&mut out, 5, 8);
    put(&mut out, 6, LINUX_MSGMNI as i32);
    if cmd == LINUX_MSG_INFO {
        put(&mut out, 0, metrics.queues as i32);
        put(&mut out, 1, metrics.messages as i32);
        put(&mut out, 6, metrics.bytes.min(i32::MAX as u64) as i32);
    }
    cx.memory.write_bytes(addr, &out).map_err(|_| LINUX_EFAULT)
}

fn msg_stat_by_index<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    selector: u64,
    buf: u64,
    creds: &crate::kernel::Credentials,
    enforce_read_permission: bool,
) -> Result<DispatchOutcome, LinuxErrno> {
    if buf == 0 {
        return Err(LINUX_EFAULT);
    }
    let ids = sorted_msg_queue_ids();
    let id = usize::try_from(selector)
        .ok()
        .and_then(|index| ids.get(index).copied())
        .or_else(|| MsgQueueId::from_syscall_arg(selector).ok())
        .filter(|id| lookup_msg_queue_path(*id).is_ok())
        .ok_or(LINUX_EINVAL)?;
    let path = lookup_msg_queue_path(id)?;
    let lock = MsgQueueLock::acquire(&path)?;
    let queue = lock.read_queue()?;
    if enforce_read_permission && !queue.can_read(creds) {
        return Err(LINUX_EACCES);
    }
    if buf != 0 {
        cx.memory
            .write_bytes(buf, &queue.stat_bytes())
            .map_err(|_| LINUX_EFAULT)?;
    }
    Ok(DispatchOutcome::Returned { value: id.as_i64() })
}

fn sysv_msgctl<M: GuestMemory>(
    this: &SyscallDispatcher,
    cx: &mut SyscallCtx<M>,
    msqid: u64,
    cmd: u64,
    buf: u64,
) -> Result<DispatchOutcome, LinuxErrno> {
    let creds = this.cred_snapshot();
    match cmd {
        LINUX_IPC_INFO | LINUX_MSG_INFO => {
            let metrics = msg_queue_metrics();
            write_msginfo(cx, buf, metrics, cmd)?;
            return Ok(DispatchOutcome::Returned {
                value: (metrics.queues as i64 - 1).max(0),
            });
        }
        LINUX_MSG_STAT | LINUX_MSG_STAT_ANY => {
            return msg_stat_by_index(cx, msqid, buf, &creds, cmd == LINUX_MSG_STAT);
        }
        _ => {}
    }

    let msqid = MsgQueueId::from_syscall_arg(msqid)?;
    match cmd {
        LINUX_IPC_RMID => {
            let path = lookup_msg_queue_path(msqid)?;
            {
                let lock = MsgQueueLock::acquire(&path)?;
                let queue = lock.read_queue()?;
                if !queue.can_admin(&creds) {
                    return Err(LINUX_EPERM);
                }
            }
            wake_msg_queue_waiters(&path, msqid);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(msg_queue_wait_path(&path));
            this.sysv.lock().message_queues.remove(&msqid);
            Ok(DispatchOutcome::Returned { value: 0 })
        }
        LINUX_IPC_STAT => {
            if buf == 0 {
                return Err(LINUX_EFAULT);
            }
            let path = lookup_msg_queue_path(msqid)?;
            let lock = MsgQueueLock::acquire(&path)?;
            let queue = lock.read_queue()?;
            if !queue.can_read(&creds) {
                return Err(LINUX_EACCES);
            }
            cx.memory
                .write_bytes(buf, &queue.stat_bytes())
                .map_err(|_| LINUX_EFAULT)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }
        LINUX_IPC_SET => {
            if buf == 0 {
                return Err(LINUX_EFAULT);
            }
            let uid_addr = buf.checked_add(4).ok_or(LINUX_EFAULT)?;
            let gid_addr = buf.checked_add(8).ok_or(LINUX_EFAULT)?;
            let mode_addr = buf.checked_add(20).ok_or(LINUX_EFAULT)?;
            let qbytes_addr = buf
                .checked_add(u64::try_from(LIN_MSG_QBYTES).map_err(|_| LINUX_EINVAL)?)
                .ok_or(LINUX_EFAULT)?;
            let read4 = |memory: &mut M, addr: u64| -> Result<u32, LinuxErrno> {
                let bytes = memory.read_bytes(addr, 4).map_err(|_| LINUX_EFAULT)?;
                Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            };
            let new_uid = read4(cx.memory, uid_addr)?;
            let new_gid = read4(cx.memory, gid_addr)?;
            let new_mode = read4(cx.memory, mode_addr)?;
            let qbytes = cx
                .memory
                .read_bytes(qbytes_addr, 8)
                .map_err(|_| LINUX_EFAULT)?;
            let new_qbytes = u64::from_le_bytes([
                qbytes[0], qbytes[1], qbytes[2], qbytes[3], qbytes[4], qbytes[5], qbytes[6],
                qbytes[7],
            ]);
            if new_qbytes > LINUX_MSGMNB && !creds.euid.is_root() {
                return Err(LINUX_EPERM);
            }
            let path = lookup_msg_queue_path(msqid)?;
            let lock = MsgQueueLock::acquire(&path)?;
            let mut queue = lock.read_queue()?;
            if !queue.can_admin(&creds) {
                return Err(LINUX_EPERM);
            }
            queue.uid = NsUid::new(new_uid);
            queue.gid = NsGid::new(new_gid);
            queue.mode = ShmPermMode::from_ipc_set(new_mode, queue.mode);
            queue.qbytes = new_qbytes;
            queue.ctime = unix_now_secs();
            lock.write_queue(&queue)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }
        _ => Err(LINUX_EINVAL),
    }
}

fn sysv_msg_wait_interrupted(
    this: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    tid: crate::thread::ThreadId,
) -> bool {
    this.has_deliverable_dispatch_pending_for_wait(context, tid, carrick_abi::WaitSigMask::NONE)
        || carrick_signal_core::xsig::xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE)
        || carrick_signal_core::has_pending_for(tid.raw())
}

// Linux SysV semaphore command constants (linux/sem.h + ipc.h).
const LINUX_GETPID: u64 = 11;
const LINUX_GETVAL: u64 = 12;
const LINUX_GETALL: u64 = 13;
const LINUX_GETNCNT: u64 = 14;
const LINUX_GETZCNT: u64 = 15;
const LINUX_SETVAL: u64 = 16;
const LINUX_SETALL: u64 = 17;

/// One parked `semop`'s contribution to a set's `semncnt`/`semzcnt`, held for
/// exactly as long as the caller is parked. Every registered entry is undone
/// on `Drop`, so no early return — satisfied, EAGAIN on timeout, EINTR, EIDRM
/// or any other host error — can leak a count.
struct SemWaitRegistration {
    counts: SemWaitCounters,
    entries: Vec<(usize, SemWaitKind)>,
}

impl SemWaitRegistration {
    /// Count this caller against every operation that can park it. The whole
    /// `sops` array is applied atomically by Linux, so a blocked caller is
    /// waiting on each of its decrement (`GETNCNT`) and wait-for-zero
    /// (`GETZCNT`) operations at once.
    fn arm(counts: &SemWaitCounters, sops: &[LinuxSembuf]) -> Self {
        let mut entries = Vec::new();
        {
            let mut slots = counts.lock();
            for sop in sops {
                let Some(kind) = SemWaitKind::for_op(sop.sem_op) else {
                    continue;
                };
                let index = usize::from(sop.sem_num);
                let Some(slot) = slots.get_mut(index) else {
                    continue;
                };
                slot.enter_wait(kind);
                entries.push((index, kind));
            }
        }
        Self {
            counts: Arc::clone(counts),
            entries,
        }
    }
}

impl Drop for SemWaitRegistration {
    fn drop(&mut self) {
        let mut slots = self.counts.lock();
        for (index, kind) in self.entries.drain(..) {
            if let Some(slot) = slots.get_mut(index) {
                slot.leave_wait(kind);
            }
        }
    }
}

/// Publishes the guest thread's Blocked/'S' run state for as long as it is
/// parked in a SysV IPC wait. For `semop` it also carries the blocked-waiter
/// registration behind `GETNCNT`/`GETZCNT`, so the counts a sibling guest
/// process reads have exactly the same lifetime as the 'S' state that LTP's
/// `TST_PROCESS_STATE_WAIT` polls for before reading them.
struct SysvSemBlockStateGuard {
    task_pid: Option<i32>,
    tid: crate::thread::ThreadId,
    waits: Option<SemWaitRegistration>,
}

/// The authoritative Linux task pid this run-state publication belongs to, or
/// `None` off the kernel lane.
///
/// HVPatch multiplexes every Linux process inside ONE Darwin carrier, so
/// `run_state::publish` — which keys on `std::process::id()` — writes the
/// CARRIER's slot, a slot no guest pid ever names. `/proc/<pid>/stat` for a
/// peer resolves through `published_stat_char(process.key.id)` (the logical
/// Linux pid), so the publisher must use that same domain via
/// `publish_task_thread`. Mirrors `ThreadRuntimeState::publish_process_run_state`.
fn sysv_run_state_task_pid(
    this: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
) -> Option<i32> {
    (this.execution_backend() == crate::page_profile::ExecutionBackend::HvPatch)
        .then(|| context.task().key().id.raw())
}

fn publish_sysv_block_run_state(
    task_pid: Option<i32>,
    tid: crate::thread::ThreadId,
    state: crate::run_state::RunState,
) {
    match task_pid {
        Some(task_pid) => crate::run_state::publish_task_thread(task_pid, tid.raw(), state),
        None => {
            crate::run_state::publish(state);
            crate::run_state::publish_guest_tid(tid.raw(), state);
        }
    }
}

impl SysvSemBlockStateGuard {
    fn new(task_pid: Option<i32>, tid: crate::thread::ThreadId) -> Self {
        Self::with_waits(task_pid, tid, None)
    }

    fn for_semop(
        task_pid: Option<i32>,
        tid: crate::thread::ThreadId,
        counts: &SemWaitCounters,
        sops: &[LinuxSembuf],
    ) -> Self {
        Self::with_waits(task_pid, tid, Some(SemWaitRegistration::arm(counts, sops)))
    }

    fn with_waits(
        task_pid: Option<i32>,
        tid: crate::thread::ThreadId,
        waits: Option<SemWaitRegistration>,
    ) -> Self {
        publish_sysv_block_run_state(task_pid, tid, crate::run_state::RunState::Blocked);
        crate::thread::set_current_thread_state(tid, 'S');
        Self {
            task_pid,
            tid,
            waits,
        }
    }
}

impl Drop for SysvSemBlockStateGuard {
    fn drop(&mut self) {
        self.waits = None;
        crate::thread::set_current_thread_state(self.tid, 'R');
        publish_sysv_block_run_state(self.task_pid, self.tid, crate::run_state::RunState::Running);
    }
}

struct SemopWaitCtx<'a> {
    task_pid: Option<i32>,
    wait_counts: &'a SemWaitCounters,
    interrupted: &'a dyn Fn() -> bool,
    completed: &'a dyn Fn(&[LinuxSembuf]),
}

fn sysv_semop<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    sem_set: &SemSet,
    sops_addr: u64,
    nsops: usize,
    timeout: Option<LinuxTimespec>,
    wait: SemopWaitCtx<'_>,
) -> Result<DispatchOutcome, DispatchError> {
    let SemopWaitCtx {
        task_pid,
        wait_counts,
        interrupted,
        completed,
    } = wait;
    if nsops == 0 {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    if nsops > LINUX_SEMOPM as usize {
        return Ok(DispatchOutcome::errno(LINUX_E2BIG));
    }
    let bytes = match cx.memory.read_bytes(sops_addr, nsops * 6) {
        Ok(b) => b,
        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
    };
    let mut sops: Vec<LinuxSembuf> = Vec::with_capacity(nsops);
    for i in 0..nsops {
        let o = i * 6;
        let sem_num = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let sem_op = i16::from_le_bytes([bytes[o + 2], bytes[o + 3]]);
        let sem_flg = i16::from_le_bytes([bytes[o + 4], bytes[o + 5]]);
        if usize::from(sem_num) >= sem_set.nsems {
            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
        }
        sops.push(LinuxSembuf {
            sem_num,
            sem_op,
            sem_flg,
        });
    }
    let may_block = sops.iter().any(|s| {
        s.sem_op <= 0
            && !SemOpFlags::from_bits_retain(s.sem_flg as u16).contains(SemOpFlags::NOWAIT)
    });

    let deadline = timeout.map(|ts| {
        let total_ns = (ts.tv_sec.max(0) as u128) * 1_000_000_000 + ts.tv_nsec.max(0) as u128;
        std::time::Instant::now()
            + std::time::Duration::from_nanos(total_ns.min(u64::MAX as u128) as u64)
    });

    let mut block_state: Option<SysvSemBlockStateGuard> = None;
    loop {
        if interrupted() {
            return Ok(DispatchOutcome::errno(LINUX_EINTR));
        }
        {
            let mut vals = sem_set.values.lock();
            let mut can_apply = true;
            let mut would_block_nowait = false;
            let mut sim_vals = vals.clone();
            for sop in &sops {
                let idx = usize::from(sop.sem_num);
                let cur = sim_vals[idx];
                let is_nowait =
                    SemOpFlags::from_bits_retain(sop.sem_flg as u16).contains(SemOpFlags::NOWAIT);
                if sop.sem_op > 0 {
                    if (cur as i32 + sop.sem_op as i32) > 32767 {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ERANGE));
                    }
                    sim_vals[idx] = cur + sop.sem_op as u16;
                } else if sop.sem_op < 0 {
                    let req = (-sop.sem_op) as u16;
                    if cur < req {
                        can_apply = false;
                        if is_nowait {
                            would_block_nowait = true;
                        }
                        break;
                    }
                    sim_vals[idx] = cur - req;
                } else {
                    if cur != 0 {
                        can_apply = false;
                        if is_nowait {
                            would_block_nowait = true;
                        }
                        break;
                    }
                }
            }
            if can_apply {
                *vals = sim_vals;
                drop(vals);
                completed(&sops);
                sem_set.changed.notify_all();
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if would_block_nowait || !may_block {
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            if block_state.is_none() {
                block_state = Some(SysvSemBlockStateGuard::for_semop(
                    task_pid,
                    cx.tid(),
                    wait_counts,
                    &sops,
                ));
            }
            sem_set
                .changed
                .wait_for(&mut vals, std::time::Duration::from_millis(10));
        }
    }
}

impl SyscallDispatcher {
    fn sysv_semop<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        semid: i32,
        sops_addr: u64,
        nsops: usize,
        timeout: Option<LinuxTimespec>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let guest_semid = match GuestSemId::from_syscall_arg(semid) {
            Ok(guest_semid) => guest_semid,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        let (sem_set, wait_counts) = {
            let state = self.sysv.lock();
            let meta = state.semaphores.get(&guest_semid).ok_or(LINUX_EINVAL);
            match meta {
                Ok(meta) => (meta.clone(), Arc::clone(&meta.logical_wait_counts)),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        };
        let creds = self.cred_snapshot();
        if !sem_set.can_write(&creds) {
            return Ok(DispatchOutcome::errno(LINUX_EACCES));
        }
        let logical_operator = self
            .hvpatch_process()
            .map(|_| cx.kernel.task().key().id.raw());
        let tid = cx.tid();
        let interrupted = || {
            crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            ) || self.has_deliverable_dispatch_pending_for_wait(
                cx.kernel,
                tid,
                carrick_abi::WaitSigMask::NONE,
            )
        };
        let completed = |sops: &[LinuxSembuf]| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Some(pid) = logical_operator
                && let Some(meta) = self.sysv.lock().semaphores.get_mut(&guest_semid)
            {
                meta.record_logical_semop(pid, sops);
                meta.otime = now;
            }
        };
        sysv_semop(
            cx,
            &sem_set,
            sops_addr,
            nsops,
            timeout,
            SemopWaitCtx {
                task_pid: sysv_run_state_task_pid(self, cx.kernel),
                wait_counts: &wait_counts,
                interrupted: &interrupted,
                completed: &completed,
            },
        )
    }

    fn sysv_semctl<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        semid: i32,
        semnum: i32,
        cmd: u64,
        arg: u64,
        creds: &crate::kernel::Credentials,
    ) -> Result<DispatchOutcome, DispatchError> {
        match cmd {
            LINUX_IPC_INFO | LINUX_SEM_INFO => {
                return self.write_sem_info(cx, arg);
            }
            LINUX_SEM_STAT | LINUX_SEM_STAT_ANY => {
                let Ok(index) = SemScanIndex::from_semctl_arg(semid) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let selector = if cmd == LINUX_SEM_STAT_ANY {
                    SemStatSelector::AnyIndex(index)
                } else {
                    SemStatSelector::StatIndex(index)
                };
                return self.write_sem_stat(cx, selector, arg, creds);
            }
            _ => {}
        }

        let guest_semid = match GuestSemId::from_syscall_arg(semid) {
            Ok(guest_semid) => guest_semid,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        let mut state = self.sysv.lock();
        let Some(meta) = state.semaphores.get_mut(&guest_semid) else {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        };
        if matches!(cmd, LINUX_IPC_RMID | LINUX_IPC_SET) && !meta.can_admin(creds) {
            return Ok(DispatchOutcome::errno(LINUX_EPERM));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let caller_pid = self
            .hvpatch_process()
            .map(|_| cx.kernel.task().key().id.raw())
            .unwrap_or(0);

        match cmd {
            LINUX_IPC_RMID => {
                let key = meta.key;
                let changed = Arc::clone(&meta.changed);
                state.semaphores.remove(&guest_semid);
                if key != LINUX_IPC_PRIVATE {
                    state.sem_keys.remove(&key);
                }
                drop(state);
                changed.notify_all();
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_IPC_SET => {
                if arg == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                let bytes = match cx.memory.read_bytes(arg + 20, 4) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let mode = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                meta.mode = ShmPermMode::from_ipc_set(mode, meta.mode);
                meta.ctime = now;
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_IPC_STAT => {
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                if arg != 0 {
                    let out = LinuxSemidDs {
                        sem_perm: LinuxIpcPerm {
                            key: meta.key,
                            uid: meta.uid.raw(),
                            gid: meta.gid.raw(),
                            cuid: meta.cuid.raw(),
                            cgid: meta.cgid.raw(),
                            mode: meta.mode.perms(),
                            seq: meta.scan_index.0 as u16,
                            ..Default::default()
                        },
                        sem_otime: meta.otime,
                        sem_ctime: meta.ctime,
                        sem_nsems: meta.nsems as u64,
                        __unused3: 0,
                        __unused4: 0,
                    };
                    if cx.memory.write_bytes(arg, out.as_bytes()).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_GETVAL => {
                let Ok(idx) = usize::try_from(semnum) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if idx >= meta.nsems {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let val = meta.values.lock()[idx];
                Ok(DispatchOutcome::Returned { value: val as i64 })
            }
            LINUX_SETVAL => {
                let Ok(idx) = usize::try_from(semnum) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if idx >= meta.nsems {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !meta.can_write(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let val = arg as i32;
                if !(0..=32767).contains(&val) {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ERANGE));
                }
                meta.values.lock()[idx] = val as u16;
                meta.record_logical_setval(caller_pid, semnum);
                meta.ctime = now;
                let changed = Arc::clone(&meta.changed);
                drop(state);
                changed.notify_all();
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_GETPID => {
                let Ok(idx) = usize::try_from(semnum) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if idx >= meta.nsems {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let pid = meta.logical_last_operator(semnum).unwrap_or(0);
                Ok(DispatchOutcome::Returned {
                    value: i64::from(pid),
                })
            }
            LINUX_GETNCNT => {
                let Ok(idx) = usize::try_from(semnum) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if idx >= meta.nsems {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let count = meta
                    .logical_wait_count(semnum, SemWaitKind::Increase)
                    .unwrap_or(0);
                Ok(DispatchOutcome::Returned {
                    value: i64::from(count),
                })
            }
            LINUX_GETZCNT => {
                let Ok(idx) = usize::try_from(semnum) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if idx >= meta.nsems {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let count = meta
                    .logical_wait_count(semnum, SemWaitKind::Zero)
                    .unwrap_or(0);
                Ok(DispatchOutcome::Returned {
                    value: i64::from(count),
                })
            }
            LINUX_GETALL => {
                if !meta.can_read(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let vals = meta.values.lock().clone();
                let mut out = Vec::with_capacity(vals.len() * 2);
                for v in &vals {
                    out.extend_from_slice(&v.to_le_bytes());
                }
                drop(state);
                if cx.memory.write_bytes(arg, &out).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_SETALL => {
                if !meta.can_write(creds) {
                    return Ok(DispatchOutcome::errno(LINUX_EACCES));
                }
                let nsems = meta.nsems;
                let bytes = match cx.memory.read_bytes(arg, nsems * 2) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let mut vals = Vec::with_capacity(nsems);
                for i in 0..nsems {
                    let v = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
                    if v > 32767 {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ERANGE));
                    }
                    vals.push(v);
                }
                *meta.values.lock() = vals;
                meta.record_logical_setall(caller_pid);
                meta.ctime = now;
                let changed = Arc::clone(&meta.changed);
                drop(state);
                changed.notify_all();
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
        }
    }

    fn write_sem_info<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        arg: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let state = self.sysv.lock();
        let used_sets = state.semaphores.len() as u32;
        let used_sems = state
            .semaphores
            .values()
            .map(|meta| meta.nsems as u32)
            .sum::<u32>();
        let max_index = state
            .semaphores
            .values()
            .map(|meta| meta.scan_index)
            .max()
            .map_or(0, SemScanIndex::as_i64);
        drop(state);

        if arg != 0 {
            let fields = [
                LINUX_SEMMNI as u32,
                LINUX_SEMMNI as u32,
                1_024_000_000u32,
                1_024_000_000u32,
                LINUX_SEMMSL as u32,
                LINUX_SEMOPM,
                LINUX_SEMMNI as u32,
                used_sets,
                LINUX_SEMVMX,
                used_sems,
            ];
            let mut bytes = Vec::with_capacity(fields.len() * 4);
            for field in fields {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
            if cx.memory.write_bytes(arg, &bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
        }
        Ok(DispatchOutcome::Returned { value: max_index })
    }

    fn write_sem_stat<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        selector: SemStatSelector,
        arg: u64,
        creds: &crate::kernel::Credentials,
    ) -> Result<DispatchOutcome, DispatchError> {
        let state = self.sysv.lock();
        let Some((guest_semid, meta)) = state
            .semaphores
            .iter()
            .find(|(_, meta)| meta.scan_index == selector.scan_index())
        else {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        };
        let guest_semid = *guest_semid;
        let meta = meta.clone();
        if selector.enforces_read_permission() && !meta.can_read(creds) {
            return Ok(DispatchOutcome::errno(LINUX_EACCES));
        }
        drop(state);

        if arg != 0 {
            let out = LinuxSemidDs {
                sem_perm: LinuxIpcPerm {
                    key: meta.key,
                    uid: meta.uid.raw(),
                    gid: meta.gid.raw(),
                    cuid: meta.cuid.raw(),
                    cgid: meta.cgid.raw(),
                    mode: meta.mode.perms(),
                    seq: meta.scan_index.0 as u16,
                    ..Default::default()
                },
                sem_otime: meta.otime,
                sem_ctime: meta.ctime,
                sem_nsems: meta.nsems as u64,
                __unused3: 0,
                __unused4: 0,
            };
            if cx.memory.write_bytes(arg, out.as_bytes()).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
        }
        Ok(DispatchOutcome::Returned {
            value: guest_semid.as_i64(),
        })
    }
}

#[cfg(test)]
mod ipc_set_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn msg_queue_wait_outcome_owns_send_state_without_executor_tls() {
        fn assert_send_static<T: Send + 'static>(_: &T) {}

        let wait = SysvWaitState::for_tests(0x5a5a).expect("owned SysV wait state");
        assert_send_static(&wait);
        let owned_fd = wait.wait_word_fd();
        let outcome = wait.wait_outcome();
        match outcome {
            DispatchOutcome::WaitOnSharedWord {
                waiter_key,
                sysv: Some(wait),
                ..
            } => {
                assert_eq!(waiter_key, 0x5a5a);
                assert_eq!(wait.blocked_id(), 0x5a5a);
                assert!(wait.wait_word_fd() >= 0);
            }
            other => panic!("expected owned SysV continuation outcome, got {other:?}"),
        }
        assert_eq!(unsafe { libc::fcntl(owned_fd, libc::F_GETFD) }, -1);
        assert!(SyscallDispatcher::sysv_executor_boundary_state_is_clear_for_test());
    }

    struct FailingUnmapMemory {
        inner: LinearMemory,
        set_unmapped_calls: Vec<(u64, usize, bool)>,
    }

    impl FailingUnmapMemory {
        fn new(base: u64, len: usize) -> Self {
            Self {
                inner: LinearMemory::new(base, vec![0; len]),
                set_unmapped_calls: Vec::new(),
            }
        }
    }

    impl GuestMemory for FailingUnmapMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes_raw(address, bytes)
        }

        fn unmap_alias_range(&mut self, _address: u64, _len: usize) -> Result<(), MemoryError> {
            Err(MemoryError::HostMap(
                "injected alias unmap failure".to_string(),
            ))
        }

        fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
            self.set_unmapped_calls.push((address, len, unmapped));
        }
    }

    fn insert_test_shm_segment(
        dispatcher: &SyscallDispatcher,
        shmid: i32,
        size: usize,
    ) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temporary shm backing");
        file.as_file()
            .set_len(size as u64)
            .expect("size temporary shm backing");
        dispatcher.sysv.lock().segments.insert(
            shmid,
            ShmSegment {
                path: file.path().to_path_buf(),
                key: 0,
                size,
                mode: ShmPermMode::requested(0o600),
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                cuid: NsUid::ROOT,
                cgid: NsGid::ROOT,
                nattch: 0,
                ctime: 1,
                atime: 0,
                dtime: 0,
                cpid: 1,
                lpid: 0,
            },
        );
        file
    }

    #[test]
    fn scoped_host_sem_key_separates_run_scopes() {
        let key = 0x1234_5678u32 as i32;
        let first = scoped_host_sem_key_for_scope("conf-a", key);
        let first_again = scoped_host_sem_key_for_scope("conf-a", key);
        let second = scoped_host_sem_key_for_scope("conf-b", key);
        let other_key = scoped_host_sem_key_for_scope("conf-a", key.wrapping_add(1));

        assert_eq!(first, first_again, "mapping must be stable within a run");
        assert_ne!(first, second, "same guest key must not collide across runs");
        assert_ne!(
            first, other_key,
            "different guest keys must remain distinct"
        );
        assert_ne!(first, LINUX_IPC_PRIVATE as libc::key_t);
        assert_eq!(
            scoped_host_sem_key(LINUX_IPC_PRIVATE),
            LINUX_IPC_PRIVATE as libc::key_t,
            "IPC_PRIVATE must stay host-private"
        );
    }

    #[test]
    fn logical_sempid_is_shared_across_in_process_fork_clones() {
        let parent = SemSet {
            key: LINUX_IPC_PRIVATE,
            scan_index: SemScanIndex(0),
            nsems: 3,
            mode: ShmPermMode::requested(0o600),
            uid: NsUid::ROOT,
            gid: NsGid::ROOT,
            cuid: NsUid::ROOT,
            cgid: NsGid::ROOT,
            ctime: 0,
            otime: 0,
            values: Arc::new(Mutex::new(vec![0u16; 3])),
            logical_last_operators: Arc::new(Mutex::new(vec![None; 3])),
            logical_wait_counts: Arc::new(Mutex::new(vec![SemWaitCounts::default(); 3])),
            changed: Arc::new(parking_lot::Condvar::new()),
        };
        let child = parent.clone();
        child.record_logical_semop(
            73,
            &[LinuxSembuf {
                sem_num: 2,
                sem_op: 1,
                sem_flg: 0,
            }],
        );

        assert_eq!(parent.logical_last_operator(0), None);
        assert_eq!(parent.logical_last_operator(2), Some(73));
    }

    struct InMemSemFixture {
        set: SemSet,
    }

    impl InMemSemFixture {
        fn new(nsems: usize) -> Self {
            let set = SemSet {
                key: LINUX_IPC_PRIVATE,
                scan_index: SemScanIndex(0),
                nsems,
                mode: ShmPermMode::requested(0o600),
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                cuid: NsUid::ROOT,
                cgid: NsGid::ROOT,
                ctime: 0,
                otime: 0,
                values: Arc::new(Mutex::new(vec![0u16; nsems])),
                logical_last_operators: Arc::new(Mutex::new(vec![None; nsems])),
                logical_wait_counts: Arc::new(Mutex::new(vec![SemWaitCounts::default(); nsems])),
                changed: Arc::new(parking_lot::Condvar::new()),
            };
            Self { set }
        }

        fn value(&self, semnum: i32) -> i32 {
            self.set.values.lock()[semnum as usize] as i32
        }

        fn post(&self, semnum: u16) {
            self.set.values.lock()[semnum as usize] += 1;
            self.set.changed.notify_all();
        }

        #[allow(dead_code)]
        fn remove(&self) {
            self.set.changed.notify_all();
        }
    }

    fn sembuf_bytes(sops: &[LinuxSembuf]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(sops.len() * 6);
        for sop in sops {
            bytes.extend_from_slice(&sop.sem_num.to_le_bytes());
            bytes.extend_from_slice(&sop.sem_op.to_le_bytes());
            bytes.extend_from_slice(&sop.sem_flg.to_le_bytes());
        }
        bytes
    }

    const SEMOP_TEST_SOPS_ADDR: u64 = 0x1000;

    fn run_semop_probe(
        fixture: &InMemSemFixture,
        sops: &[LinuxSembuf],
        timeout: Option<LinuxTimespec>,
        counts: &SemWaitCounters,
        watch: (i32, SemWaitKind),
        on_wait: impl Fn(usize, u32) -> bool,
    ) -> DispatchOutcome {
        let dispatcher = SyscallDispatcher::new();
        let kernel = dispatcher
            .capture_one_task_context()
            .expect("kernel context");
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(SEMOP_TEST_SOPS_ADDR, vec![0; 0x1000]);
        memory
            .write_bytes(SEMOP_TEST_SOPS_ADDR, &sembuf_bytes(sops))
            .expect("stage sembuf array");
        let mut cx = SyscallCtx {
            kernel: &kernel,
            request: SyscallRequest::new(193, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            memory: &mut memory,
            reporter: &reporter,
            thread: None,
        };
        let (watch_semnum, watch_kind) = watch;
        let consultations = std::cell::Cell::new(0usize);
        let interrupted = || -> bool {
            let index = usize::try_from(watch_semnum).expect("watch semnum");
            let observed = counts.lock().get(index).map_or(0, |c| c.get(watch_kind));
            let calls = consultations.get() + 1;
            consultations.set(calls);
            on_wait(calls, observed)
        };
        sysv_semop(
            &mut cx,
            &fixture.set,
            SEMOP_TEST_SOPS_ADDR,
            sops.len(),
            timeout,
            SemopWaitCtx {
                task_pid: None,
                wait_counts: counts,
                interrupted: &interrupted,
                completed: &|_| {},
            },
        )
        .expect("semop probe dispatch")
    }

    fn decrement_sop(sem_num: u16, sem_flg: i16) -> LinuxSembuf {
        LinuxSembuf {
            sem_num,
            sem_op: -1,
            sem_flg,
        }
    }

    fn wait_zero_sop(sem_num: u16, sem_flg: i16) -> LinuxSembuf {
        LinuxSembuf {
            sem_num,
            sem_op: 0,
            sem_flg,
        }
    }

    fn fresh_wait_counts(nsems: usize) -> SemWaitCounters {
        Arc::new(Mutex::new(vec![SemWaitCounts::default(); nsems]))
    }

    fn peak_wait_count(counts: &SemWaitCounters, kind: SemWaitKind) -> u32 {
        counts
            .lock()
            .iter()
            .map(|slot| slot.get(kind))
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn semop_wait_counts_rise_while_parked_and_unwind_on_every_exit() {
        // Satisfied: the value rises while the caller is parked.
        let fixture = InMemSemFixture::new(2);
        let counts = fresh_wait_counts(2);
        let observed = std::cell::Cell::new(0u32);
        let outcome = run_semop_probe(
            &fixture,
            &[decrement_sop(1, 0)],
            None,
            &counts,
            (1, SemWaitKind::Increase),
            |calls, count| {
                observed.set(observed.get().max(count));
                if calls == 2 {
                    fixture.post(1);
                }
                false
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Returned { value: 0 }),
            "a posted semaphore completes the wait: {outcome:?}"
        );
        assert_eq!(observed.get(), 1, "the parked waiter must show in semncnt");
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Increase), 0);
        assert_eq!(fixture.value(1), 0, "the decrement must have been applied");

        // EINTR.
        let counts = fresh_wait_counts(2);
        let observed = std::cell::Cell::new(0u32);
        let outcome = run_semop_probe(
            &fixture,
            &[decrement_sop(1, 0)],
            None,
            &counts,
            (1, SemWaitKind::Increase),
            |calls, count| {
                observed.set(observed.get().max(count));
                calls >= 2
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Errno { errno } if errno == LINUX_EINTR),
            "an interrupted wait reports EINTR: {outcome:?}"
        );
        assert_eq!(observed.get(), 1);
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Increase), 0);

        // EAGAIN on a semtimedop deadline, counted as a GETZCNT waiter.
        fixture.post(0);
        let counts = fresh_wait_counts(2);
        let observed = std::cell::Cell::new(0u32);
        let outcome = run_semop_probe(
            &fixture,
            &[wait_zero_sop(0, 0)],
            Some(LinuxTimespec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            }),
            &counts,
            (0, SemWaitKind::Zero),
            |_, count| {
                observed.set(observed.get().max(count));
                false
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN),
            "a timed wait that expires reports EAGAIN: {outcome:?}"
        );
        assert_eq!(observed.get(), 1, "the parked waiter must show in semzcnt");
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Zero), 0);
    }

    #[test]
    fn guest_nowait_semop_fails_immediately_instead_of_polling() {
        let fixture = InMemSemFixture::new(2);
        let counts = fresh_wait_counts(2);
        let nowait = SemOpFlags::NOWAIT.bits() as i16;

        // sem_op = -1 against a zero value.
        let outcome = run_semop_probe(
            &fixture,
            &[decrement_sop(1, nowait)],
            None,
            &counts,
            (1, SemWaitKind::Increase),
            |calls, _| {
                assert_eq!(calls, 1, "a guest IPC_NOWAIT op must not park");
                false
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN),
            "IPC_NOWAIT decrement must fail with EAGAIN: {outcome:?}"
        );
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Increase), 0);

        // sem_op = 0 against a non-zero value.
        fixture.post(0);
        let outcome = run_semop_probe(
            &fixture,
            &[wait_zero_sop(0, nowait)],
            None,
            &counts,
            (0, SemWaitKind::Zero),
            |calls, _| {
                assert_eq!(calls, 1, "a guest IPC_NOWAIT op must not park");
                false
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN),
            "IPC_NOWAIT wait-for-zero must fail with EAGAIN: {outcome:?}"
        );
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Zero), 0);

        // Mixed array: semaphore 0 is non-zero so the leading decrement is
        // satisfiable, and semaphore 1 is non-zero so the trailing wait-for-zero
        // is the operation that blocks — and it carries IPC_NOWAIT, so the whole
        // call fails rather than parking on the other operation.
        fixture.post(1);
        let outcome = run_semop_probe(
            &fixture,
            &[decrement_sop(0, 0), wait_zero_sop(1, nowait)],
            None,
            &counts,
            (1, SemWaitKind::Zero),
            |calls, _| {
                assert!(calls <= 1, "a blocking IPC_NOWAIT op must not park");
                false
            },
        );
        assert!(
            matches!(outcome, DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN),
            "mixed array with a blocking IPC_NOWAIT op must fail: {outcome:?}"
        );
        assert_eq!(peak_wait_count(&counts, SemWaitKind::Zero), 0);
    }

    #[test]
    fn logical_wait_counts_are_shared_across_in_process_fork_clones() {
        let parent = SemSet {
            key: LINUX_IPC_PRIVATE,
            scan_index: SemScanIndex(0),
            nsems: 3,
            mode: ShmPermMode::requested(0o600),
            uid: NsUid::ROOT,
            gid: NsGid::ROOT,
            cuid: NsUid::ROOT,
            cgid: NsGid::ROOT,
            ctime: 0,
            otime: 0,
            values: Arc::new(Mutex::new(vec![0u16; 3])),
            logical_last_operators: Arc::new(Mutex::new(vec![None; 3])),
            logical_wait_counts: Arc::new(Mutex::new(vec![SemWaitCounts::default(); 3])),
            changed: Arc::new(parking_lot::Condvar::new()),
        };
        let child = parent.clone();

        {
            let _first = SemWaitRegistration::arm(
                &child.logical_wait_counts,
                &[decrement_sop(2, 0), wait_zero_sop(1, 0)],
            );
            let _second =
                SemWaitRegistration::arm(&child.logical_wait_counts, &[decrement_sop(2, 0)]);

            assert_eq!(
                parent.logical_wait_count(2, SemWaitKind::Increase),
                Some(2),
                "a sibling process must see both waiters"
            );
            assert_eq!(parent.logical_wait_count(1, SemWaitKind::Zero), Some(1));
            assert_eq!(parent.logical_wait_count(2, SemWaitKind::Zero), Some(0));
            assert_eq!(parent.logical_wait_count(0, SemWaitKind::Increase), Some(0));
            assert_eq!(parent.logical_wait_count(3, SemWaitKind::Increase), None);
        }

        assert_eq!(parent.logical_wait_count(2, SemWaitKind::Increase), Some(0));
        assert_eq!(parent.logical_wait_count(1, SemWaitKind::Zero), Some(0));
    }

    #[test]
    fn shmdt_ambiguous_backend_unmap_failure_aborts_with_sigabrt() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork shmdt failure child");
        if pid == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let dispatcher = SyscallDispatcher::new();
            let shmid = 4240;
            let addr = crate::memory::LINUX_HIGH_VA_THRESHOLD;
            dispatcher.sysv.lock().segments.insert(
                shmid,
                ShmSegment {
                    path: PathBuf::from("/tmp/carrick-shm/test-failing-shmdt"),
                    key: 0,
                    size: LINUX_PAGE_SIZE as usize,
                    mode: ShmPermMode::requested(0o600),
                    uid: NsUid::ROOT,
                    gid: NsGid::ROOT,
                    cuid: NsUid::ROOT,
                    cgid: NsGid::ROOT,
                    nattch: 7,
                    ctime: 1,
                    atime: 2,
                    dtime: 3,
                    cpid: 4,
                    lpid: 5,
                },
            );
            dispatcher.sysv.lock().attachments.insert(addr, shmid);
            let mut memory = FailingUnmapMemory::new(0x1000, 0x1000);
            let _ = dispatcher.dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(197, SyscallArgs::from([addr, 0, 0, 0, 0, 0])),
                &mut memory,
                &CompatReporter::default(),
                None,
            );
            unsafe { libc::_exit(111) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[test]
    fn shmdt_success_retires_all_committed_mmap_metadata_before_attachment() {
        let dispatcher = SyscallDispatcher::new();
        let shmid = 4245;
        let addr = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let len = crate::trap::HVF_PAGE_SIZE;
        dispatcher.sysv.lock().segments.insert(
            shmid,
            ShmSegment {
                path: PathBuf::from("/tmp/carrick-shm/test-successful-shmdt"),
                key: 0,
                size: LINUX_PAGE_SIZE as usize,
                mode: ShmPermMode::requested(0o600),
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                cuid: NsUid::ROOT,
                cgid: NsGid::ROOT,
                nattch: 1,
                ctime: 1,
                atime: 2,
                dtime: 0,
                cpid: 4,
                lpid: 5,
            },
        );
        dispatcher.sysv.lock().attachments.insert(addr, shmid);
        let range = crate::vfs::GuestMemoryRange::new(GuestVa(addr), GuestVa(addr + len))
            .expect("shmat metadata range");
        let writable_memfd = kernel_file_description(std::sync::Arc::new(
            parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(0),
                path: "memfd:shmdt-test".into(),
                contents: Vec::new(),
                offset: 0,
            }),
        ));
        dispatcher.commit_host_alias_mmap(crate::dispatch::mem::HostAliasMmapCommit {
            start: addr,
            len,
            prot: crate::linux_abi::LinuxProtFlags::READ | crate::linux_abi::LinuxProtFlags::WRITE,
            sharing: ProcMapSharing::Shared,
            path: String::new(),
            file_page_offset: None,
            locked: Some(range),
            resident: true,
            bus_fault: Some((addr, len)),
            write_sealed_shared: true,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: Some(writable_memfd),
            shared_file_alias: None,
        });
        assert!(dispatcher.range_has_mapping_metadata_for_test(addr, len));
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);

        let outcome = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(197, SyscallArgs::from([addr, 0, 0, 0, 0, 0])),
                &mut memory,
                &CompatReporter::default(),
                None,
            )
            .expect("shmdt is claimed")
            .expect("successful shmdt dispatch");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert!(!dispatcher.range_has_mapping_metadata_for_test(addr, len));
        let state = dispatcher.sysv.lock();
        assert!(!state.attachments.contains_key(&addr));
        let segment = state.segments.get(&shmid).expect("detached segment");
        assert_eq!(segment.nattch, 0);
        assert_ne!(segment.dtime, 0);
    }

    #[test]
    fn explicit_shmat_rejects_dynamic_vma_overlap_before_alias_install() {
        const REQUESTED: u64 = 0x20_0000_0000;
        let dispatcher = SyscallDispatcher::new();
        let shmid = 4246;
        let _file = insert_test_shm_segment(&dispatcher, shmid, LINUX_PAGE_SIZE as usize);
        dispatcher.commit_host_alias_mmap(crate::dispatch::mem::HostAliasMmapCommit {
            start: REQUESTED,
            len: crate::trap::HVF_PAGE_SIZE,
            prot: crate::linux_abi::LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: "occupied-dynamic".into(),
            file_page_offset: None,
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            read_only_shared_file: false,
            secretmem: false,
            writable_memfd: None,
            shared_file_alias: None,
        });
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let outcome = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    196,
                    SyscallArgs::from([shmid as u64, REQUESTED, 0, 0, 0, 0]),
                ),
                &mut memory,
                &CompatReporter::default(),
                None,
            )
            .expect("shmat is claimed")
            .expect("overlap rejection dispatch");
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EINVAL));
        assert!(dispatcher.sysv.lock().attachments.is_empty());
    }

    #[test]
    fn explicit_shmat_rejects_real_boot_vma_overlap_before_alias_install() {
        const REQUESTED: u64 = 0x20_0000_0000;
        let dispatcher = SyscallDispatcher::new();
        let shmid = 4247;
        let _file = insert_test_shm_segment(&dispatcher, shmid, LINUX_PAGE_SIZE as usize);
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: REQUESTED,
            end: REQUESTED + crate::trap::HVF_PAGE_SIZE,
            read: true,
            write: false,
            execute: true,
            sharing: ProcMapSharing::Private,
            path: "boot-text".into(),
        }]);
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let outcome = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    196,
                    SyscallArgs::from([shmid as u64, REQUESTED, 0, 0, 0, 0]),
                ),
                &mut memory,
                &CompatReporter::default(),
                None,
            )
            .expect("shmat is claimed")
            .expect("boot overlap rejection dispatch");
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EINVAL));
        assert!(dispatcher.sysv.lock().attachments.is_empty());
    }

    #[test]
    fn aborted_host_alias_leaves_sysv_attachment_and_nattch_exact() {
        let dispatcher = SyscallDispatcher::new();
        let shmid = 4241;
        dispatcher.sysv.lock().segments.insert(
            shmid,
            ShmSegment {
                path: PathBuf::from("/tmp/carrick-shm/test-pending-shmat"),
                key: 0,
                size: LINUX_PAGE_SIZE as usize,
                mode: ShmPermMode::requested(0o600),
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                cuid: NsUid::ROOT,
                cgid: NsGid::ROOT,
                nattch: 7,
                ctime: 1,
                atime: 2,
                dtime: 3,
                cpid: 4,
                lpid: 5,
            },
        );
        let va = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::shmat(
            crate::dispatch::mem::HostAliasMmapCommit {
                start: va,
                len: LINUX_PAGE_SIZE,
                prot: crate::linux_abi::LinuxProtFlags::READ
                    | crate::linux_abi::LinuxProtFlags::WRITE,
                sharing: ProcMapSharing::Shared,
                path: String::new(),
                file_page_offset: None,
                locked: None,
                resident: true,
                bus_fault: None,
                write_sealed_shared: false,
                read_only_shared_file: false,
                secretmem: false,
                writable_memfd: None,
                shared_file_alias: None,
            },
            HostAliasShmatCommit {
                va,
                shmid,
                atime: 99,
                lpid: 100,
            },
        ));
        {
            let state = dispatcher.sysv.lock();
            assert!(!state.attachments.contains_key(&va));
            let segment = state.segments.get(&shmid).expect("pending segment");
            assert_eq!((segment.nattch, segment.atime, segment.lpid), (7, 2, 5));
        }
        let install = transaction
            .claim()
            .expect("claim pending host alias install");
        drop(install);
        let state = dispatcher.sysv.lock();
        assert!(!state.attachments.contains_key(&va));
        let segment = state.segments.get(&shmid).expect("aborted segment");
        assert_eq!((segment.nattch, segment.atime, segment.lpid), (7, 2, 5));
    }

    /// `shmctl(IPC_SET)` must APPLY the requested permission bits to carrick's
    /// owned shm-segment bookkeeping — it was a silent no-op on every lane, so
    /// the mode change a guest requested was dropped. After IPC_SET, an IPC_STAT
    /// must read the new mode back. (Mirrors the semctl/msgctl IPC_SET twins,
    /// which already apply their supplied fields.) Pre-fix the stat read-back
    /// would still report the unchanged 0o600.
    #[test]
    fn shmctl_ipc_set_stores_mode_and_round_trips_via_ipc_stat() {
        let dispatcher = SyscallDispatcher::new();
        let reporter = CompatReporter::default();

        // Seed a segment with an initial mode of 0o600. IPC_SET/IPC_STAT operate
        // purely on carrick's metadata, so no host backing file is needed.
        let shmid: i32 = 4242;
        dispatcher.sysv.lock().segments.insert(
            shmid,
            ShmSegment {
                path: PathBuf::from("/tmp/carrick-shm/test-ipc-set"),
                key: 0,
                size: 4096,
                mode: ShmPermMode::requested(0o600),
                uid: NsUid::ROOT,
                gid: NsGid::ROOT,
                cuid: NsUid::ROOT,
                cgid: NsGid::ROOT,
                nattch: 0,
                ctime: 1,
                atime: 0,
                dtime: 0,
                cpid: 1,
                lpid: 0,
            },
        );

        // Guest shmid_ds whose shm_perm.mode (offset 20) requests 0o666.
        let buf_addr = 0x10000u64;
        let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x400]);
        memory
            .write_bytes(buf_addr + 20, &0o666u32.to_le_bytes())
            .unwrap();

        let set = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    195,
                    SyscallArgs::from([shmid as u64, LINUX_IPC_SET, buf_addr, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .expect("shmctl is a claimed syscall")
            .expect("shmctl IPC_SET must not be a fatal DispatchError");
        assert_eq!(set, DispatchOutcome::Returned { value: 0 });

        // IPC_STAT into a fresh region of the same buffer.
        let stat_addr = 0x10100u64;
        let stat = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    195,
                    SyscallArgs::from([shmid as u64, LINUX_IPC_STAT, stat_addr, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .expect("shmctl is a claimed syscall")
            .expect("shmctl IPC_STAT must not be a fatal DispatchError");
        assert_eq!(stat, DispatchOutcome::Returned { value: 0 });

        // shm_perm.mode is at offset 20 of the shmid_ds written by IPC_STAT.
        let b = memory.read_bytes(stat_addr + 20, 4).unwrap();
        let mode = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        assert_eq!(
            mode & ShmPermMode::PERMS_MASK,
            0o666,
            "IPC_SET must store the requested mode so IPC_STAT reads it back \
             (pre-fix IPC_SET was a no-op and this stayed 0o600)"
        );
    }
}
