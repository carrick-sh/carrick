//! `/proc` mount: a synthetic procfs rendered on demand.
//!
//! # Theory of operation
//!
//! Linux's `/proc` is a window into kernel data structures. carrick has no
//! Linux kernel, so it *fabricates* `/proc` from the state it does have: the
//! loaded ELF address space, the guest's argv/environ/auxv, signal-disposition
//! masks, the modeled credentials and namespaces, and — because each guest
//! process is a real macOS process — the host's own process/thread tables.
//!
//! Every `/proc` file is generated when read, not stored. `synthetic_file`
//! is the central registry: it maps a path to the bytes a fresh read would
//! return, calling a `synthetic_proc_*` renderer that formats live state into
//! the exact text layout glibc, the Go runtime, systemd, apt, and the LTP
//! `tst_test` framework parse. Adding a new `/proc` file is a new arm here plus
//! its renderer and a test — and *only* here, which is the point of routing
//! `/proc` through one mount.
//!
//! ## `self`, numeric pids, and the namespace model
//!
//! `/proc/self/<x>`, `/proc/thread-self/<x>`, and `/proc/<pid>/<x>` for the
//! caller's own pid all name the same object. Guest pids are *namespace* pids
//! ([`crate::namespace::pid`]); the renderers are written against the literal
//! `/proc/self/*` form, so `normalize_self_pid_path` rewrites a numeric
//! self-pid (host pid *or* ns-pid) back to `/proc/self/*` before the match.
//! Enumerating or reading another process's `/proc/<pid>` works for a live
//! guest process, plus the Linux zombie interval for a namespace-mapped child
//! that has exited but has not yet been reaped. The path is translated ns-pid →
//! host-pid and gated on guest ownership (`proc_pid_dir_host_pid` /
//! `synthetic_task_dir`, which consult [`crate::host_proc::is_guest_process`],
//! namespace membership, and the thread tables). A `/proc/<pid>` for a reaped or
//! non-guest pid returns `ENOENT`, matching Linux.
//!
//! ## Live context is threaded in, not captured
//!
//! Several files reflect mutable dispatcher state — `/proc/self/maps` and
//! `smaps` need the current address-space regions, `cmdline`/`environ`/`auxv`
//! need the stack image, `status` needs the live signal masks and creds. The
//! dispatcher passes that snapshot in via [`SyntheticProcContext`] (for the
//! whole-file generators) and [`OpenContext`] (at `open`
//! time), so this module stays decoupled from the dispatcher struct. The
//! writable tunables (`oom_score_adj`, `loginuid`, …; see
//! `is_writable_tunable_path`) and the user-namespace map files
//! (`uid_map`/`gid_map`/`setgroups`; see `write_userns_map`) are the few
//! `/proc` paths that *accept* writes — the tunables are accepted-and-ignored
//! (carrick has no live OOM/audit state to mutate) so container managers that
//! poke them at startup succeed instead of getting EACCES, and the map files
//! drive real user-namespace id mapping.
//!
//! ## Honest limitations
//!
//! These files are faithful in *shape* and in the fields real software reads,
//! not in every value. Counters that carrick does not track (`io`, `schedstat`,
//! parts of `stat`/`statm`) report plausible constants rather than live
//! accounting; cross-process map writes (another process's `uid_map`) are not
//! modeled (only the `self/` forms). The bar is "the programs we run parse it
//! and behave like they do under Docker", verified against a Linux oracle —
//! not bit-exact procfs emulation.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use carrick_abi::{NsGid, NsUid};

use crate::linux_abi::{
    LINUX_DEFAULT_TIMERSLACK_NS, LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR, LINUX_EROFS, LinuxErrno,
};
use crate::memory::{
    LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_HEAP_BASE, LINUX_HEAP_SIZE,
    LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE, LINUX_RLIMIT_STACK_SOFT,
    LINUX_SIGRETURN_TRAMPOLINE_BASE, LINUX_STACK_SIZE, LINUX_STACK_TOP,
};

use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcMapsEntry {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub sharing: ProcMapSharing,
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcMapSharing {
    Private,
    Shared,
}

impl ProcMapSharing {
    fn marker(self) -> char {
        match self {
            Self::Private => 'p',
            Self::Shared => 's',
        }
    }
}

/// The ISA a guest reports about *itself* through arch-dependent synthetic
/// surfaces — `uname(2)`, `/proc/cpuinfo`, and any future arch-keyed file. A
/// single source (`ProcState::reported_arch`, mirroring `guest_hostname()`)
/// feeds all of them so they can never contradict each other: the bug this
/// closes was an x86_64 guest seeing `uname=x86_64` but `/proc/cpuinfo=ARM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuestReportedArch {
    #[default]
    Aarch64,
    X86_64,
}

pub type GuestMemoryRange = carrick_guest_mem::GuestVaRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticProcIdentity {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
}

/// One authoritative Linux thread rendered by the in-process HVPatch `/proc`
/// view. The Linux TID is distinct from the runtime registry id on this lane;
/// carrying the resolved state/name snapshot prevents `/proc/self/task/<tid>`
/// from accidentally consulting another HVPatch process's global registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticProcThread {
    pub tid: u32,
    pub state: char,
    pub comm: Option<String>,
}

/// One LIVE Linux process other than the reader, rendered by the in-process
/// HVPatch `/proc` view — the sibling of [`SyntheticProcZombie`], covering the
/// interval before a process exits.
///
/// It exists for the same reason: under HVPatch every Linux process is a thread
/// of ONE Darwin process, so Darwin's process table cannot describe a peer at
/// all. Asking it yields the CARRIER's identity — which is how a guest reading
/// `/proc/<peer>/stat` used to receive five-digit host ppid/pgrp/session values
/// straight out of macOS. The authoritative Kernel task record must cross the
/// dispatcher/VFS boundary instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticProcProcess {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub state: char,
    /// Every live thread's Linux tid, straight from the kernel graph's per-task
    /// thread claims. It is what `/proc/<pid>/task/` lists and what `stat`
    /// field 20 / `status`' `Threads:` count; Darwin's thread table cannot be
    /// asked, because on HVPatch it describes every process in the carrier at
    /// once.
    pub tids: Vec<u32>,
    pub comm: String,
}

/// One exited-but-unreaped Linux process rendered by the in-process HVPatch
/// `/proc` view. HVPatch children are host threads, so Darwin's process table
/// cannot observe their zombie interval; the authoritative Kernel record must
/// cross the dispatcher/VFS boundary instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticProcZombie {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub comm: String,
}

/// Minimal live state needed by synthetic `/proc` renderers.
#[derive(Debug, Clone, Default)]
pub struct SyntheticProcContext {
    pub executable_path: String,
    pub argv: Vec<String>,
    /// Current process comm as recorded by `prctl(PR_SET_NAME)`.
    pub task_comm: String,
    /// Current `prctl(PR_SET_TIMERSLACK)` value in nanoseconds.
    pub timerslack_ns: u64,
    /// The ISA this guest reports about itself, so `/proc/cpuinfo` agrees with
    /// `uname(2)` for x86_64 guests (native x86 backends + Rosetta-translated).
    pub guest_arch: GuestReportedArch,
    /// The guest UTS hostname, kept in lockstep with `uname(2)` nodename and
    /// `/etc/hostname`.
    pub guest_hostname: String,
    /// Guest environment (`KEY=VALUE`) as opaque bytes, surfaced via
    /// `/proc/self/environ` (env values need not be UTF-8).
    pub environ: Vec<Vec<u8>>,
    /// The guest's currently-open fd numbers, for the `/proc/self/fd` listing.
    pub open_fds: Vec<i32>,
    /// The active Linux-visible network namespace model.
    pub network: carrick_spec::NetworkNamespaceSpec,
    /// The serialized ELF auxv byte image (type/value pairs through AT_NULL) the
    /// guest received on its stack, surfaced verbatim via `/proc/self/auxv`.
    pub auxv: Vec<u8>,
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    pub locked_memory: Vec<GuestMemoryRange>,
    pub brk_current: u64,
    pub mmap_next: u64,
    /// The memory layout's heap (brk arena) base — see
    /// [`crate::vfs::OpenContext::heap_base`]. 0 = unknown.
    pub heap_base: u64,
    /// Guest VAs are host VAs (native exec backend) — see
    /// [`crate::vfs::OpenContext::native_guest_va`].
    pub native_guest_va: bool,
    pub ruid: NsUid,
    pub euid: NsUid,
    pub suid: NsUid,
    pub rgid: NsGid,
    pub egid: NsGid,
    pub sgid: NsGid,
    pub groups: Vec<NsGid>,
    /// Signal-disposition masks for `/proc/<pid>/status` (bit `signum-1`).
    pub sig_ignored: u64,
    pub sig_caught: u64,
    pub sig_shdpnd: u64,
    /// Exact task identity for the in-process HVPatch kernel lane. `None`
    /// preserves mature native/VMM host-process rendering byte-for-byte.
    pub identity: Option<SyntheticProcIdentity>,
    /// Every live process's `oom_score_adj`, keyed by Linux pid. The dispatcher
    /// fills this from whichever backend owns per-process state, so this
    /// renderer has exactly one lookup path and never has to guess whether a
    /// guest process is a host process. A pid absent from the map has no live
    /// process behind it, which is what makes `/proc/<dead-pid>/oom_score_adj`
    /// ENOENT rather than a fabricated 0.
    pub oom_score_adj: std::collections::BTreeMap<u32, i32>,
    /// The CALLING process's capability sets and user-namespace view, snapshot
    /// from its `Task` by the dispatcher. `/proc/self/status`'s `Cap*` lines and
    /// `/proc/self/{uid_map,gid_map,setgroups}` render from this rather than
    /// from a process-global cell, because under HVPatch every Linux process is
    /// a thread of one Darwin process and a global would show every guest the
    /// same capabilities and maps.
    pub creds_ns: crate::namespace::process::ProcessCredsNs,
    /// Every LIVE Linux process, from the kernel graph. This is the authority
    /// for a `/proc/<peer-pid>/…` read: HVPatch peers have no host process of
    /// their own, so without it the renderer falls through to a host-derived
    /// answer that describes the Darwin carrier. `None` on a lane with no
    /// kernel graph, where one Linux process IS one host process and the
    /// mature host-process derivation is correct.
    pub processes: Option<Vec<SyntheticProcProcess>>,
    /// Exact live-thread snapshot for the same task. `None` preserves the
    /// mature one-process-per-host-process registry lookup byte-for-byte.
    pub threads: Option<Vec<SyntheticProcThread>>,
    /// Exact exited-but-unreaped process snapshot for HVPatch. `None`
    /// preserves mature native/VMM host-process zombie discovery byte-for-byte.
    pub zombies: Option<Vec<SyntheticProcZombie>>,
    pub sysvipc_shm: String,
    pub sysvipc_sem: String,
    pub sysvipc_msg: String,
}

/// The three writable user-namespace map files (only the `self/` forms; writing
/// another live process's map needs a parent relationship carrick does not yet
/// model — design §4.3). Phase 1 supports the self-map case, which is what
/// `unshare -Ur`, apt's sandbox, and bubblewrap exercise.
pub(crate) fn is_userns_map_path(path: &str) -> bool {
    matches!(
        path,
        "/proc/self/uid_map" | "/proc/self/gid_map" | "/proc/self/setgroups"
    )
}

/// The per-process tunables Linux exposes read-WRITE. `oom_score_adj` is
/// backed by real per-process state (see [`TunableWrite`]); the rest carrick
/// accepts but does not act on, because it has no live audit/timer-slack
/// state. Making them writable means systemd/container managers that write
/// them at startup get a successful write instead of EACCES/EBADF (and the
/// warning that follows); the read keeps returning the documented default.
///
/// The pid component may be `self`, `thread-self`, or ANY numeric pid: Linux
/// lets one process write another's `oom_score_adj`, and LTP's `tst_test`
/// setup does exactly that. Liveness is not re-checked here — `open` only
/// reaches this predicate after `synthetic_file` resolved the path, which
/// already gates a numeric pid on being a live process.
pub(crate) fn is_writable_tunable_path(path: &str) -> bool {
    matches!(
        proc_tunable_name(path),
        Some((
            "oom_score_adj" | "oom_adj" | "loginuid" | "timerslack_ns",
            _
        ))
    )
}

/// Split a `/proc/<pid>/<tunable>` path into its trailing file name and the
/// explicit numeric pid it named, if any (`self`/`thread-self` yield `None`
/// for the pid — the caller substitutes its own).
fn proc_tunable_name(path: &str) -> Option<(&str, Option<u32>)> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, name) = rest.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    match pid {
        "self" | "thread-self" => Some((name, None)),
        _ if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) => {
            Some((name, pid.parse().ok()))
        }
        _ => None,
    }
}

/// A parsed, already-validated write to a `/proc/<pid>/` tunable. The VFS
/// parses; the dispatcher applies, because only the dispatcher knows which
/// backend owns per-process state (the HVPatch kernel graph, where every Linux
/// process is a thread of one Darwin process, versus a lane where a guest
/// process IS a host process). Keeping the choice at that one seam is what
/// stops the two models from being silently conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunableWrite {
    /// Set `oom_score_adj` on `pid` (`None` = the calling process).
    OomScoreAdj { pid: Option<u32>, value: i32 },
    /// Accepted and dropped — carrick models no state behind it.
    Ignored,
}

/// Parse a write(2) to a writable `/proc/<pid>/` tunable, applying Linux's
/// front-door validation. `oom_score_adj` outside [-1000, 1000] or unparseable
/// is EINVAL, exactly as Linux rejects it before touching the process.
pub(crate) fn parse_tunable_write(path: &str, data: &[u8]) -> Result<TunableWrite, LinuxErrno> {
    let Some((name, pid)) = proc_tunable_name(path) else {
        return Ok(TunableWrite::Ignored);
    };
    if name != "oom_score_adj" {
        return Ok(TunableWrite::Ignored);
    }
    let value: i32 = std::str::from_utf8(data)
        .map_err(|_| crate::namespace::user::EINVAL)?
        .trim()
        .parse()
        .map_err(|_| crate::namespace::user::EINVAL)?;
    if !(OOM_SCORE_ADJ_MIN..=OOM_SCORE_ADJ_MAX).contains(&value) {
        return Err(crate::namespace::user::EINVAL);
    }
    Ok(TunableWrite::OomScoreAdj { pid, value })
}

/// Apply a write(2) to one of the user-namespace map files. Returns the
/// `write(2)` result: `Ok(bytes_written)` on success (the whole buffer is
/// "consumed" per kernel behavior), or `Err(positive_errno)` (EPERM / EINVAL)
/// to be returned as a negative errno. The write-once, setgroups-gate, ≤5-line
/// and unprivileged-single-id rules are enforced by [`crate::namespace::user`].
///
/// `ns` is the CALLING process's user namespace and `privileged` its own
/// `CAP_SETUID`/`CAP_SETGID` verdict — both supplied by the dispatcher from the
/// caller's task. `/proc/self/uid_map` names the writer's own namespace, so
/// resolving it from anything process-global would let one guest process
/// rewrite another's maps.
pub(crate) fn write_userns_map(
    ns: &mut crate::namespace::user::UserNs,
    privileged: bool,
    path: &str,
    data: &[u8],
) -> Result<usize, LinuxErrno> {
    let text = std::str::from_utf8(data).map_err(|_| crate::namespace::user::EINVAL)?;
    // The writer's outside id for the unprivileged single-id rule. carrick runs
    // the guest as a single host identity; the parent-ns euid/egid is the host
    // identity, which for the default container is 0. The unprivileged path is
    // only reached after the guest unshared a userns, where the parent-ns id is
    // the pre-unshare euid; for the common rootful case `privileged` is true and
    // this value is unused.
    let euid_outside = 0;
    let egid_outside = 0;
    match path {
        "/proc/self/uid_map" => ns.write_uid_map(text, privileged, euid_outside),
        "/proc/self/gid_map" => ns.write_gid_map(text, privileged, egid_outside),
        "/proc/self/setgroups" => ns.write_setgroups(text),
        _ => Err(crate::namespace::user::EINVAL),
    }
    .map(|()| data.len())
}

/// Linux's documented `oom_score_adj` range (proc(5)); anything outside it is
/// EINVAL at the write, before the process is touched.
const OOM_SCORE_ADJ_MIN: i32 = -1000;
const OOM_SCORE_ADJ_MAX: i32 = 1000;

/// `oom_score_adj` for a lane with NO kernel graph, where one Linux process is
/// one host process and this whole host process therefore IS one Linux
/// process. On HVPatch the value lives on the kernel-graph task instead (see
/// `Task::oom_score_adj`) — that is the authority, and the dispatcher picks
/// between them at the single seam where the backend is known.
static OOM_SCORE_ADJ_SINGLE_PROCESS: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);

/// Read the single-host-process lane's `oom_score_adj`.
pub(crate) fn single_process_oom_score_adj() -> i32 {
    OOM_SCORE_ADJ_SINGLE_PROCESS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Store the single-host-process lane's `oom_score_adj`. The value is already
/// range-checked by [`parse_tunable_write`].
pub(crate) fn set_single_process_oom_score_adj(value: i32) {
    OOM_SCORE_ADJ_SINGLE_PROCESS.store(value, std::sync::atomic::Ordering::Relaxed);
}

/// Seconds since the guest booted, for `/proc/uptime` field 1 and (via
/// [`boot_epoch_secs`]) `/proc/stat`'s `btime`.
///
/// This is `CLOCK_BOOTTIME`, because on Linux that is exactly what
/// `/proc/uptime` field 1 reports — so it MUST be the same authority the
/// `clock_gettime(CLOCK_BOOTTIME)` path uses, not a second one.
///
/// It used to be a lazily-initialised `OnceLock<Instant>` seeded on the FIRST
/// READ, which made the first reader see `0.00`. libuv's `uv_uptime()` slurps
/// `/proc/uptime` and asserts `uptime > 0` (`ASSERT_GT` in
/// `test-platform-output.c`), so the very first read failed — and the
/// `CLOCK_BOOTTIME` fallback in libuv never ran, because the slurp had
/// *succeeded*. It also disagreed with `clock_gettime(CLOCK_BOOTTIME)`, which
/// already reported host uptime: two sources of truth for one fact.
fn boot_elapsed() -> Duration {
    crate::dispatch::boottime_duration()
}

/// 16 cryptographically-random bytes (best-effort; all-zero on the rare
/// getrandom failure so we never panic in production — the no-panic gate).
fn random_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let _ = getrandom::fill(&mut buf);
    buf
}

/// Format 16 bytes as a version-4 UUID string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`),
/// newline-terminated. Used for both `kernel/random/uuid` (fresh per read) and
/// `kernel/random/boot_id` (stable per run).
fn format_uuid_v4(mut b: [u8; 16]) -> Vec<u8> {
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant RFC 4122
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
    .into_bytes()
}

/// `/proc/sys/kernel/random/uuid`: a fresh random v4 UUID on every read — Linux
/// uses this as a cheap unique-id/entropy source, so it must NOT be static.
fn sysctl_random_uuid() -> Vec<u8> {
    format_uuid_v4(random_16())
}

/// `/proc/sys/kernel/random/boot_id`: a random v4 UUID generated once per
/// carrick run and stable thereafter (proc_sys_kernel(5)). Replaces the old
/// all-zero sentinel that made every guest look like the same boot.
fn sysctl_boot_id() -> Vec<u8> {
    static BOOT_ID: OnceLock<Vec<u8>> = OnceLock::new();
    BOOT_ID.get_or_init(|| format_uuid_v4(random_16())).clone()
}

/// `/proc/sys/kernel/hostname`: fallback hostname for context-free procfs
/// lookups. Real opens receive a dispatcher snapshot and use the per-container
/// UTS hostname when one is configured.
fn sysctl_hostname() -> Vec<u8> {
    format!("{}\n", crate::execute::guest_hostname()).into_bytes()
}

/// `/proc/sys/kernel/osrelease`, `version` and `domainname` all render from the
/// same constants `uname(2)` uses. `newuname01` compares the syscall against
/// these three leaves field by field, so a second literal here is a guaranteed
/// TFAIL — which is exactly what it was before.
fn sysctl_osrelease() -> Vec<u8> {
    format!("{}\n", carrick_abi::CARRICK_KERNEL_RELEASE).into_bytes()
}

fn sysctl_kernel_version() -> Vec<u8> {
    format!("{}\n", carrick_abi::CARRICK_KERNEL_VERSION).into_bytes()
}

fn sysctl_domainname() -> Vec<u8> {
    format!("{}\n", carrick_abi::CARRICK_DOMAINNAME).into_bytes()
}

#[derive(Clone, Copy)]
struct KernelThreadLimit(u64);

impl KernelThreadLimit {
    const fn new(value: u64) -> Self {
        Self(value)
    }

    const fn raw(self) -> u64 {
        self.0
    }
}

const DEFAULT_THREADS_MAX: KernelThreadLimit = KernelThreadLimit::new(63_087);

fn sysctl_threads_max() -> Vec<u8> {
    let limit = host_threads_max().unwrap_or(DEFAULT_THREADS_MAX);
    format!("{}\n", limit.raw()).into_bytes()
}

fn host_threads_max() -> Option<KernelThreadLimit> {
    host_rlimit_nproc().or_else(host_kernel_threads_max)
}

// `rlim_t` width varies per host OS, so the fallible conversion below is
// load-bearing on FreeBSD (signed) and an identity elsewhere (u64).
#[allow(clippy::useless_conversion)]
fn host_rlimit_nproc() -> Option<KernelThreadLimit> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `getrlimit` initializes the passed `rlimit` on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, limit.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: success above initialized `limit`.
    let limit = unsafe { limit.assume_init() };
    if limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur == 0 {
        None
    } else {
        // `rlim_t` is signed on FreeBSD (i64) and unsigned elsewhere; a
        // negative soft limit names no real bound, so it degrades to None
        // (the caller's kernel-threads-max fallback) instead of wrapping.
        // The conversion is an identity where `rlim_t` is already u64.
        u64::try_from(limit.rlim_cur)
            .ok()
            .map(KernelThreadLimit::new)
    }
}

#[cfg(target_os = "linux")]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/threads-max").ok()?;
    raw.trim().parse::<u64>().ok().map(KernelThreadLimit::new)
}

#[cfg(target_os = "macos")]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    host_sysctl_u64("kern.maxprocperuid")
        .or_else(|| host_sysctl_u64("kern.maxproc"))
        .map(KernelThreadLimit::new)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    None
}

#[cfg(target_os = "macos")]
fn host_sysctl_u64(name: &str) -> Option<u64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut value: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: `sysctlbyname` writes at most `len` bytes into `value`; we pass a
    // matching size and a valid NUL-terminated sysctl name.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            &mut value as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 && len == std::mem::size_of::<u64>() {
        Some(value)
    } else {
        None
    }
}

fn context_guest_hostname(ctx: &SyntheticProcContext) -> &str {
    if ctx.guest_hostname.is_empty() {
        crate::execute::guest_hostname()
    } else {
        &ctx.guest_hostname
    }
}

/// A sysctl leaf value: a fixed byte string or a per-read generator.
enum Sysctl {
    Static(&'static [u8]),
    Dynamic(fn() -> Vec<u8>),
}

/// Single source of truth for the `/proc/sys/**` leaf files carrick serves.
/// `lookup`, `readdir`, `open`, and `synthetic_file` all derive from this table
/// so directory enumeration can never disagree with what `open()` will serve.
/// Values match the Docker linux/arm64 oracle (proc_sys_*(5)); where carrick
/// owns the real behaviour (overcommit, fd/pipe ceilings) they reflect that.
/// The `sched_rr_timeslice_ms` leaf body, rendered from the shared constant so
/// the file and `sched_rr_get_interval(2)` can never drift apart — LTP
/// `sched_rr_get_interval01` reads both and compares them.
const SCHED_RR_TIMESLICE_MS_LEAF: &[u8] = match carrick_abi::LINUX_SCHED_RR_TIMESLICE_MS {
    100 => b"100\n",
    // A new value needs its rendering added here; a silent mismatch between the
    // leaf and the syscall is exactly what this constant exists to prevent.
    _ => panic!("LINUX_SCHED_RR_TIMESLICE_MS has no rendered sysctl leaf"),
};

const SYSCTL_TABLE: &[(&str, Sysctl)] = &[
    // kernel.*
    ("/proc/sys/kernel/ostype", Sysctl::Static(b"Linux\n")),
    (
        "/proc/sys/kernel/osrelease",
        Sysctl::Dynamic(sysctl_osrelease),
    ),
    (
        "/proc/sys/kernel/version",
        Sysctl::Dynamic(sysctl_kernel_version),
    ),
    // Context-free fallback; synthetic_file handles this path first when a live
    // SyntheticProcContext supplies a per-container hostname.
    (
        "/proc/sys/kernel/hostname",
        Sysctl::Dynamic(sysctl_hostname),
    ),
    // Default 64-bit Linux pid ceiling. LTP (setpgid02) reads this to bound pid
    // scans; without it tst_test aborts with ENOENT.
    ("/proc/sys/kernel/pid_max", Sysctl::Static(b"4194304\n")),
    ("/proc/sys/kernel/ns_last_pid", Sysctl::Static(b"0\n")),
    // Linux default core dump filename pattern (matches the Docker oracle). Read
    // by tools deciding whether a core-dumping signal produces a dump — a leading
    // '|' means a pipe handler (dumps regardless of RLIMIT_CORE); "core" does not
    // (waitid10 setup reads this).
    ("/proc/sys/kernel/core_pattern", Sysctl::Static(b"core\n")),
    (
        "/proc/sys/kernel/shmall",
        Sysctl::Static(b"18446744073692774399\n"),
    ),
    (
        "/proc/sys/kernel/shmmax",
        Sysctl::Static(b"18446744073692774399\n"),
    ),
    ("/proc/sys/kernel/shmmni", Sysctl::Static(b"4096\n")),
    // SysV message-queue tunables. MSGMAX/MSGMNB mirror Linux defaults; MSGMNI
    // is Carrick's current owned-service queue-count capacity, not a host
    // process/thread shaping knob.
    ("/proc/sys/kernel/msgmax", Sysctl::Static(b"8192\n")),
    ("/proc/sys/kernel/msgmnb", Sysctl::Static(b"16384\n")),
    ("/proc/sys/kernel/msgmni", Sysctl::Static(b"8\n")),
    (
        "/proc/sys/kernel/sem",
        Sysctl::Static(b"32000\t1024000000\t500\t32000\n"),
    ),
    // perf_event_open(2) support marker: the man page's documented way to
    // detect perf support is this file's EXISTENCE (LTP perf_event_open01/02
    // TCONF without it). Value 2 = "unprivileged: user-space measurements
    // only", matching the Docker arm64 oracle; carrick's guest root passes the
    // paranoid gate the way root-with-CAP_PERFMON does on Linux.
    (
        "/proc/sys/kernel/perf_event_paranoid",
        Sysctl::Static(b"2\n"),
    ),
    // Default sampling-rate ceiling (matches the oracle). carrick refuses
    // sampling events, but tools read the knob before deciding a rate.
    (
        "/proc/sys/kernel/perf_event_max_sample_rate",
        Sysctl::Static(b"100000\n"),
    ),
    // Kernel taint flags: 0 = untainted. The LTP tst_test framework reads this at
    // setup/teardown for tests with `.taint_check` to detect kernel warnings/oopses;
    // a missing file made every such test TBROK in setup (tst_taint.c ENOENT).
    ("/proc/sys/kernel/tainted", Sysctl::Static(b"0\n")),
    // Highest capability number carrick models — libcap/systemd/runc loop
    // 0..=cap_last_cap dropping bounding-set caps.
    ("/proc/sys/kernel/cap_last_cap", Sysctl::Static(b"40\n")),
    // Present but read-only in Docker's LTP container. LTP io_uring tests use
    // this save/restore path to skip when they cannot change the kernel knob.
    ("/proc/sys/kernel/io_uring_disabled", Sysctl::Static(b"0\n")),
    // The keyring quota knobs (proc(5) "kernel/keys/*"). carrick implements no
    // keyring — add_key/keyctl return ENOSYS — but LTP's `tst_sys_conf` save/
    // restore does NOT probe the syscall: it `access(path, F_OK)`s the leaf,
    // and only `access(path, W_OK)` failing yields the TST_SR_TCONF_RO skip.
    // Missing leaves take the TST_SR_SKIP_MISSING branch instead, which merely
    // TINFOs and lets the test run against a keyring that is not there. The
    // sysctl-leaf writability gate already answers W_OK with EROFS, so
    // declaring the leaves is what converts add_key05 from a blind run into
    // the same honest TCONF Docker produces — the same declare-it-absent
    // pattern as `io_uring_disabled` above. Values are Linux's defaults.
    ("/proc/sys/kernel/keys/gc_delay", Sysctl::Static(b"300\n")),
    ("/proc/sys/kernel/keys/maxkeys", Sysctl::Static(b"200\n")),
    ("/proc/sys/kernel/keys/maxbytes", Sysctl::Static(b"20000\n")),
    // The root quota pair, same argument as the three above: `keyctl02` saves
    // and restores them through `tst_sys_conf`, so their ABSENCE made it TBROK
    // on a read the oracle answers.
    (
        "/proc/sys/kernel/keys/root_maxkeys",
        Sysctl::Static(b"1000000\n"),
    ),
    (
        "/proc/sys/kernel/keys/root_maxbytes",
        Sysctl::Static(b"25000000\n"),
    ),
    // `syslog11` saves this through tst_sys_conf; without the leaf it reports
    // "Path not found: ENOENT" where the oracle reports the read-only EROFS the
    // writability gate below already produces. Linux's default console/message
    // loglevel quad.
    ("/proc/sys/kernel/printk", Sysctl::Static(b"4\t4\t1\t7\n")),
    // `newuname01` cross-checks uname(2) against these leaves, and TBROKs on a
    // missing one. Docker leaves the domain name unset, which reads as the
    // literal "(none)".
    (
        "/proc/sys/kernel/domainname",
        Sysctl::Dynamic(sysctl_domainname),
    ),
    // The SCHED_RR quantum, in milliseconds. `sched_rr_get_interval01` reads
    // this leaf and compares it against what the syscall reports, so the two
    // must agree: see `LINUX_SCHED_RR_TIMESLICE_MS`.
    (
        "/proc/sys/kernel/sched_rr_timeslice_ms",
        Sysctl::Static(SCHED_RR_TIMESLICE_MS_LEAF),
    ),
    // `fcntl33`/`fcntl33_64` save and restore the lease break timeout.
    ("/proc/sys/fs/lease-break-time", Sysctl::Static(b"45\n")),
    // `clone09` saves this per-interface leaf; carrick has no net namespace, so
    // it is declared for the loopback device only, which is what the oracle's
    // container has.
    ("/proc/sys/net/ipv4/conf/lo/tag", Sysctl::Static(b"0\n")),
    // Host-powered process/thread ceiling. This is intentionally not used to
    // tune SysV IPC workloads; queue throughput belongs to the SysV service.
    (
        "/proc/sys/kernel/threads-max",
        Sysctl::Dynamic(sysctl_threads_max),
    ),
    ("/proc/sys/kernel/ngroups_max", Sysctl::Static(b"65536\n")),
    // carrick has no autogroup scheduler, so the honest value is 0.
    (
        "/proc/sys/kernel/sched_autogroup_enabled",
        Sysctl::Static(b"0\n"),
    ),
    ("/proc/sys/kernel/overflowuid", Sysctl::Static(b"65534\n")),
    ("/proc/sys/kernel/overflowgid", Sysctl::Static(b"65534\n")),
    (
        "/proc/sys/kernel/random/uuid",
        Sysctl::Dynamic(sysctl_random_uuid),
    ),
    (
        "/proc/sys/kernel/random/boot_id",
        Sysctl::Dynamic(sysctl_boot_id),
    ),
    (
        "/proc/sys/kernel/random/entropy_avail",
        Sysctl::Static(b"256\n"),
    ),
    // vm.* — carrick freely satisfies large anon mmaps, so "always overcommit"
    // (1) is the honest match; Redis warns loudly on anything else.
    ("/proc/sys/vm/overcommit_memory", Sysctl::Static(b"1\n")),
    // Elasticsearch hard-fails to boot if this is < 262144.
    ("/proc/sys/vm/max_map_count", Sysctl::Static(b"262144\n")),
    // Lowest address a process may mmap — matches carrick's null-guard.
    ("/proc/sys/vm/mmap_min_addr", Sysctl::Static(b"65536\n")),
    // Present but read-only in Docker's LTP container. shmget02 probes this
    // after seeing `/sys/kernel/mm/hugepages/` and skips hugepage-specific
    // assertions when the container cannot tune it.
    ("/proc/sys/vm/nr_hugepages", Sysctl::Static(b"0\n")),
    ("/proc/sys/vm/swappiness", Sysctl::Static(b"60\n")),
    // LTP's tst_sys_conf probes this before the fanotify dirty-cache tests
    // (fanotify10/23); absent, they TCONF "Path not found" where the oracle
    // TCONFs "Path is not writable". 100 is the kernel default and the value
    // the oracle reports.
    ("/proc/sys/vm/vfs_cache_pressure", Sysctl::Static(b"100\n")),
    // fs.* — file-max/nr_open match NOFILE_HARD (the RLIMIT_NOFILE ceiling
    // carrick enforces). file-nr is exactly THREE tab-separated ints.
    ("/proc/sys/fs/file-max", Sysctl::Static(b"1048576\n")),
    ("/proc/sys/fs/file-nr", Sysctl::Static(b"256\t0\t1048576\n")),
    ("/proc/sys/fs/nr_open", Sysctl::Static(b"1048576\n")),
    ("/proc/sys/fs/aio-max-nr", Sysctl::Static(b"65536\n")),
    ("/proc/sys/fs/pipe-max-size", Sysctl::Static(b"1048576\n")),
    // Per-user pipe-buffer accounting ceilings (in pages). carrick does not
    // enforce a per-user pipe-pages cap, but pipe15 SCANFs the soft limit to
    // size a pipe-creation loop, so it must be present and a positive integer;
    // the Linux default is 16384 pages (soft) with no hard cap (0).
    (
        "/proc/sys/fs/pipe-user-pages-soft",
        Sysctl::Static(b"16384\n"),
    ),
    ("/proc/sys/fs/pipe-user-pages-hard", Sysctl::Static(b"0\n")),
    ("/proc/sys/fs/overflowuid", Sysctl::Static(b"65534\n")),
    ("/proc/sys/fs/overflowgid", Sysctl::Static(b"65534\n")),
    // fs/inotify/* — file-watchers (chokidar/webpack/vite/fsnotify) read these.
    (
        "/proc/sys/fs/inotify/max_user_watches",
        Sysctl::Static(b"1048576\n"),
    ),
    (
        "/proc/sys/fs/inotify/max_user_instances",
        Sysctl::Static(b"8192\n"),
    ),
    (
        "/proc/sys/fs/inotify/max_queued_events",
        Sysctl::Static(b"16384\n"),
    ),
    // fs/mqueue/* (mq_overview(7) defaults).
    ("/proc/sys/fs/mqueue/msg_max", Sysctl::Static(b"10\n")),
    ("/proc/sys/fs/mqueue/msgsize_max", Sysctl::Static(b"8192\n")),
    ("/proc/sys/fs/mqueue/queues_max", Sysctl::Static(b"256\n")),
    // net/core/* — listen backlog + socket buffer ceilings.
    ("/proc/sys/net/core/somaxconn", Sysctl::Static(b"4096\n")),
    ("/proc/sys/net/core/rmem_max", Sysctl::Static(b"212992\n")),
    ("/proc/sys/net/core/wmem_max", Sysctl::Static(b"212992\n")),
    // net/ipv4/* — ip_local_port_range is exactly TWO tab-separated ints;
    // tcp_rmem/tcp_wmem are exactly THREE (min default max).
    (
        "/proc/sys/net/ipv4/ip_local_port_range",
        Sysctl::Static(b"32768\t60999\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_rmem",
        Sysctl::Static(b"4096\t131072\t6291456\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_wmem",
        Sysctl::Static(b"4096\t16384\t4194304\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_fin_timeout",
        Sysctl::Static(b"60\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_keepalive_time",
        Sysctl::Static(b"7200\n"),
    ),
    ("/proc/sys/net/ipv4/tcp_syncookies", Sysctl::Static(b"1\n")),
];

/// The rendered bytes for a `/proc/sys/**` leaf, or `None` if `path` is not a
/// served sysctl file.
fn sysctl_value(path: &str) -> Option<Vec<u8>> {
    SYSCTL_TABLE.iter().find_map(|(p, v)| {
        (*p == path).then(|| match v {
            Sysctl::Static(b) => b.to_vec(),
            Sysctl::Dynamic(f) => f(),
        })
    })
}

/// True iff `path` is one of the synthetic `/proc/sys/**` leaves carrick serves.
pub(crate) fn is_sysctl_leaf_path(path: &str) -> bool {
    SYSCTL_TABLE.iter().any(|(p, _)| *p == path)
}

/// True iff `path` is a `/proc/sys` directory (the root or any intermediate
/// component on the way to a leaf). Derived from the table so it can never
/// drift from what `readdir`/`open` will serve.
fn sysctl_is_dir(path: &str) -> bool {
    if path == "/proc/sys" {
        return true;
    }
    if !path.starts_with("/proc/sys/") {
        return false;
    }
    let prefix = format!("{path}/");
    SYSCTL_TABLE.iter().any(|(p, _)| p.starts_with(&prefix))
}

/// Immediate children of a `/proc/sys` directory: sub-directories and leaf
/// files derived from `SYSCTL_TABLE` by taking the next path component after
/// `path`. `None` if `path` is not a sysctl directory.
fn sysctl_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !sysctl_is_dir(path) {
        return None;
    }
    let prefix = format!("{path}/");
    let mut children: Vec<(String, EntryKind)> = Vec::new();
    for (p, _) in SYSCTL_TABLE {
        let Some(rest) = p.strip_prefix(&prefix) else {
            continue;
        };
        let (name, kind) = match rest.split_once('/') {
            Some((dir, _)) => (dir.to_string(), EntryKind::Directory),
            None => (rest.to_string(), EntryKind::File),
        };
        if !children.iter().any(|(n, _)| *n == name) {
            children.push((name, kind));
        }
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(
        children
            .into_iter()
            .map(|(name, kind)| DirEnt { name, kind }),
    );
    Some(entries)
}

/// The reader's OWN Linux pid — the one and only numeric `/proc/<n>` that is an
/// alias for `/proc/self`.
///
/// On HVPatch this MUST come from the kernel graph. Every Linux process there is
/// a thread of one Darwin process, so `std::process::id()` and
/// `namespace::pid::self_ns_pid()` both name the CARRIER, not the caller — and
/// inside a container the carrier's ns-pid is **1**. Treating that as "self"
/// aliased every guest process's `/proc/1/*` onto whichever process happened to
/// be reading it: `cat /proc/1/stat` from a shell that really was pid 1 printed
/// `2 (cat) R …`, and LTP `getpgid01` read the reader's pgrp out of
/// `/proc/1/stat` field 5 while `getpgid(1)` correctly answered 1.
///
/// Without a kernel graph one Linux process IS one host process, so the host
/// pid and its namespace translation are both genuinely this caller.
fn context_self_pid(ctx: &SyntheticProcContext) -> u32 {
    ctx.identity
        .map_or_else(crate::namespace::pid::self_ns_pid, |identity| identity.pid)
}

/// A numeric `/proc/<self-pid>/<rest>` is the same object as `/proc/self/<rest>`.
/// Rewrite it so the literal `/proc/self/*` renderers (which hold the live
/// `SyntheticProcContext`) serve it too — keeping `ls /proc/<pid>` consistent
/// with what `open()` resolves for the self process. Any OTHER pid is a peer and
/// must fall through to `synthetic_proc_pid_file`; see [`context_self_pid`] for
/// why "self" cannot be recognised from a host-process identity here.
fn normalize_self_pid_path<'a>(path: &'a str, ctx: &SyntheticProcContext) -> Cow<'a, str> {
    if let Some(rest) = path.strip_prefix("/proc/")
        && let Some((pid, sub)) = rest.split_once('/')
        && !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
    {
        let n: u32 = pid.parse().unwrap_or(0);
        if n != 0 && n == context_self_pid(ctx) {
            return Cow::Owned(format!("/proc/self/{sub}"));
        }
    }
    Cow::Borrowed(path)
}

/// `oom_score_adj` for `pid`, or `None` when no live process has that pid.
///
/// The dispatcher's per-process snapshot is the authority. An EMPTY snapshot
/// means the lane published none (one Linux process is one host process, so
/// this host process is the only Linux process there is) and every pid that
/// reached this renderer resolves to the single-process cell — the liveness
/// gate upstream already rejected pids with no process behind them.
fn pid_oom_score_adj(ctx: &SyntheticProcContext, pid: u32) -> Option<i32> {
    if let Some(value) = ctx.oom_score_adj.get(&pid) {
        return Some(*value);
    }
    ctx.oom_score_adj
        .is_empty()
        .then(single_process_oom_score_adj)
}

/// `oom_score_adj` for the calling process (`pid` = `None`) or an explicit pid.
fn context_oom_score_adj(ctx: &SyntheticProcContext, pid: Option<u32>) -> i32 {
    pid.or_else(|| ctx.identity.as_ref().map(|identity| identity.pid))
        .and_then(|pid| pid_oom_score_adj(ctx, pid))
        .unwrap_or_else(single_process_oom_score_adj)
}

/// The reader's own Linux pid, for the callers that hold an identity rather
/// than a whole [`SyntheticProcContext`]. See [`context_self_pid`] for why the
/// host pid cannot answer this on the HVPatch lane.
pub(crate) fn self_linux_pid(identity: Option<SyntheticProcIdentity>) -> u32 {
    identity.map_or_else(crate::namespace::pid::self_ns_pid, |identity| identity.pid)
}

/// True iff the `<pid>` component of a `/proc/<pid>/…` live-memory path names
/// the CALLER — a `self` alias or its own pid spelled numerically.
///
/// This gate is load-bearing, not cosmetic. Reads of `/proc/<pid>/mem` are NOT
/// a byte blob: the `read` handler's `SyntheticFile` arm translates the file
/// offset as a GUEST VIRTUAL ADDRESS and reads it out of the CALLER's address
/// space. When the predicate accepted any all-digit pid, `/proc/<peer>/mem`
/// therefore returned the READER's bytes at that address, presented as the
/// peer's — silent wrong data, which a debugger cannot tell from truth.
/// Measured live: a parent reading a forked child's `/proc/<child>/mem` at a
/// COW-broken page got its own `READERAA` marker where the Docker oracle
/// returned the child's `PEERBBBB`.
fn names_calling_process(mid: &str, self_pid: u32) -> bool {
    mid == "self" || mid == "thread-self" || (self_pid != 0 && mid.parse::<u32>() == Ok(self_pid))
}

/// True iff `path` is the CALLER's own `/proc/<pid>/mem`. A peer's is never
/// this — see [`names_calling_process`].
pub(crate) fn is_proc_self_mem_path(path: &str, self_pid: u32) -> bool {
    path.strip_prefix("/proc/")
        .and_then(|rest| rest.strip_suffix("/mem"))
        .is_some_and(|mid| names_calling_process(mid, self_pid))
}

/// True iff `path` is the CALLER's own `/proc/<pid>/pagemap`. Same shape and
/// same hazard as [`is_proc_self_mem_path`]: the renderer describes the
/// caller's address space, so a peer's pid must not reach it.
pub(crate) fn is_proc_self_pagemap_path(path: &str, self_pid: u32) -> bool {
    path.strip_prefix("/proc/")
        .and_then(|rest| rest.strip_suffix("/pagemap"))
        .is_some_and(|mid| names_calling_process(mid, self_pid))
}

/// The errno an open of a FOREIGN `/proc/<pid>/{mem,pagemap}` must fail with,
/// or `None` when `path` is not one of those (or names the caller, which is
/// served normally).
///
/// Carrick cannot address a non-current HVPatch `mm` — the same missing
/// capability that blocks cross-process `process_vm_readv`/`writev` — so these
/// two files cannot be SERVED for a peer. The choice is between failing and
/// lying, and this is a deliberate, stated DIVERGENCE from Linux, which does
/// serve them for a ptrace-eligible target (measured: the Docker oracle returns
/// the child's bytes). `EACCES` is the errno Linux itself produces on this exact
/// path when `mm_access` denies, so a caller sees a Linux-shaped refusal rather
/// than fabricated memory.
///
/// A pid the kernel graph does not know is `ENOENT`: its `/proc/<pid>`
/// directory does not exist, which is what the oracle reports and what carrick
/// used to get wrong by opening `/proc/424242/mem` successfully.
pub(crate) fn proc_foreign_live_memory_open_errno(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<crate::linux_abi::LinuxErrno> {
    let mid = path.strip_prefix("/proc/").and_then(|rest| {
        rest.strip_suffix("/mem")
            .or_else(|| rest.strip_suffix("/pagemap"))
    })?;
    if mid.contains('/') || names_calling_process(mid, context_self_pid(ctx)) {
        return None;
    }
    if !mid.bytes().all(|b| b.is_ascii_digit()) || mid.is_empty() {
        return None;
    }
    // Without a kernel graph this lane cannot enumerate peers at all; leave its
    // behaviour to the mature host-process path rather than inventing a refusal.
    ctx.processes.as_ref()?;
    Some(match graph_process(mid, ctx) {
        Some(_) => crate::linux_abi::LINUX_EACCES,
        None => LINUX_ENOENT,
    })
}

pub(crate) fn synthetic_file(path: &str, ctx: &SyntheticProcContext) -> Option<Vec<u8>> {
    let normalized = normalize_self_pid_path(path, ctx);
    let path = normalized.as_ref();
    // The CALLER's own `/proc/<pid>/mem` and `/proc/<pid>/pagemap` are live
    // files, not precomputed blobs: return an EMPTY blob so they OPEN as
    // `SyntheticFile`; the read handler recognizes the path and derives bytes
    // from guest memory or from the sparse pagemap offset. A PEER's must not
    // reach that handler — it would describe this caller's address space; see
    // `proc_foreign_live_memory_open_errno`.
    let self_pid = context_self_pid(ctx);
    if is_proc_self_mem_path(path, self_pid) || is_proc_self_pagemap_path(path, self_pid) {
        return Some(Vec::new());
    }
    match path {
        "/proc/cmdline" => Some(synthetic_proc_cmdline().to_vec()),
        "/proc/config.gz" => Some(synthetic_proc_config_gz(ctx.guest_arch)),
        "/proc/cpuinfo" => Some(synthetic_proc_cpuinfo(ctx.guest_arch)),
        "/proc/devices" => Some(synthetic_proc_devices().to_vec()),
        "/proc/diskstats" => Some(synthetic_proc_diskstats().to_vec()),
        "/proc/filesystems" => Some(synthetic_proc_filesystems().to_vec()),
        "/proc/loadavg" => Some(synthetic_proc_loadavg().to_vec()),
        "/proc/locks" => Some(Vec::new()),
        "/proc/meminfo" => Some(synthetic_proc_meminfo().to_vec()),
        "/proc/modules" => Some(Vec::new()),
        "/proc/mounts" => Some(synthetic_proc_mounts().to_vec()),
        "/proc/partitions" => Some(synthetic_proc_partitions().to_vec()),
        "/proc/stat" => Some(synthetic_proc_stat()),
        "/proc/swaps" => Some(synthetic_proc_swaps().to_vec()),
        "/proc/sysvipc/shm" => Some(ctx.sysvipc_shm.as_bytes().to_vec()),
        "/proc/sysvipc/sem" => Some(ctx.sysvipc_sem.as_bytes().to_vec()),
        "/proc/sysvipc/msg" => Some(ctx.sysvipc_msg.as_bytes().to_vec()),
        "/proc/uptime" => Some(synthetic_proc_uptime().into_bytes()),
        "/proc/version" => Some(synthetic_proc_version().to_vec()),
        "/proc/vmstat" => Some(synthetic_proc_vmstat().to_vec()),
        "/proc/self/auxv" => Some(synthetic_proc_self_auxv(&ctx.auxv)),
        "/proc/self/autogroup" => Some(b"/autogroup-0 nice 0\n".to_vec()),
        "/proc/self/cgroup" => Some(b"0::/\n".to_vec()),
        "/proc/self/cmdline" => Some(synthetic_proc_self_cmdline(&ctx.argv, &ctx.executable_path)),
        "/proc/self/comm" => Some(synthetic_proc_self_comm(ctx).into_bytes()),
        "/proc/self/environ" => Some(synthetic_proc_self_environ(&ctx.environ)),
        "/proc/self/io" => Some(synthetic_proc_self_io().to_vec()),
        "/proc/self/limits" => Some(synthetic_proc_self_limits().to_vec()),
        // The audit loginuid/sessionid "unset" sentinel ((uint32)-1), no newline.
        "/proc/self/loginuid" | "/proc/self/sessionid" => Some(b"4294967295".to_vec()),
        "/proc/self/maps" => Some(synthetic_proc_maps(ctx).into_bytes()),
        "/proc/self/mountinfo" => Some(synthetic_proc_self_mountinfo().to_vec()),
        "/proc/self/mounts" => Some(synthetic_proc_mounts().to_vec()),
        "/proc/self/mountstats" => Some(Vec::new()),
        // oom_score is the volatile computed score (0 is acceptable); oom_adj is
        // the legacy knob (0). oom_score_adj persists writes (per-process,
        // fork-inherited) so tst_test's OOM-protection read-back sees its -1000.
        "/proc/self/oom_score" | "/proc/self/oom_adj" => Some(b"0\n".to_vec()),
        "/proc/self/oom_score_adj" => {
            Some(format!("{}\n", context_oom_score_adj(ctx, None)).into_bytes())
        }
        // 8-digit hex personality flags (default ADDR/Linux = 0), no newline.
        "/proc/self/personality" => Some(b"00000000".to_vec()),
        "/proc/self/schedstat" => Some(b"0 0 1\n".to_vec()),
        "/proc/self/smaps" => Some(synthetic_proc_smaps(ctx).into_bytes()),
        "/proc/self/smaps_rollup" => Some(synthetic_proc_smaps_rollup(ctx).into_bytes()),
        "/proc/self/stat" => Some(synthetic_proc_self_stat(ctx).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm()),
        "/proc/self/status" => Some(synthetic_proc_self_status(ctx).into_bytes()),
        // A running/on-CPU task: syscall reports "running", wchan 0 (no newline).
        "/proc/self/syscall" => Some(b"running\n".to_vec()),
        "/proc/self/timerslack_ns" => {
            Some(format!("{}\n", context_timerslack_ns(ctx)).into_bytes())
        }
        "/proc/self/wchan" => Some(b"0".to_vec()),
        // User-namespace map files (user_namespaces(7)). For the initial
        // identity namespace these read as `0 0 4294967295` / `allow`, matching
        // observed `docker run` (docs/namespaces-design.md §1.2, §4.3). Writable
        // — see ProcVfs::open + the write(2) handler.
        "/proc/self/uid_map" => Some(ctx.creds_ns.user.uid_map_text().into_bytes()),
        "/proc/self/gid_map" => Some(ctx.creds_ns.user.gid_map_text().into_bytes()),
        "/proc/self/setgroups" => Some(ctx.creds_ns.user.setgroups_text().as_bytes().to_vec()),
        _ => {
            if path == "/proc/sys/kernel/hostname" {
                return Some(format!("{}\n", context_guest_hostname(ctx)).into_bytes());
            }
            if let Some(v) = sysctl_value(path) {
                return Some(v);
            }
            // /proc/net/<f>, plus the namespace-correct /proc/self/net/<f> and
            // /proc/<pid>/net/<f> aliases, share one renderer (proc_net(5)).
            if let Some(name) = proc_net_basename(path)
                && let Some(v) = synthetic_proc_net_file(name, &ctx.network)
            {
                return Some(v);
            }
            let self_comm = context_task_comm(ctx);
            parse_proc_pid_path(path)
                .and_then(|(pid, rest)| synthetic_proc_pid_file(pid, rest, &self_comm, ctx))
        }
    }
}

/// The `<f>` of a `/proc/net/<f>`, `/proc/self/net/<f>`, `/proc/thread-self/net/<f>`
/// or `/proc/<pid>/net/<f>` path — the namespace-correct net paths every tool
/// reaches all resolve to the same per-file renderer. `None` otherwise.
fn proc_net_basename(path: &str) -> Option<&str> {
    if let Some(name) = path.strip_prefix("/proc/net/") {
        return (!name.contains('/')).then_some(name);
    }
    let rest = path.strip_prefix("/proc/")?;
    let (pid, tail) = rest.split_once('/')?;
    if pid != "self" && pid != "thread-self" && !pid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let name = tail.strip_prefix("net/")?;
    (!name.contains('/')).then_some(name)
}

/// The `/proc/net/*` files carrick serves — listed by `readdir` so `ls /proc/net`
/// enumerates and `synthetic_proc_net_file` stays in sync with what's openable.
const PROC_NET_FILES: &[&str] = &[
    "arp",
    "dev",
    "dev_mcast",
    "if_inet6",
    "igmp",
    "igmp6",
    "ipv6_route",
    "netstat",
    "packet",
    "raw",
    "raw6",
    "route",
    "snmp",
    "snmp6",
    "sockstat",
    "sockstat6",
    "tcp",
    "tcp6",
    "udp",
    "udp6",
    "unix",
];

/// True iff `path` is a `/proc/net` directory: the bare `/proc/net` or the
/// namespace-correct `/proc/<pid>/net` of a LIVE process (self alias or a live
/// guest pid).
fn proc_net_is_dir(path: &str) -> bool {
    if path == "/proc/net" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    let Some(pid) = rest.strip_suffix("/net") else {
        return false;
    };
    proc_live_pid(pid).is_some()
}

/// Directory listing for a `/proc/net` directory, else `None`.
fn proc_net_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !proc_net_is_dir(path) {
        return None;
    }
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(PROC_NET_FILES.iter().map(|f| DirEnt {
        name: (*f).to_string(),
        kind: EntryKind::File,
    }));
    Some(entries)
}

/// Classify the process component of a `/proc/<pid>/…` path: `Some((is_self,
/// host_pid))` ONLY when it names a LIVE process — a self alias
/// (self/thread-self/curproc/this), or a numeric pid that resolves (ns→host) to
/// a live guest or to this process. `None` for a syntactically-numeric but
/// non-existent pid, so per-pid magic links / ns / net only materialize for
/// processes that actually exist (no `/proc/999999/exe` reported present) and a
/// foreign pid is distinguishable from self (no leaking self's identity).
pub(crate) fn proc_live_pid(pid: &str) -> Option<(bool, u32)> {
    if matches!(pid, "self" | "thread-self" | "curproc" | "this") {
        return Some((true, std::process::id()));
    }
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // proc_pid_dir_host_pid does the ns→host translation AND the liveness gate
    // (synthetic_task_dir), returning the host pid only for a live process.
    let host = proc_pid_dir_host_pid(&format!("/proc/{pid}"))?;
    Some((host == std::process::id(), host))
}

/// For a `/proc/{self,…,<pid>}/<rest>` path of a LIVE process, the `<rest>`
/// after the process component plus whether the pid is THIS process. `None` for
/// a non-existent pid (gating per-pid magic links/ns/net on liveness).
fn proc_pid_subpath(path: &str) -> Option<(bool, &str)> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, sub) = rest.split_once('/')?;
    let (is_self, _host) = proc_live_pid(pid)?;
    Some((is_self, sub))
}

/// `/proc/<pid>/ns/<type>` namespace symlinks. Each readlinks to `<type>:[<inode>]`
/// (namespaces(7)); the inodes are the standard initial-namespace numbers so a
/// same-namespace equality check (readlink ns/pid == another proc's ns/pid)
/// holds across the single guest carrick models. `*_for_children` mirror their
/// base type's inode.
const PROC_NS_TYPES: &[(&str, u64)] = &[
    ("cgroup", 4026531835),
    ("ipc", 4026531839),
    ("mnt", 4026531840),
    ("net", 4026531992),
    ("pid", 4026531836),
    ("pid_for_children", 4026531836),
    ("time", 4026531834),
    ("time_for_children", 4026531834),
    ("user", 4026531837),
    ("uts", 4026531838),
];

/// The stable initial-namespace inode for ns `<type>` (e.g. `"uts"`), or `None`
/// if `<type>` is not a recognised namespace. This is the SAME inode the
/// `<type>:[<inode>]` readlink reports, so an fd opened on the magic link can
/// fstat to a `st_ino` that matches — two opens of the same ns type then compare
/// equal (the invariant `ioctl_ns` checks). `*_for_children` map to their base
/// type's inode.
pub(crate) fn ns_type_inode(ns_type: &str) -> Option<u64> {
    PROC_NS_TYPES
        .iter()
        .find(|(name, _)| *name == ns_type)
        .map(|(_, ino)| *ino)
}

/// The initial-namespace inode for a `/proc/{self,…,<pid>}/ns/<type>` path, if
/// it is one. Unlike `ns_type_inode` this takes the FULL path; it is the fstat
/// `st_ino` source for an fd opened on the nsfs magic link, so two opens of the
/// same ns type report the same inode. No liveness gate: the fd already exists,
/// so this only needs the type → inode mapping.
pub(crate) fn ns_link_inode(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("/proc/")?;
    let (_pid, leaf) = rest.split_once('/')?;
    let ns_type = leaf.strip_prefix("ns/")?;
    ns_type_inode(ns_type)
}

/// True iff `path` is a `/proc/<pid>/ns` directory of a live process.
fn proc_ns_is_dir(path: &str) -> bool {
    matches!(proc_pid_subpath(path), Some((_, "ns")))
}

/// True iff `path` is `/proc/<self>/fd` — the self process's open-fd directory.
/// Only self: a foreign process's fd table isn't reachable from carrick.
fn proc_fd_is_dir(path: &str) -> bool {
    matches!(proc_pid_subpath(path), Some((true, "fd")))
}

/// The fd number `N` of a `/proc/<self>/fd/N` magic symlink, if `path` is one.
fn proc_self_fd_link(path: &str) -> Option<i32> {
    let (is_self, rest) = proc_pid_subpath(path)?;
    if !is_self {
        return None;
    }
    let n = rest.strip_prefix("fd/")?;
    (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .then(|| n.parse().ok())
        .flatten()
}

/// True iff `path` is `/proc/<self>/fdinfo` — the self process's fdinfo dir.
fn proc_fdinfo_is_dir(path: &str) -> bool {
    matches!(proc_pid_subpath(path), Some((true, "fdinfo")))
}

/// True iff `path` is `/proc/<self>/fdinfo/N` — a per-fd info FILE (its contents
/// are rendered dispatcher-side from the live fd table).
fn proc_is_self_fdinfo_file(path: &str) -> bool {
    let Some((true, rest)) = proc_pid_subpath(path) else {
        return false;
    };
    rest.strip_prefix("fdinfo/")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Directory listing for a `/proc/<pid>/ns` directory (one symlink per ns type).
fn proc_ns_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !proc_ns_is_dir(path) {
        return None;
    }
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(PROC_NS_TYPES.iter().map(|(name, _)| DirEnt {
        name: (*name).to_string(),
        kind: EntryKind::Symlink,
    }));
    Some(entries)
}

/// The `<type>:[<inode>]` readlink target for a live `/proc/<pid>/ns/<type>` path.
fn proc_ns_link_target(path: &str) -> Option<String> {
    let (_is_self, rest) = proc_pid_subpath(path)?;
    let t = rest.strip_prefix("ns/")?;
    PROC_NS_TYPES
        .iter()
        .find(|(name, _)| *name == t)
        .map(|(name, ino)| format!("{name}:[{ino}]"))
}

/// If `path` is a *leaf* `/proc` magic symlink, its readlink-target length (for
/// the `st_size` an lstat reports). Drives `lookup_nofollow` reporting
/// `S_IFLNK` for the per-pid `exe`/`cwd`/`root` and `ns/<type>` links.
///
/// Deliberately does NOT include the bare `/proc/self`, `/proc/thread-self` or
/// `/proc/net` links: those must stay *traversable directories* so a path walk
/// into `/proc/self/<file>` descends rather than trying to follow a symlink to
/// a per-pid directory carrick doesn't fully serve (which would ENOTDIR every
/// `/proc/self/*` open — the intermediate-component check at
/// `dispatch/fs.rs` `validate_intermediate_dirs`). `readlink` still resolves
/// them (a readlink doesn't require the target to lstat as a symlink), so
/// `readlink /proc/self` → the pid and `readlink /proc/net` → self/net work.
fn proc_magic_symlink_size(path: &str) -> Option<u64> {
    // /proc/self/fd/N is a per-fd symlink (its target is synthesized by the
    // dispatcher's readlinkat, which can see the fd table).
    if proc_self_fd_link(path).is_some() {
        return Some(0);
    }
    let (is_self, rest) = proc_pid_subpath(path)?;
    if matches!(rest, "exe" | "cwd" | "root") {
        // exe/cwd/root are self-specific (carrick can't derive a foreign
        // process's executable/cwd), so only the self process resolves them;
        // a foreign live pid's exe/cwd/root is ENOENT rather than a leak of
        // self's identity. size = target length is reported by the dispatcher
        // on lstat where the live target is known.
        return is_self.then_some(0);
    }
    proc_ns_link_target(path).map(|t| t.len() as u64)
}

/// The `<tgid>/task/<tid>` readlink target for `/proc/thread-self`. ProcVfs has
/// no per-thread context, so this is the single-threaded approximation
/// (tid == tgid); the dispatcher overrides it with the live tid when threaded.
fn proc_thread_self_target() -> String {
    let p = crate::namespace::pid::self_ns_pid();
    format!("{p}/task/{p}")
}

/// Metadata for a `/proc` magic symlink: `S_IFLNK` mode 0o777, `size` = target
/// length (what an lstat reports as `st_size`).
fn proc_symlink_metadata(size: u64) -> Metadata {
    Metadata {
        kind: EntryKind::Symlink,
        mode: 0o777,
        size,
        uid: 0,
        gid: 0,
        mtime_secs: 0,
        mtime_nanos: 0,
    }
}

/// Host interfaces mapped to Linux-plausible names: `lo0`→`lo` (always present),
/// the first ethernet-like uplink (`enN`)→`eth0`; Darwin-only pseudo-interfaces
/// (awdl/llw/utun/bridge/gif/stf/…) are dropped so a guest never sees macOS-isms
/// or tries `if_nametoindex("en0")`. Feeds dev/igmp/igmp6/dev_mcast so the iface
/// NAME correlates across all of /proc/net.
fn linux_interfaces(
    network: &carrick_spec::NetworkNamespaceSpec,
) -> Vec<(u32, String, bool, bool)> {
    if network.mode != carrick_spec::NetworkMode::Host {
        return crate::network::model::LinuxNetworkModel::from_spec(network)
            .links
            .into_iter()
            .map(|link| (link.index, link.name, link.has_ipv4, link.has_ipv6))
            .collect();
    }
    host_linux_interfaces()
}

fn host_linux_interfaces() -> Vec<(u32, String, bool, bool)> {
    let mut out: Vec<(u32, String, bool, bool)> = Vec::new();
    let mut have_eth = false;
    for (_idx, name, v4, v6) in host_mc_interfaces() {
        if name == "lo0" || name == "lo" {
            if !out.iter().any(|(_, n, _, _)| n == "lo") {
                // Loopback always carries both IPv4 (127.0.0.1) and IPv6 (::1).
                out.push((1, "lo".to_owned(), true, true));
            }
        } else if name.starts_with("en") && !have_eth {
            have_eth = true;
            // NO IPv6 on the uplink, even in host mode, and for the same reason
            // `LinuxNetworkModel` gives none: what would be emitted is not the
            // host's real address but a FABRICATED `fe80::…:1`
            // (`synthetic_proc_net_if_inet6`), and carrick cannot service an IPv6
            // multicast join on it — libuv's `udp_multicast_join6` gets
            // EADDRNOTAVAIL where the oracle skips.
            //
            // Inheriting the host's `v6` here made the fabrication guest-visible
            // in host mode only, which is the mode the conformance surface runs
            // in, so the model's fix never applied where it mattered. It is wrong
            // in both directions: libuv's `can_ipv6_external()` and
            // `tcp_connect6_link_local` both key off "does any enumerated
            // interface carry an fe80:: address", and Linux answers no.
            let _ = v6;
            out.push((2, "eth0".to_owned(), v4, false));
        }
    }
    if !out.iter().any(|(_, n, _, _)| n == "lo") {
        out.insert(0, (1, "lo".to_owned(), true, true));
    }
    out
}

/// Render `/proc/net/<name>` (and its `self/net` / `<pid>/net` aliases). carrick
/// is host-socket-passthrough, so the socket tables (tcp/udp/unix/…) are emitted
/// header-only — the high-fidelity idle case; a present, correctly-headered file
/// beats ENOENT for ss/netstat/lsof/node_exporter. Counters tables (snmp/netstat/
/// sockstat) carry the exact LABELS parsers key on, with zero values.
fn synthetic_proc_net_file(
    name: &str,
    network: &carrick_spec::NetworkNamespaceSpec,
) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = match name {
        "dev" => return Some(synthetic_proc_net_dev(network)),
        "igmp" => return Some(synthetic_proc_net_igmp(network)),
        "igmp6" => return Some(synthetic_proc_net_igmp6(network)),
        "dev_mcast" => return Some(synthetic_proc_net_dev_mcast(network)),
        "if_inet6" => synthetic_proc_net_if_inet6(network),
        "tcp" => b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_vec(),
        "tcp6" => b"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_vec(),
        "udp" => b"   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "udp6" => b"   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "raw" => b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "raw6" => b"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "unix" => b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec(),
        "packet" => b"sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n".to_vec(),
        "arp" => b"IP address       HW type     Flags       HW address            Mask     Device\n".to_vec(),
        "route" => synthetic_proc_net_route(network),
        "ipv6_route" => synthetic_proc_net_ipv6_route(),
        "snmp" => synthetic_proc_net_snmp(),
        "snmp6" => synthetic_proc_net_snmp6(),
        "netstat" => synthetic_proc_net_netstat(),
        "sockstat" => b"sockets: used 0\nTCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0\nUDP: inuse 0 mem 0\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n".to_vec(),
        "sockstat6" => b"TCP6: inuse 0\nUDP6: inuse 0\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n".to_vec(),
        _ => return None,
    };
    Some(bytes)
}

/// `/proc/net/if_inet6`: one row per IPv6 interface (proc_net(5)). Loopback's
/// `::1/128` plus a row per mapped uplink; glibc's `__check_pf` reads this.
fn synthetic_proc_net_if_inet6(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, _v4, v6) in linux_interfaces(network) {
        if name == "lo" {
            s.push_str(&format!(
                "00000000000000000000000000000001 {idx:02x} 80 10 80 {name:>9}\n"
            ));
        } else if v6 {
            s.push_str(&format!(
                "fe800000000000000000000000000001 {idx:02x} 40 20 80 {name:>9}\n"
            ));
        }
    }
    s.into_bytes()
}

/// `/proc/net/dev`: the two verbatim header lines (proc_net(5) quotes them
/// exactly) then one all-zero-counter row per Linux-mapped interface.
fn synthetic_proc_net_dev(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    if network.mode != carrick_spec::NetworkMode::Host {
        return crate::network::model::LinuxNetworkModel::from_spec(network).render_proc_net_dev();
    }
    let mut s = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for (_idx, name, _v4, _v6) in linux_interfaces(network) {
        s.push_str(&format!(
            "{name:>6}: 0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        ));
    }
    s.into_bytes()
}

/// `/proc/net/dev_mcast`: the standard all-nodes multicast MAC memberships per
/// interface (333300000001 = IPv6 all-nodes, 01005e000001 = IPv4 all-hosts).
fn synthetic_proc_net_dev_mcast(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, v4, v6) in linux_interfaces(network) {
        if v6 {
            s.push_str(&format!("{idx:<4} {name:<15} 1     0     333300000001\n"));
        }
        if v4 {
            s.push_str(&format!("{idx:<4} {name:<15} 1     0     01005e000001\n"));
        }
    }
    s.into_bytes()
}

/// `/proc/net/route`: header + an on-link default route via the primary uplink
/// and a loopback route. Addresses are little-endian hex (proc_net(5)).
fn synthetic_proc_net_route(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    if network.mode != carrick_spec::NetworkMode::Host {
        return crate::network::model::LinuxNetworkModel::from_spec(network)
            .render_proc_net_route();
    }
    let eth = linux_interfaces(network)
        .into_iter()
        .find(|(_, n, _, _)| n == "eth0")
        .map(|(_, n, _, _)| n);
    if let Some(eth) = eth {
        // Default route, on-link (gateway 0.0.0.0), mask 0.0.0.0.
        s.push_str(&format!(
            "{eth}\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
        ));
    }
    s.into_bytes()
}

/// `/proc/net/ipv6_route`: loopback rows in the fixed 32-hex-digit layout, no
/// header (proc_net(5)). `::1/128` and `::/0` on lo.
fn synthetic_proc_net_ipv6_route() -> Vec<u8> {
    b"00000000000000000000000000000001 80 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000000 00000001 00000000 00000001 lo\n"
        .to_vec()
}

/// `/proc/net/snmp`: the paired `Label: names` / `Label: values` lines per
/// protocol group. Static-but-correctly-labelled (cumulative counters), which
/// is what node_exporter/SNMP collectors key on.
fn synthetic_proc_net_snmp() -> Vec<u8> {
    b"Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
IcmpMsg: InType3 OutType3\n\
IcmpMsg: 0 0\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
Udp: 0 0 0 0 0 0 0 0\n\
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
UdpLite: 0 0 0 0 0 0 0 0\n".to_vec()
}

/// `/proc/net/snmp6`: flat `Label\tvalue` IPv6 counter list (zeros).
fn synthetic_proc_net_snmp6() -> Vec<u8> {
    b"Ip6InReceives\t0\n\
Ip6InHdrErrors\t0\n\
Ip6InTooBigErrors\t0\n\
Ip6InNoRoutes\t0\n\
Ip6InDelivers\t0\n\
Ip6OutRequests\t0\n\
Ip6OutNoRoutes\t0\n\
Icmp6InMsgs\t0\n\
Icmp6OutMsgs\t0\n\
Udp6InDatagrams\t0\n\
Udp6OutDatagrams\t0\n"
        .to_vec()
}

/// `/proc/net/netstat`: the `TcpExt:`/`IpExt:` label line + matching zero-value
/// line. Read positionally-by-name, so the label set matters, values can be 0.
fn synthetic_proc_net_netstat() -> Vec<u8> {
    b"TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPSlowStartRetrans TCPTimeouts\n\
TcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps\n\
IpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".to_vec()
}

/// `(index, name, has_ipv4, has_ipv6)` for each host interface, via getifaddrs.
/// Used to synthesize `/proc/net/igmp[6]` so a guest's `Interface.MulticastAddrs`
/// reports the standard multicast groups every Linux interface joins.
#[cfg(target_os = "macos")]
fn host_mc_interfaces() -> Vec<(u32, String, bool, bool)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, (u32, bool, bool)> = BTreeMap::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Vec::new();
    }
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let idx = {
            let c = std::ffi::CString::new(name.clone()).unwrap_or_default();
            unsafe { libc::if_nametoindex(c.as_ptr()) }
        };
        let entry = map.entry(name).or_insert((idx, false, false));
        if idx != 0 {
            entry.0 = idx;
        }
        if !ifa.ifa_addr.is_null() {
            match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
                libc::AF_INET => entry.1 = true,
                libc::AF_INET6 => entry.2 = true,
                _ => {}
            }
        }
    }
    unsafe { libc::freeifaddrs(head) };
    map.into_iter()
        .map(|(name, (idx, v4, v6))| (idx, name, v4, v6))
        .collect()
}
#[cfg(not(target_os = "macos"))]
fn host_mc_interfaces() -> Vec<(u32, String, bool, bool)> {
    vec![(1, "lo".to_owned(), true, true)]
}

/// `/proc/net/igmp`: one block per IPv4 interface listing the all-hosts group
/// (224.0.0.1), matching the format Go's `parseProcNetIGMP` reads (the group is
/// the address in NATIVE/little-endian hex).
fn synthetic_proc_net_igmp(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    let mut s = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    for (idx, name, v4, _v6) in linux_interfaces(network) {
        if !v4 {
            continue;
        }
        s.push_str(&format!("{idx}\t{name:<10}:     1      V3\n"));
        // 224.0.0.1 = 0xE0000001; native (LE) byte order -> "010000E0".
        s.push_str("\t\t\t\t010000E0     1 0:00000000\t\t0\n");
    }
    s.into_bytes()
}

/// `/proc/net/igmp6`: the all-nodes link-local (ff02::1) and interface-local
/// (ff01::1) groups per IPv6 interface — the address is straight network-order
/// hex, as Go's `parseProcNetIGMP6` reads.
fn synthetic_proc_net_igmp6(network: &carrick_spec::NetworkNamespaceSpec) -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, _v4, v6) in linux_interfaces(network) {
        if !v6 {
            continue;
        }
        s.push_str(&format!(
            "{idx:<4} {name:<16}ff020000000000000000000000000001     1 0000000C 0\n"
        ));
        s.push_str(&format!(
            "{idx:<4} {name:<16}ff010000000000000000000000000001     1 00000008 0\n"
        ));
    }
    s.into_bytes()
}

/// Directory entries (tid names) for `/proc/<pid>/task/`, or `None` if `pid`
/// isn't a guest we expose.
pub(crate) fn synthetic_task_dir(pid: u32) -> Option<Vec<String>> {
    let own = crate::current_thread_states();
    if own.iter().any(|(t, _)| t.raw() as u32 == pid) {
        let self_host_pid = std::process::id();
        let self_ns_pid = crate::namespace::pid::self_ns_pid();
        return Some(
            own.iter()
                .map(|(t, _)| {
                    let raw = t.raw() as u32;
                    if raw == self_host_pid {
                        self_ns_pid.to_string()
                    } else {
                        raw.to_string()
                    }
                })
                .collect(),
        );
    }
    if crate::host_proc::is_guest_process(pid) {
        let display_pid = if crate::namespace::pid::enabled() {
            crate::namespace::pid::host_to_ns_or_self(pid)
        } else {
            pid
        };
        if display_pid == 0 {
            return None;
        }
        return Some(vec![display_pid.to_string()]);
    }
    // The calling process is always its own live task, so `/proc/self` (which
    // resolves to `std::process::id()`) must stay openable even when no guest
    // thread is registered (unit tests) or `is_guest_process` is gated by a
    // namespace region this process was never registered in.
    if pid == std::process::id() {
        return Some(vec![pid.to_string()]);
    }
    None
}

/// Translate a guest-supplied (namespace) pid to a HOST pid; identity when no
/// PID namespace is active. `None` for an ns-pid that maps to no live process.
/// The synthetic `/proc/<pid>` machinery validates against HOST tids/pids
/// (`current_thread_states`/`is_guest_process`), so a numeric `/proc/<ns-pid>`
/// must be translated before it can be matched (without this, every
/// `/proc/<pid>` under a PID namespace missed → ENOSYS).
fn ns_pid_to_host(ns_pid: u32) -> Option<u32> {
    if crate::namespace::pid::enabled() {
        crate::namespace::pid::ns_to_host_or_self(ns_pid)
    } else {
        Some(ns_pid)
    }
}

#[derive(Debug, Clone, Copy)]
struct ProcHostPid(u32);

impl ProcHostPid {
    fn waitid_id(self) -> libc::id_t {
        self.0 as libc::id_t
    }

    fn raw_i32(self) -> i32 {
        self.0 as i32
    }
}

fn host_child_exited_unreaped(pid: ProcHostPid) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid.waitid_id(),
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc != 0 {
        return false;
    }

    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    carrick_portable::si_pid(&info) == pid.raw_i32()
        && matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED)
}

fn mapped_existing_ns_pid(ns_pid: u32, host_pid: u32) -> bool {
    crate::namespace::pid::enabled()
        && crate::namespace::pid::ns_to_host_or_self(ns_pid) == Some(host_pid)
        && (crate::host_proc::pid_info(host_pid).is_some()
            || host_child_exited_unreaped(ProcHostPid(host_pid)))
}

/// The backing HOST pid for a `/proc/<pid>` DIRECTORY path (the pid component
/// only, no sub-path), or `None` if the path isn't a numeric process directory
/// or the pid isn't a process we expose. Used both to gate the directory
/// open and to let `pidfd_send_signal` treat a `/proc/<pid>` directory fd as a
/// pidfd (Linux allows a `/proc/<pid>` dir fd anywhere a pidfd is expected).
pub(crate) fn proc_pid_dir_host_pid(path: &str) -> Option<u32> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let comp = p.strip_prefix("/proc/")?;
    if comp.contains('/') {
        return None; // a sub-path (/proc/<pid>/task, …), not the pid dir itself
    }
    // `self`/`thread-self` resolve to the calling process (the same mapping
    // parse_proc_pid_path uses for sub-path file reads), so the bare /proc/self
    // directory is openable/stat-able/scandir-able — not just /proc/self/<file>.
    let (host_pid, ns_pid) = if comp == "self" || comp == "thread-self" {
        (std::process::id(), None)
    } else {
        let ns_pid = comp.parse().ok()?;
        (ns_pid_to_host(ns_pid)?, Some(ns_pid))
    };
    if synthetic_task_dir(host_pid).is_none()
        && !ns_pid.is_some_and(|pid| mapped_existing_ns_pid(pid, host_pid))
    {
        return None;
    }
    Some(host_pid)
}

/// Linux pid encoded by a bare `/proc/<pid>` directory path. Unlike
/// [`proc_pid_dir_host_pid`], this parser does not consult the host process
/// table: HVPatch processes have no distinct host pid and resolve the result
/// against Carrick's Kernel task graph instead.
pub(crate) fn proc_pid_dir_linux_pid(path: &str) -> Option<u32> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let component = path.strip_prefix("/proc/")?;
    if component.contains('/') {
        return None;
    }
    if matches!(component, "self" | "thread-self") {
        return Some(crate::namespace::pid::self_ns_pid());
    }
    component.parse().ok()
}

/// `(., .., <tid>...)` entries for a `/proc/<pid>/task/` path. Accepts the
/// `self`/`thread-self`/… aliases as well as a numeric pid (so `/proc/self/task`
/// resolves — it is listed in the self dir's readdir, and must not ENOENT).
fn proc_task_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let pid_comp = p.strip_prefix("/proc/")?.strip_suffix("/task")?;
    let (_is_self, host_pid) = proc_live_pid(pid_comp)?;
    let tids = synthetic_task_dir(host_pid)?;
    Some(proc_task_dir_entries_from_tids(tids))
}

fn proc_task_dir_entries_from_tids(tids: impl IntoIterator<Item = String>) -> Vec<DirEnt> {
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(tids.into_iter().map(|t| DirEnt {
        name: t,
        kind: EntryKind::Directory,
    }));
    entries
}

/// How Carrick's kernel task graph knows the pid a `/proc/<pid>` path names.
enum GraphProcess<'a> {
    /// The reader itself, named by a `self` alias or by its own pid.
    Reader,
    /// A live PEER process, as the graph's live-task snapshot describes it.
    Peer(&'a SyntheticProcProcess),
    /// An exited-but-unreaped process. Linux keeps `/proc/<pid>` present for a
    /// zombie (with a single `task/<pid>` entry) until it is reaped.
    Zombie,
}

/// THE liveness authority for the pid component of a `/proc/<pid>…` path:
/// a `self` alias or a numeric Linux pid resolved against Carrick's kernel task
/// graph. `None` means "no such process" — the ENOENT Linux reports for a pid
/// that does not exist.
///
/// This exists because [`proc_pid_dir_host_pid`] cannot answer the question on
/// the lane that matters. Under HVPatch every Linux process is a THREAD of one
/// Darwin process, so a peer has no host pid of its own and the host process
/// table cannot tell `/proc/<live-peer>` from a pid that never existed — it
/// answers `None` for both, and every `/proc/<peer>` `stat`/`opendir` became
/// ENOENT. The graph reaches the VFS as the `identity`/`processes`/`zombies`
/// snapshot the dispatcher already assembles for `oom_score_adj` and the
/// per-pid renderers; this is the same authority, asked one layer earlier.
///
/// A lane that publishes no graph leaves `processes` `None`, and the caller
/// falls back to the host process table.
fn graph_process<'a>(component: &str, ctx: &'a SyntheticProcContext) -> Option<GraphProcess<'a>> {
    let identity = ctx.identity?;
    if matches!(component, "self" | "thread-self" | "curproc" | "this") {
        return Some(GraphProcess::Reader);
    }
    let pid: u32 = component.parse().ok()?;
    if pid == identity.pid {
        return Some(GraphProcess::Reader);
    }
    if let Some(peer) = ctx
        .processes
        .as_ref()?
        .iter()
        .find(|process| process.pid == pid)
    {
        return Some(GraphProcess::Peer(peer));
    }
    ctx.zombies
        .as_ref()
        .is_some_and(|zombies| zombies.iter().any(|zombie| zombie.pid == pid))
        .then_some(GraphProcess::Zombie)
}

/// The pid component of a `/proc/<pid>` path with `suffix` (`""` for the bare
/// process directory, `"/task"` for its thread directory).
fn proc_pid_path_component<'a>(path: &'a str, suffix: &str) -> Option<&'a str> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let rest = path.strip_prefix("/proc/")?;
    let component = if suffix.is_empty() {
        rest
    } else {
        rest.strip_suffix(suffix)?
    };
    (!component.is_empty() && !component.contains('/')).then_some(component)
}

/// Context-aware `/proc/<tgid>/task` listing, resolved through the kernel task
/// graph ([`graph_process`]) so a live PEER's thread directory exists — not
/// only the reader's. The tids come from the graph's own per-task thread
/// claims; Darwin's thread table describes the whole carrier on this lane and
/// would list every process's threads under every pid.
fn proc_task_dir_entries_with_context(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<Vec<DirEnt>> {
    let component = proc_pid_path_component(path, "/task")?;
    let tids = graph_process_tids(component, ctx)?;
    Some(proc_task_dir_entries_from_tids(
        tids.into_iter().map(|tid| tid.to_string()),
    ))
}

/// The tids of the process a `/proc/<pid>…` component names, per the kernel
/// task graph. `None` when no such process exists.
fn graph_process_tids(component: &str, ctx: &SyntheticProcContext) -> Option<Vec<u32>> {
    Some(match graph_process(component, ctx)? {
        GraphProcess::Reader => {
            let identity = ctx.identity?;
            ctx.threads
                .as_ref()
                .map(|threads| threads.iter().map(|thread| thread.tid).collect())
                .unwrap_or_else(|| vec![identity.tid])
        }
        GraphProcess::Peer(peer) => {
            if peer.tids.is_empty() {
                vec![peer.pid]
            } else {
                peer.tids.clone()
            }
        }
        GraphProcess::Zombie => vec![component.parse().ok()?],
    })
}

/// `/proc/<pid>/task/<tid>` — a per-THREAD directory, which Linux serves with
/// the same shape as the process directory. LTP `tgkill03` `access(2)`es one
/// and requires it to vanish (ENOENT) once the thread is joined, so the tid
/// must be checked against the graph's live claims rather than merely being
/// numeric.
fn proc_task_tid_dir_entries_with_context(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<Vec<DirEnt>> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let (pid_comp, tid_comp) = path.strip_prefix("/proc/")?.split_once("/task/")?;
    if pid_comp.is_empty() || pid_comp.contains('/') || tid_comp.contains('/') {
        return None;
    }
    let tid: u32 = tid_comp.parse().ok()?;
    graph_process_tids(pid_comp, ctx)?
        .contains(&tid)
        .then(|| proc_pid_dir_entries_for_known_process_named(false))
}

/// Per-process files Carrick exposes under a FOREIGN `/proc/<pid>/` (matching
/// what `synthetic_proc_pid_file` serves for another guest process).
///
/// The OOM knobs are here and not only under `self/` because Linux lets one
/// process read and write ANOTHER's: LTP's `tst_test` setup writes -1000 to
/// `/proc/<lib-pid>/oom_score_adj` from the test child and `access(2)`-checks
/// it first, so a self-only view TBROKs the entire new-API LTP framework
/// before a single assertion runs (`tst_memutils.c:set_oom_score_adj`).
const PROC_PID_FILES: &[&str] = &[
    "cmdline",
    "comm",
    "oom_adj",
    "oom_score",
    "oom_score_adj",
    "stat",
    "status",
];

/// The richer file set under the SELF process dir — every `/proc/self/<f>`
/// flat file `synthetic_file` actually serves — so `ls /proc/self` enumerates
/// what `open()` can resolve (proc(5)), not just the foreign 4-file subset.
const PROC_SELF_FILES: &[&str] = &[
    "auxv",
    "autogroup",
    "cgroup",
    "cmdline",
    "comm",
    "environ",
    "gid_map",
    "io",
    "limits",
    "loginuid",
    "maps",
    "mountinfo",
    "mounts",
    "mountstats",
    "oom_adj",
    "oom_score",
    "oom_score_adj",
    "personality",
    "schedstat",
    "sessionid",
    "setgroups",
    "smaps",
    "smaps_rollup",
    "stat",
    "statm",
    "status",
    "syscall",
    "timerslack_ns",
    "uid_map",
    "wchan",
];

/// Directory listing for `/proc/<pid>` when `pid` is a known process (an own
/// guest thread or a guest process), else `None`. The SELF dir is populated
/// with the full set of files/symlinks/sub-dirs carrick serves; a foreign pid
/// gets the subset its synthetic renderer can actually answer.
fn proc_pid_dir_entries_for_known_process(path: &str, is_self: bool) -> Option<Vec<DirEnt>> {
    proc_pid_dir_linux_pid(path)?;
    Some(proc_pid_dir_entries_for_known_process_named(is_self))
}

/// The listing itself, once the pid has been resolved. Split out so the
/// per-thread `/proc/<pid>/task/<tid>` directory — which Linux gives the same
/// shape — can share it without re-parsing a `/proc/<pid>` path.
fn proc_pid_dir_entries_for_known_process_named(is_self: bool) -> Vec<DirEnt> {
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "task".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    let files = if is_self {
        // Sub-directories and magic symlinks only the self dir fully serves.
        for dir in ["fd", "fdinfo", "ns", "net"] {
            entries.push(DirEnt {
                name: dir.to_string(),
                kind: EntryKind::Directory,
            });
        }
        for link in ["exe", "cwd", "root"] {
            entries.push(DirEnt {
                name: link.to_string(),
                kind: EntryKind::Symlink,
            });
        }
        PROC_SELF_FILES
    } else {
        PROC_PID_FILES
    };
    entries.extend(files.iter().map(|f| DirEnt {
        name: (*f).to_string(),
        kind: EntryKind::File,
    }));
    entries
}

fn proc_pid_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    // Gate on a numeric /proc/<pid> for a live process (ns-pid → host pid).
    let host_pid = proc_pid_dir_host_pid(path)?;
    proc_pid_dir_entries_for_known_process(path, host_pid == std::process::id())
}

fn proc_pid_dir_entries_with_context(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<Vec<DirEnt>> {
    let component = proc_pid_path_component(path, "")?;
    match graph_process(component, ctx) {
        Some(GraphProcess::Reader) => proc_pid_dir_entries_for_known_process(path, true),
        Some(GraphProcess::Peer(_) | GraphProcess::Zombie) => {
            proc_pid_dir_entries_for_known_process(path, false)
        }
        // No kernel graph on this lane: the host process table is still the
        // authority, one Linux process being one host process there.
        None => proc_pid_dir_entries(path),
    }
}

/// Whether the pid component of a `/proc/<pid>…` path names a process that
/// exists, asked of the kernel task graph FIRST and the host process table only
/// as the no-graph fallback.
///
/// This is the same authority [`graph_process`] provides, exposed as a bare
/// predicate for the subtrees that only need "does this process exist" and not
/// the process record itself.
pub(crate) fn proc_pid_component_is_live(component: &str, ctx: &SyntheticProcContext) -> bool {
    graph_process(component, ctx).is_some() || proc_live_pid(component).is_some()
}

/// The `/proc/<pid>/ns` component pair of a path, if it has one.
fn proc_ns_path_parts(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let rest = path.strip_prefix("/proc/")?;
    let (component, leaf) = rest.split_once('/')?;
    (!component.is_empty()).then_some((component, leaf))
}

/// Context-aware `/proc/<pid>/ns` listing.
///
/// The whole ns family used to resolve liveness through [`proc_live_pid`], i.e.
/// the HOST process table. Under HVPatch a peer Linux process is a thread of one
/// Darwin process and owns no host pid, so every numeric-pid ns path answered
/// ENOENT while `/proc/self/ns` worked (the `self` alias short-circuits ahead of
/// the lookup). LTP `setns01` reads `/proc/<pid>/ns/<type>` by number and
/// TCONF'd at `setns01.c:153` "no ns types/proc entries"; `setns02` reported the
/// same thing as a bogus kconfig failure.
///
/// The graph-backed authority was already threaded into `/proc`, `/proc/<pid>`
/// and `/proc/<pid>/task` — the `ns` subtree was simply left behind. Note the
/// bug is invisible with a single guest process, since pid 1 IS the caller;
/// it needs a live peer, which is exactly the identity-domain shape
/// `docs/identity-and-scope-domains.md` describes.
fn proc_ns_dir_entries_with_context(path: &str, ctx: &SyntheticProcContext) -> Option<Vec<DirEnt>> {
    let (component, leaf) = proc_ns_path_parts(path)?;
    if leaf != "ns" || !proc_pid_component_is_live(component, ctx) {
        return None;
    }
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(PROC_NS_TYPES.iter().map(|(name, _)| DirEnt {
        name: (*name).to_string(),
        kind: EntryKind::Symlink,
    }));
    Some(entries)
}

/// Context-aware `<type>:[<inode>]` readlink target for `/proc/<pid>/ns/<type>`,
/// resolving the pid through the kernel task graph. The context-free
/// [`proc_ns_link_target`] stays for the callers that have no context.
pub(crate) fn proc_ns_link_target_with_context(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<String> {
    let (component, leaf) = proc_ns_path_parts(path)?;
    let ns_type = leaf.strip_prefix("ns/")?;
    if !proc_pid_component_is_live(component, ctx) {
        return None;
    }
    PROC_NS_TYPES
        .iter()
        .find(|(name, _)| *name == ns_type)
        .map(|(name, ino)| format!("{name}:[{ino}]"))
}

/// Context-aware readlink-target LENGTH for `/proc/<pid>/ns/<type>` — the
/// `st_size` an lstat reports for the magic symlink. The context-free
/// [`proc_magic_symlink_size`] cannot see a peer.
pub(crate) fn proc_ns_link_size_with_context(
    path: &str,
    ctx: &SyntheticProcContext,
) -> Option<u64> {
    proc_ns_link_target_with_context(path, ctx).map(|t| t.len() as u64)
}

/// Context-aware `/proc/<pid>/ns/<type>` recogniser: the namespace `<type>` when
/// the pid names a live process. Mirrors the dispatcher's `proc_ns_link`, which
/// can only consult the host process table.
pub(crate) fn proc_ns_link_type_with_context<'a>(
    path: &'a str,
    ctx: &SyntheticProcContext,
) -> Option<&'a str> {
    let (component, leaf) = proc_ns_path_parts(path)?;
    let ns_type = leaf.strip_prefix("ns/")?;
    if !proc_pid_component_is_live(component, ctx) {
        return None;
    }
    ns_type_inode(ns_type).map(|_| ns_type)
}

/// Every synthetic `/proc` DIRECTORY whose existence only the kernel task graph
/// can settle: `/proc`, `/proc/<pid>` and `/proc/<pid>/task`.
///
/// [`Vfs::lookup`] and [`Vfs::readdir`] carry no context, so they answer these
/// from the host process table — which on HVPatch describes the carrier and
/// therefore reports ENOENT for every peer. The dispatcher DOES hold the
/// context at `stat`/`access` time, so it consults this first, exactly as it
/// already consults [`synthetic_file`] for the per-pid FILES. Non-directory and
/// non-`/proc` paths return `None` and fall through unchanged.
pub(crate) fn synthetic_dir_entries(path: &str, ctx: &SyntheticProcContext) -> Option<Vec<DirEnt>> {
    if path == "/proc" {
        return Some(proc_top_level_entries(ctx));
    }
    proc_task_dir_entries_with_context(path, ctx)
        .or_else(|| proc_task_tid_dir_entries_with_context(path, ctx))
        .or_else(|| proc_pid_dir_entries_with_context(path, ctx))
        .or_else(|| proc_ns_dir_entries_with_context(path, ctx))
}

/// The `/proc` top-level listing: `.`/`..`, the self aliases, every synthetic
/// top-level file carrick actually serves (so `ls /proc` agrees with what
/// `open()` resolves, proc(5)), the sub-directories, and one entry per LIVE
/// process.
///
/// The process entries come from the kernel task graph when the caller has one.
/// The host-pid enumeration below cannot see them on HVPatch: every Linux
/// process is a thread of ONE Darwin process, so `proc_listallpids` reports the
/// carrier once and `ls /proc | grep <peer>` found nothing while
/// `cat /proc/<peer>/stat` worked. Zombies are listed too — Linux keeps an
/// unreaped process's directory present, which is what lets `ps` show a `Z`.
fn proc_top_level_entries(ctx: &SyntheticProcContext) -> Vec<DirEnt> {
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
        // `self`/`thread-self` readlink to the caller's pid dir, but carrick
        // models them as traversable directories (so `/proc/self/<file>`
        // resolves without following into an unserved per-pid tree); report
        // them as directories for getdents consistency with lstat.
        DirEnt {
            name: "self".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "thread-self".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    for name in [
        "cmdline",
        "config.gz",
        "cpuinfo",
        "devices",
        "diskstats",
        "filesystems",
        "loadavg",
        "locks",
        "meminfo",
        "modules",
        "mounts",
        "partitions",
        "stat",
        "swaps",
        "uptime",
        "version",
        "vmstat",
    ] {
        entries.push(DirEnt {
            name: name.to_string(),
            kind: EntryKind::File,
        });
    }
    // `/proc/sys` and `/proc/net` are both directories here (net readlinks
    // to self/net but is served as a traversable dir).
    for dir in ["sys", "net", "sysvipc"] {
        entries.push(DirEnt {
            name: dir.to_string(),
            kind: EntryKind::Directory,
        });
    }
    let mut pids: Vec<u32> = Vec::new();
    if let Some(processes) = ctx.processes.as_ref() {
        pids.extend(processes.iter().map(|process| process.pid));
        if let Some(zombies) = ctx.zombies.as_ref() {
            pids.extend(zombies.iter().map(|zombie| zombie.pid));
        }
        if let Some(identity) = ctx.identity {
            pids.push(identity.pid);
        }
    } else {
        // No kernel graph on this lane. Enumerated host pids must be shown as
        // the NAMESPACE pids the guest sees (what getpid()/$!/status report),
        // or a guest can't correlate `ls /proc` with its own pids. Identity
        // when no PID namespace is active; drop host pids that map to no
        // ns-pid (host_to_ns → 0).
        pids.extend(
            enumerate_guest_pids()
                .into_iter()
                .map(crate::namespace::pid::host_to_ns_or_self)
                .filter(|&ns_pid| ns_pid != 0),
        );
    }
    pids.sort_unstable();
    pids.dedup();
    entries.extend(pids.into_iter().map(|pid| DirEnt {
        name: pid.to_string(),
        kind: EntryKind::Directory,
    }));
    entries
}

/// Guest process pids (this process + its guest descendants) for enumerating
/// `/proc`. libproc's all-pids list filtered by `is_guest_process`.
#[cfg(target_os = "macos")]
fn enumerate_guest_pids() -> Vec<u32> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; count as usize + 16];
    let cap = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), cap) };
    if got <= 0 {
        return Vec::new();
    }
    pids.truncate(got as usize);
    pids.into_iter()
        .filter(|&p| p > 0 && crate::host_proc::is_guest_process(p as u32))
        .map(|p| p as u32)
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn enumerate_guest_pids() -> Vec<u32> {
    Vec::new()
}

pub struct ProcVfs;

impl ProcVfs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcVfs {
    fn default() -> Self {
        Self::new()
    }
}

fn synthetic_proc_context_from_open(ctx: &OpenContext<'_>) -> SyntheticProcContext {
    SyntheticProcContext {
        oom_score_adj: ctx.oom_score_adj.cloned().unwrap_or_default(),
        creds_ns: ctx.creds_ns.cloned().unwrap_or_default(),
        executable_path: ctx.executable_path.unwrap_or("").to_owned(),
        argv: ctx.argv.unwrap_or(&[]).to_vec(),
        task_comm: ctx.task_comm.unwrap_or("").to_owned(),
        timerslack_ns: ctx.timerslack_ns,
        guest_arch: ctx.guest_arch,
        guest_hostname: ctx.guest_hostname.unwrap_or("").to_owned(),
        environ: ctx.environ.unwrap_or(&[]).to_vec(),
        open_fds: ctx.open_fds.unwrap_or(&[]).to_vec(),
        network: ctx.network.cloned().unwrap_or_default(),
        auxv: ctx.auxv.unwrap_or(&[]).to_vec(),
        address_space_regions: ctx.address_space_regions.map(|regions| regions.to_vec()),
        locked_memory: ctx.locked_memory.unwrap_or(&[]).to_vec(),
        brk_current: ctx.brk_current,
        mmap_next: ctx.mmap_next,
        heap_base: ctx.heap_base,
        native_guest_va: ctx.native_guest_va,
        ruid: ctx.ruid,
        euid: ctx.euid,
        suid: ctx.suid,
        rgid: ctx.rgid,
        egid: ctx.egid,
        sgid: ctx.sgid,
        groups: ctx.groups.unwrap_or(&[]).to_vec(),
        sig_ignored: ctx.sig_ignored,
        sig_caught: ctx.sig_caught,
        sig_shdpnd: ctx.sig_shdpnd,
        identity: ctx.identity,
        processes: ctx.processes.map(|processes| processes.to_vec()),
        threads: ctx.threads.map(|threads| threads.to_vec()),
        zombies: ctx.zombies.map(|zombies| zombies.to_vec()),
        sysvipc_shm: ctx.sysvipc_shm.unwrap_or("").to_owned(),
        sysvipc_sem: ctx.sysvipc_sem.unwrap_or("").to_owned(),
        sysvipc_msg: ctx.sysvipc_msg.unwrap_or("").to_owned(),
    }
}

impl Vfs for ProcVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/proc"
            || path == "/proc/sysvipc"
            || sysctl_is_dir(path)
            || proc_net_is_dir(path)
            || proc_ns_is_dir(path)
            || proc_fd_is_dir(path)
            || proc_fdinfo_is_dir(path)
            || proc_task_dir_entries(path).is_some()
            || proc_pid_dir_entries(path).is_some()
        {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o555,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        // Magic symlinks (exe/cwd/root/ns/<type>, and the bare process aliases
        // when not caught as directories above). A follow-stat lands here too,
        // so faccessat(F_OK)/`test -e` see the link exist.
        if let Some(size) = proc_magic_symlink_size(path) {
            return Ok(proc_symlink_metadata(size));
        }
        // /proc/self/fdinfo/N is a regular file (its contents are rendered
        // dispatcher-side); report it so stat/`test -e`/opendir-then-stat work.
        if proc_is_self_fdinfo_file(path) {
            return Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o400,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        // Context-free existence only for files whose existence is
        // context-free. A NUMERIC-pid per-process file (oom_score_adj and its
        // family) exists iff that pid names a LIVE process, which this
        // default-context probe cannot know: its empty oom map trips the
        // single-process fallback and fabricates the file for ANY digits —
        // `access("/proc/<reaped-pid>/oom_score_adj", F_OK)` answered true
        // (probe `oomscoreadj`, `dead_pid_file_absent=false`) while the
        // ctx-aware open of the same path correctly ENOENTed. Liveness-scoped
        // paths are answered ONLY by the dispatcher-side ctx-aware pass
        // (`synthetic_access`/`is_synthetic_virtual_file`), which runs before
        // this mount lookup; reaching HERE with such a path means that pass
        // already said "no live process".
        let liveness_scoped = proc_tunable_name(path).is_some_and(|(_, pid)| pid.is_some())
            || path
                .strip_prefix("/proc/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(pid, rest)| {
                    !pid.is_empty()
                        && pid.bytes().all(|b| b.is_ascii_digit())
                        && matches!(rest, "oom_score" | "oom_adj" | "oom_score_adj")
                });
        if !liveness_scoped && synthetic_file(path, &SyntheticProcContext::default()).is_some() {
            return Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o444,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        // lstat must report the magic symlinks as `S_IFLNK` BEFORE the
        // directory interpretation (e.g. `/proc/self` and `/proc/net` are
        // symlinks to lstat, directories only when followed).
        if let Some(size) = proc_magic_symlink_size(path) {
            return Ok(proc_symlink_metadata(size));
        }
        self.lookup(path)
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        // Context-free magic links (the dispatcher handles exe/cwd/root, which
        // need live state). `/proc/self` → the caller's ns-pid; `/proc/net` →
        // the namespace-correct self/net; `/proc/<pid>/ns/<t>` → `<t>:[<ino>]`.
        match path {
            "/proc/self" | "/proc/curproc" | "/proc/this" => Ok(PathBuf::from(
                crate::namespace::pid::self_ns_pid().to_string(),
            )),
            "/proc/thread-self" => Ok(PathBuf::from(proc_thread_self_target())),
            "/proc/net" => Ok(PathBuf::from("self/net")),
            _ => proc_ns_link_target(path)
                .map(PathBuf::from)
                .ok_or(crate::linux_abi::LINUX_EINVAL),
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<super::DirEnt>, VfsError> {
        if path == "/proc" {
            return Ok(proc_top_level_entries(&SyntheticProcContext::default()));
        }
        if path == "/proc/sysvipc" {
            return Ok(vec![
                DirEnt {
                    name: ".".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "..".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "sem".to_string(),
                    kind: EntryKind::File,
                },
                DirEnt {
                    name: "shm".to_string(),
                    kind: EntryKind::File,
                },
                DirEnt {
                    name: "msg".to_string(),
                    kind: EntryKind::File,
                },
            ]);
        }
        if let Some(entries) = sysctl_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_net_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_ns_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_task_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_pid_dir_entries(path) {
            return Ok(entries);
        }
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let synth_ctx = std::cell::OnceCell::new();
        // Opening the /proc directory itself: serve our synthetic listing
        // (`.`/`..`, `self`, the representative top-level files, and every
        // guest process pid) so `getdents64` / `ls /proc` and `ps` enumerate.
        // Without this branch the open falls through to the (empty) rootfs
        // `/proc` directory and `readdir` is never reached. Mirrors `DevVfs`.
        if path == "/proc" {
            let entries = proc_top_level_entries(
                synth_ctx.get_or_init(|| synthetic_proc_context_from_open(ctx)),
            );
            return Ok(VfsHandle::Directory {
                path: "/proc".to_string(),
                entries,
                status_flags: 0,
            });
        }
        // `/proc/self/fd`: one symlink entry per currently-open fd. Built from
        // the OpenContext snapshot (the only dir whose listing is live fd state),
        // so `ls /proc/self/fd` and `for fd in /proc/self/fd/*` enumerate.
        if proc_fd_is_dir(path) {
            let mut entries = vec![
                DirEnt {
                    name: ".".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "..".to_string(),
                    kind: EntryKind::Directory,
                },
            ];
            entries.extend(ctx.open_fds.unwrap_or(&[]).iter().map(|fd| DirEnt {
                name: fd.to_string(),
                kind: EntryKind::Symlink,
            }));
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        // `/proc/self/fdinfo`: one regular-FILE entry per open fd (the per-fd
        // contents are rendered dispatcher-side at open of fdinfo/N).
        if proc_fdinfo_is_dir(path) {
            let mut entries = vec![
                DirEnt {
                    name: ".".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "..".to_string(),
                    kind: EntryKind::Directory,
                },
            ];
            entries.extend(ctx.open_fds.unwrap_or(&[]).iter().map(|fd| DirEnt {
                name: fd.to_string(),
                kind: EntryKind::File,
            }));
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        if let Some(entries) = sysctl_dir_entries(path)
            .or_else(|| proc_net_dir_entries(path))
            .or_else(|| proc_ns_dir_entries(path))
            .or_else(|| {
                synthetic_dir_entries(
                    path,
                    synth_ctx.get_or_init(|| synthetic_proc_context_from_open(ctx)),
                )
            })
            .or_else(|| proc_task_dir_entries(path))
        {
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        // A PEER's `/proc/<pid>/{mem,pagemap}` fails here rather than falling
        // through to a generic errno, and above all rather than being served
        // from THIS caller's address space.
        if let Some(errno) = proc_foreign_live_memory_open_errno(
            path,
            synth_ctx.get_or_init(|| synthetic_proc_context_from_open(ctx)),
        ) {
            return Err(errno);
        }
        let Some(contents) = synthetic_file(
            path,
            synth_ctx.get_or_init(|| synthetic_proc_context_from_open(ctx)),
        ) else {
            return Err(crate::linux_abi::LINUX_ENOSYS);
        };
        // The user-namespace map files and the rw tunables (oom_score_adj/…)
        // are writable; the dispatcher routes write(2) on their SyntheticFile to
        // the appropriate handler. All other /proc files stay read-only.
        if flags.write && sysctl_value(path).is_some() {
            return Err(LINUX_EROFS);
        }
        if flags.write && !is_userns_map_path(path) && !is_writable_tunable_path(path) {
            return Err(LINUX_EACCES);
        }
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents,
            status_flags: 0,
        })
    }

    fn name(&self) -> &'static str {
        "proc"
    }
}

fn synthetic_proc_maps(ctx: &SyntheticProcContext) -> String {
    if let Some(regions) = ctx.address_space_regions.as_deref() {
        return render_proc_maps_from_regions(
            regions,
            &ctx.executable_path,
            ctx.brk_current,
            ctx.mmap_next,
        );
    }
    format!(
        "0000000000400000-0000000000410000 r-xp 00000000 00:00 0 {executable_path}\n\
         {heap_base:016x}-{heap_end:016x} rw-p 00000000 00:00 0 [heap]\n\
         {mmap_base:016x}-{mmap_end:016x} rwxp 00000000 00:00 0 [carrick-mmap]\n\
         0000007fffe00000-0000008000000000 rw-p 00000000 00:00 0 [stack]\n",
        executable_path = ctx.executable_path,
        heap_base = LINUX_HEAP_BASE,
        heap_end = LINUX_HEAP_BASE + LINUX_HEAP_SIZE,
        mmap_base = LINUX_MMAP_BASE,
        mmap_end = LINUX_MMAP_BASE + crate::memory::mmap_arena_size(),
    )
}

fn render_proc_maps_from_regions(
    regions: &[ProcMapsEntry],
    executable_path: &str,
    brk_current: u64,
    mmap_next: u64,
) -> String {
    let mut sorted: Vec<&ProcMapsEntry> = regions.iter().collect();
    sorted.sort_by_key(|r| r.start);
    let mut out = String::new();
    for region in sorted {
        let (start, mut end, label) = label_for_region(region, executable_path);
        match label.as_str() {
            "[heap]" if brk_current > start && brk_current <= region.end => {
                end = brk_current;
            }
            "[carrick-mmap]" if mmap_next > start && mmap_next <= region.end => {
                end = mmap_next;
            }
            _ => {}
        }
        let r = if region.read { 'r' } else { '-' };
        let w = if region.write { 'w' } else { '-' };
        let x = if region.execute { 'x' } else { '-' };
        let s = region.sharing.marker();
        // Real Linux /proc/self/maps reports Linux page-aligned VMA bounds.
        // LTP scans for an exact 4 KiB page start after MAP_FIXED remaps.
        const PAGE: u64 = crate::linux_abi::LINUX_PAGE_SIZE;
        let start = start & !(PAGE - 1);
        let end = end.div_ceil(PAGE) * PAGE;
        out.push_str(&format!(
            "{start:08x}-{end:08x} {r}{w}{x}{s} 00000000 00:00 0                          {label}\n",
        ));
    }
    out
}

fn label_for_region(region: &ProcMapsEntry, executable_path: &str) -> (u64, u64, String) {
    let mut start = region.start;
    let end = region.end;
    let label = if start == LINUX_HEAP_BASE {
        "[heap]".to_owned()
    } else if start == LINUX_MMAP_BASE {
        "[carrick-mmap]".to_owned()
    } else if start == LINUX_STACK_TOP.saturating_sub(LINUX_STACK_SIZE) {
        // Report the [stack] VMA as the RLIMIT_STACK extent (8 MiB below the top).
        // glibc's pthread_getattr_np derives the main-thread C-stack bounds from
        // this line and runtimes (CPython) calibrate their recursion guard to it,
        // so it must equal the reported RLIMIT_STACK. Today LINUX_STACK_SIZE ==
        // LINUX_RLIMIT_STACK_SOFT so this is a no-op, but it keeps the [stack] VMA
        // pinned to the reported limit should we ever back extra guard-page slack
        // (LINUX_STACK_SIZE > LINUX_RLIMIT_STACK_SOFT) below it.
        start = LINUX_STACK_TOP.saturating_sub(LINUX_RLIMIT_STACK_SOFT);
        "[stack]".to_owned()
    } else if start == LINUX_EL0_TRAMPOLINE_BASE {
        "[carrick-trampoline]".to_owned()
    } else if start == LINUX_SIGRETURN_TRAMPOLINE_BASE {
        "[carrick-sigreturn]".to_owned()
    } else if start == LINUX_EL1_VECTORS_BASE {
        "[carrick-vectors]".to_owned()
    } else if start == LINUX_PAGE_TABLES_BASE {
        "[carrick-pagetables]".to_owned()
    } else if !region.path.is_empty() {
        region.path.clone()
    } else if region.execute {
        executable_path.to_owned()
    } else {
        String::new()
    };
    (start, end, label)
}

fn synthetic_proc_cpuinfo(arch: GuestReportedArch) -> Vec<u8> {
    // One "processor" block per Linux-visible logical CPU so the count agrees with
    // sched_getaffinity, /proc/stat and /sys/.../cpu/online. Go/nproc count
    // CPUs via sched_getaffinity, but lscpu and some runtimes parse this. The
    // block shape is per-ISA: an x86_64 guest (native x86 backends or a
    // Rosetta-translated guest) must NOT read an ARM block — that contradicts
    // `uname(2)` and breaks lscpu / language runtimes that parse cpuinfo.
    let ncpu = crate::host_facts::logical_cpu_count();
    let mut out = String::new();
    match arch {
        GuestReportedArch::Aarch64 => {
            for cpu in 0..ncpu {
                // NOTE: the kernel emits `CPU architecture: 8` with NO tab before
                // the colon (unlike the other rows); some strict parsers split on
                // `: `.
                out.push_str(&format!(
                    "processor\t: {cpu}\n\
BogoMIPS\t: 48.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm sb dcpodp flagm2 frint i8mm bf16 afp rpres\n\
CPU implementer\t: 0x61\n\
CPU architecture: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0x000\n\
CPU revision\t: 0\n\
\n"
                ));
            }
        }
        GuestReportedArch::X86_64 => {
            for cpu in 0..ncpu {
                // x86_64 blocks are colon-tab separated throughout. The `flags`
                // line advertises the baseline x86-64 feature set carrick's x86
                // backends present (SSE/SSE2, syscall, nx, long mode), enough for
                // lscpu / glibc HWCAP probing without claiming features the guest
                // ISA does not expose.
                out.push_str(&format!(
                    "processor\t: {cpu}\n\
vendor_id\t: GenuineIntel\n\
cpu family\t: 6\n\
model\t\t: 85\n\
model name\t: carrick virtual x86_64\n\
stepping\t: 4\n\
microcode\t: 0x1\n\
cpu MHz\t\t: 2500.000\n\
cache size\t: 16384 KB\n\
physical id\t: 0\n\
siblings\t: {ncpu}\n\
core id\t\t: {cpu}\n\
cpu cores\t: {ncpu}\n\
apicid\t\t: {cpu}\n\
initial apicid\t: {cpu}\n\
fpu\t\t: yes\n\
fpu_exception\t: yes\n\
cpuid level\t: 22\n\
wp\t\t: yes\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec\n\
bugs\t\t:\n\
bogomips\t: 5000.00\n\
clflush size\t: 64\n\
cache_alignment\t: 64\n\
address sizes\t: 46 bits physical, 48 bits virtual\n\
power management:\n\
\n"
                ));
            }
        }
    }
    out.into_bytes()
}

/// `/proc/version`, built from the same release/version constants as `uname(2)`
/// and the `/proc/sys/kernel/*` leaves.
fn synthetic_proc_version() -> Vec<u8> {
    format!(
        "Linux version {} (carrick@bootstrap) (rustc) {}\n",
        carrick_abi::CARRICK_KERNEL_RELEASE,
        carrick_abi::CARRICK_KERNEL_VERSION,
    )
    .into_bytes()
}

fn synthetic_proc_loadavg() -> &'static [u8] {
    b"0.00 0.00 0.00 1/1 1\n"
}

fn synthetic_proc_uptime() -> String {
    // Field 1 is seconds since (guest) boot; field 2 is cumulative idle time
    // across all CPUs (>= field 1 on a multi-CPU box). Both 2-dp floats. The
    // old code emitted epoch-seconds here, yielding a ~56-year "uptime".
    let up = boot_elapsed().as_secs_f64();
    let idle = up * crate::host_facts::logical_cpu_count().max(1) as f64;
    format!("{up:.2} {idle:.2}\n")
}

/// Boot time in seconds since the Epoch, for `/proc/stat`'s `btime` line:
/// now - uptime. Non-zero so `start_epoch = btime + starttime/HZ` math works.
fn boot_epoch_secs() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(boot_elapsed().as_secs())
}

fn synthetic_proc_meminfo() -> &'static [u8] {
    b"MemTotal:       16777216 kB\n\
MemFree:        16000000 kB\n\
MemAvailable:   16000000 kB\n\
Buffers:               0 kB\n\
Cached:                0 kB\n\
SwapCached:            0 kB\n\
Active:                0 kB\n\
Inactive:              0 kB\n\
Active(anon):          0 kB\n\
Inactive(anon):        0 kB\n\
Active(file):          0 kB\n\
Inactive(file):        0 kB\n\
Unevictable:           0 kB\n\
Mlocked:               0 kB\n\
SwapTotal:             0 kB\n\
SwapFree:              0 kB\n\
Dirty:                 0 kB\n\
Writeback:             0 kB\n\
AnonPages:             0 kB\n\
Mapped:                0 kB\n\
Shmem:                 0 kB\n\
KReclaimable:          0 kB\n\
Slab:                  0 kB\n\
SReclaimable:          0 kB\n\
SUnreclaim:            0 kB\n\
KernelStack:           0 kB\n\
PageTables:            0 kB\n\
SecPageTables:         0 kB\n\
NFS_Unstable:          0 kB\n\
Bounce:                0 kB\n\
WritebackTmp:          0 kB\n\
CommitLimit:    16777216 kB\n\
Committed_AS:          0 kB\n\
VmallocTotal:   17179869184 kB\n\
VmallocUsed:           0 kB\n\
VmallocChunk:          0 kB\n\
Percpu:                0 kB\n\
AnonHugePages:         0 kB\n\
ShmemHugePages:        0 kB\n\
ShmemPmdMapped:        0 kB\n\
FileHugePages:         0 kB\n\
FilePmdMapped:         0 kB\n\
HugePages_Total:       0\n\
HugePages_Free:        0\n\
HugePages_Rsvd:        0\n\
HugePages_Surp:        0\n\
Hugepagesize:       2048 kB\n\
Hugetlb:               0 kB\n"
}

fn synthetic_proc_stat() -> Vec<u8> {
    // Aggregate "cpu" line followed by one "cpuN" line per logical CPU, so the
    // per-CPU count agrees with sched_getaffinity and /proc/cpuinfo. The jiffy
    // columns are zero (carrick has no global CPU-time accounting yet).
    let ncpu = crate::host_facts::logical_cpu_count();
    let mut out = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for cpu in 0..ncpu {
        out.push_str(&format!("cpu{cpu} 0 0 0 0 0 0 0 0 0 0\n"));
    }
    out.push_str(&format!(
        "intr 0\n\
ctxt 0\n\
btime {btime}\n\
processes 1\n\
procs_running 1\n\
procs_blocked 0\n\
softirq 0\n",
        btime = boot_epoch_secs(),
    ));
    out.into_bytes()
}

/// Kernel `Cpus_allowed` bitmask format: comma-separated 32-bit groups, most
/// significant first, the high group unpadded and lower groups zero-padded to
/// 8 hex digits (e.g. 10 CPUs → "000003ff" is shown as "3ff"; 33 CPUs →
/// "1,ffffffff"). Built from the online set.
fn cpus_allowed_hex(ncpu: usize) -> String {
    let groups = ncpu.div_ceil(32).max(1);
    let mut parts = Vec::with_capacity(groups);
    for g in (0..groups).rev() {
        let lo = g * 32;
        let mut word: u32 = 0;
        for bit in 0..32 {
            if lo + bit < ncpu {
                word |= 1u32 << bit;
            }
        }
        if g == groups - 1 {
            parts.push(format!("{word:x}"));
        } else {
            parts.push(format!("{word:08x}"));
        }
    }
    parts.join(",")
}

/// Kernel `Cpus_allowed_list` range list: "0" for a uniprocessor, "0-9" for 10.
fn cpus_allowed_list(ncpu: usize) -> String {
    if ncpu <= 1 {
        "0".to_owned()
    } else {
        format!("0-{}", ncpu - 1)
    }
}

/// The guest's committed VMA spans for `/proc/self/status`: every snapshot
/// region with the heap clamped to the current break and the mmap arena
/// clamped to its used high-water mark (exactly as `/proc/self/maps` does),
/// PLUS the brk-grown heap span when the snapshot carries no heap region (the
/// native backend maps its brk heap lazily and never lists it as an image
/// region). `None` when there is no usable VMA snapshot. VmSize sums this
/// list and the native VmRSS measurement walks the SAME list, so the pair is
/// coherent by construction (resident-within-spans ≤ total-span bytes).
fn guest_vm_ranges(ctx: &SyntheticProcContext) -> Option<Vec<(u64, u64)>> {
    let regions = ctx.address_space_regions.as_deref()?;
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut snapshot_has_heap_region = false;
    for r in regions {
        let mut end = r.end;
        if r.start == LINUX_HEAP_BASE && ctx.brk_current > r.start && ctx.brk_current <= r.end {
            end = ctx.brk_current;
        } else if r.start == LINUX_MMAP_BASE && ctx.mmap_next > r.start && ctx.mmap_next <= r.end {
            end = ctx.mmap_next;
        }
        if ctx.heap_base != 0 && r.start == ctx.heap_base {
            snapshot_has_heap_region = true;
        }
        ranges.push((r.start, end));
    }
    if !snapshot_has_heap_region && ctx.heap_base != 0 && ctx.brk_current > ctx.heap_base {
        ranges.push((ctx.heap_base, ctx.brk_current));
    }
    // An empty/zero snapshot (no regions captured on this backend) is unusable;
    // the caller falls back to the host-virtual-size estimate so VmSize is
    // never spuriously 0.
    ranges
        .iter()
        .any(|(start, end)| end > start)
        .then_some(ranges)
}

/// The guest's committed virtual size in kB for `/proc/self/status` VmSize:
/// the [`guest_vm_ranges`] total when a VMA snapshot exists, else a host
/// virtual-size estimate.
fn guest_committed_vm_kb(ranges: Option<&[(u64, u64)]>, host_virtual_bytes: u64) -> u64 {
    if let Some(ranges) = ranges {
        let total: u64 = ranges
            .iter()
            .map(|(start, end)| end.saturating_sub(*start))
            .sum();
        if total > 0 {
            return total / 1024;
        }
    }
    // Fallback (no VMA snapshot): derive from the host virtual size. On
    // macOS/HVF that size INCLUDES the large sparse mmap-arena window mapped at
    // boot (≫ the 32 GiB arena), which must be subtracted so the guest doesn't
    // look like a ~half-TiB process. On the x86 backends (bhyve/KVM) the host
    // virtual size is `kinfo_proc.ki_size` / statm — the REAL committed guest
    // address space, which does NOT include that sparse window, so subtracting
    // the arena would wrongly drive VmSize to 0 (saturating_sub underflow). Only
    // subtract the arena when the host size actually exceeds it (the macOS case);
    // otherwise report the host size directly. Either way VmSize stays positive
    // whenever the host size is, keeping VmRSS ≤ VmSize.
    let arena = crate::memory::mmap_arena_size();
    if host_virtual_bytes > arena {
        (host_virtual_bytes - arena) / 1024
    } else {
        host_virtual_bytes / 1024
    }
}

fn synthetic_proc_self_status(ctx: &SyntheticProcContext) -> String {
    let comm = context_task_comm(ctx);
    let sigign_hex = ctx.sig_ignored;
    let sigcgt_hex = ctx.sig_caught;
    let shdpnd_hex = ctx.sig_shdpnd;
    // Live thread count for the `Threads:` line — CPython reads this to decide
    // whether os.fork() must emit the multi-threaded-fork DeprecationWarning
    // (test_threading.test_*_after_fork). Was hardcoded 1, so a guest with live
    // worker threads looked single-threaded and the warning never fired.
    let nthreads = ctx
        .threads
        .as_ref()
        .map_or_else(|| crate::current_thread_states().len(), Vec::len)
        .max(1);
    let ncpu = crate::host_facts::logical_cpu_count();
    let cpus_hex = cpus_allowed_hex(ncpu);
    let cpus_list = cpus_allowed_list(ncpu);
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    // VmSize must reflect the guest's committed virtual size, NOT carrick's host
    // virtual size — which includes the 512 GiB sparse mmap window and made the
    // guest look like a ~521 GB process (tripping RSS/VSZ sanity + OOM
    // heuristics). Derive it from the guest's own VMAs when known (clamping the
    // heap to brk and the mmap arena to its used high-water mark, like
    // /proc/self/maps does); else subtract the reserved arena from the host size.
    let vm_ranges = guest_vm_ranges(ctx);
    let vsize_kb = guest_committed_vm_kb(vm_ranges.as_deref(), host.virtual_bytes);
    // VmRSS: on the VMM backends the host process is dominated by the guest
    // (its RAM lives in this process), so the whole-process phys_footprint is
    // the honest resident size. Under the NATIVE backend guest VAs are host
    // VAs but the host process also carries the carrick runtime itself —
    // phys_footprint over-reports the guest (measured 19 MB vs a ~0.5 MB
    // guest) and can exceed the modeled VmSize. Measure residency over
    // exactly the VmSize spans instead (mach region walk), which keeps
    // VmRSS ≤ VmSize by construction rather than by clamping.
    let measured_native_rss_kb = if ctx.native_guest_va {
        vm_ranges
            .as_deref()
            .and_then(crate::host_proc::resident_bytes_in_ranges)
            .map(|bytes| bytes / 1024)
    } else {
        None
    };
    // VmRSS ≤ VmSize is a hard kernel invariant (resident pages are a subset of
    // the mapped virtual size). When the per-span residency walk is unavailable
    // (`resident_bytes_in_ranges` returns None on the FreeBSD/native lane), the
    // fallback whole-process host RSS also carries the carrick runtime itself and
    // can exceed the modeled guest VmSize — so clamp to keep the pair coherent
    // (probe accounting: status_vmrss_le_vmsize).
    let rss_kb = measured_native_rss_kb
        .unwrap_or(host.resident_bytes / 1024)
        .min(vsize_kb);
    let peak_kb = vsize_kb.max(host.maxrss_bytes / 1024);
    let hwm_kb = host.maxrss_bytes / 1024;
    // Pid/Tgid must match what getpid()/gettid() return — in a PID namespace
    // that is the ns-local pid (1 for the container init), not the host pid;
    // identity otherwise. LTP gettid01 reads "Pid:" and asserts it equals
    // getpid(). A single-threaded process has Pid == Tgid.
    let pid = ctx
        .identity
        .map_or_else(crate::namespace::pid::self_ns_pid, |identity| identity.pid);
    // PPid is the ns-translated parent: 0 for the init, the parent's ns-pid for
    // others (was hardcoded 0, which diverged from Docker for non-init members).
    // Preserve the historical `PPid: 0` for non-namespaced runs (run-elf) so
    // that path is unchanged. The kernel's NStgid/NSpid/NSpgid/NSsid quartet is
    // intentionally omitted — NSpgid/NSsid need pgid/sid translation that stays
    // host-level in Phase 2, so a partial quartet would diverge worse than its
    // absence (§5.3, §6.6).
    let ppid = ctx.identity.map_or_else(
        || {
            if crate::namespace::pid::enabled() {
                crate::namespace::pid::self_ns_ppid()
            } else {
                0
            }
        },
        |identity| identity.ppid,
    );
    let groups = if ctx.groups.is_empty() {
        String::new()
    } else {
        ctx.groups
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    };
    // Capabilities: report the modeled set (Docker default 00000000a80425fb,
    // or a full set inside a freshly-created user namespace), NOT the all-zero
    // set — capability-probing tools (apt/dpkg/setpriv) refuse to proceed if
    // they think they hold nothing (docs/namespaces-design.md §4.4).
    let cap_lines = ctx.creds_ns.caps.status_lines();
    let locked_kb = locked_memory_kb(ctx);
    format!(
        "Name:\t{comm}\n\
Umask:\t0022\n\
State:\tR (running)\n\
Tgid:\t{pid}\n\
Ngid:\t0\n\
Pid:\t{pid}\n\
PPid:\t{ppid}\n\
TracerPid:\t0\n\
Uid:\t{ruid}\t{euid}\t{suid}\t{fsuid}\n\
Gid:\t{rgid}\t{egid}\t{sgid}\t{fsgid}\n\
FDSize:\t256\n\
Groups:\t{groups}\n\
VmPeak:\t{peak_kb:>8} kB\n\
VmSize:\t{vsize_kb:>8} kB\n\
VmLck:\t{locked_kb:>8} kB\n\
VmPin:\t       0 kB\n\
VmHWM:\t{hwm_kb:>8} kB\n\
VmRSS:\t{rss_kb:>8} kB\n\
RssAnon:\t{rss_kb:>8} kB\n\
RssFile:\t       0 kB\n\
RssShmem:\t       0 kB\n\
VmData:\t       0 kB\n\
VmStk:\t       0 kB\n\
VmExe:\t       0 kB\n\
VmLib:\t       0 kB\n\
VmPTE:\t       0 kB\n\
VmSwap:\t       0 kB\n\
CoreDumping:\t0\n\
THP_enabled:\t1\n\
Threads:\t{nthreads}\n\
SigQ:\t0/63880\n\
SigPnd:\t0000000000000000\n\
ShdPnd:\t{shdpnd_hex:016x}\n\
SigBlk:\t0000000000000000\n\
SigIgn:\t{sigign_hex:016x}\n\
SigCgt:\t{sigcgt_hex:016x}\n\
{cap_lines}\
NoNewPrivs:\t0\n\
Seccomp:\t0\n\
Seccomp_filters:\t0\n\
Speculation_Store_Bypass:\tthread vulnerable\n\
SpeculationIndirectBranch:\tconditional enabled\n\
Cpus_allowed:\t{cpus_hex}\n\
Cpus_allowed_list:\t{cpus_list}\n\
Mems_allowed:\t1\n\
Mems_allowed_list:\t0\n\
voluntary_ctxt_switches:\t0\n\
nonvoluntary_ctxt_switches:\t0\n",
        ruid = ctx.ruid,
        euid = ctx.euid,
        suid = ctx.suid,
        fsuid = ctx.euid,
        rgid = ctx.rgid,
        egid = ctx.egid,
        sgid = ctx.sgid,
        fsgid = ctx.egid,
    )
}

fn synthetic_proc_self_cmdline(argv: &[String], executable_path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let args: Vec<&str> = if argv.is_empty() {
        vec![executable_path]
    } else {
        argv.iter().map(String::as_str).collect()
    };
    for arg in args {
        bytes.extend_from_slice(arg.as_bytes());
        bytes.push(0);
    }
    bytes
}

/// `/proc/self/environ`: the guest environment as NUL-separated `KEY=VALUE`
/// entries (proc_pid_environ(5)), reflecting the actual launched env. The
/// entries are opaque bytes (not necessarily UTF-8). mode r-------- in Linux;
/// carrick serves it read-only like the other self files.
fn synthetic_proc_self_environ(environ: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in environ {
        bytes.extend_from_slice(entry);
        bytes.push(0);
    }
    bytes
}

fn context_task_comm(ctx: &SyntheticProcContext) -> String {
    if ctx.task_comm.is_empty() {
        return process_short_name(&ctx.executable_path);
    }
    ctx.task_comm.clone()
}

fn context_timerslack_ns(ctx: &SyntheticProcContext) -> u64 {
    if ctx.timerslack_ns == 0 {
        return LINUX_DEFAULT_TIMERSLACK_NS;
    }
    ctx.timerslack_ns
}

fn synthetic_proc_self_comm(ctx: &SyntheticProcContext) -> String {
    let mut comm = context_task_comm(ctx);
    comm.push('\n');
    comm
}

fn synthetic_proc_self_stat(ctx: &SyntheticProcContext) -> String {
    let comm = process_short_name(&ctx.executable_path);
    let identity = ctx.identity;
    let pid = identity.map_or_else(std::process::id, |identity| identity.pid);
    let ppid = identity.map_or_else(
        || unsafe { libc::getppid() } as u32,
        |identity| identity.ppid,
    );
    let pgrp = identity.map_or(pid, |identity| identity.pgrp);
    let session = identity.map_or(pid, |identity| identity.session);
    let (nthreads, state) = match ctx.threads.as_ref() {
        Some(threads) => (
            threads.len().max(1),
            threads
                .iter()
                .find(|thread| thread.tid == pid)
                .or_else(|| threads.first())
                .map_or('R', |thread| thread.state),
        ),
        None => {
            let thread_states = crate::current_thread_states();
            (
                thread_states.len().max(1),
                proc_self_stat_state_from_threads(
                    &thread_states,
                    pid,
                    crate::namespace::pid::self_ns_pid(),
                ),
            )
        }
    };
    proc_stat_line(
        pid,
        &comm,
        state,
        ppid,
        pgrp,
        session,
        nthreads,
        self_utime_ticks(),
    )
}

fn proc_self_stat_state_from_threads(
    thread_states: &[(crate::thread::ThreadId, char)],
    self_pid: u32,
    self_ns_pid: u32,
) -> char {
    if let Some(state) = thread_states.iter().find_map(|(tid, state)| {
        let raw = u32::try_from(tid.raw()).ok()?;
        (raw == self_pid || raw == self_ns_pid).then_some(*state)
    }) {
        return state;
    }

    thread_states
        .iter()
        .filter_map(|(tid, state)| {
            let raw = u32::try_from(tid.raw()).ok()?;
            Some((raw, *state))
        })
        .min_by_key(|(raw, _)| *raw)
        .map(|(_, state)| state)
        .unwrap_or('R')
}

#[allow(clippy::too_many_arguments)]
fn proc_stat_line(
    pid: u32,
    comm: &str,
    state: char,
    ppid: u32,
    pgrp: u32,
    session: u32,
    num_threads: usize,
    utime_ticks: u64,
) -> String {
    // Field 14 is utime (user CPU, in clock ticks). It MUST advance: a real test
    // setup spins `do { read } while (utime == 0)` to confirm CPU was consumed
    // before timing the clocks (LTP clock_gettime01) — a hardcoded 0 hangs it
    // forever. Callers source it from the CHEAP guest_cpu accumulator (atomic,
    // no syscall) so /proc/self/stat stays trap-free under tight read loops.
    //
    // Field 20 is num_threads: CPython's os.fork() reads it from /proc/self/stat
    // to decide whether to emit the multi-threaded-fork DeprecationWarning
    // (test_threading.test_*_after_fork). Was a hardcoded 1.
    //
    // The line must carry exactly 52 space-separated fields through field 52
    // (exit_code) per proc_pid_stat(5); a strict parser that splits and indexes
    // the tail (Go runtime, ps, monitoring agents) reads a short array if any
    // are missing. The final `0` is field 52.
    format!(
        "{pid} ({comm}) {state} {ppid} {pgrp} {session} 0 -1 4194560 0 0 0 0 {utime_ticks} 0 0 0 \
20 0 {num_threads} 0 1 10485760 256 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 \
17 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

/// This process's accumulated guest user-CPU time in clock ticks (field 14 of
/// `/proc/<pid>/stat`). Reads only the cheap cross-process `guest_cpu` atomic
/// accumulator — NO syscall — so it is safe to call on every `/proc/self/stat`
/// read (which tight loops hammer). All guest cycles count as user time; there
/// is no cheap cross-platform user/system split, so `stime` stays 0.
fn self_utime_ticks() -> u64 {
    crate::guest_cpu::total_us().saturating_mul(carrick_abi::LINUX_CLK_TCK as u64) / 1_000_000
}

fn synthetic_proc_pid_file(
    pid: u32,
    rest: &str,
    self_comm: &str,
    ctx: &SyntheticProcContext,
) -> Option<Vec<u8>> {
    if let Some(task_rest) = rest.strip_prefix("task/") {
        if let Some((tid_str, file)) = task_rest.split_once('/')
            && let Ok(tid) = tid_str.parse::<u32>()
        {
            return synthetic_proc_pid_file(tid, file, self_comm, ctx);
        }
        return None;
    }

    // The OOM knobs are process-wide and answerable for ANY live pid, so they
    // are served before the per-branch renderers below (each of which only
    // knows how to describe one flavour of process). A pid with no live task
    // and no zombie record falls through to `None` -> ENOENT, which is what
    // makes LTP's `access(2)` probe of a dead pid fail the way Linux fails it
    // rather than reporting a fabricated 0.
    if matches!(rest, "oom_score" | "oom_adj" | "oom_score_adj") {
        let known = pid_oom_score_adj(ctx, pid).or_else(|| {
            ctx.zombies
                .as_ref()
                .is_some_and(|zombies| zombies.iter().any(|zombie| zombie.pid == pid))
                .then_some(0)
        })?;
        return Some(match rest {
            // oom_score is the volatile computed score and oom_adj the legacy
            // knob; carrick models neither, and 0 is a valid answer for both.
            "oom_score" | "oom_adj" => b"0\n".to_vec(),
            _ => format!("{known}\n").into_bytes(),
        });
    }

    if let Some(threads) = ctx.threads.as_ref()
        && let Some(thread) = threads.iter().find(|thread| thread.tid == pid)
    {
        let identity = ctx.identity?;
        let name = thread.comm.as_deref().unwrap_or(self_comm);
        match rest {
            "stat" => {
                return Some(
                    proc_stat_line(
                        pid,
                        name,
                        thread.state,
                        identity.ppid,
                        identity.pgrp,
                        identity.session,
                        threads.len().max(1),
                        self_utime_ticks(),
                    )
                    .into_bytes(),
                );
            }
            "comm" => return Some(format!("{name}\n").into_bytes()),
            "cmdline" => {
                let mut bytes = name.as_bytes().to_vec();
                bytes.push(0);
                return Some(bytes);
            }
            "status" => {
                return Some(
                    format!(
                        "Name:\t{name}\nState:\t{state} ({long})\nTgid:\t{tgid}\n\
Pid:\t{pid}\nPPid:\t{ppid}\nThreads:\t{count}\n",
                        state = thread.state,
                        long = proc_state_long(thread.state),
                        tgid = identity.pid,
                        ppid = identity.ppid,
                        count = threads.len(),
                    )
                    .into_bytes(),
                );
            }
            _ => return None,
        }
    }

    if let Some(zombies) = ctx.zombies.as_ref()
        && let Some(zombie) = zombies.iter().find(|zombie| zombie.pid == pid)
    {
        let name = if zombie.comm.is_empty() {
            self_comm
        } else {
            zombie.comm.as_str()
        };
        return match rest {
            "stat" => Some(
                proc_stat_line(
                    pid,
                    name,
                    'Z',
                    zombie.ppid,
                    zombie.pgrp,
                    zombie.session,
                    1,
                    0,
                )
                .into_bytes(),
            ),
            "comm" => Some(format!("{name}\n").into_bytes()),
            // Linux exposes an empty cmdline after the process has exited.
            "cmdline" => Some(Vec::new()),
            "status" => Some(
                format!(
                    "Name:\t{name}\nState:\tZ (zombie)\nTgid:\t{pid}\n\
Pid:\t{pid}\nPPid:\t{ppid}\nThreads:\t1\n",
                    ppid = zombie.ppid,
                )
                .into_bytes(),
            ),
            _ => None,
        };
    }

    // A live PEER process, straight from the kernel graph. This must be answered
    // BEFORE every host-derived branch below: on HVPatch a peer has no host
    // process of its own, so those branches describe the Darwin CARRIER and
    // leaked its ppid/pgrp/session (five-digit macOS pids) into the guest.
    // Ordered after the thread arm so a tid of the READER's own task — which
    // can numerically equal a peer's pid only if the graph is inconsistent —
    // still resolves through the richer per-thread snapshot.
    if let Some(processes) = ctx.processes.as_ref()
        && let Some(process) = processes.iter().find(|process| process.pid == pid)
    {
        let name = if process.comm.is_empty() {
            self_comm
        } else {
            process.comm.as_str()
        };
        let threads = process.tids.len().max(1);
        return match rest {
            "stat" => Some(
                proc_stat_line(
                    pid,
                    name,
                    process.state,
                    process.ppid,
                    process.pgrp,
                    process.session,
                    threads,
                    // CPU accounting is per-carrier, not per-Linux-process, so
                    // charging a peer this process's ticks would be a fresh
                    // instance of exactly the bug this arm fixes. 0 until the
                    // kernel graph carries per-task CPU.
                    0,
                )
                .into_bytes(),
            ),
            "comm" => Some(format!("{name}\n").into_bytes()),
            "cmdline" => {
                let mut bytes = name.as_bytes().to_vec();
                bytes.push(0);
                Some(bytes)
            }
            "status" => Some(
                format!(
                    "Name:\t{name}\n\
State:\t{state} ({state_long})\n\
Tgid:\t{pid}\n\
Pid:\t{pid}\n\
PPid:\t{ppid}\n\
TracerPid:\t0\n\
Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
Threads:\t{threads}\n",
                    state = process.state,
                    state_long = proc_state_long(process.state),
                    ppid = process.ppid,
                    // Per-process credentials are not in the kernel graph yet.
                    // The reader's own modeled container credentials are the
                    // honest stand-in — every process in the default rootful
                    // container shares them — and they are at least a GUEST
                    // value, unlike the macOS 501/20 the host path reported.
                    uid = ctx.euid,
                    gid = ctx.egid,
                )
                .into_bytes(),
            ),
            _ => None,
        };
    }

    let own_threads = crate::current_thread_states();
    // Worker threads are addressed by their (untranslated) registry tid, but the
    // MAIN thread is addressed by its ns-pid (== tgid) under a PID namespace,
    // which the registry keys by the host id instead. Match either so a
    // /proc/self/task/<tgid>/comm read of the main thread still resolves.
    let host_pid = if crate::namespace::pid::enabled() {
        crate::namespace::pid::ns_to_host_or_self(pid).unwrap_or(pid)
    } else {
        pid
    };
    if let Some(&(tid, state)) = own_threads
        .iter()
        .find(|(t, _)| t.raw() as u32 == pid || t.raw() as u32 == host_pid)
    {
        let ppid = unsafe { libc::getppid() } as u32;
        let me = std::process::id();
        // Per-thread name (prctl PR_SET_NAME / pthread_setname_np), falling back
        // to the process comm for a thread that never named itself.
        let name = per_thread_comm(tid, self_comm);
        match rest {
            "stat" => {
                return Some(
                    proc_stat_line(
                        pid,
                        &name,
                        state,
                        ppid,
                        me,
                        me,
                        own_threads.len().max(1),
                        self_utime_ticks(),
                    )
                    .into_bytes(),
                );
            }
            "comm" => return Some(format!("{name}\n").into_bytes()),
            "cmdline" => {
                let mut b = name.into_bytes();
                b.push(0);
                return Some(b);
            }
            "status" => {
                return Some(
                    format!(
                        "Name:\t{name}\nState:\t{state} ({long})\nTgid:\t{me}\n\
Pid:\t{pid}\nPPid:\t{ppid}\nThreads:\t{n}\n",
                        long = proc_state_long(state),
                        n = own_threads.len(),
                    )
                    .into_bytes(),
                );
            }
            _ => return None,
        }
    }

    // Host-observed death outranks any published run-state: a dead process
    // cannot retract its own last publish (`Booting`/`Running` render `R`), so
    // an exited-but-unreaped child would otherwise keep reading `R` where Linux
    // reports `Z` (the sysvsem `semctl_getpid_child_state` divergence, seen on
    // both native and HVF `run-elf` where guest pids are host pids). Deadness
    // falls through to the host/ns derivation below, which renders the zombie.
    if let Some(state) = crate::run_state::published_stat_char(pid)
        && !host_child_exited_unreaped(ProcHostPid(pid))
    {
        let ppid = unsafe { libc::getppid() } as u32;
        let me = std::process::id();
        let comm = self_comm;
        return match rest {
            "stat" => Some(proc_stat_line(pid, comm, state, ppid, me, me, 1, 0).into_bytes()),
            "comm" => Some(format!("{comm}\n").into_bytes()),
            "cmdline" => {
                let mut b = comm.as_bytes().to_vec();
                b.push(0);
                Some(b)
            }
            "status" => Some(
                format!(
                    "Name:\t{comm}\nState:\t{state} ({long})\nTgid:\t{me}\n\
Pid:\t{pid}\nPPid:\t{ppid}\nThreads:\t1\n",
                    long = proc_state_long(state),
                )
                .into_bytes(),
            ),
            _ => None,
        };
    }

    // PID namespace (§5.3): the guest addresses `/proc/<ns_pid>/…` by ns-pid.
    // Translate it to the host pid for the host-backed lookups, but keep the
    // ns-pid for the displayed `Pid:` field; translate the host ppid/pgid back
    // to ns-pids for display. Identity when namespaces are off (host pid == the
    // value the guest passed).
    let ns_enabled = crate::namespace::pid::enabled();
    let host_pid = if ns_enabled {
        crate::namespace::pid::ns_to_host_or_self(pid)?
    } else {
        pid
    };
    let zombie = host_child_exited_unreaped(ProcHostPid(host_pid));
    let info = crate::host_proc::pid_info(host_pid);
    if info.is_none() && !zombie {
        return None;
    }
    if !zombie && !crate::host_proc::is_guest_process(host_pid) && !ns_enabled {
        return None;
    }
    let comm = info
        .as_ref()
        .and_then(|info| (!info.comm.is_empty()).then(|| info.comm.clone()))
        .unwrap_or_else(|| "carrick".to_owned());
    // Prefer the guest's TRUE published run-state over the host vCPU-thread's
    // scheduler state. The host park is `S`/`D` (`do_sys_poll`) for BOTH a guest
    // genuinely blocked in pause()/futex AND a freshly-forked child still in its
    // post-fork runtime boot (before any guest code) — host-indistinguishable —
    // so trusting the host state reports a booting child as Sleeping/uninterruptible,
    // ~45 ms too early (the pauseinterrupt2 bug; the KVM boot ppoll shows host `D`).
    // The publisher knows whether the guest is genuinely blocked, so its state wins
    // for any LIVE host state (`R`/`S`/`D`). Only the terminal/job-control states
    // the publisher never reports — zombie (`Z`) and stopped (`T`) — stay with the
    // host kernel (a dead/stopped process has no fresh publish to trust).
    let state = if zombie {
        'Z'
    } else {
        let info = info.as_ref()?;
        match info.state {
            'Z' | 'T' => info.state,
            _ => crate::run_state::published_stat_char(host_pid).unwrap_or(info.state),
        }
    };
    // Display pids are ns-local: the requested ns-pid for self, and the
    // ns-translation of the host ppid/pgid (0 / reparent handled by the
    // translation). When ns is off these are the raw host values.
    let fallback_ppid = std::process::id();
    let fallback_pgid = unsafe { libc::getpgrp() as u32 };
    let host_ppid = info.as_ref().map(|info| info.ppid).unwrap_or(fallback_ppid);
    let host_pgid = info.as_ref().map(|info| info.pgid).unwrap_or(fallback_pgid);
    let disp_ppid = if ns_enabled {
        crate::namespace::pid::ns_ppid_for_host(host_pid)
            .unwrap_or_else(|| crate::namespace::pid::host_to_ns_or_self(host_ppid))
    } else {
        host_ppid
    };
    let disp_pgid = if ns_enabled {
        crate::namespace::pid::host_to_ns_pgid(host_pgid)
    } else {
        host_pgid
    };
    match rest {
        // Another guest process: we don't track its thread registry, so report
        // a single thread (num_threads=1). The multi-threaded-fork warning only
        // reads the caller's OWN /proc/self/stat, which uses the live count.
        "stat" => Some(
            proc_stat_line(pid, &comm, state, disp_ppid, disp_pgid, disp_pgid, 1, 0).into_bytes(),
        ),
        "comm" => Some(format!("{comm}\n").into_bytes()),
        "cmdline" => {
            let mut b = comm.clone().into_bytes();
            b.push(0);
            Some(b)
        }
        "status" => Some(
            format!(
                "Name:\t{comm}\n\
State:\t{state} ({state_long})\n\
Tgid:\t{pid}\n\
Pid:\t{pid}\n\
PPid:\t{ppid}\n\
TracerPid:\t0\n\
Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
Threads:\t1\n",
                state = state,
                state_long = proc_state_long(state),
                ppid = disp_ppid,
                // Report the modeled container credentials, NOT the macOS host
                // uid/gid (501/20) `host_proc` reads — a sibling guest process
                // is root:0 in the default rootful container, consistent with
                // its own getuid()==0 and with /proc/self/status.
                uid = crate::cred_ipc::read_target(host_pid as i32).unwrap_or(NsUid::ROOT),
                gid = NsGid::ROOT,
            )
            .into_bytes(),
        ),
        _ => None,
    }
}

fn proc_state_long(state: char) -> &'static str {
    match state {
        'S' => "sleeping",
        'T' => "stopped",
        'Z' => "zombie",
        _ => "running",
    }
}

fn parse_proc_pid_path(path: &str) -> Option<(u32, &str)> {
    let tail = path.strip_prefix("/proc/")?;
    let (pid_str, rest) = tail.split_once('/')?;
    // `self` (and `thread-self`) resolve to this process; the `task/<tid>/`
    // recursion in synthetic_proc_pid_file then picks the specific thread.
    // glibc's pthread_getname_np opens /proc/self/task/<tid>/comm.
    let pid: u32 = match pid_str {
        "self" | "thread-self" => std::process::id(),
        _ => pid_str.parse().ok()?,
    };
    Some((pid, rest))
}

fn synthetic_proc_self_statm() -> Vec<u8> {
    // "size resident shared text lib data dt" in pages. size = virtual size,
    // resident = RSS, both from the host kernel; the rest are zero (we don't
    // separately account shared/text/data). Page unit is the guest's page size.
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    let pg = crate::linux_abi::LINUX_PAGE_SIZE;
    let size = host.virtual_bytes / pg;
    let resident = host.resident_bytes / pg;
    format!("{size} {resident} 0 0 0 0 0\n").into_bytes()
}

fn synthetic_proc_cmdline() -> &'static [u8] {
    b"BOOT_IMAGE=/boot/Image root=/dev/vda1 ro\n"
}

fn synthetic_proc_mounts() -> &'static [u8] {
    b"overlay / overlay ro,relatime 0 0\n"
}

/// The `/proc/filesystems` the guest sees. `pub(crate)` so the new-mount-API
/// dispatch (`fsopen`'s ENODEV list) can pin itself to this exact list — the
/// two surfaces answering "which filesystems exist" must never drift apart.
pub(crate) fn synthetic_proc_filesystems() -> &'static [u8] {
    b"nodev\ttmpfs\n\
nodev\tproc\n\
nodev\tsysfs\n\
nodev\toverlay\n"
}

fn synthetic_proc_config_gz(guest_arch: GuestReportedArch) -> Vec<u8> {
    use std::io::Write;
    use std::sync::OnceLock;
    static AARCH64_CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    static X86_64_CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    let cache = match guest_arch {
        GuestReportedArch::Aarch64 => &AARCH64_CACHE,
        GuestReportedArch::X86_64 => &X86_64_CACHE,
    };
    cache
        .get_or_init(|| {
            let arch_config = match guest_arch {
                GuestReportedArch::Aarch64 => "CONFIG_ARM64=y\n",
                GuestReportedArch::X86_64 => "CONFIG_X86_64=y\n",
            };
            let body = format!(
                "\
# Synthesised by carrick for /proc/config.gz\n\
CONFIG_64BIT=y\n\
{arch_config}\
CONFIG_MMU=y\n\
CONFIG_EVENTFD=y\n\
CONFIG_SIGNALFD=y\n\
CONFIG_TIMERFD=y\n\
CONFIG_EPOLL=y\n\
CONFIG_FUTEX=y\n\
CONFIG_FUTEX_PI=y\n\
CONFIG_POSIX_TIMERS=y\n\
CONFIG_POSIX_MQUEUE=y\n\
CONFIG_AIO=y\n\
CONFIG_FHANDLE=y\n\
CONFIG_INOTIFY_USER=y\n\
CONFIG_DNOTIFY=y\n\
CONFIG_FANOTIFY=y\n\
CONFIG_BLK_DEV_LOOP=y\n\
CONFIG_SYSVIPC=y\n\
CONFIG_CHECKPOINT_RESTORE=y\n\
CONFIG_SECCOMP=y\n\
CONFIG_SECCOMP_FILTER=y\n\
CONFIG_CGROUPS=y\n\
CONFIG_PROC_FS=y\n\
CONFIG_SYSFS=y\n\
CONFIG_TMPFS=y\n\
CONFIG_SECRETMEM=y\n\
CONFIG_OVERLAY_FS=y\n\
CONFIG_UNIX=y\n\
CONFIG_INET=y\n\
CONFIG_IPV6=y\n\
CONFIG_NET=y\n\
CONFIG_NAMESPACES=y\n\
CONFIG_UTS_NS=y\n\
CONFIG_IPC_NS=y\n\
CONFIG_PID_NS=y\n\
CONFIG_NET_NS=y\n\
CONFIG_TIME_NS=y\n\
CONFIG_USER_NS=y\n\
# CONFIG_USERFAULTFD is not set\n"
            );
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            let _ = enc.write_all(body.as_bytes());
            enc.finish().unwrap_or_default()
        })
        .clone()
}

fn synthetic_proc_partitions() -> &'static [u8] {
    b"major minor  #blocks  name\n\n"
}

fn synthetic_proc_diskstats() -> &'static [u8] {
    b""
}

/// `/proc/devices`: char + block driver-major map. MAKEDEV/udev/busybox-mdev
/// parse this to resolve driver names to majors before `mknod`. Kept
/// consistent with the device nodes carrick exposes under `/dev`.
fn synthetic_proc_devices() -> &'static [u8] {
    b"Character devices:\n\
  1 mem\n\
  4 tty\n\
  4 ttyS\n\
  5 /dev/tty\n\
  5 /dev/console\n\
  5 /dev/ptmx\n\
 10 misc\n\
136 pts\n\
\n\
Block devices:\n\
254 virtblk\n"
}

/// `/proc/swaps`: header only (no swap configured). `free`/`swapon -s`/systemd
/// read this; an empty-but-headered file beats ENOENT.
fn synthetic_proc_swaps() -> &'static [u8] {
    b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
}

/// `/proc/vmstat`: the small set of keys real readers (psutil, node_exporter,
/// JVM GC tooling) touch. Values 0 — carrick has no global page accounting.
fn synthetic_proc_vmstat() -> &'static [u8] {
    b"nr_free_pages 0\n\
nr_anon_pages 0\n\
nr_mapped 0\n\
nr_file_pages 0\n\
nr_dirty 0\n\
nr_writeback 0\n\
pgpgin 0\n\
pgpgout 0\n\
pswpin 0\n\
pswpout 0\n\
pgfault 0\n\
pgmajfault 0\n\
oom_kill 0\n"
}

/// `/proc/self/io`: the 7 labeled I/O-accounting lines (proc_pid_io(5)).
/// carrick does not track per-process byte/syscall counts yet, so 0s — still
/// far better than ENOENT for monitoring tools that open this.
fn synthetic_proc_self_io() -> &'static [u8] {
    b"rchar: 0\n\
wchar: 0\n\
syscr: 0\n\
syscw: 0\n\
read_bytes: 0\n\
write_bytes: 0\n\
cancelled_write_bytes: 0\n"
}

/// `/proc/self/mountinfo` (proc_pid_mountinfo(5)): the richer mount table
/// modern tooling (systemd, findmnt, container runtimes) parses instead of the
/// legacy /proc/mounts. Synthetic mount-ids/major:minor; consistent with the
/// mounts carrick actually provides (overlay root + proc/sys/dev/pts/shm).
fn synthetic_proc_self_mountinfo() -> &'static [u8] {
    b"23 0 0:23 / / ro,relatime - overlay overlay ro\n\
24 23 0:24 / /proc rw,relatime - proc proc rw\n\
25 23 0:25 / /sys rw,relatime - sysfs sysfs rw\n\
26 23 0:26 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755\n\
27 26 0:27 / /dev/pts rw,relatime - devpts devpts rw\n\
28 26 0:28 / /dev/shm rw,nosuid,nodev - tmpfs shm rw\n"
}

fn locked_memory_kb(ctx: &SyntheticProcContext) -> u64 {
    ctx.locked_memory
        .iter()
        .map(|range| range.len() as u64)
        .sum::<u64>()
        / 1024
}

fn locked_memory_overlap_kb(ctx: &SyntheticProcContext, start: u64, end: u64) -> u64 {
    ctx.locked_memory
        .iter()
        .map(|range| range.overlap_bytes(start, end))
        .sum::<u64>()
        / 1024
}

/// The standard per-VMA smaps field block (proc(5)). The kB values are
/// approximate; locked pages are reported as resident because Linux's mlock
/// contract makes those pages resident and LTP checks that exact relationship.
/// `size_kb` is the VMA extent.
fn smaps_region_fields(size_kb: u64, locked_kb: u64) -> String {
    let pg = crate::linux_abi::LINUX_PAGE_SIZE / 1024;
    format!(
        "Size:           {size_kb:>8} kB\n\
KernelPageSize: {pg:>8} kB\n\
MMUPageSize:    {pg:>8} kB\n\
Rss:            {locked_kb:>8} kB\n\
Pss:            {locked_kb:>8} kB\n\
Pss_Dirty:             0 kB\n\
Shared_Clean:          0 kB\n\
Shared_Dirty:          0 kB\n\
Private_Clean:         0 kB\n\
Private_Dirty:         0 kB\n\
Referenced:     {locked_kb:>8} kB\n\
Anonymous:             0 kB\n\
LazyFree:              0 kB\n\
AnonHugePages:         0 kB\n\
ShmemPmdMapped:        0 kB\n\
FilePmdMapped:         0 kB\n\
Shared_Hugetlb:        0 kB\n\
Private_Hugetlb:       0 kB\n\
Swap:                  0 kB\n\
SwapPss:               0 kB\n\
Locked:         {locked_kb:>8} kB\n\
VmFlags: rd mr mw me\n"
    )
}

/// Parse the `start-end ...` of one `/proc/self/maps` line.
fn maps_line_range(line: &str) -> Option<(u64, u64)> {
    let range = line.split_whitespace().next()?;
    let (lo, hi) = range.split_once('-')?;
    match (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) {
        (Ok(lo), Ok(hi)) => Some((lo, hi)),
        _ => None,
    }
}

/// `/proc/self/smaps`: each maps line followed by the standard kB-labeled
/// per-region fields (proc(5)). Built from the same maps rendering so the VMA
/// list always agrees with `/proc/self/maps`.
fn synthetic_proc_smaps(ctx: &SyntheticProcContext) -> String {
    let maps = synthetic_proc_maps(ctx);
    let mut out = String::new();
    for line in maps.lines() {
        out.push_str(line);
        out.push('\n');
        let (size_kb, locked_kb) = match maps_line_range(line) {
            Some((start, end)) => (
                end.saturating_sub(start) / 1024,
                locked_memory_overlap_kb(ctx, start, end),
            ),
            None => (0, 0),
        };
        out.push_str(&smaps_region_fields(size_kb, locked_kb));
    }
    out
}

/// `/proc/self/smaps_rollup`: a `[rollup]` header line + aggregate fields.
/// Rss/Pss approximated from host RSS; labels/order per proc(5).
fn synthetic_proc_smaps_rollup(ctx: &SyntheticProcContext) -> String {
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    let rss_kb = host.resident_bytes / 1024;
    let locked_kb = locked_memory_kb(ctx);
    // The rollup header spans the whole user address range, ending at the
    // reported stack top, mirroring what the kernel emits.
    let hi = LINUX_STACK_TOP;
    format!(
        "{:016x}-{hi:016x} ---p 00000000 00:00 0                          [rollup]\n\
Rss:            {rss_kb:>8} kB\n\
Pss:            {rss_kb:>8} kB\n\
Pss_Dirty:             0 kB\n\
Pss_Anon:       {rss_kb:>8} kB\n\
Pss_File:              0 kB\n\
Pss_Shmem:             0 kB\n\
Shared_Clean:          0 kB\n\
Shared_Dirty:          0 kB\n\
Private_Clean:         0 kB\n\
Private_Dirty:  {rss_kb:>8} kB\n\
Referenced:     {rss_kb:>8} kB\n\
Anonymous:      {rss_kb:>8} kB\n\
LazyFree:              0 kB\n\
AnonHugePages:         0 kB\n\
ShmemPmdMapped:        0 kB\n\
FilePmdMapped:         0 kB\n\
Shared_Hugetlb:        0 kB\n\
Private_Hugetlb:       0 kB\n\
Swap:                  0 kB\n\
SwapPss:               0 kB\n\
Locked:         {locked_kb:>8} kB\n",
        0u64,
    )
}

/// `/proc/self/auxv`: the byte-exact ELF auxiliary vector the guest received on
/// its stack (proc(5)), captured at exec — AT_HWCAP/AT_PAGESZ/AT_PHDR/AT_RANDOM/
/// AT_EXECFN/… through AT_NULL. Falls back to a single AT_NULL pair (16 zero
/// bytes) when no image is loaded (e.g. unit tests), never an empty file.
fn synthetic_proc_self_auxv(auxv: &[u8]) -> Vec<u8> {
    if auxv.is_empty() {
        return vec![0u8; 16];
    }
    auxv.to_vec()
}

fn synthetic_proc_self_limits() -> &'static [u8] {
    b"Limit                     Soft Limit           Hard Limit           Units\n\
Max cpu time              unlimited            unlimited            seconds\n\
Max file size             unlimited            unlimited            bytes\n\
Max data size             unlimited            unlimited            bytes\n\
Max stack size            8388608              unlimited            bytes\n\
Max core file size        0                    unlimited            bytes\n\
Max resident set          unlimited            unlimited            bytes\n\
Max processes             unlimited            unlimited            processes\n\
Max open files            1048576              1048576              files\n\
Max locked memory         65536                65536                bytes\n\
Max address space         unlimited            unlimited            bytes\n\
Max file locks            unlimited            unlimited            locks\n\
Max pending signals       63880                63880                signals\n\
Max msgqueue size         819200               819200               bytes\n\
Max nice priority         0                    0                    \n\
Max realtime priority     0                    0                    \n\
Max realtime timeout      unlimited            unlimited            us\n"
}

fn process_short_name(executable_path: &str) -> String {
    Path::new(executable_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.chars().take(15).collect())
        .unwrap_or_else(|| "carrick".to_string())
}

/// The name to report in `/proc/<pid>/task/<tid>/comm`: the thread's own
/// prctl/pthread-set name if it has one, else the process comm (`fallback`).
fn per_thread_comm(tid: crate::thread::ThreadId, fallback: &str) -> String {
    crate::thread::current_thread_name(tid)
        .map(|n| {
            let len = n.iter().position(|&b| b == 0).unwrap_or(n.len());
            String::from_utf8_lossy(&n[..len]).into_owned()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `/proc/uptime` field 1 must be > 0 on the FIRST read, and must agree with
    /// `clock_gettime(CLOCK_BOOTTIME)`.
    ///
    /// It was a lazily-initialised `OnceLock<Instant>` seeded by the first
    /// reader, so the first read was always `0.00`. libuv's `uv_uptime()` slurps
    /// this file and asserts `> 0`, and because the slurp SUCCEEDS its
    /// `CLOCK_BOOTTIME` fallback never ran — `platform_output` failed on a
    /// hard-zero. Reading it twice would have hidden the bug, which is why this
    /// asserts on the very first call in the process.
    #[test]
    fn proc_uptime_is_nonzero_on_first_read_and_tracks_boottime() {
        let text = synthetic_proc_uptime();
        let mut fields = text.split_whitespace();
        let up: f64 = fields
            .next()
            .expect("uptime field 1")
            .parse()
            .expect("field 1 parses as a float");
        let idle: f64 = fields
            .next()
            .expect("uptime field 2")
            .parse()
            .expect("field 2 parses as a float");
        assert!(
            up > 0.0,
            "/proc/uptime field 1 must be > 0 on the first read, got {up}"
        );
        // Field 2 is cumulative idle across all CPUs, so >= field 1.
        assert!(idle >= up, "idle {idle} must be >= uptime {up}");

        // Same authority as CLOCK_BOOTTIME, not a second clock. Allow a small
        // delta for the time between the two reads.
        let boottime = crate::dispatch::boottime_duration().as_secs_f64();
        assert!(
            (boottime - up).abs() < 5.0,
            "/proc/uptime ({up}) must track CLOCK_BOOTTIME ({boottime})"
        );

        // btime is an absolute epoch second derived from the same clock.
        assert!(boot_epoch_secs() > 0, "btime must be a real epoch second");
    }

    #[test]
    fn hvpatch_proc_uses_authoritative_linux_thread_snapshot() {
        let ctx = SyntheticProcContext {
            task_comm: "fallback".to_owned(),
            identity: Some(SyntheticProcIdentity {
                pid: 1,
                tid: 1,
                ppid: 0,
                pgrp: 1,
                session: 1,
            }),
            threads: Some(vec![
                SyntheticProcThread {
                    tid: 1,
                    state: 'R',
                    comm: Some("mainthread".to_owned()),
                },
                SyntheticProcThread {
                    tid: 2,
                    state: 'S',
                    comm: Some("worker-thread".to_owned()),
                },
            ]),
            ..SyntheticProcContext::default()
        };

        let status = String::from_utf8(synthetic_file("/proc/self/status", &ctx).unwrap()).unwrap();
        assert!(status.contains("Threads:\t2\n"), "{status}");
        assert_eq!(
            synthetic_file("/proc/self/task/2/comm", &ctx).unwrap(),
            b"worker-thread\n"
        );
    }

    #[test]
    fn recognizes_proc_self_mem_paths() {
        // `/proc/<pid>/mem` for self, thread-self, or the caller's OWN pid.
        assert!(is_proc_self_mem_path("/proc/self/mem", 3));
        assert!(is_proc_self_mem_path("/proc/thread-self/mem", 3));
        assert!(is_proc_self_mem_path("/proc/3/mem", 3));
        // A PEER's pid is NOT the caller's address space. Accepting it made
        // `/proc/<peer>/mem` return the READER's bytes at that VA.
        assert!(!is_proc_self_mem_path("/proc/1/mem", 3));
        assert!(!is_proc_self_mem_path("/proc/12345/mem", 3));
        assert!(!is_proc_self_pagemap_path("/proc/12345/pagemap", 3));
        assert!(is_proc_self_pagemap_path("/proc/3/pagemap", 3));
        // Not a mem file: other proc files, a bad pid, or a deeper path.
        assert!(!is_proc_self_mem_path("/proc/self/maps", 3));
        assert!(!is_proc_self_mem_path("/proc/self/status", 3));
        assert!(!is_proc_self_mem_path("/proc/meminfo", 3));
        assert!(!is_proc_self_mem_path("/proc//mem", 3));
        assert!(!is_proc_self_mem_path("/proc/self/mem/extra", 3));
    }

    /// A peer's live-memory files must FAIL, and fail differently for a live
    /// peer (refused) than for a pid that never existed (absent) — Linux's
    /// `/proc/424242/mem` is ENOENT, which carrick used to open successfully.
    #[test]
    fn foreign_live_memory_is_refused_not_fabricated() {
        let ctx = peer_dir_ctx();
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/7/mem", &ctx),
            Some(crate::linux_abi::LINUX_EACCES)
        );
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/7/pagemap", &ctx),
            Some(crate::linux_abi::LINUX_EACCES)
        );
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/424242/mem", &ctx),
            Some(LINUX_ENOENT)
        );
        // The caller's own is served normally, by pid or by alias.
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/3/mem", &ctx),
            None
        );
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/self/mem", &ctx),
            None
        );
        assert!(synthetic_file("/proc/3/mem", &ctx).is_some());
        assert!(
            synthetic_file("/proc/7/mem", &ctx).is_none(),
            "a peer's /proc/<pid>/mem must not open as a live-memory file"
        );
        // A lane with no kernel graph keeps the mature host-process behaviour.
        let no_graph = SyntheticProcContext::default();
        assert_eq!(
            proc_foreign_live_memory_open_errno("/proc/7/mem", &no_graph),
            None
        );
    }

    #[test]
    fn lookup_root_returns_directory() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(md.mode, 0o555);
    }

    #[test]
    fn hvpatch_numeric_self_directory_uses_authoritative_identity() {
        let v = ProcVfs::new();
        let threads = [
            SyntheticProcThread {
                tid: 73,
                state: 'R',
                comm: Some("leader".to_owned()),
            },
            SyntheticProcThread {
                tid: 74,
                state: 'S',
                comm: Some("waiter".to_owned()),
            },
        ];
        let ctx = OpenContext {
            identity: Some(SyntheticProcIdentity {
                pid: 73,
                tid: 73,
                ppid: 1,
                pgrp: 73,
                session: 73,
            }),
            threads: Some(&threads),
            ..OpenContext::default()
        };
        let opened = v
            .open(
                "/proc/73",
                OpenFlags {
                    read: true,
                    directory: true,
                    ..OpenFlags::default()
                },
                &ctx,
            )
            .expect("logical /proc/<self> directory must open");
        let VfsHandle::Directory { entries, .. } = opened else {
            panic!("logical /proc/<self> must be a directory");
        };
        assert!(entries.iter().any(|entry| entry.name == "status"));

        let opened = v
            .open(
                "/proc/73/task",
                OpenFlags {
                    read: true,
                    directory: true,
                    ..OpenFlags::default()
                },
                &ctx,
            )
            .expect("logical /proc/<self>/task directory must open");
        let VfsHandle::Directory { entries, .. } = opened else {
            panic!("logical /proc/<self>/task must be a directory");
        };
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [".", "..", "73", "74"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn proc_pid_dir_enumerates_and_lists_files() {
        // Mark this process as the guest root so is_guest_process(self) is true,
        // then /proc and /proc/<self> enumerate. Restore the root afterwards so
        // sibling tests are unaffected.
        let me = std::process::id();
        crate::host_proc::set_root_guest_pid(me);
        let v = ProcVfs::new();

        // /proc/<self> is a directory listing the RICH per-process surface
        // (files + magic symlinks + sub-dirs) since it is the self pid.
        let pid_path = format!("/proc/{me}");
        assert_eq!(v.lookup(&pid_path).unwrap().kind, EntryKind::Directory);
        let by_name: std::collections::HashMap<String, EntryKind> = v
            .readdir(&pid_path)
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.kind))
            .collect();
        for want in [
            "stat", "comm", "cmdline", "status", "maps", "limits", "auxv", "io", "cgroup", "statm",
        ] {
            assert_eq!(by_name.get(want), Some(&EntryKind::File), "file {want}");
        }
        for dir in ["task", "ns", "net"] {
            assert_eq!(by_name.get(dir), Some(&EntryKind::Directory), "dir {dir}");
        }
        for link in ["exe", "cwd", "root"] {
            assert_eq!(by_name.get(link), Some(&EntryKind::Symlink), "link {link}");
        }
        // Every listed flat file must actually open (readdir ⇄ open in sync).
        for (name, kind) in &by_name {
            if *kind == EntryKind::File {
                let p = format!("{pid_path}/{name}");
                assert!(
                    synthetic_file(&p, &demo_ctx()).is_some()
                        || synthetic_file(&format!("/proc/self/{name}"), &demo_ctx()).is_some(),
                    "listed file {name} does not open"
                );
            }
        }
        // /proc enumerates this guest process (as its ns-pid; identity here).
        let root = v.readdir("/proc").unwrap();
        assert!(
            root.iter().any(|d| d.name == me.to_string()),
            "/proc should list the guest pid {me}"
        );

        // /proc/self/task is LISTED in the self dir, so it must also resolve and
        // readdir (the readdir⇄lookup consistency the review flagged). It used to
        // ENOENT because the task helper only parsed a numeric pid.
        assert_eq!(
            v.lookup("/proc/self/task").unwrap().kind,
            EntryKind::Directory
        );
        assert!(v.readdir("/proc/self/task").is_ok());
        assert_eq!(
            v.lookup(&format!("/proc/{me}/task")).unwrap().kind,
            EntryKind::Directory
        );

        crate::host_proc::set_root_guest_pid(0);
    }

    #[test]
    fn lookup_known_file_returns_file() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc/cpuinfo").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.mode, 0o444);
    }

    #[test]
    fn lookup_unknown_proc_is_enoent() {
        let v = ProcVfs::new();
        assert_eq!(v.lookup("/proc/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_cpuinfo_returns_bytes() {
        let v = ProcVfs::new();
        let h = v
            .open(
                "/proc/cpuinfo",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { path, contents, .. } => {
                assert_eq!(path, "/proc/cpuinfo");
                assert!(!contents.is_empty());
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("processor"));
            }
            _ => panic!("expected Bytes variant, got {:?}", h),
        }
    }

    #[test]
    fn writable_tunables_open_for_write_others_eacces() {
        let v = ProcVfs::new();
        for p in [
            "/proc/self/oom_score_adj",
            "/proc/self/oom_adj",
            "/proc/self/loginuid",
            "/proc/self/timerslack_ns",
        ] {
            let h = v.open(
                p,
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            );
            assert!(h.is_ok(), "{p} should open for write, got {h:?}");
        }
        // A read-only tunable (oom_score) still rejects a write-open.
        assert_eq!(
            v.open(
                "/proc/self/oom_score",
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default()
            ),
            Err(LINUX_EACCES)
        );
    }

    #[test]
    fn open_write_is_eacces() {
        let v = ProcVfs::new();
        let result = v.open(
            "/proc/cpuinfo",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EACCES));
    }

    #[test]
    fn open_self_cmdline_uses_executable_path() {
        let v = ProcVfs::new();
        let argv = vec![
            "/usr/bin/test-exe".to_owned(),
            "--flag".to_owned(),
            "value".to_owned(),
        ];
        let h = v
            .open(
                "/proc/self/cmdline",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext {
                    executable_path: Some("/usr/bin/test-exe"),
                    argv: Some(&argv),
                    ..Default::default()
                },
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                assert_eq!(contents, b"/usr/bin/test-exe\0--flag\0value\0");
            }
            _ => panic!("expected Bytes variant"),
        }
    }

    #[test]
    fn proc_maps_uses_vfs_owned_context() {
        // Reserve a 64 KiB heap region but set the program break partway in, at an
        // unaligned offset. Real Linux reports page-aligned VMA bounds, so the [heap]
        // line must end at the break rounded UP to Linux's 4 KiB page — not at the
        // raw break, and not at the full region end. 0x1234 rounds up to 0x2000.
        let ctx = SyntheticProcContext {
            executable_path: "/bin/demo".to_owned(),
            argv: vec!["/bin/demo".to_owned()],
            environ: vec![b"PATH=/usr/bin".to_vec(), b"HOME=/root".to_vec()],
            open_fds: vec![0, 1, 2],
            auxv: Vec::new(),
            address_space_regions: Some(vec![ProcMapsEntry {
                start: LINUX_HEAP_BASE,
                end: LINUX_HEAP_BASE + 0x10000,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            }]),
            brk_current: LINUX_HEAP_BASE + 0x1234,
            mmap_next: LINUX_MMAP_BASE,
            sig_ignored: 0,
            sig_caught: 0,
            sig_shdpnd: 0,
            ..SyntheticProcContext::default()
        };
        let maps = String::from_utf8(synthetic_file("/proc/self/maps", &ctx).unwrap()).unwrap();
        assert!(maps.contains("[heap]"));
        // The heap ends at the page-aligned break (0x1234 -> 0x2000), proving the
        // VFS-owned brk_current drives the end rather than the reserved region end.
        assert!(maps.contains(&format!("{:08x}", LINUX_HEAP_BASE + 0x2000)));
        assert!(!maps.contains(&format!("{:08x}", LINUX_HEAP_BASE + 0x10000)));
    }

    fn ctx() -> SyntheticProcContext {
        SyntheticProcContext::default()
    }

    #[test]
    fn sysctl_dirs_resolve_as_directories() {
        let v = ProcVfs::new();
        for dir in [
            "/proc/sys",
            "/proc/sys/kernel",
            "/proc/sys/kernel/random",
            "/proc/sys/vm",
            "/proc/sys/fs",
            "/proc/sys/fs/inotify",
            "/proc/sys/fs/mqueue",
            "/proc/sys/net",
            "/proc/sys/net/core",
            "/proc/sys/net/ipv4",
        ] {
            assert_eq!(
                v.lookup(dir).unwrap().kind,
                EntryKind::Directory,
                "{dir} should be a directory"
            );
            assert!(v.readdir(dir).is_ok(), "{dir} should readdir");
        }
    }

    #[test]
    fn sysctl_readdir_lists_children() {
        let v = ProcVfs::new();
        let kernel: Vec<String> = v
            .readdir("/proc/sys/kernel")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        for want in ["ostype", "osrelease", "cap_last_cap", "pid_max", "random"] {
            assert!(kernel.iter().any(|n| n == want), "kernel/ missing {want}");
        }
        // `random` is enumerated as a sub-directory, not a leaf.
        let random_kind = v
            .readdir("/proc/sys/kernel")
            .unwrap()
            .into_iter()
            .find(|d| d.name == "random")
            .unwrap()
            .kind;
        assert_eq!(random_kind, EntryKind::Directory);
    }

    #[test]
    fn sysctl_leaf_values_match_oracle() {
        for (path, want) in [
            ("/proc/sys/kernel/ostype", "Linux\n"),
            ("/proc/sys/kernel/cap_last_cap", "40\n"),
            ("/proc/sys/kernel/io_uring_disabled", "0\n"),
            ("/proc/sys/kernel/ns_last_pid", "0\n"),
            ("/proc/sys/vm/overcommit_memory", "1\n"),
            ("/proc/sys/vm/max_map_count", "262144\n"),
            ("/proc/sys/net/core/somaxconn", "4096\n"),
            ("/proc/sys/fs/inotify/max_user_watches", "1048576\n"),
            ("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n"),
            ("/proc/sys/net/ipv4/tcp_rmem", "4096\t131072\t6291456\n"),
            ("/proc/sys/fs/file-nr", "256\t0\t1048576\n"),
            ("/proc/sys/fs/aio-max-nr", "65536\n"),
            ("/proc/sys/kernel/random/entropy_avail", "256\n"),
            // LTP's tst_sys_conf save/restore only TCONFs a test when the leaf
            // EXISTS and is not writable; a missing leaf silently lets the test
            // run against a keyring carrick does not implement (add_key05).
            ("/proc/sys/kernel/keys/gc_delay", "300\n"),
            ("/proc/sys/kernel/keys/maxkeys", "200\n"),
            ("/proc/sys/kernel/keys/maxbytes", "20000\n"),
        ] {
            let got = synthetic_file(path, &ctx()).unwrap();
            assert_eq!(String::from_utf8(got).unwrap(), want, "{path}");
        }
    }

    #[test]
    fn sysctl_io_uring_disabled_is_readonly_like_docker() {
        let v = ProcVfs::new();
        let write_open = v.open(
            "/proc/sys/kernel/io_uring_disabled",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(write_open, Err(crate::linux_abi::LINUX_EROFS));
    }

    #[test]
    fn sysctl_uuid_is_fresh_v4_each_read() {
        let a = String::from_utf8(synthetic_file("/proc/sys/kernel/random/uuid", &ctx()).unwrap())
            .unwrap();
        let b = String::from_utf8(synthetic_file("/proc/sys/kernel/random/uuid", &ctx()).unwrap())
            .unwrap();
        assert_eq!(a.trim_end().len(), 36, "uuid is 36 chars: {a:?}");
        assert_eq!(a.as_bytes()[14], b'4', "version-4 nibble");
        assert!(
            matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "variant"
        );
        assert_ne!(a, b, "uuid must differ each read");
    }

    #[test]
    fn sysctl_boot_id_is_stable_and_nonzero() {
        let a = synthetic_file("/proc/sys/kernel/random/boot_id", &ctx()).unwrap();
        let b = synthetic_file("/proc/sys/kernel/random/boot_id", &ctx()).unwrap();
        assert_eq!(a, b, "boot_id stable within a run");
        assert_ne!(
            String::from_utf8(a).unwrap().trim_end(),
            "00000000-0000-4000-8000-000000000000",
            "boot_id must not be the all-zero sentinel"
        );
    }

    #[test]
    fn uptime_is_seconds_since_boot_not_epoch() {
        let up = synthetic_proc_uptime();
        let first: f64 = up.split_whitespace().next().unwrap().parse().unwrap();
        // A freshly-booted guest's uptime is small — certainly not ~1.78e9
        // (the old epoch-seconds bug).
        assert!(
            first < 1_000_000.0,
            "uptime field 1 should be small: {up:?}"
        );
    }

    #[test]
    fn self_stat_has_exactly_52_fields() {
        let line =
            String::from_utf8(synthetic_file("/proc/self/stat", &demo_ctx()).unwrap()).unwrap();
        let n = line.trim_end().split(' ').count();
        assert_eq!(n, 52, "stat must have 52 fields: {line:?}");
    }

    #[test]
    fn self_stat_uses_explicit_kernel_identity_when_present() {
        let mut context = demo_ctx();
        context.identity = Some(SyntheticProcIdentity {
            pid: 2,
            tid: 2,
            ppid: 1,
            pgrp: 2,
            session: 1,
        });

        let line = String::from_utf8(synthetic_file("/proc/self/stat", &context).unwrap()).unwrap();
        let fields: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!(fields[0], "2", "pid: {line}");
        assert_eq!(fields[3], "1", "ppid: {line}");
        assert_eq!(fields[4], "2", "pgrp: {line}");
        assert_eq!(fields[5], "1", "session: {line}");
    }

    #[test]
    fn self_stat_state_uses_tracked_leader_state() {
        let leader = crate::thread::ThreadId::synthetic_for_tests(1000);
        let worker = crate::thread::ThreadId::synthetic_for_tests(1001);
        let states = [(leader, 'S'), (worker, 'R')];

        assert_eq!(proc_self_stat_state_from_threads(&states, 1000, 1), 'S');
        assert_eq!(proc_self_stat_state_from_threads(&states, 2000, 1000), 'S');
        assert_eq!(proc_self_stat_state_from_threads(&states, 2000, 1), 'S');
        assert_eq!(proc_self_stat_state_from_threads(&[], 2000, 1), 'R');
    }

    #[test]
    fn self_status_has_new_labels_and_sane_vmsize() {
        let s =
            String::from_utf8(synthetic_file("/proc/self/status", &demo_ctx()).unwrap()).unwrap();
        for label in [
            "RssAnon:",
            "RssFile:",
            "RssShmem:",
            "NoNewPrivs:",
            "Seccomp:",
            "Seccomp_filters:",
            "CoreDumping:",
            "Speculation_Store_Bypass:",
        ] {
            assert!(s.contains(label), "status missing {label}");
        }
        // SigQ must carry a non-zero denominator (the pending-signal limit).
        assert!(s.contains("SigQ:\t0/63880"), "SigQ denominator: {s}");
        // VmSize must be derived from the guest VMAs, NOT the 521 GB host window.
        let vmsize_line = s.lines().find(|l| l.starts_with("VmSize:")).unwrap();
        let kb: u64 = vmsize_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert!(kb < 64 * 1024 * 1024, "VmSize should be sane, got {kb} kB");
    }

    #[test]
    fn self_status_reflects_live_credentials_and_groups() {
        let ctx = SyntheticProcContext {
            ruid: carrick_abi::NsUid::new(101),
            euid: carrick_abi::NsUid::new(102),
            suid: carrick_abi::NsUid::new(103),
            rgid: carrick_abi::NsGid::new(201),
            egid: carrick_abi::NsGid::new(202),
            sgid: carrick_abi::NsGid::new(203),
            groups: vec![
                carrick_abi::NsGid::new(0),
                carrick_abi::NsGid::new(1),
                carrick_abi::NsGid::new(2),
                carrick_abi::NsGid::new(3),
            ],
            ..demo_ctx()
        };
        let s = String::from_utf8(synthetic_file("/proc/self/status", &ctx).unwrap()).unwrap();
        assert!(s.contains("Uid:\t101\t102\t103\t102\n"), "status: {s}");
        assert!(s.contains("Gid:\t201\t202\t203\t202\n"), "status: {s}");
        assert!(s.contains("Groups:\t0 1 2 3\n"), "status: {s}");
    }

    #[test]
    fn sigq_denominator_matches_limits_max_pending_signals() {
        // The SigQ second field IS RLIMIT_SIGPENDING, which is also what
        // /proc/self/limits prints — the two files must agree (review finding).
        let limits = String::from_utf8(synthetic_proc_self_limits().to_vec()).unwrap();
        let status =
            String::from_utf8(synthetic_file("/proc/self/status", &demo_ctx()).unwrap()).unwrap();
        assert!(
            limits.contains("Max pending signals       63880                63880"),
            "limits Max pending signals must be 63880: {limits}"
        );
        assert!(status.contains("SigQ:\t0/63880"), "status SigQ: {status}");
    }

    #[test]
    fn self_auxv_serves_captured_image_else_at_null() {
        // With a captured image, /proc/self/auxv is byte-exact.
        let image: Vec<u8> = (0..48).collect();
        let ctx = SyntheticProcContext {
            auxv: image.clone(),
            ..SyntheticProcContext::default()
        };
        assert_eq!(synthetic_file("/proc/self/auxv", &ctx).unwrap(), image);
        // Without one (no image loaded / unit tests), a single AT_NULL pair —
        // never an empty file.
        let empty = SyntheticProcContext::default();
        assert_eq!(
            synthetic_file("/proc/self/auxv", &empty).unwrap(),
            vec![0u8; 16]
        );
    }

    #[test]
    fn self_environ_is_nul_separated_and_byte_exact() {
        // Includes a non-UTF-8 value to prove env is served as opaque bytes,
        // not lossily round-tripped through String.
        let ctx = SyntheticProcContext {
            environ: vec![
                b"PATH=/usr/bin".to_vec(),
                vec![b'X', b'=', 0xff, 0xfe],
                b"HOME=/root".to_vec(),
            ],
            ..SyntheticProcContext::default()
        };
        let out = synthetic_file("/proc/self/environ", &ctx).unwrap();
        assert_eq!(
            out,
            b"PATH=/usr/bin\0X=\xff\xfe\0HOME=/root\0".to_vec(),
            "environ must be NUL-separated and byte-exact"
        );
    }

    #[test]
    fn self_io_has_seven_labeled_lines() {
        let io = String::from_utf8(synthetic_file("/proc/self/io", &ctx()).unwrap()).unwrap();
        for label in [
            "rchar:",
            "wchar:",
            "syscr:",
            "syscw:",
            "read_bytes:",
            "write_bytes:",
            "cancelled_write_bytes:",
        ] {
            assert!(io.contains(label), "io missing {label}");
        }
        assert_eq!(io.lines().count(), 7);
    }

    #[test]
    fn devices_has_char_and_block_sections() {
        let d = String::from_utf8(synthetic_file("/proc/devices", &ctx()).unwrap()).unwrap();
        assert!(d.contains("Character devices:"));
        assert!(d.contains("Block devices:"));
        assert!(d.contains("136 pts"));
    }

    #[test]
    fn smaps_pairs_maps_lines_with_fields() {
        let s =
            String::from_utf8(synthetic_file("/proc/self/smaps", &demo_ctx()).unwrap()).unwrap();
        assert!(s.contains("[heap]"), "smaps includes the maps lines");
        assert!(s.contains("Rss:"), "smaps includes per-region fields");
        assert!(s.contains("VmFlags:"));
        let rollup =
            String::from_utf8(synthetic_file("/proc/self/smaps_rollup", &demo_ctx()).unwrap())
                .unwrap();
        assert!(rollup.contains("[rollup]"));
        assert!(rollup.contains("Pss:"));
    }

    /// LTP's `tst_test` setup writes -1000 to ANOTHER process's
    /// `/proc/<pid>/oom_score_adj` and `access(2)`-checks it first
    /// (`tst_memutils.c:set_oom_score_adj`). Serving that file only under
    /// `self/` TBROKs every new-API LTP test before its first assertion, so a
    /// foreign live pid must resolve and must report ITS OWN value — not the
    /// reader's, which is what a process-global cell would return once every
    /// Linux process is a thread of one Darwin process.
    #[test]
    fn foreign_pid_oom_score_adj_is_per_process() {
        let mut ctx = ctx();
        ctx.oom_score_adj = std::collections::BTreeMap::from([(2, -1000), (7, 250)]);

        for (pid, expected) in [(2u32, "-1000\n"), (7, "250\n")] {
            let got = synthetic_file(&format!("/proc/{pid}/oom_score_adj"), &ctx)
                .map(|bytes| String::from_utf8(bytes).unwrap());
            assert_eq!(got.as_deref(), Some(expected), "/proc/{pid}/oom_score_adj");
        }

        // A pid with no live process behind it is ENOENT (None), not a
        // fabricated 0 — LTP's access(2) probe distinguishes the two.
        assert_eq!(synthetic_file("/proc/9999/oom_score_adj", &ctx), None);

        // The foreign dir must also ENUMERATE it, so `ls /proc/<pid>` agrees
        // with what open(2) resolves (proc(5)).
        assert!(PROC_PID_FILES.contains(&"oom_score_adj"));
    }

    /// A write names a pid, and the pid may be someone else's. The VFS parses
    /// and validates; the dispatcher applies against the backend that owns
    /// per-process state.
    #[test]
    fn tunable_write_parses_target_pid_and_range() {
        assert_eq!(
            parse_tunable_write("/proc/2/oom_score_adj", b"-1000"),
            Ok(TunableWrite::OomScoreAdj {
                pid: Some(2),
                value: -1000
            })
        );
        assert_eq!(
            parse_tunable_write("/proc/self/oom_score_adj", b"250\n"),
            Ok(TunableWrite::OomScoreAdj {
                pid: None,
                value: 250
            })
        );
        // Out of Linux's [-1000, 1000] and unparseable are both EINVAL, before
        // the target process is touched.
        assert!(parse_tunable_write("/proc/self/oom_score_adj", b"-1001").is_err());
        assert!(parse_tunable_write("/proc/self/oom_score_adj", b"nope").is_err());
        // Tunables carrick models no state for stay accept-and-ignore.
        assert_eq!(
            parse_tunable_write("/proc/self/loginuid", b"0"),
            Ok(TunableWrite::Ignored)
        );
        // Every one of these is writable regardless of how the pid is spelled.
        for path in [
            "/proc/2/oom_score_adj",
            "/proc/self/oom_score_adj",
            "/proc/thread-self/oom_score_adj",
            "/proc/self/timerslack_ns",
        ] {
            assert!(is_writable_tunable_path(path), "{path} should be writable");
        }
        assert!(!is_writable_tunable_path("/proc/self/stat"));
    }

    #[test]
    fn flat_self_files_present() {
        for (path, needle) in [
            ("/proc/self/cgroup", "0::/"),
            ("/proc/self/oom_score", "0"),
            ("/proc/self/oom_score_adj", "0"),
            ("/proc/self/personality", "00000000"),
            ("/proc/self/loginuid", "4294967295"),
            ("/proc/self/timerslack_ns", "50000"),
            ("/proc/self/syscall", "running"),
            ("/proc/self/wchan", "0"),
            ("/proc/self/mountinfo", " / / "),
            ("/proc/vmstat", "pgfault"),
            ("/proc/swaps", "Filename"),
        ] {
            let got = String::from_utf8(synthetic_file(path, &ctx()).unwrap_or_default()).unwrap();
            assert!(
                got.contains(needle),
                "{path} should contain {needle:?}, got {got:?}"
            );
        }
    }

    #[test]
    fn net_files_present_with_headers() {
        // Header-bearing socket tables and the namespace-correct aliases all
        // resolve to the same renderer.
        for (path, needle) in [
            ("/proc/net/dev", "Inter-|"),
            ("/proc/net/tcp", "local_address"),
            ("/proc/net/tcp6", "local_address"),
            ("/proc/net/udp", "rem_address"),
            ("/proc/net/unix", "RefCount Protocol"),
            ("/proc/net/route", "Iface\tDestination"),
            ("/proc/net/snmp", "Tcp: RtoAlgorithm"),
            ("/proc/net/netstat", "TcpExt:"),
            ("/proc/net/sockstat", "sockets: used"),
            ("/proc/net/arp", "IP address"),
            ("/proc/self/net/tcp", "local_address"),
            ("/proc/1/net/dev", "Inter-|"),
        ] {
            let got = String::from_utf8(synthetic_file(path, &ctx()).unwrap_or_default()).unwrap();
            assert!(got.contains(needle), "{path} should contain {needle:?}");
        }
    }

    #[test]
    fn proc_net_route_uses_bridge_gateway() {
        let ctx = SyntheticProcContext {
            network: carrick_spec::NetworkNamespaceSpec::bridge_default(
                Some("web".to_string()),
                Vec::new(),
                Vec::new(),
            ),
            ..SyntheticProcContext::default()
        };
        let route = String::from_utf8(synthetic_file("/proc/net/route", &ctx).unwrap()).unwrap();
        assert!(
            route.contains("eth0\t00000000\t01001FAC"),
            "bridge route should report default gateway 172.31.0.1 in /proc/net/route: {route}"
        );
    }

    #[test]
    fn proc_net_exposes_each_bridge_attachment() {
        let mut network = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        network.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 8)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["api".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 8)),
            ),
        ];
        network.bridge_id = network.attachments[0].bridge_id.clone();
        network.ipv4 = network.attachments[0].ipv4;
        network.gateway_v4 = network.attachments[0].gateway_v4;

        let dev = String::from_utf8(synthetic_proc_net_dev(&network)).unwrap();
        assert!(dev.contains("  eth0:"), "primary bridge missing: {dev}");
        assert!(dev.contains("  eth1:"), "secondary bridge missing: {dev}");

        let route = String::from_utf8(synthetic_proc_net_route(&network)).unwrap();
        assert!(
            route.contains("eth0\t00000000\t01001FAC"),
            "default route should stay on primary bridge: {route}"
        );
        assert!(
            route.contains("eth0\t00001FAC\t00000000"),
            "primary connected route missing: {route}"
        );
        assert!(
            route.contains("eth1\t000020AC\t00000000"),
            "secondary connected route missing: {route}"
        );
    }

    #[test]
    fn proc_net_for_none_mode_does_not_leak_host_uplink() {
        let network = carrick_spec::NetworkNamespaceSpec::none();

        let dev = String::from_utf8(synthetic_proc_net_dev(&network)).unwrap();
        assert!(dev.contains("    lo:"), "loopback should be present: {dev}");
        assert!(
            !dev.contains("  eth0:"),
            "none mode leaked host eth0: {dev}"
        );

        let route = String::from_utf8(synthetic_proc_net_route(&network)).unwrap();
        assert!(
            !route.contains("eth0\t"),
            "none mode leaked host eth0 route: {route}"
        );
    }

    #[test]
    fn self_is_traversable_dir_that_readlinks_to_pid() {
        let v = ProcVfs::new();
        // Modeled as a traversable directory (so /proc/self/<file> descends),
        // but readlink still yields the pid for tools that resolve it.
        assert_eq!(
            v.lookup_nofollow("/proc/self").unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(v.lookup("/proc/self").unwrap().kind, EntryKind::Directory);
        assert_eq!(
            v.readlink("/proc/self").unwrap().to_string_lossy(),
            crate::namespace::pid::self_ns_pid().to_string()
        );
    }

    #[test]
    fn net_dir_readlinks_to_self_net() {
        let v = ProcVfs::new();
        assert_eq!(
            v.lookup_nofollow("/proc/net").unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(
            v.readlink("/proc/net").unwrap().to_string_lossy(),
            "self/net"
        );
    }

    #[test]
    fn thread_self_readlinks_to_task_tid() {
        let v = ProcVfs::new();
        let t = v.readlink("/proc/thread-self").unwrap();
        let p = crate::namespace::pid::self_ns_pid();
        assert_eq!(t.to_string_lossy(), format!("{p}/task/{p}"));
    }

    #[test]
    fn exe_cwd_root_lstat_as_symlinks() {
        let v = ProcVfs::new();
        // Only the SELF aliases resolve exe/cwd/root (they're self-specific).
        for link in [
            "/proc/self/exe",
            "/proc/self/cwd",
            "/proc/self/root",
            "/proc/thread-self/exe",
        ] {
            assert_eq!(
                v.lookup_nofollow(link).unwrap().kind,
                EntryKind::Symlink,
                "{link} should lstat as a symlink"
            );
            // faccessat(F_OK)/`test -e` path goes through follow-lookup too.
            assert_eq!(v.lookup(link).unwrap().kind, EntryKind::Symlink, "{link}");
        }
        // A non-existent / non-guest numeric pid must NOT report exe as present
        // (no liveness leak), and a foreign pid must not masquerade as self.
        assert_eq!(v.lookup_nofollow("/proc/999999/exe"), Err(LINUX_ENOENT));
        assert_eq!(v.lookup("/proc/999999/exe"), Err(LINUX_ENOENT));
    }

    #[test]
    fn self_fd_dir_lists_open_fds_as_symlinks() {
        let v = ProcVfs::new();
        // /proc/self/fd is a directory; /proc/self/fd/N lstat as a symlink.
        assert_eq!(
            v.lookup("/proc/self/fd").unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(
            v.lookup_nofollow("/proc/self/fd/1").unwrap().kind,
            EntryKind::Symlink
        );
        // open() lists one symlink per fd from the context snapshot.
        let fds = [0i32, 1, 2, 7];
        let ctx = OpenContext {
            open_fds: Some(&fds),
            ..Default::default()
        };
        let h = v
            .open(
                "/proc/self/fd",
                OpenFlags {
                    read: true,
                    directory: true,
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
        match h {
            VfsHandle::Directory { entries, .. } => {
                let names: Vec<String> = entries
                    .into_iter()
                    .filter(|e| e.kind == EntryKind::Symlink)
                    .map(|e| e.name)
                    .collect();
                assert_eq!(names, vec!["0", "1", "2", "7"]);
            }
            _ => panic!("expected a Directory handle"),
        }
        // A foreign / non-existent pid's fd dir is not reachable.
        assert!(v.lookup("/proc/999999/fd").is_err());
    }

    #[test]
    fn self_fdinfo_dir_lists_open_fds_as_files() {
        let v = ProcVfs::new();
        assert_eq!(
            v.lookup("/proc/self/fdinfo").unwrap().kind,
            EntryKind::Directory
        );
        // fdinfo/N is a regular FILE (contents rendered dispatcher-side).
        assert_eq!(
            v.lookup("/proc/self/fdinfo/2").unwrap().kind,
            EntryKind::File
        );
        let fds = [0i32, 1, 2, 9];
        let ctx = OpenContext {
            open_fds: Some(&fds),
            ..Default::default()
        };
        let h = v
            .open(
                "/proc/self/fdinfo",
                OpenFlags {
                    read: true,
                    directory: true,
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
        match h {
            VfsHandle::Directory { entries, .. } => {
                let files: Vec<String> = entries
                    .into_iter()
                    .filter(|e| e.kind == EntryKind::File)
                    .map(|e| e.name)
                    .collect();
                assert_eq!(files, vec!["0", "1", "2", "9"]);
            }
            _ => panic!("expected a Directory handle"),
        }
        assert!(v.lookup("/proc/999999/fdinfo").is_err());
    }

    #[test]
    fn proc_sys_hostname_uses_open_context_hostname() {
        let v = ProcVfs::new();
        let ctx = OpenContext {
            guest_hostname: Some("api-host"),
            ..Default::default()
        };
        let h = v
            .open(
                "/proc/sys/kernel/hostname",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &ctx,
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => assert_eq!(contents, b"api-host\n"),
            _ => panic!("expected hostname bytes"),
        }
    }

    #[test]
    fn ns_dir_and_links() {
        let v = ProcVfs::new();
        assert_eq!(
            v.lookup("/proc/self/ns").unwrap().kind,
            EntryKind::Directory
        );
        let names: Vec<String> = v
            .readdir("/proc/self/ns")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        for want in ["net", "pid", "user", "mnt", "uts", "ipc", "cgroup"] {
            assert!(names.iter().any(|n| n == want), "ns/ missing {want}");
        }
        assert_eq!(
            v.lookup_nofollow("/proc/self/ns/net").unwrap().kind,
            EntryKind::Symlink
        );
        let t = v.readlink("/proc/self/ns/net").unwrap();
        assert_eq!(t.to_string_lossy(), "net:[4026531992]");
        // Same-namespace equality across the self aliases (both live): the ns
        // inode is shared, so a same-namespace check holds.
        assert_eq!(
            v.readlink("/proc/thread-self/ns/pid").unwrap(),
            v.readlink("/proc/self/ns/pid").unwrap()
        );
        // A non-live numeric pid does not materialize an ns dir/link.
        assert!(v.lookup_nofollow("/proc/999999/ns/pid").is_err());
    }

    #[test]
    fn top_level_readdir_has_self_threadself_net_sys() {
        let v = ProcVfs::new();
        let by_name: std::collections::HashMap<String, EntryKind> = v
            .readdir("/proc")
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.kind))
            .collect();
        // Traversable directories (carrick model); readlink still resolves them.
        for dir in ["self", "thread-self", "net", "sys"] {
            assert_eq!(by_name.get(dir), Some(&EntryKind::Directory), "{dir}");
        }
    }

    #[test]
    fn proc_net_resolves_as_directory_with_self_alias() {
        let v = ProcVfs::new();
        for dir in ["/proc/net", "/proc/self/net", "/proc/thread-self/net"] {
            assert_eq!(
                v.lookup(dir).unwrap().kind,
                EntryKind::Directory,
                "{dir} should be a directory"
            );
            let names: Vec<String> = v
                .readdir(dir)
                .unwrap()
                .into_iter()
                .map(|d| d.name)
                .collect();
            for want in ["dev", "tcp", "unix", "route"] {
                assert!(names.iter().any(|n| n == want), "{dir} missing {want}");
            }
        }
        // A non-live numeric pid's net dir does not resolve.
        assert!(v.lookup("/proc/999999/net").is_err());
    }

    #[test]
    fn proc_top_level_readdir_breadth() {
        let v = ProcVfs::new();
        let names: Vec<String> = v
            .readdir("/proc")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        for want in [
            "sys",
            "net",
            "devices",
            "vmstat",
            "swaps",
            "modules",
            "locks",
            "config.gz",
        ] {
            assert!(names.iter().any(|n| n == want), "/proc missing {want}");
        }
    }

    #[test]
    fn proc_config_reports_loop_device_support_and_guest_isa() {
        use std::io::Read;

        for (arch, expected, excluded) in [
            (
                GuestReportedArch::Aarch64,
                "CONFIG_ARM64=y",
                "CONFIG_X86_64=y",
            ),
            (
                GuestReportedArch::X86_64,
                "CONFIG_X86_64=y",
                "CONFIG_ARM64=y",
            ),
        ] {
            let gz = synthetic_proc_config_gz(arch);
            let mut decoder = flate2::read::GzDecoder::new(&gz[..]);
            let mut config = String::new();
            decoder.read_to_string(&mut config).unwrap();
            assert!(config.contains("CONFIG_BLK_DEV_LOOP=y"));
            assert!(config.contains(expected));
            assert!(!config.contains(excluded));
        }
    }

    #[test]
    fn net_dev_uses_linux_iface_names_not_darwin() {
        let dev = String::from_utf8(synthetic_proc_net_dev(
            &carrick_spec::NetworkNamespaceSpec::default(),
        ))
        .unwrap();
        assert!(dev.contains("lo:"), "dev lists lo");
        // Never leak macOS pseudo-interfaces into the guest.
        for darwin in ["en0", "awdl0", "llw0", "utun", "lo0"] {
            assert!(!dev.contains(darwin), "dev must not leak {darwin}: {dev}");
        }
    }

    /// A context with a small populated address space (heap + mmap) so
    /// status/stat/smaps render realistically.
    fn demo_ctx() -> SyntheticProcContext {
        SyntheticProcContext {
            executable_path: "/bin/demo".to_owned(),
            argv: vec!["/bin/demo".to_owned()],
            environ: vec![b"PATH=/usr/bin".to_vec(), b"HOME=/root".to_vec()],
            open_fds: vec![0, 1, 2],
            auxv: Vec::new(),
            address_space_regions: Some(vec![ProcMapsEntry {
                start: LINUX_HEAP_BASE,
                end: LINUX_HEAP_BASE + 0x10000,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            }]),
            brk_current: LINUX_HEAP_BASE + 0x4000,
            mmap_next: LINUX_MMAP_BASE,
            sig_ignored: 0,
            sig_caught: 0,
            sig_shdpnd: 0,
            ..SyntheticProcContext::default()
        }
    }

    #[test]
    fn cpuinfo_block_matches_guest_arch() {
        // aarch64 guest: ARM block, never the x86 vendor line.
        let arm = String::from_utf8(synthetic_proc_cpuinfo(GuestReportedArch::Aarch64)).unwrap();
        assert!(arm.contains("CPU architecture: 8"), "arm cpuinfo: {arm}");
        assert!(
            !arm.contains("GenuineIntel"),
            "arm cpuinfo leaked x86: {arm}"
        );

        // x86_64 guest: x86 block, never the ARM markers — the bug this closes
        // was an x86_64 guest (uname=x86_64) reading an ARM /proc/cpuinfo.
        let x86 = String::from_utf8(synthetic_proc_cpuinfo(GuestReportedArch::X86_64)).unwrap();
        assert!(x86.contains("GenuineIntel"), "x86 cpuinfo: {x86}");
        assert!(
            x86.contains("flags\t\t:"),
            "x86 cpuinfo missing flags: {x86}"
        );
        assert!(
            x86.contains(" lm "),
            "x86 cpuinfo missing long-mode flag: {x86}"
        );
        assert!(x86.contains(" xsavec"), "x86 cpuinfo lost XSAVEC: {x86}");
        assert!(
            !x86.contains(" xgetbv1") && !x86.contains(" xsaves"),
            "x86 cpuinfo advertised unsupported XGETBV1/XSAVES: {x86}"
        );
        assert!(
            !x86.contains("CPU architecture: 8") && !x86.contains("CPU implementer"),
            "x86 cpuinfo leaked ARM: {x86}"
        );
    }

    #[test]
    fn synthetic_file_cpuinfo_keys_off_context_arch() {
        let mut ctx = demo_ctx();
        ctx.guest_arch = GuestReportedArch::X86_64;
        let out = String::from_utf8(synthetic_file("/proc/cpuinfo", &ctx).unwrap()).unwrap();
        assert!(
            out.contains("GenuineIntel"),
            "ctx-routed x86 cpuinfo: {out}"
        );
    }

    #[test]
    fn stat_btime_is_nonzero_recent() {
        let stat = String::from_utf8(synthetic_proc_stat()).unwrap();
        let btime_line = stat.lines().find(|l| l.starts_with("btime ")).unwrap();
        let btime: u64 = btime_line.trim_start_matches("btime ").parse().unwrap();
        // After ~2020 and before far-future — a real epoch boot time.
        assert!(
            btime > 1_600_000_000,
            "btime should be a recent epoch: {btime}"
        );
    }

    /// A reader that is NOT pid 1 asking for `/proc/1` must be told about
    /// pid 1, not about itself.
    ///
    /// Under HVPatch the whole guest shares one Darwin process whose ns-pid
    /// inside a container is 1, so recognising "self" from the host identity
    /// rewrote EVERY process's `/proc/1/*` to `/proc/self/*`. Live, from a
    /// shell that really was pid 1: `cat /proc/1/stat` printed
    /// `2 (cat) R 1 1 1` — the reader. LTP `getpgid01` compares
    /// `getpgid(1)` (right, from the kernel graph) against `/proc/1/stat`
    /// field 5 (the reader's pgrp).
    #[test]
    fn proc_one_renders_init_not_the_reader() {
        let ctx = SyntheticProcContext {
            identity: Some(SyntheticProcIdentity {
                pid: 2,
                tid: 2,
                ppid: 1,
                pgrp: 1,
                session: 1,
            }),
            processes: Some(vec![
                SyntheticProcProcess {
                    pid: 1,
                    ppid: 0,
                    pgrp: 1,
                    session: 1,
                    state: 'S',
                    tids: vec![1],
                    comm: "sh".to_owned(),
                },
                SyntheticProcProcess {
                    pid: 2,
                    ppid: 1,
                    pgrp: 1,
                    session: 1,
                    state: 'R',
                    tids: vec![2],
                    comm: "cat".to_owned(),
                },
            ]),
            ..demo_ctx()
        };

        let init = String::from_utf8(synthetic_file("/proc/1/stat", &ctx).unwrap()).unwrap();
        assert!(
            init.starts_with("1 (sh) S 0 1 1 "),
            "/proc/1/stat aliased onto the reader instead of rendering pid 1: {init:?}"
        );

        // …while the reader's own `/proc/self` is untouched: the alias is a
        // rewrite of exactly one pid, not a disabled feature.
        let own = String::from_utf8(synthetic_file("/proc/self/stat", &ctx).unwrap()).unwrap();
        assert!(
            own.starts_with("2 ("),
            "the reader's own /proc/self/stat regressed: {own:?}"
        );
        let via_pid = String::from_utf8(synthetic_file("/proc/2/stat", &ctx).unwrap()).unwrap();
        assert_eq!(
            via_pid, own,
            "/proc/<own-pid> must still alias to /proc/self"
        );
    }

    /// A live peer's ppid/pgrp/session/comm come from the kernel graph, never
    /// from Darwin. HVPatch peers are threads of one carrier, so the
    /// host-derived fallback answered with the CARRIER's identity: live,
    /// `cat /proc/2/stat` for a `sleep` peer printed
    /// `2 (cat) S 27206 27207 27207` — a macOS ppid, pgrp and session, plus
    /// the READER's comm.
    #[test]
    fn live_peer_identity_comes_from_the_kernel_graph() {
        let ctx = SyntheticProcContext {
            identity: Some(SyntheticProcIdentity {
                pid: 3,
                tid: 3,
                ppid: 1,
                pgrp: 1,
                session: 1,
            }),
            processes: Some(vec![SyntheticProcProcess {
                pid: 7,
                ppid: 4,
                pgrp: 5,
                session: 6,
                state: 'S',
                tids: vec![7, 8],
                comm: "sleep".to_owned(),
            }]),
            ..demo_ctx()
        };

        let stat = String::from_utf8(synthetic_file("/proc/7/stat", &ctx).unwrap()).unwrap();
        assert!(
            stat.starts_with("7 (sleep) S 4 5 6 "),
            "peer identity was not taken from the kernel graph: {stat:?}"
        );
        // Field 20 is num_threads: the graph's live thread count, not 1.
        assert_eq!(
            stat.split_whitespace().nth(19),
            Some("2"),
            "peer thread count was not taken from the kernel graph: {stat:?}"
        );

        let status = String::from_utf8(synthetic_file("/proc/7/status", &ctx).unwrap()).unwrap();
        assert!(
            status.contains("Name:\tsleep\n") && status.contains("PPid:\t4\n"),
            "peer status was not taken from the kernel graph: {status:?}"
        );

        let comm = synthetic_file("/proc/7/comm", &ctx).unwrap();
        assert_eq!(comm, b"sleep\n");

        // No host identity may reach the guest. The bug this guards put
        // 5-digit macOS pids in stat fields 4-6 and in `status`' PPid.
        let identity_fields: Vec<&str> = stat.split_whitespace().skip(3).take(3).collect();
        assert_eq!(
            identity_fields,
            ["4", "5", "6"],
            "stat ppid/pgrp/session were host values: {stat:?}"
        );
        for line in status.lines() {
            let Some((_, value)) = line.split_once('\t') else {
                continue;
            };
            assert!(
                value.parse::<u32>().ok().is_none_or(|n| n < 1000),
                "a host-scale pid leaked into /proc/7/status: {line:?}"
            );
        }
    }

    /// A pid the kernel graph has never heard of stays ENOENT: the peer arm
    /// answers from a snapshot, so it must not fabricate one.
    #[test]
    fn unknown_peer_pid_is_not_fabricated() {
        let ctx = SyntheticProcContext {
            identity: Some(SyntheticProcIdentity {
                pid: 3,
                tid: 3,
                ppid: 1,
                pgrp: 1,
                session: 1,
            }),
            processes: Some(Vec::new()),
            ..demo_ctx()
        };
        assert!(
            synthetic_file("/proc/999999/stat", &ctx).is_none(),
            "a pid with no kernel-graph record must not render"
        );
    }

    fn peer_dir_ctx() -> SyntheticProcContext {
        SyntheticProcContext {
            identity: Some(SyntheticProcIdentity {
                pid: 3,
                tid: 3,
                ppid: 1,
                pgrp: 1,
                session: 1,
            }),
            processes: Some(vec![SyntheticProcProcess {
                pid: 7,
                ppid: 3,
                pgrp: 1,
                session: 1,
                state: 'S',
                tids: vec![7, 9],
                comm: "sleep".to_owned(),
            }]),
            zombies: Some(vec![SyntheticProcZombie {
                pid: 11,
                ppid: 3,
                pgrp: 1,
                session: 1,
                comm: "gone".to_owned(),
            }]),
            ..demo_ctx()
        }
    }

    fn names(entries: &[DirEnt]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// `/proc/<peer>` must EXIST, not just render its files. The per-pid file
    /// renderers were routed through the kernel graph first, which left
    /// `cat /proc/<peer>/stat` working while `ls -d /proc/<peer>`,
    /// `test -d /proc/<peer>` and `stat /proc/<peer>` all reported ENOENT —
    /// `Vfs::lookup` carries no context and asks Darwin, where every HVPatch
    /// Linux process is a thread of the one carrier.
    #[test]
    fn peer_pid_directory_exists_in_the_kernel_graph() {
        let ctx = peer_dir_ctx();
        let entries = synthetic_dir_entries("/proc/7", &ctx)
            .expect("a live peer's /proc/<pid> directory must exist");
        let names = names(&entries);
        for expected in ["stat", "status", "cmdline", "comm", "oom_score_adj", "task"] {
            assert!(
                names.contains(&expected),
                "/proc/<peer> listing is missing {expected}: {names:?}"
            );
        }
        assert!(
            synthetic_dir_entries("/proc/11", &ctx).is_some(),
            "an unreaped zombie keeps its /proc/<pid> directory until it is reaped"
        );
        assert!(
            synthetic_dir_entries("/proc/999999", &ctx).is_none(),
            "a pid the graph never knew must stay ENOENT"
        );
    }

    /// `/proc/<peer>/task` lists the graph's own per-task thread claims. Asking
    /// Darwin would list every process in the carrier under every pid.
    #[test]
    fn peer_task_directory_lists_graph_tids() {
        let ctx = peer_dir_ctx();
        let entries = synthetic_dir_entries("/proc/7/task", &ctx)
            .expect("a live peer's task directory must exist");
        let mut tids = names(&entries);
        tids.sort_unstable();
        assert_eq!(
            tids,
            [".", "..", "7", "9"],
            "peer tids were not the graph's"
        );
        let zombie = synthetic_dir_entries("/proc/11/task", &ctx)
            .expect("a zombie keeps its leader listed under task/");
        assert!(names(&zombie).contains(&"11"));
    }

    /// `ls /proc` must enumerate peers. The host-pid enumeration reports the
    /// carrier once on HVPatch, so `ls /proc | grep <peer>` found nothing while
    /// `cat /proc/<peer>/stat` worked.
    #[test]
    fn proc_top_level_enumerates_graph_processes() {
        let ctx = peer_dir_ctx();
        let entries = proc_top_level_entries(&ctx);
        let names = names(&entries);
        for expected in ["3", "7", "11", "self", "stat"] {
            assert!(
                names.contains(&expected),
                "/proc listing is missing {expected}: {names:?}"
            );
        }
    }

    #[test]
    fn logical_zombie_is_rendered_without_a_host_process() {
        let pid = 0x7fff_0001;
        let ctx = SyntheticProcContext {
            zombies: Some(vec![SyntheticProcZombie {
                pid,
                ppid: 41,
                pgrp: 40,
                session: 39,
                comm: "logical-child".to_owned(),
            }]),
            ..SyntheticProcContext::default()
        };
        let stat = synthetic_proc_pid_file(pid, "stat", "parent", &ctx)
            .expect("an authoritative logical zombie must have a proc stat");
        let stat = String::from_utf8(stat).unwrap();
        assert!(
            stat.starts_with("2147418113 (logical-child) Z 41 40 39 "),
            "logical zombie identity/state was not preserved: {stat:?}"
        );
    }

    /// Host-observed death must outrank a published run-state: a child that
    /// exited but is not yet reaped reads `Z` in `/proc/<pid>/stat` even while
    /// its (stale, unretractable) `Booting`/`Running` publish still sits in
    /// the shared table. This is the sysvsem `semctl_getpid_child_state`
    /// divergence: without the precedence check, the published `R` masked the
    /// zombie on every no-ns path (native `carrick run`, HVF/native `run-elf`).
    #[cfg(target_os = "macos")]
    #[test]
    fn published_run_state_does_not_mask_an_unreaped_zombie_child() {
        // Real host fork: the child exits immediately; the parent (this test)
        // is the only process allowed to waitid(WNOWAIT) it, matching the
        // /proc reader whose stale-R this guards (the guest parent).
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let child_pid = child as u32;
        // The parent-side fork path publishes Booting for the child before the
        // guest can observe it; mirror that here, then let the child die with
        // the entry still published (nothing retires it until the reap).
        crate::run_state::publish_child_booting(child_pid);

        // Wait until the host reports the exited-unreaped child (bounded).
        let mut zombie_seen = false;
        for _ in 0..200 {
            if host_child_exited_unreaped(ProcHostPid(child_pid)) {
                zombie_seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(zombie_seen, "child never became an unreaped zombie");

        let ctx = SyntheticProcContext::default();
        let stat = synthetic_proc_pid_file(child_pid, "stat", "test", &ctx)
            .expect("stat for an unreaped zombie child must resolve");
        let stat = String::from_utf8(stat).unwrap();
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, tail)| tail.chars().next())
            .expect("stat line has a state field");
        let status = synthetic_proc_pid_file(child_pid, "status", "test", &ctx)
            .expect("status for an unreaped zombie child must resolve");
        let status = String::from_utf8(status).unwrap();

        // Reap + wipe the published entry BEFORE asserting so a failure does
        // not leak a zombie or a stale shared-table slot into sibling tests.
        let mut wait_status = 0;
        unsafe { libc::waitpid(child, &mut wait_status, 0) };
        crate::run_state::wipe_id_for_tests(child_pid);

        assert_eq!(
            state, 'Z',
            "published run-state masked the zombie: {stat:?}"
        );
        assert!(
            status.contains("State:\tZ (zombie)"),
            "status must render the zombie: {status:?}"
        );
    }
}
