//! USDT (DTrace) probe provider — SHARED across the DTrace-capable backends.
//!
//! This module hosts the carrick USDT provider so EVERY backend whose host OS
//! supports `usdt` (macOS, FreeBSD, and Linux) fires REAL probes, while the
//! others (e.g. NetBSD) link a no-op stub with identical signatures. It was
//! formerly private to carrick-vmm-hvf (macOS-only); hoisting it here lets the
//! FreeBSD bhyve build get the genuine provider too, and lets the dispatcher
//! call one `crate::probes::…` surface on all platforms.
//!
//! Linux gets REAL probes via usdt's SystemTap SDT backend (`.note.stapsdt`
//! anchors), read by `bpftrace -l 'usdt:<carrick-bin>:carrick:*'` — e.g.
//! `carrick:futex-route`, `carrick:fork-quiesce`. usdt ≥0.6 emits these on
//! stable Rust (the old `asm` feature is now a no-op); `register_dtrace_probes`
//! (called from carrick-cli `main`) registers them at startup. (An earlier
//! comment gated Linux out as "no-op"; that predated usdt's Linux support.)
//!
//! Layout:
//!   * `real` — the genuine `#[usdt::provider]` plus its safe wrappers, compiled
//!     where usdt can emit probe anchors: `macos` (both arches — the HVF aarch64
//!     path) and `x86_64` `linux`/`freebsd`. usdt 0.6's SDT backend emits x86
//!     asm and keys the decision off the BUILD HOST, so an `aarch64`
//!     `linux`/`freebsd` target cross-built from an x86_64 host would otherwise
//!     emit `rdi`/`rsi`/… and fail with "invalid register" — those targets take
//!     the stub instead.
//!   * `stub` — a byte-for-byte signature mirror with empty bodies, compiled on
//!     every OTHER target (NetBSD, and aarch64 linux/freebsd), which is also
//!     exactly the set that links NO `usdt` at all. The non-probe
//!     helpers (`guest_mem_probe_points`,
//!     `guest_mem_copy`, `guest_mem_point`) carry their REAL bodies in BOTH arms
//!     so behaviour is identical regardless of platform.
//!
//! `usdt` is a TARGET-SCOPED dependency of this crate, gated to exactly the set
//! above (see the crate manifest). Nothing outside the `real` module names a
//! `usdt` type: [`register_dtrace_probes`] returns the crate-local
//! [`ProbeRegistrationError`], so the `stub` arm needs no `usdt` at all.

use std::num::NonZeroU64;
use std::ops::Range;

use carrick_guest_mem::HostVa;

/// Failure returned by `register_dtrace_probes`.
///
/// Deliberately a crate-local type rather than `usdt::Error`. `usdt` is
/// target-scoped to the `real` arm's target set, so its error type does not
/// exist on `stub` targets, and the dispatcher calls `register_dtrace_probes` on
/// EVERY platform. The `real` arm forwards `usdt::Error`'s own `Display` text
/// verbatim, so what a user sees is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeRegistrationError(String);

impl ProbeRegistrationError {
    /// Build a registration failure from an already-rendered message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The failure text, as the underlying provider rendered it.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProbeRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeRegistrationError {}

/// Stable Darwin process incarnation used by birth-keyed trace records.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HostProcessBirth {
    pid: u32,
    start_sec: i64,
    start_usec: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostProcessBirthError {
    #[error("host process birth PID must be nonzero")]
    ZeroPid,
    #[error("host process start seconds must be positive, got {0}")]
    InvalidStartSeconds(i64),
    #[error("host process start microseconds are outside timeval range: {0}")]
    InvalidMicroseconds(i32),
    #[error("host process birth value does not fit the signed wire domain")]
    WireDomainOverflow,
    #[error("proc_pidinfo({pid}) returned {result}, expected {expected}, errno={errno}")]
    Query {
        pid: u32,
        result: i32,
        expected: i32,
        errno: i32,
    },
    #[error("proc_pidinfo({requested}) described pid {observed}")]
    PidMismatch { requested: u32, observed: u32 },
}

impl HostProcessBirth {
    pub fn new(pid: u32, start_sec: i64, start_usec: i32) -> Result<Self, HostProcessBirthError> {
        if pid == 0 {
            return Err(HostProcessBirthError::ZeroPid);
        }
        if start_sec <= 0 {
            return Err(HostProcessBirthError::InvalidStartSeconds(start_sec));
        }
        if !(0..1_000_000).contains(&start_usec) {
            return Err(HostProcessBirthError::InvalidMicroseconds(start_usec));
        }
        Ok(Self {
            pid,
            start_sec,
            start_usec,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn query(pid: u32) -> Result<Self, HostProcessBirthError> {
        let pid_arg = i32::try_from(pid).map_err(|_| HostProcessBirthError::WireDomainOverflow)?;
        let expected = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(|_| HostProcessBirthError::WireDomainOverflow)?;
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let result = unsafe {
            libc::proc_pidinfo(
                pid_arg,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                expected,
            )
        };
        if result != expected {
            return Err(HostProcessBirthError::Query {
                pid,
                result,
                expected,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        let info = unsafe { info.assume_init() };
        if info.pbi_pid != pid {
            return Err(HostProcessBirthError::PidMismatch {
                requested: pid,
                observed: info.pbi_pid,
            });
        }
        let start_sec = i64::try_from(info.pbi_start_tvsec)
            .map_err(|_| HostProcessBirthError::WireDomainOverflow)?;
        let start_usec = i32::try_from(info.pbi_start_tvusec)
            .map_err(|_| HostProcessBirthError::WireDomainOverflow)?;
        Self::new(pid, start_sec, start_usec)
    }

    pub const fn pid(self) -> u32 {
        self.pid
    }

    pub const fn start_sec(self) -> i64 {
        self.start_sec
    }

    pub const fn start_usec(self) -> i32 {
        self.start_usec
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
))]
pub use real::*;
#[cfg(not(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
)))]
pub use stub::*;

#[derive(Clone, Copy, Debug)]
pub struct EpollMaskedProbe {
    pub origin: i32,
    pub fd: i32,
    pub host_fd: i32,
    pub requested: u32,
    pub raw_ready: u32,
    pub last_ready: u32,
    pub read_avail: u64,
    pub last_read_avail: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UlockRequeueProbe {
    pub phase: u32,
    pub from_key: u64,
    pub to_key: u64,
    pub wake_req: u32,
    pub requeue_req: u32,
    pub wake_ret: u32,
    pub requeue_ret: u32,
    pub from_count: u32,
    pub from_requeue_wake: u32,
    pub from_requeue_count: u32,
    pub from_logical_requeued: u32,
    pub from_logical_wake: u32,
    pub to_count: u32,
    pub to_requeue_wake: u32,
    pub to_requeue_count: u32,
    pub to_logical_requeued: u32,
    pub to_logical_wake: u32,
}

/// Stable lifecycle phases for Linux processes multiplexed inside one hvpatch VM.
/// These ordinals are part of the DTrace provider ABI; append, never renumber.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchGuestLifecyclePhase {
    Root = 0,
    Fork = 1,
    Exec = 2,
    ThreadStart = 3,
    ThreadExit = 4,
    ProcessExit = 5,
    /// Entered `handle_execve`, before ELF loading, patching, address-space
    /// replacement, or publication. The existing `Exec` phase is its success
    /// boundary and therefore closes a complete in-process exec latency window.
    ExecBegin = 6,
}

impl HvpatchGuestLifecyclePhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source event for the scalar `hvpatch-guest-lifecycle` USDT ABI.
///
/// `detail` is phase-specific: it is the Linux wait exit code for
/// `ProcessExit` and zero for the currently published Root/Fork/Exec events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchGuestLifecycle {
    phase: HvpatchGuestLifecyclePhase,
    pid: i32,
    ppid: i32,
    tid: i32,
    asid: u32,
    /// `TaskSerial` of this exact task generation. Never reused by one Kernel.
    ///
    /// `pid` and `asid` are both recycled within a run, so the pair cannot
    /// distinguish two generations that share a number. K1's observability
    /// contract requires unambiguous identity, so every lifecycle record
    /// carries the serial that disambiguates it.
    task_serial: u64,
    /// `TaskSerial` of the parent generation, or zero for a root with no
    /// parent. Zero is unambiguous: serials start at one.
    parent_serial: u64,
    /// `MmId` of the address space this task was using at the event.
    mm: u64,
    detail: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HvpatchGuestLifecycleError {
    #[error("hvpatch guest pid and tid must be positive")]
    InvalidTaskIdentity,
    #[error("hvpatch guest ppid must be nonnegative")]
    InvalidParentIdentity,
    #[error("hvpatch guest ASID must be nonzero")]
    InvalidAsid,
    #[error(
        "hvpatch guest lifecycle identity is ambiguous: task serial, mm, and parent presence must all be exact"
    )]
    AmbiguousIdentity,
    #[error("hvpatch guest process bank must be nonempty")]
    InvalidBank,
    #[error("hvpatch TTBR0 does not encode the event ASID and bank root")]
    InvalidTtbr0,
}

impl HvpatchGuestLifecycle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        phase: HvpatchGuestLifecyclePhase,
        pid: i32,
        ppid: i32,
        tid: i32,
        asid: u32,
        task_serial: u64,
        parent_serial: u64,
        mm: u64,
        detail: i64,
    ) -> Result<Self, HvpatchGuestLifecycleError> {
        if pid <= 0 || tid <= 0 {
            return Err(HvpatchGuestLifecycleError::InvalidTaskIdentity);
        }
        if ppid < 0 {
            return Err(HvpatchGuestLifecycleError::InvalidParentIdentity);
        }
        if asid == 0 {
            return Err(HvpatchGuestLifecycleError::InvalidAsid);
        }
        // An identity-bearing record with no serial is worse than no record:
        // a consumer would silently join two generations that share a pid.
        if task_serial == 0 || mm == 0 {
            return Err(HvpatchGuestLifecycleError::AmbiguousIdentity);
        }
        // A parent pid and a parent serial must agree about existing.
        if (ppid == 0) != (parent_serial == 0) {
            return Err(HvpatchGuestLifecycleError::AmbiguousIdentity);
        }
        Ok(Self {
            phase,
            pid,
            ppid,
            tid,
            asid,
            task_serial,
            parent_serial,
            mm,
            detail,
        })
    }

    pub const fn phase(self) -> HvpatchGuestLifecyclePhase {
        self.phase
    }

    pub const fn pid(self) -> i32 {
        self.pid
    }

    pub const fn ppid(self) -> i32 {
        self.ppid
    }

    pub const fn tid(self) -> i32 {
        self.tid
    }

    pub const fn asid(self) -> u32 {
        self.asid
    }

    pub const fn task_serial(self) -> u64 {
        self.task_serial
    }

    pub const fn parent_serial(self) -> u64 {
        self.parent_serial
    }

    pub const fn mm(self) -> u64 {
        self.mm
    }

    pub const fn detail(self) -> i64 {
        self.detail
    }
}

/// Completed Linux syscall service with one-VM task/address-space identity and
/// monotonic wall duration. Publishing the duration in the event keeps DTrace
/// consumers stateless under hot all-syscall workloads, where dynamic-variable
/// drops can otherwise make paired boundary captures look complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchSyscallService {
    pid: i32,
    tid: i32,
    asid: u32,
    number: u64,
    duration_ns: u64,
}

impl HvpatchSyscallService {
    pub fn new(
        pid: i32,
        tid: i32,
        asid: u32,
        number: u64,
        duration_ns: u64,
    ) -> Result<Self, HvpatchGuestLifecycleError> {
        if pid <= 0 || tid <= 0 {
            return Err(HvpatchGuestLifecycleError::InvalidTaskIdentity);
        }
        if asid == 0 {
            return Err(HvpatchGuestLifecycleError::InvalidAsid);
        }
        Ok(Self {
            pid,
            tid,
            asid,
            number,
            duration_ns,
        })
    }

    pub const fn pid(self) -> i32 {
        self.pid
    }

    pub const fn tid(self) -> i32 {
        self.tid
    }

    pub const fn asid(self) -> u32 {
        self.asid
    }

    pub const fn number(self) -> u64 {
        self.number
    }

    pub const fn duration_ns(self) -> u64 {
        self.duration_ns
    }
}

/// Fatal or signal-lowered AArch64 fault with its Linux guest identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchGuestFault {
    syndrome: u64,
    elr: u64,
    far: u64,
    pid: i32,
    tid: i32,
    asid: u32,
}

impl HvpatchGuestFault {
    pub fn new(
        syndrome: u64,
        elr: u64,
        far: u64,
        pid: i32,
        tid: i32,
        asid: u32,
    ) -> Result<Self, HvpatchGuestLifecycleError> {
        if pid <= 0 || tid <= 0 {
            return Err(HvpatchGuestLifecycleError::InvalidTaskIdentity);
        }
        if asid == 0 {
            return Err(HvpatchGuestLifecycleError::InvalidAsid);
        }
        Ok(Self {
            syndrome,
            elr,
            far,
            pid,
            tid,
            asid,
        })
    }

    pub const fn syndrome(self) -> u64 {
        self.syndrome
    }

    pub const fn elr(self) -> u64 {
        self.elr
    }

    pub const fn far(self) -> u64 {
        self.far
    }

    pub const fn pid(self) -> i32 {
        self.pid
    }

    pub const fn tid(self) -> i32 {
        self.tid
    }

    pub const fn asid(self) -> u32 {
        self.asid
    }
}

/// Process-bank provenance for one Linux guest address space in the shared VM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchGuestAddressSpace {
    pid: i32,
    asid: u32,
    bank_base: u64,
    bank_size: u64,
    ttbr0: u64,
}

/// Result of preparing the stage-1 page-table layout for one hvpatch process
/// bank. These ordinals are part of the DTrace provider ABI; append only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchExecBankLayoutPhase {
    CacheMiss = 0,
    CacheHit = 1,
}

impl HvpatchExecBankLayoutPhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-exec-bank-layout`.
///
/// `bank_base` joins this low-level engine event to
/// `hvpatch-guest-address-space`, which supplies the Linux PID and ASID without
/// relying on Darwin's host process namespace. `elapsed_ns` covers lookup plus
/// a cache miss's complete page-table rebase/remap construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchExecBankLayout {
    phase: HvpatchExecBankLayoutPhase,
    bank_base: u64,
    mapping_count: u64,
    cache_entries: u64,
    elapsed_ns: u64,
}

impl HvpatchExecBankLayout {
    pub const fn new(
        phase: HvpatchExecBankLayoutPhase,
        bank_base: u64,
        mapping_count: u64,
        cache_entries: u64,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            phase,
            bank_base,
            mapping_count,
            cache_entries,
            elapsed_ns,
        }
    }

    pub const fn phase(self) -> HvpatchExecBankLayoutPhase {
        self.phase
    }

    pub const fn bank_base(self) -> u64 {
        self.bank_base
    }

    pub const fn mapping_count(self) -> u64 {
        self.mapping_count
    }

    pub const fn cache_entries(self) -> u64 {
        self.cache_entries
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

/// Result of materializing one exec-image host backing. Append-only DTrace ABI
/// ordinals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchExecBackingPhase {
    Materialized = 0,
    Reused = 1,
    /// Fresh MAP_PRIVATE view of an immutable, fully-patched file artifact.
    PrivateFileMapped = 2,
}

impl HvpatchExecBackingPhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-exec-backing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchExecBacking {
    phase: HvpatchExecBackingPhase,
    guest_start: u64,
    ipa_start: u64,
    mapped_size: u64,
    elapsed_ns: u64,
}

impl HvpatchExecBacking {
    pub const fn new(
        phase: HvpatchExecBackingPhase,
        guest_start: u64,
        ipa_start: u64,
        mapped_size: u64,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            phase,
            guest_start,
            ipa_start,
            mapped_size,
            elapsed_ns,
        }
    }

    pub const fn phase(self) -> HvpatchExecBackingPhase {
        self.phase
    }

    pub const fn guest_start(self) -> u64 {
        self.guest_start
    }

    pub const fn ipa_start(self) -> u64 {
        self.ipa_start
    }

    pub const fn mapped_size(self) -> u64 {
        self.mapped_size
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

/// Raw Hypervisor.framework stage-2 transition boundaries during one-VM exec.
/// Append-only DTrace ABI ordinals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchExecStage2Phase {
    UnmapBegin = 0,
    UnmapEnd = 1,
    MapBegin = 2,
    MapEnd = 3,
}

impl HvpatchExecStage2Phase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-exec-stage2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchExecStage2 {
    phase: HvpatchExecStage2Phase,
    ipa: u64,
    size: u64,
    guest_start: u64,
    rc: i32,
}

/// Coarse, mutually exclusive host stages inside one persistent-VM exec image
/// replacement. These append-only ordinals are a stable DTrace ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchExecReplaceStagePhase {
    AliasCleanup = 0,
    DropBackings = 1,
    PageTables = 2,
    MapBackings = 3,
    Registers = 4,
    Mailbox = 5,
    PrivateFileArtifacts = 6,
    /// Rebase or retrieve the complete stage-1 mapping plan for this process
    /// bank. This happens before every other replacement stage.
    BankPlan = 7,
    /// Remove the predecessor image's stage-2 address space (or rebuild the VM
    /// on the mature non-persistent path).
    AddressSpaceTeardown = 8,
}

impl HvpatchExecReplaceStagePhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-exec-replace-stage`.
///
/// `mapping_count` and `mapped_bytes` describe the replacement image for
/// every phase so a consumer can compare like-shaped execs without relying on
/// process-local pointers or private Rust layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchExecReplaceStage {
    phase: HvpatchExecReplaceStagePhase,
    elapsed_ns: u64,
    mapping_count: u64,
    mapped_bytes: u64,
}

impl HvpatchExecReplaceStage {
    pub const fn new(
        phase: HvpatchExecReplaceStagePhase,
        elapsed_ns: u64,
        mapping_count: u64,
        mapped_bytes: u64,
    ) -> Self {
        Self {
            phase,
            elapsed_ns,
            mapping_count,
            mapped_bytes,
        }
    }

    pub const fn phase(self) -> HvpatchExecReplaceStagePhase {
        self.phase
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }

    pub const fn mapping_count(self) -> u64 {
        self.mapping_count
    }

    pub const fn mapped_bytes(self) -> u64 {
        self.mapped_bytes
    }
}

/// Outer runtime stages between a loaded replacement image and publication to
/// the Linux guest. This is deliberately separate from
/// [`HvpatchExecReplaceStagePhase`]: `EngineReplace` encloses that engine's
/// non-overlapping inner ledger. Ordinals are append-only DTrace ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchExecRuntimeStagePhase {
    ProcState = 0,
    CloseCloexec = 1,
    SiblingDrain = 2,
    TopologyLock = 3,
    EngineReplace = 4,
    Publication = 5,
}

impl HvpatchExecRuntimeStagePhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-exec-runtime-stage`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchExecRuntimeStage {
    phase: HvpatchExecRuntimeStagePhase,
    elapsed_ns: u64,
    region_count: u64,
    mapped_bytes: u64,
}

impl HvpatchExecRuntimeStage {
    pub const fn new(
        phase: HvpatchExecRuntimeStagePhase,
        elapsed_ns: u64,
        region_count: u64,
        mapped_bytes: u64,
    ) -> Self {
        Self {
            phase,
            elapsed_ns,
            region_count,
            mapped_bytes,
        }
    }

    pub const fn phase(self) -> HvpatchExecRuntimeStagePhase {
        self.phase
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }

    pub const fn region_count(self) -> u64 {
        self.region_count
    }

    pub const fn mapped_bytes(self) -> u64 {
        self.mapped_bytes
    }
}

/// Shared-HVF topology-lock operation classes. Ordinals are an append-only
/// DTrace ABI so offline consumers can retain stable names across releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchTopologyOperation {
    InProcessFork = 0,
    ExecReplace = 1,
    ExecSiblingGate = 2,
    SiblingMaterialize = 3,
    VcpuRebind = 4,
    VmRelease = 5,
    LegacyFork = 6,
    ProcessRetire = 7,
    AliasMap = 8,
}

impl HvpatchTopologyOperation {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Lifecycle of one topology-lock acquisition attempt. `Requested` precedes a
/// blocking lock call, `Acquired` carries its wait time, and `Released` carries
/// the hold time. `TryMiss` closes a nonblocking attempt that found contention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchTopologyPhase {
    Requested = 0,
    Acquired = 1,
    Released = 2,
    TryMiss = 3,
}

impl HvpatchTopologyPhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-topology-lock`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchTopologyLock {
    operation: HvpatchTopologyOperation,
    phase: HvpatchTopologyPhase,
    guest_pid: i32,
    guest_tid: i32,
    elapsed_ns: u64,
}

impl HvpatchTopologyLock {
    pub const fn new(
        operation: HvpatchTopologyOperation,
        phase: HvpatchTopologyPhase,
        guest_pid: i32,
        guest_tid: i32,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            operation,
            phase,
            guest_pid,
            guest_tid,
            elapsed_ns,
        }
    }

    pub const fn operation(self) -> HvpatchTopologyOperation {
        self.operation
    }

    pub const fn phase(self) -> HvpatchTopologyPhase {
        self.phase
    }

    pub const fn guest_pid(self) -> i32 {
        self.guest_pid
    }

    pub const fn guest_tid(self) -> i32 {
        self.guest_tid
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

/// Mutually exclusive parent-thread stages inside the in-process-fork
/// topology-lock hold. Ordinals are append-only DTrace ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchForkRuntimeStagePhase {
    Quiesce = 0,
    ProcessAllocate = 1,
    PidfdParent = 2,
    ProcessSpec = 3,
    DispatcherClone = 4,
    RuntimeState = 5,
    ThreadSpawn = 6,
    ChildReady = 7,
    Publication = 8,
    /// Cumulative parent-thread critical-section time. This encloses phases
    /// 0..=8 and must not be summed with them as a peer stage.
    Total = 9,
}

impl HvpatchForkRuntimeStagePhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-fork-runtime-stage`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchForkRuntimeStage {
    phase: HvpatchForkRuntimeStagePhase,
    parent_pid: i32,
    child_pid: i32,
    forking_tid: i32,
    elapsed_ns: u64,
}

impl HvpatchForkRuntimeStage {
    pub const fn new(
        phase: HvpatchForkRuntimeStagePhase,
        parent_pid: i32,
        child_pid: i32,
        forking_tid: i32,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            phase,
            parent_pid,
            child_pid,
            forking_tid,
            elapsed_ns,
        }
    }

    pub const fn phase(self) -> HvpatchForkRuntimeStagePhase {
        self.phase
    }

    pub const fn parent_pid(self) -> i32 {
        self.parent_pid
    }

    pub const fn child_pid(self) -> i32 {
        self.child_pid
    }

    pub const fn forking_tid(self) -> i32 {
        self.forking_tid
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

/// Mutually exclusive construction stages inside an hvpatch in-process fork's
/// process-spec build. Ordinals are append-only DTrace ABI. `Total` encloses
/// every peer stage and therefore must not be summed with them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchForkProcessSpecStagePhase {
    ParentPageTablesLoad = 0,
    VcpuSnapshot = 1,
    ParentPageTablesClone = 2,
    PageTablesRebase = 3,
    AliasUnion = 4,
    PrivateSnapshot = 5,
    Validation = 6,
    TablePublish = 7,
    BackendProtections = 8,
    BackendSpecFinalize = 9,
    WrapperProtections = 10,
    Total = 11,
}

impl HvpatchForkProcessSpecStagePhase {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Typed source record for `hvpatch-fork-process-spec-stage`.
///
/// `units` is stage-specific supporting shape: a boolean load flag for parent
/// table load; bytes for page-table clone, rebase, publication, and backend
/// finalization; packed bank span for private snapshot; mapping count for alias
/// union and validation; zero where no useful cardinality exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchForkProcessSpecStage {
    phase: HvpatchForkProcessSpecStagePhase,
    child_pid: i32,
    forking_tid: i32,
    elapsed_ns: u64,
    units: u64,
}

impl HvpatchForkProcessSpecStage {
    pub const fn new(
        phase: HvpatchForkProcessSpecStagePhase,
        child_pid: i32,
        forking_tid: i32,
        elapsed_ns: u64,
        units: u64,
    ) -> Self {
        Self {
            phase,
            child_pid,
            forking_tid,
            elapsed_ns,
            units,
        }
    }

    pub const fn phase(self) -> HvpatchForkProcessSpecStagePhase {
        self.phase
    }

    pub const fn child_pid(self) -> i32 {
        self.child_pid
    }

    pub const fn forking_tid(self) -> i32 {
        self.forking_tid
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }

    pub const fn units(self) -> u64 {
        self.units
    }
}

/// Stable private-mapping roles reported by
/// `hvpatch-fork-private-snapshot-outcome`.
///
/// The ordinals intentionally match the append-only fork-footprint taxonomy
/// used by the existing Phase-4 census, so consumers can join the two ledgers
/// without translating an investigation-local enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchForkPrivateSnapshotRole {
    PrivateMmapArena = 1,
    PrivateHeap = 2,
    PrivateOverlay = 3,
    PrivateHighAlias = 4,
    PrivateWritableOther = 5,
    PrivateReadOnlyOrInternal = 6,
    SharedAperture = 7,
    SharedOther = 8,
    PrivatePageTables = 9,
}

impl HvpatchForkPrivateSnapshotRole {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn from_footprint_class(raw: i32) -> Option<Self> {
        match raw {
            1 => Some(Self::PrivateMmapArena),
            2 => Some(Self::PrivateHeap),
            3 => Some(Self::PrivateOverlay),
            4 => Some(Self::PrivateHighAlias),
            5 => Some(Self::PrivateWritableOther),
            6 => Some(Self::PrivateReadOnlyOrInternal),
            7 => Some(Self::SharedAperture),
            8 => Some(Self::SharedOther),
            9 => Some(Self::PrivatePageTables),
            _ => None,
        }
    }
}

/// Host mechanism that produced one child's private mapping snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HvpatchForkPrivateSnapshotMethod {
    MachCowRemap = 0,
    SparseCopyFallback = 1,
}

impl HvpatchForkPrivateSnapshotMethod {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Timing half of the per-mapping private-snapshot DTrace record.
///
/// Keeping timing and outcome in separate five-scalar probes avoids macOS's
/// qualified sixth-USDT-argument corruption while retaining guest identity,
/// mapping address/size, duration, role, and mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchForkPrivateSnapshot {
    child_pid: i32,
    forking_tid: i32,
    guest_start: u64,
    mapped_size: u64,
    elapsed_ns: u64,
}

impl HvpatchForkPrivateSnapshot {
    pub const fn new(
        child_pid: i32,
        forking_tid: i32,
        guest_start: u64,
        mapped_size: u64,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            child_pid,
            forking_tid,
            guest_start,
            mapped_size,
            elapsed_ns,
        }
    }

    pub const fn child_pid(self) -> i32 {
        self.child_pid
    }

    pub const fn forking_tid(self) -> i32 {
        self.forking_tid
    }

    pub const fn guest_start(self) -> u64 {
        self.guest_start
    }

    pub const fn mapped_size(self) -> u64 {
        self.mapped_size
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

/// Classification half of the per-mapping private-snapshot DTrace record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchForkPrivateSnapshotOutcome {
    child_pid: i32,
    forking_tid: i32,
    guest_start: u64,
    role: HvpatchForkPrivateSnapshotRole,
    method: HvpatchForkPrivateSnapshotMethod,
}

impl HvpatchForkPrivateSnapshotOutcome {
    pub const fn new(
        child_pid: i32,
        forking_tid: i32,
        guest_start: u64,
        role: HvpatchForkPrivateSnapshotRole,
        method: HvpatchForkPrivateSnapshotMethod,
    ) -> Self {
        Self {
            child_pid,
            forking_tid,
            guest_start,
            role,
            method,
        }
    }

    pub const fn child_pid(self) -> i32 {
        self.child_pid
    }

    pub const fn forking_tid(self) -> i32 {
        self.forking_tid
    }

    pub const fn guest_start(self) -> u64 {
        self.guest_start
    }

    pub const fn role(self) -> HvpatchForkPrivateSnapshotRole {
        self.role
    }

    pub const fn method(self) -> HvpatchForkPrivateSnapshotMethod {
        self.method
    }
}

/// Typed source record for `hvpatch-fork-quiesce`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvpatchForkQuiesce {
    parent_pid: i32,
    forking_tid: i32,
    initial_siblings: u32,
    poll_iterations: u64,
    elapsed_ns: u64,
}

impl HvpatchForkQuiesce {
    pub const fn new(
        parent_pid: i32,
        forking_tid: i32,
        initial_siblings: u32,
        poll_iterations: u64,
        elapsed_ns: u64,
    ) -> Self {
        Self {
            parent_pid,
            forking_tid,
            initial_siblings,
            poll_iterations,
            elapsed_ns,
        }
    }

    pub const fn parent_pid(self) -> i32 {
        self.parent_pid
    }

    pub const fn forking_tid(self) -> i32 {
        self.forking_tid
    }

    pub const fn initial_siblings(self) -> u32 {
        self.initial_siblings
    }

    pub const fn poll_iterations(self) -> u64 {
        self.poll_iterations
    }

    pub const fn elapsed_ns(self) -> u64 {
        self.elapsed_ns
    }
}

impl HvpatchExecStage2 {
    pub const fn new(
        phase: HvpatchExecStage2Phase,
        ipa: u64,
        size: u64,
        guest_start: u64,
        rc: i32,
    ) -> Self {
        Self {
            phase,
            ipa,
            size,
            guest_start,
            rc,
        }
    }

    pub const fn phase(self) -> HvpatchExecStage2Phase {
        self.phase
    }

    pub const fn ipa(self) -> u64 {
        self.ipa
    }

    pub const fn size(self) -> u64 {
        self.size
    }

    pub const fn guest_start(self) -> u64 {
        self.guest_start
    }

    pub const fn rc(self) -> i32 {
        self.rc
    }
}

impl HvpatchGuestAddressSpace {
    pub fn new(
        pid: i32,
        asid: u32,
        bank_base: u64,
        bank_size: u64,
        ttbr0: u64,
    ) -> Result<Self, HvpatchGuestLifecycleError> {
        if pid <= 0 {
            return Err(HvpatchGuestLifecycleError::InvalidTaskIdentity);
        }
        if asid == 0 || asid > u32::from(u16::MAX) {
            return Err(HvpatchGuestLifecycleError::InvalidAsid);
        }
        if bank_size == 0 {
            return Err(HvpatchGuestLifecycleError::InvalidBank);
        }
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        if (ttbr0 >> 48) != u64::from(asid) || (ttbr0 & TTBR_ROOT_MASK) != bank_base {
            return Err(HvpatchGuestLifecycleError::InvalidTtbr0);
        }
        Ok(Self {
            pid,
            asid,
            bank_base,
            bank_size,
            ttbr0,
        })
    }

    pub const fn pid(self) -> i32 {
        self.pid
    }

    pub const fn asid(self) -> u32 {
        self.asid
    }

    pub const fn bank_base(self) -> u64 {
        self.bank_base
    }

    pub const fn bank_size(self) -> u64 {
        self.bank_size
    }

    pub const fn ttbr0(self) -> u64 {
        self.ttbr0
    }
}

#[cfg(test)]
mod hvpatch_guest_probe_abi {
    use super::*;

    #[test]
    fn lifecycle_event_keeps_guest_identity_and_phase_typed() {
        let event = HvpatchGuestLifecycle::new(
            HvpatchGuestLifecyclePhase::Fork,
            123,
            100,
            123,
            7,
            42,
            41,
            9,
            0,
        )
        .expect("valid guest lifecycle event");
        assert_eq!(event.phase(), HvpatchGuestLifecyclePhase::Fork);
        assert_eq!(event.pid(), 123);
        assert_eq!(event.ppid(), 100);
        assert_eq!(event.tid(), 123);
        assert_eq!(event.asid(), 7);
        assert_eq!(event.task_serial(), 42);
        assert_eq!(event.parent_serial(), 41);
        assert_eq!(event.mm(), 9);
        assert_eq!(event.detail(), 0);
    }

    /// A lifecycle record without a serial or an mm would let a consumer join
    /// two generations that share a recycled pid. Refuse it at construction.
    #[test]
    fn lifecycle_event_rejects_ambiguous_identity() {
        // No task serial.
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::Fork,
                123,
                100,
                123,
                7,
                0,
                41,
                9,
                0,
            )
            .is_err()
        );
        // No mm.
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::Fork,
                123,
                100,
                123,
                7,
                42,
                41,
                0,
                0,
            )
            .is_err()
        );
        // A parent pid with no parent serial, and the reverse: the two must
        // agree about whether a parent exists.
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::Fork,
                123,
                100,
                123,
                7,
                42,
                0,
                9,
                0,
            )
            .is_err()
        );
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::Root,
                123,
                0,
                123,
                7,
                42,
                41,
                9,
                0,
            )
            .is_err()
        );
        // A root with neither is exact.
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::Root,
                123,
                0,
                123,
                7,
                42,
                0,
                9,
                0,
            )
            .is_ok()
        );
    }

    #[test]
    fn lifecycle_phase_ordinals_are_append_only() {
        assert_eq!(HvpatchGuestLifecyclePhase::Root.raw(), 0);
        assert_eq!(HvpatchGuestLifecyclePhase::Fork.raw(), 1);
        assert_eq!(HvpatchGuestLifecyclePhase::Exec.raw(), 2);
        assert_eq!(HvpatchGuestLifecyclePhase::ThreadStart.raw(), 3);
        assert_eq!(HvpatchGuestLifecyclePhase::ThreadExit.raw(), 4);
        assert_eq!(HvpatchGuestLifecyclePhase::ProcessExit.raw(), 5);
        assert_eq!(HvpatchGuestLifecyclePhase::ExecBegin.raw(), 6);
    }

    #[test]
    fn lifecycle_event_rejects_non_linux_identity_values() {
        assert!(
            HvpatchGuestLifecycle::new(HvpatchGuestLifecyclePhase::Root, 0, 0, 1, 1, 1, 0, 1, 0,)
                .is_err()
        );
        assert!(
            HvpatchGuestLifecycle::new(
                HvpatchGuestLifecyclePhase::ThreadStart,
                1,
                0,
                0,
                1,
                1,
                0,
                1,
                0,
            )
            .is_err()
        );
        assert!(
            HvpatchGuestLifecycle::new(HvpatchGuestLifecyclePhase::Exec, 1, 0, 1, 0, 1, 0, 1, 0,)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_provider_and_stub_keep_the_same_typed_shape() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__guest__lifecycle(_: u32, _: i32, _: i32, _: i32, _: u32) {}",
            "fn hvpatch__guest__lifecycle__identity(_: i32, _: u64, _: u64, _: u64) {}",
            "fn hvpatch__guest__exit(_: i32, _: i32, _: u32, _: i64) {}",
            "stub!(hvpatch_guest_lifecycle(event: super::HvpatchGuestLifecycle));",
            "fn hvpatch__guest__fault(_: u64, _: u64, _: u64, _: i32, _: i32) {}",
            "fn hvpatch__guest__fault__asid(_: i32, _: i32, _: u32) {}",
            "stub!(hvpatch_guest_fault(event: super::HvpatchGuestFault));",
            "fn hvpatch__guest__address__space(_: i32, _: u32, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_guest_address_space(event: super::HvpatchGuestAddressSpace));",
        ] {
            assert!(
                source.contains(declaration),
                "missing lifecycle ABI {declaration}"
            );
        }
    }

    #[test]
    fn fork_snapshot_provider_and_stub_are_declared_outside_the_abi_test() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__fork__snapshot__begin(_: i32, _: i32) {}",
            "fn hvpatch__fork__snapshot__end(_: i32, _: u64, _: u64, _: u64, _: u64) {}",
            "fn hvpatch__fork__snapshot__shape(_: i32, _: u64, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_fork_snapshot_begin(child_pid: i32, forking_tid: i32));",
            "stub!(hvpatch_fork_snapshot_end(child_pid: i32, local_regions: u64, candidate_regions: u64, added_regions: u64, added_bytes: u64));",
            "stub!(hvpatch_fork_snapshot_shape(child_pid: i32, private_added_regions: u64, shared_added_regions: u64, largest_added_bytes: u64, bank_used_bytes: u64));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing real fork snapshot ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn exec_bank_layout_provider_and_stub_keep_the_same_typed_shape() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__exec__bank__layout(_: u32, _: u64, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_exec_bank_layout(event: super::HvpatchExecBankLayout));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing exec bank layout ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn exec_backing_provider_and_stub_keep_the_same_typed_shape() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__exec__backing(_: u32, _: u64, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_exec_backing(event: super::HvpatchExecBacking));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing exec backing ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn exec_stage2_provider_and_stub_keep_the_same_typed_shape() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__exec__stage2(_: u32, _: u64, _: u64, _: u64, _: i32) {}",
            "stub!(hvpatch_exec_stage2(event: super::HvpatchExecStage2));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing exec stage-2 ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn exec_replace_stage_provider_and_stub_keep_the_same_typed_shape() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__exec__replace__stage(_: u32, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_exec_replace_stage(event: super::HvpatchExecReplaceStage));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing exec replacement-stage ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn fault_event_keeps_guest_process_thread_and_asid_together() {
        let event = HvpatchGuestFault::new(0x9600_0004, 0x85540, 0x80, 123, 456, 7)
            .expect("valid guest fault event");
        assert_eq!(event.syndrome(), 0x9600_0004);
        assert_eq!(event.elr(), 0x85540);
        assert_eq!(event.far(), 0x80);
        assert_eq!(event.pid(), 123);
        assert_eq!(event.tid(), 456);
        assert_eq!(event.asid(), 7);
    }

    #[test]
    fn address_space_event_keeps_bank_and_ttbr_provenance_together() {
        let event = HvpatchGuestAddressSpace::new(
            123,
            7,
            0x9a_0000_0000,
            40 * 1024 * 1024 * 1024,
            0x0007_009a_0000_0000,
        )
        .expect("valid guest address-space event");
        assert_eq!(event.pid(), 123);
        assert_eq!(event.asid(), 7);
        assert_eq!(event.bank_base(), 0x9a_0000_0000);
        assert_eq!(event.bank_size(), 40 * 1024 * 1024 * 1024);
        assert_eq!(event.ttbr0(), 0x0007_009a_0000_0000);
    }

    #[test]
    fn exec_bank_layout_event_keeps_join_and_cost_fields_typed() {
        let event = HvpatchExecBankLayout::new(
            HvpatchExecBankLayoutPhase::CacheHit,
            0x9a_0000_0000,
            17,
            6,
            42_000,
        );
        assert_eq!(event.phase(), HvpatchExecBankLayoutPhase::CacheHit);
        assert_eq!(HvpatchExecBankLayoutPhase::CacheMiss.raw(), 0);
        assert_eq!(HvpatchExecBankLayoutPhase::CacheHit.raw(), 1);
        assert_eq!(event.bank_base(), 0x9a_0000_0000);
        assert_eq!(event.mapping_count(), 17);
        assert_eq!(event.cache_entries(), 6);
        assert_eq!(event.elapsed_ns(), 42_000);
    }

    #[test]
    fn exec_backing_event_keeps_virtual_and_physical_identity_typed() {
        let event = HvpatchExecBacking::new(
            HvpatchExecBackingPhase::Reused,
            0x40_0000,
            0x9a_0040_0000,
            0x20_0000,
            8_000,
        );
        assert_eq!(HvpatchExecBackingPhase::Materialized.raw(), 0);
        assert_eq!(HvpatchExecBackingPhase::Reused.raw(), 1);
        assert_eq!(HvpatchExecBackingPhase::PrivateFileMapped.raw(), 2);
        assert_eq!(event.phase(), HvpatchExecBackingPhase::Reused);
        assert_eq!(event.guest_start(), 0x40_0000);
        assert_eq!(event.ipa_start(), 0x9a_0040_0000);
        assert_eq!(event.mapped_size(), 0x20_0000);
        assert_eq!(event.elapsed_ns(), 8_000);
    }

    #[test]
    fn exec_stage2_event_keeps_operation_and_address_identity_typed() {
        let event = HvpatchExecStage2::new(
            HvpatchExecStage2Phase::MapEnd,
            0x9a_0040_0000,
            0x20_0000,
            0x40_0000,
            0,
        );
        assert_eq!(HvpatchExecStage2Phase::UnmapBegin.raw(), 0);
        assert_eq!(HvpatchExecStage2Phase::UnmapEnd.raw(), 1);
        assert_eq!(HvpatchExecStage2Phase::MapBegin.raw(), 2);
        assert_eq!(HvpatchExecStage2Phase::MapEnd.raw(), 3);
        assert_eq!(event.phase(), HvpatchExecStage2Phase::MapEnd);
        assert_eq!(event.ipa(), 0x9a_0040_0000);
        assert_eq!(event.size(), 0x20_0000);
        assert_eq!(event.guest_start(), 0x40_0000);
        assert_eq!(event.rc(), 0);
    }

    #[test]
    fn exec_replace_stage_event_keeps_stage_cost_and_shape_typed() {
        let event = HvpatchExecReplaceStage::new(
            HvpatchExecReplaceStagePhase::MapBackings,
            825_000,
            19,
            42 * 1024 * 1024,
        );
        assert_eq!(HvpatchExecReplaceStagePhase::AliasCleanup.raw(), 0);
        assert_eq!(HvpatchExecReplaceStagePhase::DropBackings.raw(), 1);
        assert_eq!(HvpatchExecReplaceStagePhase::PageTables.raw(), 2);
        assert_eq!(HvpatchExecReplaceStagePhase::MapBackings.raw(), 3);
        assert_eq!(HvpatchExecReplaceStagePhase::Registers.raw(), 4);
        assert_eq!(HvpatchExecReplaceStagePhase::Mailbox.raw(), 5);
        assert_eq!(HvpatchExecReplaceStagePhase::PrivateFileArtifacts.raw(), 6);
        assert_eq!(HvpatchExecReplaceStagePhase::BankPlan.raw(), 7);
        assert_eq!(HvpatchExecReplaceStagePhase::AddressSpaceTeardown.raw(), 8);
        assert_eq!(event.phase(), HvpatchExecReplaceStagePhase::MapBackings);
        assert_eq!(event.elapsed_ns(), 825_000);
        assert_eq!(event.mapping_count(), 19);
        assert_eq!(event.mapped_bytes(), 42 * 1024 * 1024);
    }

    #[test]
    fn exec_runtime_stage_event_keeps_outer_runtime_cost_typed() {
        let event = HvpatchExecRuntimeStage::new(
            HvpatchExecRuntimeStagePhase::EngineReplace,
            1_250_000,
            18,
            38_805_159_936,
        );
        assert_eq!(HvpatchExecRuntimeStagePhase::ProcState.raw(), 0);
        assert_eq!(HvpatchExecRuntimeStagePhase::CloseCloexec.raw(), 1);
        assert_eq!(HvpatchExecRuntimeStagePhase::SiblingDrain.raw(), 2);
        assert_eq!(HvpatchExecRuntimeStagePhase::TopologyLock.raw(), 3);
        assert_eq!(HvpatchExecRuntimeStagePhase::EngineReplace.raw(), 4);
        assert_eq!(HvpatchExecRuntimeStagePhase::Publication.raw(), 5);
        assert_eq!(event.elapsed_ns(), 1_250_000);
        assert_eq!(event.region_count(), 18);
        assert_eq!(event.mapped_bytes(), 38_805_159_936);
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__exec__runtime__stage(_: u32, _: u64, _: u64, _: u64) {}",
            "stub!(hvpatch_exec_runtime_stage(event: super::HvpatchExecRuntimeStage));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing exec runtime-stage ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn topology_lock_event_keeps_holder_identity_and_timing_typed() {
        let event = HvpatchTopologyLock::new(
            HvpatchTopologyOperation::InProcessFork,
            HvpatchTopologyPhase::Released,
            42,
            43,
            1_250_000,
        );
        assert_eq!(HvpatchTopologyOperation::InProcessFork.raw(), 0);
        assert_eq!(HvpatchTopologyOperation::ExecReplace.raw(), 1);
        assert_eq!(HvpatchTopologyOperation::ExecSiblingGate.raw(), 2);
        assert_eq!(HvpatchTopologyOperation::SiblingMaterialize.raw(), 3);
        assert_eq!(HvpatchTopologyOperation::VcpuRebind.raw(), 4);
        assert_eq!(HvpatchTopologyOperation::VmRelease.raw(), 5);
        assert_eq!(HvpatchTopologyOperation::LegacyFork.raw(), 6);
        assert_eq!(HvpatchTopologyOperation::ProcessRetire.raw(), 7);
        assert_eq!(HvpatchTopologyPhase::Requested.raw(), 0);
        assert_eq!(HvpatchTopologyPhase::Acquired.raw(), 1);
        assert_eq!(HvpatchTopologyPhase::Released.raw(), 2);
        assert_eq!(HvpatchTopologyPhase::TryMiss.raw(), 3);
        assert_eq!(event.operation(), HvpatchTopologyOperation::InProcessFork);
        assert_eq!(event.phase(), HvpatchTopologyPhase::Released);
        assert_eq!(event.guest_pid(), 42);
        assert_eq!(event.guest_tid(), 43);
        assert_eq!(event.elapsed_ns(), 1_250_000);
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__topology__lock(_: u32, _: u32, _: i32, _: i32, _: u64) {}",
            "stub!(hvpatch_topology_lock(event: super::HvpatchTopologyLock));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing topology-lock ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn fork_runtime_stage_event_keeps_parent_child_identity_and_timing_typed() {
        let event = HvpatchForkRuntimeStage::new(
            HvpatchForkRuntimeStagePhase::ChildReady,
            41,
            42,
            43,
            1_750_000,
        );
        assert_eq!(HvpatchForkRuntimeStagePhase::Quiesce.raw(), 0);
        assert_eq!(HvpatchForkRuntimeStagePhase::ProcessAllocate.raw(), 1);
        assert_eq!(HvpatchForkRuntimeStagePhase::PidfdParent.raw(), 2);
        assert_eq!(HvpatchForkRuntimeStagePhase::ProcessSpec.raw(), 3);
        assert_eq!(HvpatchForkRuntimeStagePhase::DispatcherClone.raw(), 4);
        assert_eq!(HvpatchForkRuntimeStagePhase::RuntimeState.raw(), 5);
        assert_eq!(HvpatchForkRuntimeStagePhase::ThreadSpawn.raw(), 6);
        assert_eq!(HvpatchForkRuntimeStagePhase::ChildReady.raw(), 7);
        assert_eq!(HvpatchForkRuntimeStagePhase::Publication.raw(), 8);
        assert_eq!(HvpatchForkRuntimeStagePhase::Total.raw(), 9);
        assert_eq!(event.phase(), HvpatchForkRuntimeStagePhase::ChildReady);
        assert_eq!(event.parent_pid(), 41);
        assert_eq!(event.child_pid(), 42);
        assert_eq!(event.forking_tid(), 43);
        assert_eq!(event.elapsed_ns(), 1_750_000);
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__fork__runtime__stage(_: u32, _: i32, _: i32, _: i32, _: u64) {}",
            "stub!(hvpatch_fork_runtime_stage(event: super::HvpatchForkRuntimeStage));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing fork runtime-stage ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn fork_process_spec_stage_keeps_guest_identity_timing_and_shape_typed() {
        let event = HvpatchForkProcessSpecStage::new(
            HvpatchForkProcessSpecStagePhase::TablePublish,
            42,
            43,
            1_750_000,
            0x1c0000,
        );
        assert_eq!(
            HvpatchForkProcessSpecStagePhase::ParentPageTablesLoad.raw(),
            0
        );
        assert_eq!(HvpatchForkProcessSpecStagePhase::VcpuSnapshot.raw(), 1);
        assert_eq!(
            HvpatchForkProcessSpecStagePhase::ParentPageTablesClone.raw(),
            2
        );
        assert_eq!(HvpatchForkProcessSpecStagePhase::PageTablesRebase.raw(), 3);
        assert_eq!(HvpatchForkProcessSpecStagePhase::AliasUnion.raw(), 4);
        assert_eq!(HvpatchForkProcessSpecStagePhase::PrivateSnapshot.raw(), 5);
        assert_eq!(HvpatchForkProcessSpecStagePhase::Validation.raw(), 6);
        assert_eq!(HvpatchForkProcessSpecStagePhase::TablePublish.raw(), 7);
        assert_eq!(
            HvpatchForkProcessSpecStagePhase::BackendProtections.raw(),
            8
        );
        assert_eq!(
            HvpatchForkProcessSpecStagePhase::BackendSpecFinalize.raw(),
            9
        );
        assert_eq!(
            HvpatchForkProcessSpecStagePhase::WrapperProtections.raw(),
            10
        );
        assert_eq!(HvpatchForkProcessSpecStagePhase::Total.raw(), 11);
        assert_eq!(
            event.phase(),
            HvpatchForkProcessSpecStagePhase::TablePublish
        );
        assert_eq!(event.child_pid(), 42);
        assert_eq!(event.forking_tid(), 43);
        assert_eq!(event.elapsed_ns(), 1_750_000);
        assert_eq!(event.units(), 0x1c0000);
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__fork__process__spec__stage(_: u32, _: i32, _: i32, _: u64, _: u64) {}",
            "stub!(hvpatch_fork_process_spec_stage(event: super::HvpatchForkProcessSpecStage));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing fork process-spec stage ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn fork_private_snapshot_provider_and_stub_keep_timing_and_outcome_separate() {
        let timing = HvpatchForkPrivateSnapshot::new(42, 43, 0x4000, 0x8000, 1_750_000);
        let outcome = HvpatchForkPrivateSnapshotOutcome::new(
            42,
            43,
            0x4000,
            HvpatchForkPrivateSnapshotRole::PrivateHeap,
            HvpatchForkPrivateSnapshotMethod::MachCowRemap,
        );
        assert_eq!(timing.child_pid(), 42);
        assert_eq!(timing.forking_tid(), 43);
        assert_eq!(timing.guest_start(), 0x4000);
        assert_eq!(timing.mapped_size(), 0x8000);
        assert_eq!(timing.elapsed_ns(), 1_750_000);
        assert_eq!(outcome.child_pid(), 42);
        assert_eq!(outcome.forking_tid(), 43);
        assert_eq!(outcome.guest_start(), 0x4000);
        assert_eq!(outcome.role(), HvpatchForkPrivateSnapshotRole::PrivateHeap);
        assert_eq!(
            outcome.method(),
            HvpatchForkPrivateSnapshotMethod::MachCowRemap
        );
        assert_eq!(HvpatchForkPrivateSnapshotRole::PrivateMmapArena.raw(), 1);
        assert_eq!(HvpatchForkPrivateSnapshotRole::PrivateHeap.raw(), 2);
        assert_eq!(HvpatchForkPrivateSnapshotRole::PrivatePageTables.raw(), 9);
        assert_eq!(
            HvpatchForkPrivateSnapshotRole::from_footprint_class(6),
            Some(HvpatchForkPrivateSnapshotRole::PrivateReadOnlyOrInternal)
        );
        assert_eq!(
            HvpatchForkPrivateSnapshotRole::from_footprint_class(10),
            None
        );
        assert_eq!(HvpatchForkPrivateSnapshotMethod::MachCowRemap.raw(), 0);
        assert_eq!(
            HvpatchForkPrivateSnapshotMethod::SparseCopyFallback.raw(),
            1
        );
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__fork__private__snapshot(_: i32, _: i32, _: u64, _: u64, _: u64) {}",
            "fn hvpatch__fork__private__snapshot__outcome(_: i32, _: i32, _: u64, _: u32, _: u32) {}",
            "stub!(hvpatch_fork_private_snapshot(event: super::HvpatchForkPrivateSnapshot));",
            "stub!(hvpatch_fork_private_snapshot_outcome(event: super::HvpatchForkPrivateSnapshotOutcome));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing private snapshot ABI declaration {declaration}"
            );
        }
    }

    #[test]
    fn syscall_service_provider_and_stub_keep_guest_task_identity_typed() {
        let completion =
            HvpatchSyscallService::new(41, 43, 7, 56, 12_345).expect("valid task identity");
        assert_eq!(completion.pid(), 41);
        assert_eq!(completion.tid(), 43);
        assert_eq!(completion.asid(), 7);
        assert_eq!(completion.number(), 56);
        assert_eq!(completion.duration_ns(), 12_345);
        assert!(HvpatchSyscallService::new(0, 43, 7, 56, 12_345).is_err());
        assert!(HvpatchSyscallService::new(41, 43, 0, 56, 12_345).is_err());
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__syscall__service__begin(_: i32, _: i32, _: u32, _: u64) {}",
            "fn hvpatch__syscall__args(_: u64, _: u64, _: u64, _: u64, _: u64) {}",
            "fn hvpatch__syscall__service(_: i32, _: i32, _: u32, _: u64, _: u64) {}",
            "fn hvpatch__syscall__service__clear(_: i32, _: i32, _: u32, _: u64) {}",
            "stub!(hvpatch_syscall_service_begin(event: super::HvpatchSyscallService, args: [u64; 6]) -> Option<std::time::Instant> => None);",
            "stub!(hvpatch_syscall_service(event: super::HvpatchSyscallService));",
            "stub!(hvpatch_syscall_service_clear(event: super::HvpatchSyscallService));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing hvpatch syscall-service ABI declaration {declaration}"
            );
        }
        let wrapper = source
            .split_once("pub fn hvpatch_syscall_service_begin(")
            .expect("real hvpatch service-begin wrapper")
            .1;
        let begin = wrapper
            .find("carrick_usdt::hvpatch__syscall__service__begin!")
            .expect("identity-bearing begin probe");
        let args = wrapper
            .find("carrick_usdt::hvpatch__syscall__args!")
            .expect("raw-argument companion probe");
        assert!(
            begin < args,
            "the typed identity begin must fire before its raw-argument companion"
        );
    }

    #[test]
    fn fork_quiesce_detail_keeps_guest_identity_population_and_polling_typed() {
        let event = HvpatchForkQuiesce::new(41, 43, 7, 12, 2_500_000);
        assert_eq!(event.parent_pid(), 41);
        assert_eq!(event.forking_tid(), 43);
        assert_eq!(event.initial_siblings(), 7);
        assert_eq!(event.poll_iterations(), 12);
        assert_eq!(event.elapsed_ns(), 2_500_000);
        let source = include_str!("probes.rs");
        for declaration in [
            "fn hvpatch__fork__quiesce(_: i32, _: i32, _: u32, _: u64, _: u64) {}",
            "stub!(hvpatch_fork_quiesce(event: super::HvpatchForkQuiesce));",
        ] {
            assert!(
                source.matches(declaration).count() >= 2,
                "missing fork-quiesce ABI declaration {declaration}"
            );
        }
    }
}

macro_rules! dsr_ordinal_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident = $value:expr),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum $name {
            $($variant = $value),+
        }

        impl $name {
            pub const ALL: [Self; dsr_ordinal_enum!(@count $($variant),+)] = [
                $(Self::$variant),+
            ];

            #[inline(always)]
            pub const fn raw(self) -> u32 {
                self as u32
            }
        }
    };
    (@count $($variant:ident),+) => {
        <[()]>::len(&[$(dsr_ordinal_enum!(@unit $variant)),+])
    };
    (@unit $variant:ident) => { () };
}

dsr_ordinal_enum! {
    /// Executable translated-code ownership carried by a typed range event.
    pub enum TranslatedRangeKind {
        PrivateProcessCache = 1,
        SharedUnit = 2,
    }
}

/// Rejected translated-range identity or executable extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TranslatedRangeError {
    #[error("translated-range epoch must be nonzero")]
    ZeroEpoch,
    #[error("translated-range sequence must be nonzero")]
    ZeroSequence,
    #[error("translated shared-unit identity must be nonzero")]
    ZeroUnitId,
    #[error("translated executable range is empty at 0x{address:x}")]
    EmptyRange { address: usize },
    #[error("translated executable range is reversed: 0x{start:x}..0x{end:x}")]
    ReversedRange { start: usize, end: usize },
    #[error("translated executable range is not four-byte aligned: 0x{start:x}..0x{end:x}")]
    UnalignedRange { start: usize, end: usize },
}

/// Nonzero identity for one process-image translated-range catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeEpoch(NonZeroU64);

impl TranslatedRangeEpoch {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroEpoch)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Nonzero monotonically increasing identity for one catalog addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedRangeSequence(NonZeroU64);

impl TranslatedRangeSequence {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroSequence)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable nonzero identity for one loaded shared translation unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslatedUnitId(NonZeroU64);

impl TranslatedUnitId {
    pub fn new(value: u64) -> Result<Self, TranslatedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TranslatedRangeError::ZeroUnitId)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Reset the translated-range catalog for one process-image epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReset {
    epoch: TranslatedRangeEpoch,
}

impl TranslatedRangeReset {
    pub const fn reset(epoch: TranslatedRangeEpoch) -> Self {
        Self { epoch }
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }
}

/// Add one typed executable range to the active translated-range catalog.
///
/// The enum variants keep private and shared payloads distinct:
///
/// ```compile_fail
/// use carrick_observability::probes::{
///     TranslatedRangeAdd, TranslatedRangeEpoch, TranslatedRangeSequence,
///     TranslatedSharedRange, TranslatedUnitId,
/// };
/// use carrick_guest_mem::HostVa;
///
/// let epoch = TranslatedRangeEpoch::new(1).unwrap();
/// let sequence = TranslatedRangeSequence::new(1).unwrap();
/// let unit_id = TranslatedUnitId::new(1).unwrap();
/// let shared = TranslatedSharedRange::shared(
///     epoch,
///     sequence,
///     unit_id,
///     HostVa(0x1000)..HostVa(0x2000),
/// ).unwrap();
/// let _ = TranslatedRangeAdd::Private(shared);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslatedRangeAdd {
    Private(TranslatedPrivateRange),
    Shared(TranslatedSharedRange),
}

impl TranslatedRangeAdd {
    pub const fn kind(&self) -> TranslatedRangeKind {
        match self {
            Self::Private(_) => TranslatedRangeKind::PrivateProcessCache,
            Self::Shared(_) => TranslatedRangeKind::SharedUnit,
        }
    }
}

/// Exact half-open executable extent of the process-private translation cache.
///
/// Its fields are private and there is no unit-ID parameter, so a caller
/// cannot construct a private event with shared-unit identity.
///
/// ```compile_fail
/// use carrick_observability::probes::{
///     TranslatedPrivateRange, TranslatedRangeEpoch, TranslatedRangeSequence,
/// };
/// use carrick_guest_mem::HostVa;
///
/// let epoch = TranslatedRangeEpoch::new(1).unwrap();
/// let sequence = TranslatedRangeSequence::new(1).unwrap();
/// let _ = TranslatedPrivateRange {
///     epoch,
///     sequence,
///     range: HostVa(0x1000)..HostVa(0x2000),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedPrivateRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    range: Range<HostVa>,
}

impl TranslatedPrivateRange {
    pub fn private(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            range,
        })
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn sequence(&self) -> TranslatedRangeSequence {
        self.sequence
    }

    pub const fn range(&self) -> &Range<HostVa> {
        &self.range
    }
}

/// Exact half-open executable extent of one shared translation unit.
///
/// Its fields are private and construction requires a typed unit ID, so a
/// caller cannot publish a shared event without unit identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedSharedRange {
    epoch: TranslatedRangeEpoch,
    sequence: TranslatedRangeSequence,
    unit_id: TranslatedUnitId,
    range: Range<HostVa>,
}

impl TranslatedSharedRange {
    pub fn shared(
        epoch: TranslatedRangeEpoch,
        sequence: TranslatedRangeSequence,
        unit_id: TranslatedUnitId,
        range: Range<HostVa>,
    ) -> Result<Self, TranslatedRangeError> {
        validate_translated_range(&range)?;
        Ok(Self {
            epoch,
            sequence,
            unit_id,
            range,
        })
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn sequence(&self) -> TranslatedRangeSequence {
        self.sequence
    }

    pub const fn unit_id(&self) -> TranslatedUnitId {
        self.unit_id
    }

    pub const fn range(&self) -> &Range<HostVa> {
        &self.range
    }
}

/// Close the initial translated-range replay for one process-image epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslatedRangeReady {
    epoch: TranslatedRangeEpoch,
    final_sequence: u64,
}

impl TranslatedRangeReady {
    pub const fn ready(epoch: TranslatedRangeEpoch, final_sequence: u64) -> Self {
        Self {
            epoch,
            final_sequence,
        }
    }

    pub const fn epoch(&self) -> TranslatedRangeEpoch {
        self.epoch
    }

    pub const fn final_sequence(&self) -> u64 {
        self.final_sequence
    }
}

fn validate_translated_range(range: &Range<HostVa>) -> Result<(), TranslatedRangeError> {
    let start = range.start.raw();
    let end = range.end.raw();
    if start == end {
        return Err(TranslatedRangeError::EmptyRange { address: start });
    }
    if start > end {
        return Err(TranslatedRangeError::ReversedRange { start, end });
    }
    if !start.is_multiple_of(4) || !end.is_multiple_of(4) {
        return Err(TranslatedRangeError::UnalignedRange { start, end });
    }
    Ok(())
}

/// Rejected native-owned host-range identity or mapped extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeOwnedRangeError {
    #[error("native-owned range epoch must be nonzero")]
    ZeroEpoch,
    #[error("native-owned range sequence must be nonzero")]
    ZeroSequence,
    #[error("native-owned range sequence overflow")]
    SequenceOverflow,
    #[error("native-owned range catalog must not be empty")]
    EmptyCatalog,
    #[error("native-owned range host page size must be a nonzero power of two")]
    InvalidPageSize,
    #[error("native-owned range is empty at 0x{address:x}")]
    EmptyRange { address: usize },
    #[error("native-owned range is reversed: 0x{start:x}..0x{end:x}")]
    ReversedRange { start: usize, end: usize },
    #[error(
        "native-owned range is not host-page aligned: 0x{start:x}..0x{end:x} (page size {page_size})"
    )]
    UnalignedRange {
        start: usize,
        end: usize,
        page_size: usize,
    },
    #[error(
        "native-owned ranges overlap or are out of order: previous end 0x{previous_end:x}, next start 0x{next_start:x}"
    )]
    OverlappingRanges {
        previous_end: usize,
        next_start: usize,
    },
}

/// Nonzero identity for one process-image native-owned range catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedRangeEpoch(NonZeroU64);

impl NativeOwnedRangeEpoch {
    pub fn new(value: u64) -> Result<Self, NativeOwnedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(NativeOwnedRangeError::ZeroEpoch)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Nonzero monotonically increasing identity for one catalog addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedRangeSequence(NonZeroU64);

impl NativeOwnedRangeSequence {
    pub fn new(value: u64) -> Result<Self, NativeOwnedRangeError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(NativeOwnedRangeError::ZeroSequence)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Reset the native-owned range catalog for one process-image epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedRangeReset {
    epoch: NativeOwnedRangeEpoch,
}

impl NativeOwnedRangeReset {
    pub const fn reset(epoch: NativeOwnedRangeEpoch) -> Self {
        Self { epoch }
    }

    pub const fn epoch(self) -> NativeOwnedRangeEpoch {
        self.epoch
    }
}

/// Exact half-open host extent owned by the active native guest image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOwnedRange {
    epoch: NativeOwnedRangeEpoch,
    sequence: NativeOwnedRangeSequence,
    range: Range<HostVa>,
}

impl NativeOwnedRange {
    pub fn new(
        epoch: NativeOwnedRangeEpoch,
        sequence: NativeOwnedRangeSequence,
        range: Range<HostVa>,
        host_page_size: usize,
    ) -> Result<Self, NativeOwnedRangeError> {
        validate_native_owned_range(&range, host_page_size)?;
        Ok(Self {
            epoch,
            sequence,
            range,
        })
    }

    pub const fn epoch(&self) -> NativeOwnedRangeEpoch {
        self.epoch
    }

    pub const fn sequence(&self) -> NativeOwnedRangeSequence {
        self.sequence
    }

    pub const fn range(&self) -> &Range<HostVa> {
        &self.range
    }
}

/// Close a complete, nonempty native-owned range catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedRangeReady {
    epoch: NativeOwnedRangeEpoch,
    final_sequence: NonZeroU64,
}

impl NativeOwnedRangeReady {
    pub fn ready(
        epoch: NativeOwnedRangeEpoch,
        final_sequence: u64,
    ) -> Result<Self, NativeOwnedRangeError> {
        let final_sequence =
            NonZeroU64::new(final_sequence).ok_or(NativeOwnedRangeError::EmptyCatalog)?;
        Ok(Self {
            epoch,
            final_sequence,
        })
    }

    pub const fn epoch(self) -> NativeOwnedRangeEpoch {
        self.epoch
    }

    pub const fn final_sequence(self) -> u64 {
        self.final_sequence.get()
    }
}

fn validate_native_owned_range(
    range: &Range<HostVa>,
    host_page_size: usize,
) -> Result<(), NativeOwnedRangeError> {
    if host_page_size == 0 || !host_page_size.is_power_of_two() {
        return Err(NativeOwnedRangeError::InvalidPageSize);
    }
    let start = range.start.raw();
    let end = range.end.raw();
    if start == end {
        return Err(NativeOwnedRangeError::EmptyRange { address: start });
    }
    if start > end {
        return Err(NativeOwnedRangeError::ReversedRange { start, end });
    }
    if !start.is_multiple_of(host_page_size) || !end.is_multiple_of(host_page_size) {
        return Err(NativeOwnedRangeError::UnalignedRange {
            start,
            end,
            page_size: host_page_size,
        });
    }
    Ok(())
}

dsr_ordinal_enum! {
    /// Typed reason a translated DSR run slice returned to Rust.
    pub enum DsrExitKind {
        Syscall = 1,
        DirectResolver = 2,
        IndirectResolver = 3,
        Fault = 4,
        Kick = 5,
        Sensitive = 6,
        Unsupported = 7,
    }
}

dsr_ordinal_enum! {
    /// Result of preparing a guest PC for translated execution.
    pub enum DsrPrepareOutcome {
        ResumeEntryHit = 1,
        BlockIndexHit = 2,
        Translated = 3,
        Failed = 4,
    }
}

dsr_ordinal_enum! {
    /// Stable diagnostic category for a DSR operation result.
    pub enum DsrOperationOutcome {
        Success = 0,
        PcOverflow = 1,
        Decode = 2,
        Malformed = 3,
        BlockPolicy = 4,
        MemoryRead = 5,
        UnsupportedBlockAction = 6,
        Assembler = 7,
        Gateway = 8,
        CachePolicy = 9,
        GenerationChanged = 10,
        Host = 11,
        CacheCapacity = 12,
        InvalidTarget = 13,
    }
}

dsr_ordinal_enum! {
    /// Resolver family used for a translated control-flow exit.
    pub enum DsrResolveKind {
        Direct = 1,
        Indirect = 2,
    }
}

dsr_ordinal_enum! {
    /// Low-cardinality DSR translation-cache event.
    pub enum DsrCacheEventKind {
        BlockHit = 1,
        BlockMiss = 2,
        TargetPublish = 3,
        Invalidate = 4,
        BlockPublish = 5,
        CapacityFailure = 6,
        DirectBindingEligible = 7,
        DirectBindingPublish = 8,
        DirectBindingCasLoss = 9,
        DirectBindingClear = 10,
        DirectBindingValidationFailure = 11,
        DirectBindingUnitLoaded = 12,
    }
}

dsr_ordinal_enum! {
    /// Process role for a DSR cache lifecycle boundary.
    pub enum DsrCacheRole {
        Common = 0,
        Parent = 1,
        Child = 2,
    }
}

dsr_ordinal_enum! {
    /// Stable DSR cache lifecycle boundary.
    pub enum DsrCacheLifecyclePhase {
        ForkChildRepairBegin = 1,
        ForkChildRepairEnd = 2,
        ExecResetBegin = 3,
        ExecResetEnd = 4,
        ExecImageUnmapBegin = 5,
        ExecImageUnmapEnd = 6,
        ExecImageMapBegin = 7,
        ExecImageMapEnd = 8,
        ExecCacheResetBegin = 9,
        ExecCacheResetEnd = 10,
        ExecRelocationBegin = 11,
        ExecRelocationEnd = 12,
        ExecTranslatorHandoffBegin = 13,
        ExecTranslatorHandoffEnd = 14,
        ExecMapMmapBegin = 15,
        ExecMapMmapEnd = 16,
        ExecMapCopyBegin = 17,
        ExecMapCopyEnd = 18,
        ExecMapIcacheBegin = 19,
        ExecMapIcacheEnd = 20,
        ExecMapProtectBegin = 21,
        ExecMapProtectEnd = 22,
        ExecMapVvarBegin = 23,
        ExecMapVvarEnd = 24,
        HostSelfReexecBegin = 25,
        HostSelfReexecEnd = 26,
        HostSelfReexecProbesReady = 27,
        HostSelfReexecCapsuleBegin = 28,
        HostSelfReexecCapsuleEnd = 29,
        HostSelfReexecRestoreBegin = 30,
        HostSelfReexecDispatcherReady = 31,
        HostSelfReexecImageLoadBegin = 32,
        HostSelfReexecImageLoadEnd = 33,
        HostSelfReexecResetBegin = 34,
        HostSelfReexecResetEnd = 35,
        HostSelfReexecGuestEntry = 36,
        HostSelfReexecPreflightBegin = 37,
        HostSelfReexecCapsulePrepareBegin = 38,
        HostSelfReexecPreparedBuildBegin = 39,
        HostSelfReexecPreparedBuildEnd = 40,
        HostSelfReexecPreparedValidateBegin = 41,
        HostSelfReexecPreparedValidateEnd = 42,
        HostSelfReexecPreparedMapBegin = 43,
        HostSelfReexecPreparedMapEnd = 44,
    }
}

dsr_ordinal_enum! {
    /// Aggregate component of one native DSR exec image mapping.
    pub enum DsrExecMapDetailKind {
        Mmap = 1,
        Copy = 2,
        Icache = 3,
        Protect = 4,
        Vvar = 5,
    }
}

dsr_ordinal_enum! {
    /// Non-overlapping component of a DSR block translation.
    pub enum DsrTranslationSubphase {
        Decode = 1,
        Plan = 2,
        Emit = 3,
        PublicationIndex = 4,
        DuplicateWait = 5,
    }
}

dsr_ordinal_enum! {
    /// Host synchronization boundary whose kernel waits need a stable reason.
    pub enum DsrSynchronizationKind {
        GenerationTableWrite = 1,
        ProcessStateRead = 2,
        ProcessStateWrite = 3,
    }
}

dsr_ordinal_enum! {
    /// Native syscall service branch whose child inherits the open operation.
    pub enum NativeSyscallBranchKind {
        Process = 1,
        Thread = 2,
    }
}

dsr_ordinal_enum! {
    /// Terminal outcome of one full native guest syscall service operation.
    pub enum NativeSyscallServiceOutcome {
        Resume = 1,
        ThreadExit = 2,
        InProcessExec = 3,
        Aborted = 4,
    }
}

#[cfg(test)]
mod native_syscall_service_probe_abi {
    use super::{NativeSyscallBranchKind, NativeSyscallServiceOutcome};

    fn assert_unique(values: &[u32]) {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len());
    }

    #[test]
    fn native_syscall_service_ordinals_are_stable_and_unique() {
        assert_eq!(NativeSyscallBranchKind::Process.raw(), 1);
        assert_eq!(NativeSyscallBranchKind::Thread.raw(), 2);
        assert_unique(&NativeSyscallBranchKind::ALL.map(NativeSyscallBranchKind::raw));

        assert_eq!(NativeSyscallServiceOutcome::Resume.raw(), 1);
        assert_eq!(NativeSyscallServiceOutcome::ThreadExit.raw(), 2);
        assert_eq!(NativeSyscallServiceOutcome::InProcessExec.raw(), 3);
        assert_eq!(NativeSyscallServiceOutcome::Aborted.raw(), 4);
        assert_unique(&NativeSyscallServiceOutcome::ALL.map(NativeSyscallServiceOutcome::raw));
    }

    #[test]
    fn native_syscall_service_wrappers_have_typed_real_or_stub_signatures() {
        let _: fn(u64, &str) = super::native_syscall_service_entry;
        let _: fn(NativeSyscallBranchKind) = super::native_syscall_service_branch;
        let _: fn(u64, &str, NativeSyscallServiceOutcome) = super::native_syscall_service_end;
    }

    #[test]
    fn native_syscall_service_provider_declarations_keep_dtrace_names() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn native__syscall__service__entry(_: u64, _: &str) {}",
            "fn native__syscall__service__branch(_: u32) {}",
            "fn native__syscall__service__end(_: u64, _: &str, _: u32) {}",
        ] {
            assert!(
                source.contains(declaration),
                "missing provider declaration {declaration:?}"
            );
        }
    }
}

#[cfg(test)]
mod image_publication_probe_abi {
    use super::{PreparedGuestImagePath, PreparedHostImagePublication};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn prepared_image_publication_wrappers_keep_real_or_stub_signatures() {
        let _: fn(String) -> PreparedGuestImagePath = super::prepare_guest_image_path;
        let _: fn(u64, u64, &PreparedGuestImagePath) = super::guest_image_base;
        let _: fn() = super::host_image_text_range;
        let _: fn() -> PreparedHostImagePublication = super::prepare_host_image_publication;
        let _: fn(&PreparedHostImagePublication) = super::publish_host_image_base;
        let _: fn(&PreparedHostImagePublication) = super::publish_host_image_catalog;
        assert_send_sync::<PreparedGuestImagePath>();
        assert_send_sync::<PreparedHostImagePublication>();
    }

    #[test]
    fn image_publication_provider_uses_only_prepared_raw_path_pointers() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn host__image__base(_: u32, _: u64, _: i64, _: *const u8) {}",
            "fn host__image__text__range(_: u32, _: u64, _: u64) {}",
            "fn host__image__catalog(_: *const u8) {}",
            "fn guest__image__base(_: u32, _: u64, _: u64, _: *const u8) {}",
        ] {
            assert!(
                source.contains(declaration),
                "missing raw-pointer provider declaration {declaration:?}"
            );
        }
        assert!(source.contains(
            "stub!(guest_image_base(base: u64, entry: u64, path: &PreparedGuestImagePath));"
        ));
    }
}

/// Which side of a native (DSR) fork a `fork-lifecycle` sample describes.
///
/// Deliberately the SAME role convention the HVF lane and
/// `scripts/dtrace/fork-phases.d` already use for `arg0` (that script
/// aggregates `@lifecycle_us[(int)arg0, (int)arg1]`, i.e. keyed on
/// `(role, phase)`), so a native run drops straight into the existing script
/// with no edits: `0` = the forking parent (and the common pre-fork work it
/// does on behalf of both processes), `1` = the fork child.
///
/// The role is never passed by a caller — [`NativeForkPhase::role`] derives it
/// from the phase, so a child phase can never be reported under the parent
/// role (the mis-pairing that a bare `i32` role argument invites).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum NativeForkRole {
    /// The forking thread, before `fork(2)` and on the parent's return path.
    Parent = 0,
    /// The fork child, from `fork(2)` returning zero until the guest is
    /// resumable.
    Child = 1,
}

impl NativeForkRole {
    /// The wire value for the probe's `role` argument. Raw escapes ONLY here,
    /// at the USDT boundary.
    #[inline(always)]
    pub const fn raw(self) -> i32 {
        self as i32
    }
}

/// One attributable span of a native (DSR) guest fork, as reported through the
/// shared `fork-lifecycle` USDT probe.
///
/// # Why a distinct ordinal block
///
/// The `fork-lifecycle` probe is shared with the HVF/VMM lane, whose phase
/// numbers are ad-hoc integers with no legend (runtime `0..9` and `50..55`,
/// aarch64 `0..6`, HVF `10..18`, distinguished only by a role offset). Rather
/// than extend that, the native lane claims its OWN contiguous, documented
/// ordinal block so a `fork-phases.d` capture is self-describing and a native
/// span can never be confused with an HVF span even if both ever appeared in
/// one trace:
///
/// * `100..=107` — parent / common ([`NativeForkRole::Parent`])
/// * `120..=125` — child ([`NativeForkRole::Child`])
///
/// # Legend
///
/// Every variant reports the duration of the JUST-FINISHED span in the probe's
/// `elapsed_us`; the `a`/`b` arguments are phase-specific and documented per
/// variant below. The parent spans partition the fork path end to end, so
/// summing them accounts for the whole parent-side cost; the child spans
/// partition `fork(2)`-returns-zero → guest resumable.
///
/// Discriminants are explicit and unique BY CONSTRUCTION: `rustc` rejects a
/// duplicate enum discriminant, so this table cannot silently collide the way
/// a list of hand-numbered `const`s can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum NativeForkPhase {
    /// Parent: waiting for the process-wide fork serialization token (the CAS
    /// `try_begin_fork` loop, which sleeps 200us between attempts and parks at
    /// any in-flight fork's quiesce barrier). `a` = 1 if the token was NOT
    /// taken on the first attempt (i.e. this fork actually queued behind
    /// another), else 0. `b` = 0.
    TokenAcquire = 100,
    /// Parent: the sibling stop-the-world drain. Recorded UNCONDITIONALLY,
    /// including the single-threaded case where no drain runs at all — so
    /// "the quiesce costs nothing at threads=0" is measured, not assumed.
    /// `a` = live guest-thread count at entry, `b` = 1 if the drain actually
    /// engaged (`a > 1`), else 0.
    SiblingQuiesce = 101,
    /// Parent: draining in-flight thread-exit cleanups so `fork(2)` cannot
    /// hand the child a process-global signal mutex held by a thread that does
    /// not exist in it. `a` = cleanups still in flight when the span ended
    /// (nonzero means the 5 s bound expired), `b` = 0.
    ExitCleanupDrain = 102,
    /// Parent: pinning the non-guest helper gates (network publication and the
    /// RLIMIT_CPU helper) that must not be mid-iteration across `fork(2)`.
    /// `a` = 1 if a gate failed to quiesce and the fork degraded to EAGAIN,
    /// else 0. `b` = 0.
    HelperGates = 103,
    /// Parent: pre-fork bookkeeping — the vfork suspend pipe, the child's
    /// ns-pid allocation and prepared child record, and taking the
    /// across-fork barrier/signal-static locks. `a` = the allocated child
    /// ns-pid (`-1` when PID namespaces are off or allocation failed),
    /// `b` = 1 if a vfork suspend pipe was armed, else 0.
    PreForkBookkeeping = 104,
    /// Parent AND child: the host `fork(2)` call itself, plus the immediate
    /// release of the locks held across it. Fired on BOTH sides with the same
    /// measured span (each process reads its own return from the one call), so
    /// the role distinguishes them. `a` = the `fork(2)` return value (child
    /// host pid in the parent, 0 in the child, `-1` on failure), `b` = 0.
    HostFork = 105,
    /// Parent: post-fork bookkeeping before the guest resumes — releasing the
    /// quiesce, publishing the child's process record / ns-pid registration /
    /// run-state, installing a CLONE_PIDFD descriptor, writing the child tid
    /// back to guest memory, and arming the child-exit watch. `a` = the
    /// guest-visible child pid returned to the guest, `b` = 0.
    ParentPublish = 106,
    /// Parent: the vfork suspend — guest-paced (it ends when the child
    /// `execve`s or exits), so it is reported SEPARATELY from
    /// [`Self::ParentPublish`] and must not be read as carrick overhead.
    /// `a` = child host pid, `b` = 0. Not fired for an ordinary fork.
    VforkSuspend = 107,

    /// Child: repairing the barrier/exec-replacement state inherited through
    /// `fork(2)` (quiesce + fork flags, the parked-thread count that belongs
    /// to parent threads, the exec-replacement owner, the image-replaced
    /// marker) and adopting the vfork release descriptor. `a` = 1 if this
    /// child holds a vfork release descriptor, else 0. `b` = 0.
    ChildBarrierRepair = 120,
    /// Child: the shared dispatcher fork-child reset — the nine ordered hooks
    /// in `native::fork_child::AFTER_FORK_CHILD_STEPS` (output buffers, event
    /// ring, host signals, FIFO beacons, then the network/epoll/proc/mem/sysv
    /// subsystem hooks). `a` = the number of hooks run, `b` = 0.
    ChildDispatcherReset = 121,
    /// Child: rebuilding this thread's runtime — a fresh thread runtime and
    /// registry, retiring the dead siblings' per-tid signal state, re-keying
    /// this thread's own, binding a new kick target, and starting the signal
    /// wake pump. `a` = the child's new guest tid, `b` = 0.
    ChildRuntimeReset = 122,
    /// Child: re-establishing guest-visible state — CPU-time accounting reset,
    /// the child's process record and RLIMIT_CPU helper, the vDSO RNG
    /// generation re-stamp (so the COW-inherited getrandom state does not
    /// replay the parent's keystream), run-state publication, and the
    /// parent/child tid write-backs into guest RAM. `a` = the child's ns-pid,
    /// `b` = 0.
    ChildGuestState = 123,
    /// Child: TOTAL from `fork(2)` returning zero to the end of the in-runtime
    /// child repair — the sum of [`Self::ChildBarrierRepair`],
    /// [`Self::ChildDispatcherReset`], [`Self::ChildRuntimeReset`] and
    /// [`Self::ChildGuestState`]. `a` = the child's ns-pid, `b` = 0.
    ChildRuntimeRepairTotal = 124,
    /// Child: the DSR translator's own fork-child repair
    /// (`translator.after_fork_child`) — the last work before the guest is
    /// resumable, and the span nothing measured before. Fired from the run
    /// loop rather than the fork handler because the translator lives there.
    /// `a` = the child's guest tid, `b` = 0.
    ChildTranslatorRebuild = 125,
}

impl NativeForkPhase {
    /// Every phase, for the ordinal-block/uniqueness assertions.
    pub const ALL: [Self; 14] = [
        Self::TokenAcquire,
        Self::SiblingQuiesce,
        Self::ExitCleanupDrain,
        Self::HelperGates,
        Self::PreForkBookkeeping,
        Self::HostFork,
        Self::ParentPublish,
        Self::VforkSuspend,
        Self::ChildBarrierRepair,
        Self::ChildDispatcherReset,
        Self::ChildRuntimeReset,
        Self::ChildGuestState,
        Self::ChildRuntimeRepairTotal,
        Self::ChildTranslatorRebuild,
    ];

    /// The role this phase belongs to, derived from the phase itself so a
    /// caller cannot pair a child phase with the parent role.
    ///
    /// [`Self::HostFork`] is the one phase BOTH processes fire; its role is
    /// resolved at the call site via [`native_fork_lifecycle_as`], which is
    /// the only entry point that takes a role explicitly.
    #[inline(always)]
    pub const fn role(self) -> NativeForkRole {
        match self {
            Self::TokenAcquire
            | Self::SiblingQuiesce
            | Self::ExitCleanupDrain
            | Self::HelperGates
            | Self::PreForkBookkeeping
            | Self::HostFork
            | Self::ParentPublish
            | Self::VforkSuspend => NativeForkRole::Parent,
            Self::ChildBarrierRepair
            | Self::ChildDispatcherReset
            | Self::ChildRuntimeReset
            | Self::ChildGuestState
            | Self::ChildRuntimeRepairTotal
            | Self::ChildTranslatorRebuild => NativeForkRole::Child,
        }
    }

    /// The wire value for the probe's `phase` argument. Raw escapes ONLY here,
    /// at the USDT boundary.
    #[inline(always)]
    pub const fn raw(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod native_fork_probe_abi {
    use super::{NativeForkPhase, NativeForkRole};

    #[test]
    fn roles_match_the_shared_fork_lifecycle_convention() {
        // `scripts/dtrace/fork-phases.d` keys its aggregations on
        // `(arg0, arg1)`; arg0 must keep meaning what it means on the HVF lane.
        assert_eq!(NativeForkRole::Parent.raw(), 0);
        assert_eq!(NativeForkRole::Child.raw(), 1);
    }

    #[test]
    fn phase_ordinals_are_unique_and_stay_in_the_documented_native_block() {
        let mut seen: Vec<i32> = NativeForkPhase::ALL.map(NativeForkPhase::raw).to_vec();
        let count = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), count, "native fork phase ordinals collided");

        // The native block is 100..=107 (parent) and 120..=125 (child). Every
        // HVF/aarch64 phase in the tree is < 60, so the two lanes cannot alias.
        for phase in NativeForkPhase::ALL {
            let raw = phase.raw();
            match phase.role() {
                NativeForkRole::Parent => assert!(
                    (100..=107).contains(&raw),
                    "{phase:?} = {raw} is outside the documented parent block 100..=107",
                ),
                NativeForkRole::Child => assert!(
                    (120..=125).contains(&raw),
                    "{phase:?} = {raw} is outside the documented child block 120..=125",
                ),
            }
        }
    }

    #[test]
    fn phase_block_membership_matches_the_documented_legend() {
        assert_eq!(NativeForkPhase::TokenAcquire.raw(), 100);
        assert_eq!(NativeForkPhase::SiblingQuiesce.raw(), 101);
        assert_eq!(NativeForkPhase::ExitCleanupDrain.raw(), 102);
        assert_eq!(NativeForkPhase::HelperGates.raw(), 103);
        assert_eq!(NativeForkPhase::PreForkBookkeeping.raw(), 104);
        assert_eq!(NativeForkPhase::HostFork.raw(), 105);
        assert_eq!(NativeForkPhase::ParentPublish.raw(), 106);
        assert_eq!(NativeForkPhase::VforkSuspend.raw(), 107);
        assert_eq!(NativeForkPhase::ChildBarrierRepair.raw(), 120);
        assert_eq!(NativeForkPhase::ChildDispatcherReset.raw(), 121);
        assert_eq!(NativeForkPhase::ChildRuntimeReset.raw(), 122);
        assert_eq!(NativeForkPhase::ChildGuestState.raw(), 123);
        assert_eq!(NativeForkPhase::ChildRuntimeRepairTotal.raw(), 124);
        assert_eq!(NativeForkPhase::ChildTranslatorRebuild.raw(), 125);
    }

    #[test]
    fn probe_wrappers_expose_typed_phase_only_signatures() {
        let _: fn(NativeForkPhase, u64, i64, i64) = super::native_fork_lifecycle;
        let _: fn(NativeForkRole, NativeForkPhase, u64, i64, i64) = super::native_fork_lifecycle_as;
    }
}

#[cfg(test)]
mod dsr_probe_abi {
    use super::{
        DsrCacheEventKind, DsrCacheLifecyclePhase, DsrCacheRole, DsrExecMapDetailKind, DsrExitKind,
        DsrOperationOutcome, DsrPrepareOutcome, DsrResolveKind, DsrSynchronizationKind,
        DsrTranslationSubphase,
    };

    fn assert_unique(values: &[u32]) {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len());
    }

    #[test]
    fn exit_kind_values_match_gateway_status() {
        assert_eq!(DsrExitKind::Syscall.raw(), 1);
        assert_eq!(DsrExitKind::DirectResolver.raw(), 2);
        assert_eq!(DsrExitKind::IndirectResolver.raw(), 3);
        assert_eq!(DsrExitKind::Fault.raw(), 4);
        assert_eq!(DsrExitKind::Kick.raw(), 5);
        assert_eq!(DsrExitKind::Sensitive.raw(), 6);
        assert_eq!(DsrExitKind::Unsupported.raw(), 7);
    }

    #[test]
    fn prepare_outcome_values_are_stable_and_unique() {
        assert_eq!(DsrPrepareOutcome::ResumeEntryHit.raw(), 1);
        assert_eq!(DsrPrepareOutcome::BlockIndexHit.raw(), 2);
        assert_eq!(DsrPrepareOutcome::Translated.raw(), 3);
        assert_eq!(DsrPrepareOutcome::Failed.raw(), 4);
        assert_unique(&DsrPrepareOutcome::ALL.map(DsrPrepareOutcome::raw));
    }

    #[test]
    fn operation_outcome_values_match_dsr_error_categories() {
        assert_eq!(DsrOperationOutcome::Success.raw(), 0);
        assert_eq!(DsrOperationOutcome::PcOverflow.raw(), 1);
        assert_eq!(DsrOperationOutcome::Decode.raw(), 2);
        assert_eq!(DsrOperationOutcome::Malformed.raw(), 3);
        assert_eq!(DsrOperationOutcome::BlockPolicy.raw(), 4);
        assert_eq!(DsrOperationOutcome::MemoryRead.raw(), 5);
        assert_eq!(DsrOperationOutcome::UnsupportedBlockAction.raw(), 6);
        assert_eq!(DsrOperationOutcome::Assembler.raw(), 7);
        assert_eq!(DsrOperationOutcome::Gateway.raw(), 8);
        assert_eq!(DsrOperationOutcome::CachePolicy.raw(), 9);
        assert_eq!(DsrOperationOutcome::GenerationChanged.raw(), 10);
        assert_eq!(DsrOperationOutcome::Host.raw(), 11);
        assert_eq!(DsrOperationOutcome::CacheCapacity.raw(), 12);
        assert_eq!(DsrOperationOutcome::InvalidTarget.raw(), 13);
        assert_unique(&DsrOperationOutcome::ALL.map(DsrOperationOutcome::raw));
    }

    #[test]
    fn resolver_cache_and_dsr_cache_lifecycle_values_are_stable_and_unique() {
        assert_eq!(DsrResolveKind::Direct.raw(), 1);
        assert_eq!(DsrResolveKind::Indirect.raw(), 2);
        assert_unique(&DsrResolveKind::ALL.map(DsrResolveKind::raw));

        assert_eq!(DsrCacheEventKind::BlockHit.raw(), 1);
        assert_eq!(DsrCacheEventKind::BlockMiss.raw(), 2);
        assert_eq!(DsrCacheEventKind::TargetPublish.raw(), 3);
        assert_eq!(DsrCacheEventKind::Invalidate.raw(), 4);
        assert_eq!(DsrCacheEventKind::BlockPublish.raw(), 5);
        assert_eq!(DsrCacheEventKind::CapacityFailure.raw(), 6);
        assert_eq!(DsrCacheEventKind::DirectBindingEligible.raw(), 7);
        assert_eq!(DsrCacheEventKind::DirectBindingPublish.raw(), 8);
        assert_eq!(DsrCacheEventKind::DirectBindingCasLoss.raw(), 9);
        assert_eq!(DsrCacheEventKind::DirectBindingClear.raw(), 10);
        assert_eq!(DsrCacheEventKind::DirectBindingValidationFailure.raw(), 11);
        assert_eq!(DsrCacheEventKind::DirectBindingUnitLoaded.raw(), 12);
        assert_unique(&DsrCacheEventKind::ALL.map(DsrCacheEventKind::raw));

        assert_eq!(DsrCacheRole::Common.raw(), 0);
        assert_eq!(DsrCacheRole::Parent.raw(), 1);
        assert_eq!(DsrCacheRole::Child.raw(), 2);
        assert_unique(&DsrCacheRole::ALL.map(DsrCacheRole::raw));

        assert_eq!(DsrCacheLifecyclePhase::ForkChildRepairBegin.raw(), 1);
        assert_eq!(DsrCacheLifecyclePhase::ForkChildRepairEnd.raw(), 2);
        assert_eq!(DsrCacheLifecyclePhase::ExecResetBegin.raw(), 3);
        assert_eq!(DsrCacheLifecyclePhase::ExecResetEnd.raw(), 4);
        assert_eq!(DsrCacheLifecyclePhase::ExecImageUnmapBegin.raw(), 5);
        assert_eq!(DsrCacheLifecyclePhase::ExecImageUnmapEnd.raw(), 6);
        assert_eq!(DsrCacheLifecyclePhase::ExecImageMapBegin.raw(), 7);
        assert_eq!(DsrCacheLifecyclePhase::ExecImageMapEnd.raw(), 8);
        assert_eq!(DsrCacheLifecyclePhase::ExecCacheResetBegin.raw(), 9);
        assert_eq!(DsrCacheLifecyclePhase::ExecCacheResetEnd.raw(), 10);
        assert_eq!(DsrCacheLifecyclePhase::ExecRelocationBegin.raw(), 11);
        assert_eq!(DsrCacheLifecyclePhase::ExecRelocationEnd.raw(), 12);
        assert_eq!(DsrCacheLifecyclePhase::ExecTranslatorHandoffBegin.raw(), 13);
        assert_eq!(DsrCacheLifecyclePhase::ExecTranslatorHandoffEnd.raw(), 14);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapMmapBegin.raw(), 15);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapMmapEnd.raw(), 16);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapCopyBegin.raw(), 17);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapCopyEnd.raw(), 18);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapIcacheBegin.raw(), 19);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapIcacheEnd.raw(), 20);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapProtectBegin.raw(), 21);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapProtectEnd.raw(), 22);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapVvarBegin.raw(), 23);
        assert_eq!(DsrCacheLifecyclePhase::ExecMapVvarEnd.raw(), 24);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecBegin.raw(), 25);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecEnd.raw(), 26);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecProbesReady.raw(), 27);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecCapsuleBegin.raw(), 28);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecCapsuleEnd.raw(), 29);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecRestoreBegin.raw(), 30);
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecDispatcherReady.raw(),
            31
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecImageLoadBegin.raw(),
            32
        );
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecImageLoadEnd.raw(), 33);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecResetBegin.raw(), 34);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecResetEnd.raw(), 35);
        assert_eq!(DsrCacheLifecyclePhase::HostSelfReexecGuestEntry.raw(), 36);
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreflightBegin.raw(),
            37
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecCapsulePrepareBegin.raw(),
            38
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildBegin.raw(),
            39
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildEnd.raw(),
            40
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateBegin.raw(),
            41
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateEnd.raw(),
            42
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin.raw(),
            43
        );
        assert_eq!(
            DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd.raw(),
            44
        );
        assert_unique(&DsrCacheLifecyclePhase::ALL.map(DsrCacheLifecyclePhase::raw));

        assert_eq!(DsrExecMapDetailKind::Mmap.raw(), 1);
        assert_eq!(DsrExecMapDetailKind::Copy.raw(), 2);
        assert_eq!(DsrExecMapDetailKind::Icache.raw(), 3);
        assert_eq!(DsrExecMapDetailKind::Protect.raw(), 4);
        assert_eq!(DsrExecMapDetailKind::Vvar.raw(), 5);
        assert_unique(&DsrExecMapDetailKind::ALL.map(DsrExecMapDetailKind::raw));

        assert_eq!(DsrTranslationSubphase::Decode.raw(), 1);
        assert_eq!(DsrTranslationSubphase::Plan.raw(), 2);
        assert_eq!(DsrTranslationSubphase::Emit.raw(), 3);
        assert_eq!(DsrTranslationSubphase::PublicationIndex.raw(), 4);
        assert_eq!(DsrTranslationSubphase::DuplicateWait.raw(), 5);
        assert_unique(&DsrTranslationSubphase::ALL.map(DsrTranslationSubphase::raw));

        assert_eq!(DsrSynchronizationKind::GenerationTableWrite.raw(), 1);
        assert_eq!(DsrSynchronizationKind::ProcessStateRead.raw(), 2);
        assert_eq!(DsrSynchronizationKind::ProcessStateWrite.raw(), 3);
        assert_unique(&DsrSynchronizationKind::ALL.map(DsrSynchronizationKind::raw));
    }

    #[test]
    fn probe_wrappers_expose_typed_scalar_only_signatures() {
        let _: fn(i32, u64) = super::dsr_prepare_begin;
        let _: fn(i32, u64, u64, u64, DsrPrepareOutcome) = super::dsr_prepare_end;
        let _: fn(i32, u64, u64, u64) = super::dsr_run_begin;
        let _: fn(i32, DsrExitKind, u64, u64, i32) = super::dsr_run_end;
        let _: fn(i32, u64, u64) = super::dsr_translate_begin;
        let _: fn(i32, u64, u64, u64, DsrOperationOutcome) = super::dsr_translate_end;
        let _: fn(i32, DsrTranslationSubphase, u64, u64) = super::dsr_translate_subphase_begin;
        let _: fn(i32, DsrTranslationSubphase, u64, u64) = super::dsr_translate_subphase_end;
        let _: fn(DsrSynchronizationKind) = super::dsr_synchronization_begin;
        let _: fn(DsrSynchronizationKind) = super::dsr_synchronization_end;
        let _: fn(i32, DsrResolveKind, u64, u64) = super::dsr_resolve_begin;
        let _: fn(i32, DsrResolveKind, u64, u64, DsrOperationOutcome) = super::dsr_resolve_end;
        let _: fn(i32, DsrCacheEventKind, u64, u64, u64) = super::dsr_cache_event;
        let _: fn(DsrCacheRole, u64) = super::dsr_cache_capacity;
        let _: fn(u64, u64) = super::dsr_cache_bounds;
        let _: fn(i32, DsrCacheLifecyclePhase, u64, u64, u64) = super::dsr_cache_lifecycle;
        let _: fn(i32, DsrExecMapDetailKind, u64, u64, u64) = super::dsr_exec_map_detail;
    }
}

#[cfg(test)]
mod host_process_birth_probe_abi {
    use super::{HostProcessBirth, HostProcessBirthError};

    #[test]
    fn process_birth_domain_rejects_invalid_raw_identity() {
        assert!(matches!(
            HostProcessBirth::new(0, 1, 1),
            Err(HostProcessBirthError::ZeroPid)
        ));
        assert!(matches!(
            HostProcessBirth::new(1, 1, 1_000_000),
            Err(HostProcessBirthError::InvalidMicroseconds(1_000_000))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn process_birth_query_is_nonzero_and_stable_for_current_process() {
        let first = HostProcessBirth::query(std::process::id())
            .unwrap_or_else(|error| unreachable!("query current process birth: {error}"));
        let second = HostProcessBirth::query(std::process::id())
            .unwrap_or_else(|error| unreachable!("repeat current process birth: {error}"));
        assert_eq!(first, second);
        assert_eq!(first.pid(), std::process::id());
        assert!(first.start_sec() > 0);
        assert!((0..1_000_000).contains(&first.start_usec()));
    }

    #[test]
    fn process_birth_probe_accepts_only_typed_identity() {
        let _: fn(HostProcessBirth) = super::host_process_birth;
        let source = include_str!("probes.rs");
        for declaration in [
            "fn host__process__birth(_: u32, _: i64, _: i32) {}",
            "stub!(host_process_birth(event: super::HostProcessBirth));",
            "stub!(host_process_birth_current());",
        ] {
            assert!(
                source.contains(declaration),
                "missing process-birth ABI {declaration:?}"
            );
        }
    }
}

#[cfg(test)]
mod translated_range_probe_abi {
    use std::ops::Range;

    use carrick_guest_mem::HostVa;

    use super::{
        TranslatedPrivateRange, TranslatedRangeAdd, TranslatedRangeEpoch, TranslatedRangeError,
        TranslatedRangeKind, TranslatedRangeReady, TranslatedRangeReset, TranslatedRangeSequence,
        TranslatedSharedRange, TranslatedUnitId,
    };

    fn epoch(value: u64) -> TranslatedRangeEpoch {
        TranslatedRangeEpoch::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test epoch must be valid: {error}");
        })
    }

    fn sequence(value: u64) -> TranslatedRangeSequence {
        TranslatedRangeSequence::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test sequence must be valid: {error}");
        })
    }

    fn unit_id(value: u64) -> TranslatedUnitId {
        TranslatedUnitId::new(value).unwrap_or_else(|error| {
            unreachable!("nonzero test unit identity must be valid: {error}");
        })
    }

    #[test]
    fn translated_range_identity_rejects_zero_and_round_trips_named_values() {
        assert!(matches!(
            TranslatedRangeEpoch::new(0),
            Err(TranslatedRangeError::ZeroEpoch)
        ));
        assert!(matches!(
            TranslatedRangeSequence::new(0),
            Err(TranslatedRangeError::ZeroSequence)
        ));
        assert!(matches!(
            TranslatedUnitId::new(0),
            Err(TranslatedRangeError::ZeroUnitId)
        ));

        assert_eq!(epoch(7).get(), 7);
        assert_eq!(sequence(11).get(), 11);
        assert_eq!(unit_id(13).get(), 13);
    }

    #[test]
    fn translated_range_rejects_empty_inverted_and_unaligned_extents() {
        for range in [
            HostVa(0x1000)..HostVa(0x1000),
            HostVa(0x2000)..HostVa(0x1000),
            HostVa(0x1001)..HostVa(0x2000),
            HostVa(0x1000)..HostVa(0x2002),
        ] {
            assert!(
                TranslatedPrivateRange::private(epoch(1), sequence(1), range.clone()).is_err(),
                "malformed private executable extent must be rejected"
            );
            assert!(
                TranslatedSharedRange::shared(epoch(1), sequence(1), unit_id(1), range).is_err(),
                "malformed shared executable extent must be rejected"
            );
        }
    }

    #[test]
    fn translated_range_constructors_make_kind_and_unit_payload_unambiguous() {
        let _: fn(
            TranslatedRangeEpoch,
            TranslatedRangeSequence,
            Range<HostVa>,
        ) -> Result<TranslatedPrivateRange, TranslatedRangeError> = TranslatedPrivateRange::private;
        let _: fn(
            TranslatedRangeEpoch,
            TranslatedRangeSequence,
            TranslatedUnitId,
            Range<HostVa>,
        ) -> Result<TranslatedSharedRange, TranslatedRangeError> = TranslatedSharedRange::shared;

        let private =
            TranslatedPrivateRange::private(epoch(2), sequence(3), HostVa(0x1000)..HostVa(0x2000))
                .unwrap_or_else(|error| unreachable!("valid private range: {error}"));
        let shared = TranslatedSharedRange::shared(
            epoch(2),
            sequence(4),
            unit_id(5),
            HostVa(0x3000)..HostVa(0x4000),
        )
        .unwrap_or_else(|error| unreachable!("valid shared range: {error}"));

        assert_eq!(
            TranslatedRangeAdd::Private(private.clone()).kind(),
            TranslatedRangeKind::PrivateProcessCache
        );
        assert_eq!(
            TranslatedRangeAdd::Shared(shared.clone()).kind(),
            TranslatedRangeKind::SharedUnit
        );
        assert_eq!(private.epoch(), epoch(2));
        assert_eq!(private.sequence(), sequence(3));
        assert_eq!(private.range(), &(HostVa(0x1000)..HostVa(0x2000)));
        assert_eq!(shared.epoch(), epoch(2));
        assert_eq!(shared.sequence(), sequence(4));
        assert_eq!(shared.unit_id(), unit_id(5));
        assert_eq!(shared.range(), &(HostVa(0x3000)..HostVa(0x4000)));
    }

    #[test]
    fn translated_range_kind_ordinals_are_stable_and_unique() {
        assert_eq!(TranslatedRangeKind::PrivateProcessCache.raw(), 1);
        assert_eq!(TranslatedRangeKind::SharedUnit.raw(), 2);
        let mut ordinals = TranslatedRangeKind::ALL
            .map(TranslatedRangeKind::raw)
            .to_vec();
        ordinals.sort_unstable();
        ordinals.dedup();
        assert_eq!(ordinals.len(), TranslatedRangeKind::ALL.len());
    }

    #[test]
    fn translated_range_wrappers_accept_only_typed_pid_free_events() {
        let _: fn(TranslatedRangeReset) = super::host_translated_range_reset;
        let _: fn(TranslatedPrivateRange) = super::host_translated_private_range;
        let _: fn(TranslatedSharedRange) = super::host_translated_shared_range;
        let _: fn(TranslatedRangeReady) = super::host_translated_range_ready;

        let reset = TranslatedRangeReset::reset(epoch(17));
        let ready = TranslatedRangeReady::ready(epoch(17), 23);
        assert_eq!(reset.epoch(), epoch(17));
        assert_eq!(ready.epoch(), epoch(17));
        assert_eq!(ready.final_sequence(), 23);
    }

    #[test]
    fn translated_range_provider_and_stub_keep_one_four_five_two_scalar_shapes() {
        let source = include_str!("probes.rs");
        for declaration in [
            "fn host__translated__range__reset(_: u64) {}",
            "fn host__translated__private__range(_: u64, _: u64, _: u64, _: u64) {}",
            "fn host__translated__shared__range(_: u64, _: u64, _: u64, _: u64, _: u64) {}",
            "fn host__translated__range__ready(_: u64, _: u64) {}",
            "stub!(host_translated_range_reset(event: super::TranslatedRangeReset));",
            "stub!(host_translated_private_range(event: super::TranslatedPrivateRange));",
            "stub!(host_translated_shared_range(event: super::TranslatedSharedRange));",
            "stub!(host_translated_range_ready(event: super::TranslatedRangeReady));",
        ] {
            assert!(
                source.contains(declaration),
                "missing PID-free translated-range ABI declaration {declaration:?}"
            );
        }

        let real_start = source
            .rfind("mod real {")
            .unwrap_or_else(|| unreachable!("real probe module must exist"));
        let stub_start = source
            .rfind("mod stub {")
            .unwrap_or_else(|| unreachable!("stub probe module must exist"));
        let real = &source[real_start..stub_start];
        for (wrapper, next_wrapper) in [
            (
                "pub fn host_translated_range_reset(",
                "pub fn host_translated_private_range(",
            ),
            (
                "pub fn host_translated_private_range(",
                "pub fn host_translated_shared_range(",
            ),
            (
                "pub fn host_translated_shared_range(",
                "pub fn host_translated_range_ready(",
            ),
            (
                "pub fn host_translated_range_ready(",
                "pub fn dsr_cache_lifecycle(",
            ),
        ] {
            let start = real
                .find(wrapper)
                .unwrap_or_else(|| unreachable!("missing real wrapper {wrapper}"));
            let tail = &real[start..];
            let end = tail
                .find(next_wrapper)
                .unwrap_or_else(|| unreachable!("missing wrapper boundary {next_wrapper}"));
            assert!(
                !tail[..end].contains("std::process::id"),
                "{wrapper} must source identity from DTrace's built-in pid"
            );
        }
    }
}

#[cfg(test)]
mod native_owned_range_probe_abi {
    use super::*;

    #[test]
    fn native_owned_range_identity_and_extent_fail_closed() {
        assert_eq!(
            NativeOwnedRangeEpoch::new(0),
            Err(NativeOwnedRangeError::ZeroEpoch)
        );
        assert_eq!(
            NativeOwnedRangeSequence::new(0),
            Err(NativeOwnedRangeError::ZeroSequence)
        );

        let epoch = NativeOwnedRangeEpoch::new(7).expect("nonzero epoch");
        let sequence = NativeOwnedRangeSequence::new(2).expect("nonzero sequence");
        for range in [
            HostVa(0x4000)..HostVa(0x4000),
            HostVa(0x8000)..HostVa(0x4000),
            HostVa(0x4001)..HostVa(0x8000),
            HostVa(0x4000)..HostVa(0x8001),
        ] {
            assert!(NativeOwnedRange::new(epoch, sequence, range, 0x4000).is_err());
        }

        let range = NativeOwnedRange::new(epoch, sequence, HostVa(0x4000)..HostVa(0xc000), 0x4000)
            .expect("aligned nonempty range");
        assert_eq!(range.epoch().get(), 7);
        assert_eq!(range.sequence().get(), 2);
        assert_eq!(range.range(), &(HostVa(0x4000)..HostVa(0xc000)));
    }

    #[test]
    fn native_owned_range_ready_requires_the_exact_nonzero_frontier() {
        let epoch = NativeOwnedRangeEpoch::new(9).expect("nonzero epoch");
        assert_eq!(
            NativeOwnedRangeReady::ready(epoch, 0),
            Err(NativeOwnedRangeError::EmptyCatalog)
        );
        let ready = NativeOwnedRangeReady::ready(epoch, 3).expect("ready frontier");
        assert_eq!(ready.epoch().get(), 9);
        assert_eq!(ready.final_sequence(), 3);
    }

    #[test]
    fn native_owned_range_wrappers_accept_only_typed_events() {
        let _: fn(NativeOwnedRangeReset) = super::host_native_owned_range_reset;
        let _: fn(NativeOwnedRange) = super::host_native_owned_range_add;
        let _: fn(NativeOwnedRangeReady) = super::host_native_owned_range_ready;
    }

    #[test]
    fn native_owned_range_provider_and_stub_abis_are_literal() {
        let source = include_str!("probes.rs");
        for signature in [
            "fn host__native__owned__range__reset(_: u64) {}",
            "fn host__native__owned__range__add(_: u64, _: u64, _: u64, _: u64) {}",
            "fn host__native__owned__range__ready(_: u64, _: u64) {}",
            "stub!(host_native_owned_range_reset(event: super::NativeOwnedRangeReset));",
            "stub!(host_native_owned_range_add(event: super::NativeOwnedRange));",
            "stub!(host_native_owned_range_ready(event: super::NativeOwnedRangeReady));",
        ] {
            assert!(
                source.contains(signature),
                "missing literal ABI: {signature}"
            );
        }
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
))]
mod real {
    //! THEORY OF OPERATION
    //!
    //! These are the static DTrace USDT probes the `carrick trace` tracer (and any
    //! ad-hoc D script) hangs off. The guiding principle is ZERO PERTURBATION when
    //! no consumer is attached: every wrapper here calls a `usdt`-generated probe
    //! that is gated on `is_enabled` at the call site, so a probe with no listening
    //! D script costs a single predicted-not-taken branch. That is why debugging
    //! carrick is supposed to go through these probes rather than `eprintln!`, which
    //! both perturbs timing (and so hides Heisenbugs) and pays its cost
    //! unconditionally.
    //!
    //! Two encoding conventions, chosen per-probe by how hot it is:
    //!
    //!   * RAW POINTER (hot path). A probe that fires on EVERY syscall or trap —
    //!     `syscall__entry`, `vcpu__trap`, `unhandled__syscall` — passes the ADDRESS
    //!     of a `#[repr(C)]` struct ([`crate::compat::SyscallArgs`] /
    //!     [`crate::compat::GuestRegs`]) as a `u64`. The D script does
    //!     `copyin(addr, sizeof)` and reads fields by offset as native `u64`s. This
    //!     avoids building a string on every fire (what made an earlier JSON-encoding
    //!     `carrick trace` slow — the cost was ours, not DTrace's) and, unlike
    //!     `json()`+`strtoll` in D, round-trips a full unsigned 64-bit value exactly.
    //!     The matching struct layouts in the `.d` scripts mirror these `repr(C)`
    //!     definitions field-for-field, so field ORDER is load-bearing.
    //!
    //!   * SCALARS (cold path). A probe that fires only on a rare event —
    //!     `vcpu__fault`, `fork__quiesce`, `lifecycle`, the page-table probes —
    //!     passes its diagnostics as plain scalar args captured at fire time. This is
    //!     more robust when the event is fatal (a fault that kills the process
    //!     immediately would outrun a `copyin`-a-pointer action) and the per-fire
    //!     cost is irrelevant because the probe is off the happy path.
    //!
    //! The `usdt` provider caps a probe at 6 args, which is why composite payloads
    //! ride as a pointer-to-struct rather than expanding into argument lists.

    use crate::compat::{CompatEvent, SyscallArgs};

    #[cfg(target_os = "macos")]
    #[derive(Clone, Debug, serde::Serialize)]
    pub(crate) struct HostImageRange {
        start: u64,
        end: u64,
        path: String,
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone, Debug, serde::Serialize)]
    pub(crate) struct HostImageCatalog {
        pid: u32,
        ranges: Vec<HostImageRange>,
    }

    #[cfg(target_os = "macos")]
    #[derive(Debug)]
    struct HostImageBase {
        pid: u32,
        base: u64,
        slide: i64,
        path: String,
    }

    /// Owned, immutable guest-image path in the exact NUL-terminated wire
    /// shape consumed by DTrace's `copyinstr`.
    #[derive(Debug, Eq, PartialEq)]
    pub struct PreparedGuestImagePath {
        wire: Box<[u8]>,
    }

    impl PreparedGuestImagePath {
        pub fn as_str(&self) -> &str {
            let path = &self.wire[..self.wire.len().saturating_sub(1)];
            // SAFETY: the only constructor consumes a valid `String` and
            // appends one byte; it never changes the original UTF-8 bytes.
            unsafe { std::str::from_utf8_unchecked(path) }
        }
    }

    /// Owned host-image identity collected before a native exec crosses its
    /// mapped-memory point of no return.
    ///
    /// The fields stay private so callers can only fire raw pointers into the
    /// exact prepared NUL buffers. This type is deliberately not `Clone`:
    /// publication after translated-range activation cannot rebuild the dyld
    /// path or reserialize the catalog.
    #[cfg(target_os = "macos")]
    #[derive(Debug)]
    pub struct PreparedHostImagePublication {
        pid: u32,
        base: u64,
        slide: i64,
        base_path_wire: Box<[u8]>,
        catalog_wire: Box<[u8]>,
    }

    /// Cross-target shape for the real USDT arm. Dyld identity exists only on
    /// macOS, but the runtime is platform-checked with the same probe surface.
    #[cfg(not(target_os = "macos"))]
    #[derive(Debug)]
    pub struct PreparedHostImagePublication;

    /// USDT probes for the carrick provider. The `usdt` crate's hard cap is
    /// 6 args per probe, so syscall args ride as a `&SyscallArgs` reference
    /// — usdt JSON-encodes it through serde and passes the resulting
    /// C-string pointer to DTrace. Consumers use `copyinstr(argN)` to read
    /// the JSON (looks like `[v0,v1,v2,v3,v4,v5]`).
    #[usdt::provider(provider = "carrick")]
    mod carrick_usdt {
        /// Process incarnation from Darwin `PROC_PIDTBSDINFO`.
        fn host__process__birth(_: u32, _: i64, _: i32) {}
        // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6], contiguous); DTrace
        // does `copyin(arg2, 48)` and reads the six args by offset. This probe
        // fires on EVERY guest syscall, so we must NOT JSON-encode here — that
        // string-builds on every fire even for a script that only wants one
        // syscall, which is what made `carrick trace` slow (DTrace itself is
        // production-safe; the cost was ours). Same raw-pointer trick as
        // `vcpu__trap`.
        fn syscall__entry(_: u64, _: &str, _: u64) {}
        fn syscall__return(_: u64, _: &str, _: i64, _: i32) {}
        /// Full native guest syscall service boundaries. Unlike dispatcher
        /// entry/return, these span waits, outcome lowering, and completion.
        fn native__syscall__service__entry(_: u64, _: &str) {}
        fn native__syscall__service__branch(_: u32) {}
        fn native__syscall__service__end(_: u64, _: &str, _: u32) {}
        /// Low-rate Tier-D Mach-exception lifecycle. Args: phase, host pid,
        /// and four phase-specific scalars. This never fires on ordinary
        /// guest execution or syscall service.
        fn native__tierd__exception(_: u32, _: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// First terminal Tier-D unsupported/error outcome for one process.
        /// Args: host pid, Linux syscall number, and the owned diagnostic
        /// detail. `u64::MAX` is the driver-error sentinel for a failure outside
        /// syscall service. This names otherwise-silent fork-child `_exit(125)`
        /// failures.
        fn native__tierd__unsupported(_: u32, _: u64, _: &str) {}
        /// HVF syscall-transport attribution. `transport`: 0=legacy, 1=mailbox;
        /// `phase`: 0=request decode, 1=ordinary return publication. The final
        /// three counters are actual HVF register/sysreg API operations in that
        /// phase, not inferred wall-time attribution.
        fn hvf__syscall__transport(_: u32, _: u32, _: u32, _: u32, _: u32) {}
        // The Rust provider accepts six arguments, but macOS has returned a
        // constant zero for arg5 at real DSR probe sites. Keep this scalar ABI
        // at five arguments or fewer and use a low-frequency companion probe
        // when another value is required.
        /// DSR guest-entry preparation boundaries. All arguments are copied
        /// scalars so disabled probes do not materialize diagnostic state.
        fn dsr__prepare__begin(_: i32, _: u64) {}
        fn dsr__prepare__end(_: i32, _: u64, _: u64, _: u64, _: u32) {}
        /// One translated execution slice, from gateway entry to typed exit.
        fn dsr__run__begin(_: i32, _: u64, _: u64, _: u64) {}
        fn dsr__run__end(_: i32, _: u32, _: u64, _: u64, _: i32) {}
        /// Block decode, planning, emission, and publication boundaries.
        fn dsr__translate__begin(_: i32, _: u64, _: u64) {}
        fn dsr__translate__end(_: i32, _: u64, _: u64, _: u64, _: u32) {}
        fn dsr__translate__subphase__begin(_: i32, _: u32, _: u64, _: u64) {}
        fn dsr__translate__subphase__end(_: i32, _: u32, _: u64, _: u64) {}
        /// Host synchronization acquisition boundaries.
        fn dsr__synchronization__begin(_: u32) {}
        fn dsr__synchronization__end(_: u32) {}
        /// Direct and indirect translated-control-flow resolution boundaries.
        fn dsr__resolve__begin(_: i32, _: u32, _: u64, _: u64) {}
        fn dsr__resolve__end(_: i32, _: u32, _: u64, _: u64, _: u32) {}
        /// Translation-cache activity and fork/exec lifecycle boundaries.
        fn dsr__cache__event(_: i32, _: u32, _: u64, _: u64, _: u64) {}
        fn dsr__cache__capacity(_: u32, _: u64) {}
        fn dsr__cache__bounds(_: u64, _: u64) {}
        fn host__translated__range__reset(_: u64) {}
        fn host__translated__private__range(_: u64, _: u64, _: u64, _: u64) {}
        fn host__translated__shared__range(_: u64, _: u64, _: u64, _: u64, _: u64) {}
        fn host__translated__range__ready(_: u64, _: u64) {}
        fn host__native__owned__range__reset(_: u64) {}
        fn host__native__owned__range__add(_: u64, _: u64, _: u64, _: u64) {}
        fn host__native__owned__range__ready(_: u64, _: u64) {}
        fn dsr__cache__lifecycle(_: i32, _: u32, _: u64, _: u64, _: u64) {}
        fn dsr__exec__map__detail(_: i32, _: u32, _: u64, _: u64, _: u64) {}
        // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6]); DTrace copyin's 48
        // bytes — same raw-pointer convention as `syscall__entry`, no JSON.
        fn unhandled__syscall(_: u64, _: &str, _: u64) {}
        fn partial__syscall(_: u64, _: &str, _: u64, _: &str) {}
        fn unhandled__ioctl(_: i32, _: u64, _: u64) {}
        fn proc__read__unimplemented(_: &str) {}
        fn sys__read__unimplemented(_: &str) {}
        fn signal__unsupported(_: i32, _: &str) {}
        // pid, signum, generation — fires when an interval-timer thread publishes.
        fn itimer__fire(_: u32, _: i32, _: u64) {}
        /// Fires on every guest syscall that passes flag bits we don't
        /// recognise. Catches Linux ABI drift loudly instead of letting
        /// the dispatcher silently drop behaviour the guest expected.
        fn unknown__syscall__flags(_: u64, _: &str, _: u32, _: u64) {}
        /// Fires before `libc::fork` from the trap engine's clone path.
        /// Args are the captured pre-fork vCPU PC, ELR_EL1, and CPSR.
        fn fork__pre(_: u64, _: u64, _: u64) {}
        /// Fires after the parent/child have rebuilt their HVF context and
        /// restored the snapshot. `pid` is the libc::fork return value
        /// (0 in the child, child pid in the parent).
        fn fork__post(_: i32, _: u64, _: u64) {}
        /// Fork stop-the-world quiesce trace. `phase`: 0=begin (a=others to wait
        /// for, b=kicker live count), 1=quiesce TIMEOUT (a=others, b=paused),
        /// 2=hv_vm_destroy result (a=rc — NONZERO means a vCPU was still live, the
        /// HV_BUSY root cause), 3=vcpu_create result in a sibling rebuild / spawn
        /// (a=rc, b=site: 0=rebuild 1=spawn). `tid` is the acting thread.
        fn fork__quiesce(_: i32, _: i64, _: i64, _: i32) {}
        /// Fork rebuild detail. `role`: 0=parent, 1=child. `phase`: 0=begin,
        /// 1=local-map-end, 2=sibling-map-end, 3=restore-end. `desc_count` is the
        /// local descriptor set for phases 0/1/3 and the sibling candidate set for
        /// phase 2. `map_count` is the number of `hv_vm_map` calls completed in
        /// that phase. `elapsed_us` is measured from the phase start, except phase
        /// 3 which is total rebuild elapsed.
        fn fork__rebuild(_: i32, _: i32, _: u64, _: u64, _: u64) {}
        /// Fork lifecycle phase timing. `role`: 0=runtime-parent/common,
        /// 1=runtime-child, 2=aarch64-parent/common, 3=aarch64-child,
        /// 4=hvf-parent/common, 5=hvf-child. `phase` is domain-local and
        /// documented in the E2.1 evidence artifact; `elapsed_us` is the
        /// just-finished phase duration. `a` and `b` are phase-specific counts or
        /// return codes.
        fn fork__lifecycle(_: i32, _: i32, _: u64, _: i64, _: i64) {}
        /// Fork address-space footprint sample. `phase` is sample-local; current
        /// E2.2 diagnostics use 0=immediately-before-host-fork. The remaining
        /// fields are host VM region count, guest mmap-arena high-water, current
        /// resident bytes, and current virtual bytes.
        fn fork__footprint(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Fork footprint attribution by HVF guest mapping class. Args are:
        /// class id, region count, scanned bytes, resident bytes, and flags.
        fn fork__footprint__class(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Per-run lifecycle marker, one probe fired at each phase boundary so a
        /// DTrace consumer can time each phase as a delta. `phase`:
        /// 0=run-entry, 1=image-ready, 2=vm-created, 3=guest-loaded (ready to run),
        /// 4=first-vcpu-run, 5=vm-destroy-begin, 6=vm-destroy-end. (guest-exit has
        /// its own probe between 4 and 5.) Cheap: fires a handful of times per run.
        fn lifecycle(_: u32) {}
        /// Every Hypervisor.framework VM ownership transition. `operation`:
        /// 0=create-attempt, 1=create-success, 2=destroy-attempt,
        /// 3=destroy-success. `admission` is the backend's admission class for
        /// create operations and -1 for destroy operations. This is distinct
        /// from `lifecycle`: exec/fork may transition VM ownership more than once
        /// during one Carrick run.
        fn vm__lifecycle(_: u32, _: i32) {}
        /// Linux guest lifecycle inside a shared hvpatch VM. Unlike `proc:::`
        /// and `fork__post`, these identities are guest namespace values, not
        /// Darwin host PIDs. Args: phase, pid, ppid, tid, ASID. The process-exit
        /// detail is a companion probe because macOS zeros a sixth USDT arg.
        fn hvpatch__guest__lifecycle(_: u32, _: i32, _: i32, _: i32, _: u32) {}
        /// Companion unambiguous identity for `hvpatch__guest__lifecycle`:
        /// guest PID, this generation's `TaskSerial`, the parent generation's
        /// `TaskSerial` (0 when there is no parent), and the `MmId`.
        ///
        /// Split into its own probe because a Linux TGID and an ASID are both
        /// recycled within a run, so `(pid, asid)` cannot tell two generations
        /// apart, and the lifecycle probe is already at macOS's five-reliable-
        /// argument limit. Consumers join the two on PID within one firing.
        fn hvpatch__guest__lifecycle__identity(_: i32, _: u64, _: u64, _: u64) {}
        /// Terminal process detail. Args: guest PID, guest TID, ASID, exit code.
        fn hvpatch__guest__exit(_: i32, _: i32, _: u32, _: i64) {}
        /// AArch64 guest fault with Linux process/thread identity and stage-1
        /// context. Args: ESR, ELR, FAR, guest PID, guest TID. ASID is emitted
        /// separately to stay below macOS's five-reliable-argument limit.
        fn hvpatch__guest__fault(_: u64, _: u64, _: u64, _: i32, _: i32) {}
        /// Companion identity for `hvpatch__guest__fault`: PID, TID, ASID.
        fn hvpatch__guest__fault__asid(_: i32, _: i32, _: u32) {}
        /// Address-space provenance: guest PID, ASID, bank base, bank size,
        /// TTBR0. Five scalars keep the complete record reliable on macOS.
        fn hvpatch__guest__address__space(_: i32, _: u32, _: u64, _: u64, _: u64) {}
        /// Completed Linux syscall service. Args: Linux guest PID, Linux guest
        /// TID, ASID, Linux syscall number, and monotonic duration nanoseconds.
        fn hvpatch__syscall__service__begin(_: i32, _: i32, _: u32, _: u64) {}
        /// Raw Linux syscall arguments paired with the immediately preceding
        /// enabled service-begin event on the same host thread. Args: Linux
        /// syscall number, then guest arg0..arg3. The typed begin supplies guest
        /// PID/TID/ASID; five scalars keep this companion reliable on macOS.
        fn hvpatch__syscall__args(_: u64, _: u64, _: u64, _: u64, _: u64) {}
        fn hvpatch__syscall__service(_: i32, _: i32, _: u32, _: u64, _: u64) {}
        /// Distinct post-completion retirement marker. Keeping this separate
        /// lets DTrace consumers read and then clear thread-local join state
        /// without relying on action ordering within one probe clause.
        fn hvpatch__syscall__service__clear(_: i32, _: i32, _: u32, _: u64) {}
        /// Fork snapshot timing anchor. Args: child guest PID and the guest TID
        /// that issued clone/fork. Consumers key `timestamp` by child PID and
        /// subtract it from `hvpatch__fork__snapshot__end`.
        fn hvpatch__fork__snapshot__begin(_: i32, _: i32) {}
        /// Fork snapshot census. Args: child PID, mappings already local to the
        /// forking vCPU, process-scoped alias candidates, aliases selected by the
        /// live page tables, and selected bytes.
        fn hvpatch__fork__snapshot__end(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Fork snapshot shape companion. Args: child PID, selected private
        /// regions, selected shared regions, largest selected extent, and bytes
        /// consumed in the child's private stage-2 bank.
        fn hvpatch__fork__snapshot__shape(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Exec bank-layout cache result. Args: phase (0=miss, 1=hit), process
        /// bank base, mapping count, bounded process-wide cache entries, and
        /// lookup plus construction elapsed nanoseconds. Join bank base to
        /// `hvpatch__guest__address__space` for guest PID and ASID.
        fn hvpatch__exec__bank__layout(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Exec-image host backing result. Args: phase (0=materialized,
        /// 1=reused, 2=fresh MAP_PRIVATE view of a cached patched artifact),
        /// Linux guest VA, process-bank IPA, mapped bytes, and lookup plus
        /// allocation/copy elapsed nanoseconds.
        fn hvpatch__exec__backing(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Raw stage-2 exec transition. Args: phase (0=unmap begin, 1=unmap
        /// end, 2=map begin, 3=map end), IPA, size, guest VA (`UINT64_MAX`
        /// when the unmap ledger has only an IPA extent), and raw HVF rc.
        fn hvpatch__exec__stage2(_: u32, _: u64, _: u64, _: u64, _: i32) {}
        /// Coarse persistent-VM exec replacement stage. Args: phase
        /// (0=alias cleanup, 1=drop old backings, 2=page-table manager,
        /// 3=map new backings, 4=registers, 5=mailbox, 6=private-file
        /// artifacts, 7=bank plan, 8=old address-space teardown), elapsed
        /// nanoseconds, replacement mapping count, and total mapped bytes.
        fn hvpatch__exec__replace__stage(_: u32, _: u64, _: u64, _: u64) {}
        /// Outer successful exec runtime stage. Args: phase (0=proc state,
        /// 1=close-on-exec, 2=sibling drain, 3=topology lock, 4=engine replace,
        /// 5=publication), elapsed nanoseconds, image region count, and mapped
        /// bytes. The engine-replace phase encloses the inner replacement-stage
        /// ledger rather than overlapping its siblings.
        fn hvpatch__exec__runtime__stage(_: u32, _: u64, _: u64, _: u64) {}
        /// Shared-HVF topology-lock lifecycle. Args: operation (0=in-process
        /// fork, 1=exec replacement, 2=exec sibling gate, 3=sibling
        /// materialization, 4=vCPU rebind, 5=VM release, 6=legacy fork,
        /// 7=process retire), phase (0=requested, 1=acquired, 2=released,
        /// 3=try miss), Linux guest PID, Linux guest TID, and wait/hold elapsed
        /// nanoseconds.
        fn hvpatch__topology__lock(_: u32, _: u32, _: i32, _: i32, _: u64) {}
        /// Parent-thread stages inside one in-process-fork topology critical
        /// section. Args: phase (0=quiesce, 1=process allocation, 2=pidfd and
        /// parent-TID publication, 3=process spec, 4=dispatcher clone,
        /// 5=runtime state, 6=thread spawn, 7=child ready, 8=publication,
        /// 9=cumulative total enclosing phases 0..=8), parent PID, child PID
        /// (zero before allocation), forking TID, elapsed nanoseconds.
        fn hvpatch__fork__runtime__stage(_: u32, _: i32, _: i32, _: i32, _: u64) {}
        /// Mutually exclusive process-spec construction stages. Args: phase
        /// (0=parent tables load, 1=vCPU snapshot, 2=parent table clone,
        /// 3=rebase, 4=alias union, 5=private snapshot, 6=validation,
        /// 7=table publish, 8=backend protections, 9=backend finalization,
        /// 10=wrapper protections, 11=cumulative total), Linux child PID,
        /// Linux forking TID, elapsed nanoseconds, and stage-specific units.
        fn hvpatch__fork__process__spec__stage(_: u32, _: i32, _: i32, _: u64, _: u64) {}
        /// Per-private-mapping snapshot timing. Args: Linux child PID, Linux
        /// forking TID, guest virtual start, mapped bytes, elapsed nanoseconds.
        /// Classification is a companion probe to respect macOS's five-reliable-
        /// USDT-argument ceiling.
        fn hvpatch__fork__private__snapshot(_: i32, _: i32, _: u64, _: u64, _: u64) {}
        /// Per-private-mapping snapshot classification. Args: Linux child PID,
        /// Linux forking TID, guest virtual start, stable mapping role
        /// (1..=9), mechanism (0=Mach COW remap, 1=sparse-copy fallback).
        fn hvpatch__fork__private__snapshot__outcome(_: i32, _: i32, _: u64, _: u32, _: u32) {}
        /// One in-process-fork sibling-quiesce result. Args: parent PID,
        /// forking TID, initial sibling-vCPU count, 200-us poll iterations, and
        /// elapsed nanoseconds.
        fn hvpatch__fork__quiesce(_: i32, _: i32, _: u32, _: u64, _: u64) {}
        /// Fires every syscall trap. `arg0` is the ADDRESS of a
        /// `compat::GuestRegs` (`#[repr(C)]`); DTrace does
        /// `copyin(arg0, sizeof(gregs_t))` and reads fields by offset. A
        /// raw pointer (not JSON) keeps this hot probe cheap and lets D
        /// read full u64 register values exactly.
        fn vcpu__trap(_: u64) {}
        /// Fires when a guest EL0 sync exception other than `svc #0` reaches the
        /// trap loop (the fatal `EL0Fault` path) — an instruction/data abort or
        /// undefined instruction that crashes the guest. Args: `esr`, `elr`, `far`,
        /// `x30`(LR), `sp`(SP_EL0), `tid`. Fires only on the fault, so a
        /// `carrick trace` script can `--stack`-walk the faulting guest thread with
        /// near-zero hot-path overhead (it never fires on the happy path). The key
        /// diagnostic for the c>=20 sibling-vCPU corruption faults.
        fn vcpu__fault(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
        /// Companion to `vcpu__fault` carrying the decoded fault diagnostics as
        /// SCALARS (captured at probe-fire time — robust even when the fault kills
        /// the process immediately, unlike a copyin-a-pointer probe whose action
        /// runs too late). `insn` is the faulting instruction word (read through
        /// the active guest address space at `elr`; `UINT64_MAX` means unreadable),
        /// `rn` is the base register a
        /// load/store dereferenced (`(insn>>5)&0x1f`); `xrn` is that register's
        /// value, BEST-EFFORT (read after the EL1 trap trampoline, which may have
        /// clobbered it). The AUTHORITATIVE faulting pointer is `far` (HW-latched):
        /// for a data abort `far == base + imm`, so a `ldr xN,[xN,#8]` with far=0x19
        /// means the base held 0x11=17. Lets a trace see the faulting access
        /// WITHOUT an eprintln rebuild. Fires only at the fault.
        fn vcpu__fault__regs(_: u64, _: u64, _: u64, _: u64, _: u32, _: u64) {}
        /// Native x86 synchronous guest fault captured before fatal-signal
        /// teardown. Args: host pid, guest PC, fault VA, RSP, RCX, RFLAGS.
        /// Scalars remain readable after an immediately exiting fork child.
        fn native__x86__fault(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion register payload for `native__x86__fault`. Args: host pid,
        /// RAX, RDX, RDI, RSI, R8. Split because the USDT backend supports six
        /// arguments per probe.
        fn native__x86__fault__regs(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Guest stack values at a native x86 fault. Args: host pid, qwords at
        /// RSP+0x18, RSP+0x20, RSP+0x30, and RSP+0x38, plus RBP. These offsets
        /// expose common saved-register/frame layouts without asking DTrace to
        /// dereference an identity-mapped guest VA after process teardown.
        fn native__x86__fault__stack(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Last five gateway-entered guest PCs before a native x86 fault.
        /// Chained interior blocks do not appear; the sequence identifies the
        /// indirect/syscall boundaries that led into the failing chain.
        fn native__x86__fault__history(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Opt-in native x86 guest-PC observation. Args: host pid, guest PC,
        /// RSP, RDI, RBP, and the qword at RSP. Enabled only when the
        /// runtime's targeted-PC diagnostic is configured.
        fn native__x86__pc(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Opt-in native x86 indirect-control resolution. Args: host pid,
        /// source guest PC, resolved target PC, RSP, RDI, and RBP.
        fn native__x86__resolve(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Selected native-x86 xstate transition. Args: host pid, source guest
        /// PC, target guest PC, event kind, decision flags, and XSTATE_BV.
        fn native__x86__xstate__edge(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Control fields for the selected xstate transition. Args: host pid,
        /// source PC, FCW, MXCSR, PKRU, and the full extended-state hash.
        fn native__x86__xstate__controls(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Component hashes for the selected xstate transition. Args: host pid,
        /// source PC, legacy, YMM, opmask/ZMM, and full extended-state hashes.
        fn native__x86__xstate__hashes(_: u32, _: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Fires from `map_host_alias` (the post-boot high-VA hv_vm_map path) with
        /// the MANAGER's L0..L3 stage-1 descriptors for the alias VA + whether this
        /// is a forked child and whether the page-table build succeeded (rc: 0 ok,
        /// else nonzero). Diagnoses why a forked child's alias mapping diverges from
        /// the parent's. Fires only on this path (no hot-path cost).
        fn pt__alias__walk(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
        /// Fires from `map_host_alias` right after the stage-2 `hv_vm_map` with the
        /// alias VA/IPA/size and the raw `hv_return_t` (`rc`: 0 ok). Diagnoses an
        /// hv_vm_map failure in a forked child (the stage-2 coherence wall) before
        /// the page-table build is even attempted. `forked` bit: this is a forked child.
        fn hv__vm__map__alias(_: u64, _: u64, _: u64, _: i32, _: i32) {}
        /// Fires when a signal is published for later delivery. `target_tid` is the
        /// guest tid for a thread-directed signal (tkill/tgkill route) or 0 for a
        /// process-directed one; `signum` the Linux signum; `kind` 1=thread-directed
        /// 0=process-directed. Lets `carrick trace` see WHERE a signal was routed
        /// (vs which tid actually drains it via `signal-deliver`) — the missing
        /// visibility for the cross-thread / blocked-thread delivery bugs.
        fn signal__publish(_: i32, _: i32, _: i32) {}
        /// Fires every time the dispatcher routes a `futex(2)` syscall. `pid`,
        /// `addr` (guest VA of the futex word), `op` (FUTEX_WAIT=0 / WAKE=1 / ...),
        /// `shared` (1 = routed through `__ulock` because the address lives in a
        /// host-MAP_SHARED region; 0 = routed through the per-process parking lot).
        /// A WAKE that returns 0 on a `shared=1` address but the waiter exists in
        /// another process — that's the cross-process rendezvous failing.
        fn futex__route(_: u32, _: u64, _: i32, _: i32, _: u64) {}
        /// Fires at each `ulock::wait` entry and exit. `pid`, `host_addr`,
        /// `value`, `timeout_us`, `phase` (0=entry, 1=exit), `rc` (exit only).
        fn ulock__wait(_: u32, _: u64, _: u32, _: u32, _: i32, _: i64) {}
        /// Fires for each iteration of the dispatcher's FUTEX_WAKE loop:
        /// `pid`, `host_addr`, `iter`, `rc` (0 on wake-one success, <0 on ENOENT).
        fn ulock__wake(_: u32, _: u64, _: i32, _: i64) {}
        /// Raw-pointer payload for shared-futex requeue side-table accounting.
        /// See `UlockRequeueProbe`; phase 0=before host requeue, 1=after.
        fn ulock__requeue(_: u64) {}
        /// A cross-process futex wait slice returned a host errno OUTSIDE the
        /// Linux FUTEX_WAIT set (not ETIMEDOUT/EINTR), which the shared ABI guard
        /// folds to a spurious wake instead of leaking it (glibc nptl would abort
        /// on it). `pid`, `host_addr`, `errno` (the raw host errno swallowed).
        /// Fires on EVERY backend (HVF/KVM/bhyve/NVMM) from the one shared seam,
        /// so a host whose futex primitive returns a surprising errno is visible
        /// on the bring-up lanes, not just macOS. Frequent fires = a real
        /// host-futex mismatch worth a spec, not just noise.
        fn futex__unexpected__errno(_: u32, _: u64, _: i32) {}
        /// Fires at each `deliver_pending_signal` cycle. `tid` is the delivering
        /// thread; `pending` the signum it drained (0 = nothing deliverable to it).
        /// Pair with `signal-publish` to see a signal published for tid X but never
        /// drained by X (the routing/tid-mismatch and blocked-thread cases).
        fn signal__deliver(_: i32, _: i32) {}
        /// Fires when `execve_into` has finished swapping the engine to
        /// the new image. `path`, `entry`, `initial_sp`, `mapping_count`
        /// let dtrace operators verify the new process layout.
        fn execve__loaded(_: &str, _: u64, _: u64, _: u64) {}
        /// Fires at the tail of `execve_into` with the actual SCTLR/TTBR0/
        /// MAIR values read back from HVF. Use this to verify the new
        /// process's stage-1 MMU state matches what the fresh-from-cli
        /// case sets up.
        fn execve__sysregs(_: u64, _: u64, _: u64) {}
        /// Fires every time the dispatcher's `open_at_path` resolves a
        /// guest path. `pid` is the carrick-host pid (so the parent vs
        /// forked-children streams are demultiplexable). `result_size`
        /// is the bytes returned (for File) or `0` (for Directory /
        /// errno). `errno` is `0` on success.
        fn path__open(_: u32, _: &str, _: u64, _: i32) {}
        /// Fires when a guest process exits via exit_group. `pid` is the
        /// carrick-host pid; correlate with `execve__loaded` (same pid) to
        /// see which binary exited with which code.
        fn guest__exit(_: u32, _: i32) {}
        /// M:N scheduler — a guest thread was ADMITTED to a vCPU slot (a new
        /// `clone` sibling, or the main reservation). `tid` guest thread, `slot`
        /// the granted vCPU id, `budget` the pool size N (`usize::MAX`-clamped to
        /// u32 on unbounded HVF/KVM). Pair with `mn__reclaim` to trace the M:N
        /// lifecycle of a guest thread over the bounded vCPU pool.
        fn mn__admit(_: i32, _: u32, _: u32) {}
        /// M:N scheduler — a BLOCKING guest thread's reclaim decision (the heart of
        /// the M:N: how a thread time-shares the bounded vCPU pool). `tid` guest
        /// thread, `old_slot` the slot it held entering the block, `new_slot` the
        /// slot it holds on wake, `kind`: 0=PARKED (uncontended — kept its vCPU, no
        /// reclaim, the fast path), 1=RECLAIMED and got its OWN slot back (no
        /// re-bind), 2=RECLAIMED onto a DIFFERENT slot (full state re-bind — another
        /// thread ran on its vCPU while it blocked). A trace can compute the
        /// reclaim/park ratio and spot re-bind storms.
        fn mn__reclaim(_: i32, _: u32, _: u32, _: i32) {}
        /// Fires on execve with the joined argv (space-separated), so
        /// dtrace operators can see exactly how the guest invokes a
        /// child (e.g. apt's sqv method calling /usr/bin/sqv).
        fn execve__argv(_: u32, _: &str, _: &str) {}
        /// This process's own carrick image base and ASLR slide.
        ///
        /// Guest processes on the native lane are host processes that
        /// SELF-REEXEC, so each carries a different slide from the supervisor
        /// and from its siblings. DTrace resolves a user PC to a symbol only
        /// while the owning process is still alive; guest toolchain processes
        /// live for milliseconds to seconds, so by the time a profile is read
        /// almost every sampled PC belongs to a process that no longer exists
        /// and resolves to bare hex. A profile that cannot name its own hot
        /// code is not evidence.
        ///
        /// Firing this once per guest process lets a consumer keep a pid ->
        /// base map and symbolicate OFFLINE, after exit, against the on-disk
        /// binary (`scripts/symbolicate.py`). `guest_base` carries the guest
        /// ELF's load address for the same reason: the native lane maps guest
        /// text into the same address space, so a sampled PC can legitimately
        /// land in the guest image rather than in ours.
        fn host__image__base(_: u32, _: u64, _: i64, _: *const u8) {}
        /// Exact half-open executable range of this process's Carrick image.
        ///
        /// Unlike `host-image-base`, this has no path or catalog payload. It is
        /// safe to fire at every native image activation: dyld range discovery
        /// runs inside the USDT closure and is therefore zero-work when no
        /// consumer enables the probe.
        #[cfg(target_os = "macos")]
        fn host__image__text__range(_: u32, _: u64, _: u64) {}
        /// Executable dyld image ranges for this process.
        ///
        /// The caller supplies the already encoded
        /// `{"ok":<compact-json>}\0` wire buffer. `usdt` receives only its
        /// retained raw pointer and performs no serialization at probe fire.
        #[cfg(target_os = "macos")]
        fn host__image__catalog(_: *const u8) {}
        /// The INNER guest image: `pid`, load base, entry, and path.
        ///
        /// Reported separately from `host-image-base` because they are two
        /// different files at two different bases sharing one address space.
        /// A guest PC resolved against carrick's symbol table produces a name,
        /// not an error -- so the two must never be conflated.
        fn guest__image__base(_: u32, _: u64, _: u64, _: *const u8) {}
        /// Half-open executable range of this process's anonymous DSR cache.
        ///
        /// A sampled PC outside the host and guest images may be translated
        /// code or a system dylib. The exact range lets a profiler distinguish
        /// those cases without an address-layout heuristic.
        fn host__jit__range(_: u32, _: u64, _: u64) {}
        /// Host-pipe I/O: `dir` is 0 for read, 1 for write; `n` is the
        /// byte count (negative on error). Used to trace whether a forked
        /// child's stdout actually reaches the parent's pipe read.
        fn host__pipe__io(_: u32, _: i32, _: i32, _: i64) {}
        /// epoll_ctl decision: decoded guest event values without forcing DTrace
        /// scripts to copyin guest memory. `errno` is zero on success.
        fn epoll__ctl(_: i32, _: u64, _: i32, _: u32, _: u64, _: i32) {}
        /// Per-interest epoll_pwait readiness decision. `requested`, `raw_ready`,
        /// `last_ready`, and `ready` are Linux epoll event bitmasks.
        fn epoll__interest(_: i32, _: i32, _: u32, _: u32, _: u32, _: u32) {}
        /// Masked epoll readiness sample. Arg0 is the ADDRESS of an
        /// `EpollMaskedProbe` payload.
        fn epoll__masked(_: u64) {}
        /// Epoll host-registration rebind decision. Arg0 is the ADDRESS of an
        /// `EpollRebindProbe` payload.
        fn epoll__rebind(_: u64) {}
        /// Host-backed fd that epoll_pwait hands to the runtime's kqueue waiter.
        /// `poll_events` is the libc POLL* mask used to build EVFILT registrations.
        fn epoll__wait__fd(_: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// epoll_pwait result decision. `kind` is 0 for immediate guest return and
        /// 1 for WaitOnFds handoff.
        fn epoll__result(_: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// A drained multiplexer edge whose `(guest_fd, generation)` udata handle no
        /// longer matches any live interest — a stale edge for a recycled fd (the
        /// ABA hazard). Dropped, not mis-delivered; fires here so the recycle race is
        /// observable rather than silent.
        fn epoll__stale__edge(_: u64, _: i32, _: u32) {}
        /// Runtime blocking-I/O wait begin. `tid` is the guest thread id,
        /// `timeout_ms` is -1 for infinite, and fd0/events0 + fd1/events1 are the
        /// first two host fd wait targets.
        fn io__wait__begin(_: i32, _: i32, _: i64, _: i32, _: i32, _: i32) {}
        /// Runtime blocking-I/O wait end. `result` is 0=Ready, 1=TimedOut,
        /// 2=Interrupted; fd0/fd1/fd2 are the first host fds from the wait set.
        fn io__wait__end(_: i32, _: i32, _: i32, _: i32, _: i32, _: i32) {}
        /// Fires on a filesystem-backend decision/outcome. `op` names the
        /// operation + result (e.g. "set_times:ok", "set_times:open_none",
        /// "set_times:futimens_err", "unlink", "rename"), `path` is the
        /// resolved guest path, `errno` is the Linux errno carrick returns
        /// (0 on success). Lets `carrick trace` see WHY a host-backed fs
        /// syscall returned an errno — the internal reason invisible to the guest.
        fn fs__op(_: u32, _: &str, _: &str, _: i32) {}
        /// Fires when a guest signal handler frame is injected. `signum` is the
        /// Linux signal, `saved_pc` the pre-signal PC stored in the sigframe (the
        /// PC the eventual rt_sigreturn must restore), `new_sp` the SP_EL0 the
        /// frame was written at, `handler` the guest handler entry. Lets a trace
        /// see exactly what state is captured for later restore.
        fn signal__inject(_: i32, _: u64, _: u64, _: u64) {}
        /// Fires inside rt_sigreturn/restore. `saved_pc` is the PC about to be
        /// restored into ELR_EL1, `sp` the SP_EL0 the frame was read from,
        /// `magic` the frame magic read back. A corrupted `saved_pc` or `magic`
        /// here pinpoints sigframe corruption (the "PROT_REA" wild-PC crash).
        fn signal__restore(_: u64, _: u64, _: u64) {}
        /// Fires when a cross-thread kick (`hv_vcpus_exit`) lands while the vCPU is
        /// still executing carrick's EL1 trap trampoline (not at guest EL0). `pc` is
        /// the EL1 PC, `el` the current exception level (1+). carrick resumes
        /// instead of injecting a signal at this non-guest PC; a nonzero rate here
        /// is the signal-vs-trampoline race being correctly absorbed.
        fn kick__in_kernel(_: u64, _: u32) {}
        /// Cumulative kick/inject counters fired once at process exit (cheap, one
        /// fire per process) so a trace can read the totals without paying the
        /// per-event `kick-in-kernel` cost: `el1_resumed` (kicks absorbed in the
        /// EL1 trampoline), `kick_inject` (EL0 kick-path signal injections),
        /// `inject_at_el1` (carrick-vs-guest invariant violations — must be 0).
        fn kick__stats(_: u64, _: u64, _: u64) {}
        /// Reusable guest-memory watchpoint (compiled in only under the `watchpoint`
        /// feature). When that build has `CARRICK_WATCH_ADDR=<hex>` set, fires before
        /// EVERY syscall with (`syscall_nr`, `addr`, the current little-endian u64 at
        /// `addr`). Lets a trace bracket exactly which syscall a guest address changes
        /// across — e.g. which operation corrupts a GOT slot. Absent from a stock
        /// build; zero-cost (and not even read) when the env var is unset.
        fn mem__watch(_: u64, _: u64, _: u64) {}
        /// Fires in rt_sigaction with the first four u64 words the guest passed in
        /// its `struct sigaction` (offsets 0/8/16/24). Lets a trace see the exact
        /// on-the-wire layout — sa_handler, sa_flags, and whether offset 16 is
        /// sa_restorer (glibc-style) or sa_mask (aarch64 kernel ABI, no restorer).
        fn sigaction__read(_: i32, _: u64, _: u64, _: u64, _: u64) {}
        /// Fires when the interactive session supervisor forks the Carrick runtime
        /// child. Distinct from guest fork-post; this is the host-side `run -t`
        /// process boundary.
        fn supervisor__fork(_: i32) {}
        /// Fires when the runtime child has moved into its own process group and
        /// is waiting for the supervisor to make that pgrp foreground.
        fn supervisor__child__ready(_: i32) {}
        /// Fires after the supervisor attempts to make the runtime child pgrp the
        /// pty foreground group. `errno` is 0 on success.
        fn supervisor__foreground__pgrp(_: i32, _: i32) {}
        /// Fires when the supervisor reaps the runtime child.
        fn supervisor__child__exit(_: i32, _: i32) {}
        /// Page-table-edit Pause-Modify-Resume tracing. carrick (the VMM) edits the
        /// guest's shared stage-1 descriptors from the host while sibling vCPUs run;
        /// these probes let a `carrick trace` PROVE the stop-the-world engages and
        /// converges (rather than guessing).
        ///  * `pt__pause__begin`: an editing vCPU became the sole coordinator.
        ///    `tid` editor, `others_in_guest` siblings still walking tables at entry,
        ///    `count` live vCPUs.
        ///  * `pt__pause__ready`: all siblings left guest; the edit may proceed.
        ///    `spins` wait iterations, `wait_us` microseconds waited.
        ///  * `pt__pause__timeout`: the convergence deadline was hit. MUST never
        ///    fire — a nonzero rate means a sibling stayed in guest (exactly the
        ///    corruption PMR prevents). `wait_us` is the deadline budget.
        ///  * `pt__pause__end`: the pause was released and siblings resumed. `tid`.
        fn pt__pause__begin(_: i32, _: i32, _: i32) {}
        fn pt__pause__ready(_: i32, _: i32, _: i64) {}
        fn pt__pause__timeout(_: i32, _: i64) {}
        fn pt__pause__end(_: i32) {}
        /// Stage-1 spare sub-table pool occupancy, fired after each table edit.
        /// `in_use` live split tables, `free_list` reclaimable pages, `capacity`
        /// total spare pages. A rising `in_use` toward `capacity` is the
        /// coalesce-disabled pool leak; flat `in_use` proves coalescing keeps it
        /// bounded. `changed` is 1 if this edit mutated descriptors (0 = no-op skip).
        fn pt__pool(_: u32, _: u32, _: u32, _: i32) {}
        /// Fault-site host page-table walk. On a guest EL0 translation/permission
        /// fault, the live stage-1 descriptors read from the host backing at the
        /// faulting VA: `far` and `l0`/`l1`/`l2`/`l3`. An invalid (`& 1 == 0`) leaf
        /// proves the PTE is wrong IN MEMORY (logic bug); a valid RW leaf proves the
        /// memory is fine and the faulting vCPU's TLB was stale (coherence bug).
        fn pt__fault__walk(_: u64, _: u64, _: u64, _: u64, _: u64) {}
        /// Guest-memory copy mapping decision. `dir`: 0=guest->host read,
        /// 1=host->guest internal write, 2=host->guest syscall checked write.
        /// `addr`/`len` are the guest VA range. `stage1_ipa` is the live stage-1
        /// output for `addr`, or `u64::MAX` if unmapped/non-high-VA. `mapping_start`
        /// is the host mapping Carrick actually selected.
        fn guest__mem__copy(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-copy`: `mapping_start`, `mapping_end`, and
        /// `mapping_ipa` for the selected region. Kept below five args because
        /// macOS DTrace silently reports the sixth USDT argument as zero here.
        fn guest__mem__region(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Guest-memory copy content fingerprint. Same `dir`/`addr`/`len` as
        /// `guest-mem-copy`; then a wrapping byte-sum plus little-endian first
        /// eight bytes of the copied payload. This avoids DTrace reading guest VAs.
        fn guest__mem__bytes(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-bytes`: little-endian last eight bytes.
        fn guest__mem__tail(_: u32, _: u64, _: u64, _: u64) {}
        /// Stage-1 sample point inside a guest-memory copy range. Args are:
        /// `dir`, sample guest VA, `sample_va - mapping_start`,
        /// `stage1_ipa - mapping_ipa` or `u64::MAX`, and live stage-1 IPA.
        fn guest__mem__point(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Opt-in content fingerprint for a configured subrange inside a
        /// guest-memory copy. Args are `dir`, base guest VA, subrange offset,
        /// subrange length, and wrapping byte sum.
        fn guest__mem__subrange(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-subrange`: little-endian first and last eight
        /// bytes of the configured subrange.
        fn guest__mem__subedge(_: u32, _: u64, _: u64, _: u64, _: u64) {}
        /// Companion for `guest-mem-subrange`: nonzero byte count for the
        /// configured subrange. Kept separate because macOS DTrace drops a sixth
        /// USDT argument at some probe sites.
        fn guest__mem__subcount(_: u32, _: u64, _: u64, _: u64) {}
    }

    #[inline(always)]
    pub fn native_syscall_service_entry(number: u64, name: &str) {
        carrick_usdt::native__syscall__service__entry!(|| (number, name));
    }

    #[inline(always)]
    pub fn native_syscall_service_branch(kind: super::NativeSyscallBranchKind) {
        carrick_usdt::native__syscall__service__branch!(|| kind.raw());
    }

    #[inline(always)]
    pub fn native_syscall_service_end(
        number: u64,
        name: &str,
        outcome: super::NativeSyscallServiceOutcome,
    ) {
        carrick_usdt::native__syscall__service__end!(|| (number, name, outcome.raw()));
    }

    #[inline(always)]
    pub fn native_tierd_exception(phase: u32, a: u64, b: u64, c: u64, d: u64) {
        carrick_usdt::native__tierd__exception!(|| { (phase, std::process::id(), a, b, c, d) });
    }

    #[inline(always)]
    pub fn native_tierd_unsupported(syscall: u64, detail: &str) {
        carrick_usdt::native__tierd__unsupported!(|| { (std::process::id(), syscall, detail) });
    }

    #[inline(always)]
    pub fn hvf_syscall_transport(
        transport: u32,
        phase: u32,
        register_reads: u32,
        sysreg_reads: u32,
        register_writes: u32,
    ) {
        carrick_usdt::hvf__syscall__transport!(|| (
            transport,
            phase,
            register_reads,
            sysreg_reads,
            register_writes,
        ));
    }

    #[inline(always)]
    pub fn dsr_prepare_begin(tid: i32, guest_pc: u64) {
        carrick_usdt::dsr__prepare__begin!(|| (tid, guest_pc));
    }

    #[inline(always)]
    pub fn dsr_prepare_end(
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        generation: u64,
        outcome: super::DsrPrepareOutcome,
    ) {
        carrick_usdt::dsr__prepare__end!(|| {
            (tid, guest_pc, cache_pc, generation, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_run_begin(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64) {
        carrick_usdt::dsr__run__begin!(|| (tid, guest_pc, cache_pc, generation));
    }

    #[inline(always)]
    pub fn dsr_run_end(
        tid: i32,
        kind: super::DsrExitKind,
        guest_pc: u64,
        target_pc: u64,
        status: i32,
    ) {
        carrick_usdt::dsr__run__end!(|| (tid, kind.raw(), guest_pc, target_pc, status));
    }

    #[inline(always)]
    pub fn dsr_translate_begin(tid: i32, guest_pc: u64, generation: u64) {
        carrick_usdt::dsr__translate__begin!(|| (tid, guest_pc, generation));
    }

    #[inline(always)]
    pub fn dsr_translate_end(
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        emitted_bytes: u64,
        outcome: super::DsrOperationOutcome,
    ) {
        carrick_usdt::dsr__translate__end!(|| {
            (tid, guest_pc, cache_pc, emitted_bytes, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_translate_subphase_begin(
        tid: i32,
        subphase: super::DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    ) {
        carrick_usdt::dsr__translate__subphase__begin!(|| {
            (tid, subphase.raw(), guest_pc, generation)
        });
    }

    #[inline(always)]
    pub fn dsr_translate_subphase_end(
        tid: i32,
        subphase: super::DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    ) {
        carrick_usdt::dsr__translate__subphase__end!(|| {
            (tid, subphase.raw(), guest_pc, generation)
        });
    }

    #[inline(always)]
    pub fn dsr_synchronization_begin(kind: super::DsrSynchronizationKind) {
        carrick_usdt::dsr__synchronization__begin!(|| kind.raw());
    }

    #[inline(always)]
    pub fn dsr_synchronization_end(kind: super::DsrSynchronizationKind) {
        carrick_usdt::dsr__synchronization__end!(|| kind.raw());
    }

    #[inline(always)]
    pub fn dsr_resolve_begin(
        tid: i32,
        kind: super::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
    ) {
        carrick_usdt::dsr__resolve__begin!(|| (tid, kind.raw(), source_pc, target_pc));
    }

    #[inline(always)]
    pub fn dsr_resolve_end(
        tid: i32,
        kind: super::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
        outcome: super::DsrOperationOutcome,
    ) {
        carrick_usdt::dsr__resolve__end!(|| {
            (tid, kind.raw(), source_pc, target_pc, outcome.raw())
        });
    }

    #[inline(always)]
    pub fn dsr_cache_event(
        tid: i32,
        kind: super::DsrCacheEventKind,
        guest_pc: u64,
        generation: u64,
        used_bytes: u64,
    ) {
        carrick_usdt::dsr__cache__event!(|| {
            (tid, kind.raw(), guest_pc, generation, used_bytes)
        });
    }

    #[inline(always)]
    pub fn dsr_cache_capacity(role: super::DsrCacheRole, capacity_bytes: u64) {
        carrick_usdt::dsr__cache__capacity!(|| (role.raw(), capacity_bytes));
    }

    #[inline(always)]
    pub fn dsr_cache_bounds(base: u64, end: u64) {
        carrick_usdt::dsr__cache__bounds!(|| (base, end));
    }

    #[inline(always)]
    pub fn host_process_birth(event: super::HostProcessBirth) {
        carrick_usdt::host__process__birth!(|| {
            (event.pid(), event.start_sec(), event.start_usec())
        });
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    pub fn host_process_birth_current() {
        carrick_usdt::host__process__birth!(|| {
            let pid = std::process::id();
            match super::HostProcessBirth::query(pid) {
                Ok(event) => (event.pid(), event.start_sec(), event.start_usec()),
                Err(_) => (pid, 0, 0),
            }
        });
    }

    #[cfg(not(target_os = "macos"))]
    #[inline(always)]
    pub fn host_process_birth_current() {}

    #[inline(always)]
    pub fn host_translated_range_reset(event: super::TranslatedRangeReset) {
        carrick_usdt::host__translated__range__reset!(|| event.epoch().get());
    }

    #[inline(always)]
    pub fn host_translated_private_range(event: super::TranslatedPrivateRange) {
        carrick_usdt::host__translated__private__range!(|| {
            let range = event.range();
            (
                event.epoch().get(),
                event.sequence().get(),
                range.start.raw() as u64,
                range.end.raw() as u64,
            )
        });
    }

    #[inline(always)]
    pub fn host_translated_shared_range(event: super::TranslatedSharedRange) {
        carrick_usdt::host__translated__shared__range!(|| {
            let range = event.range();
            (
                event.epoch().get(),
                event.sequence().get(),
                event.unit_id().get(),
                range.start.raw() as u64,
                range.end.raw() as u64,
            )
        });
    }

    #[inline(always)]
    pub fn host_translated_range_ready(event: super::TranslatedRangeReady) {
        carrick_usdt::host__translated__range__ready!(|| {
            (event.epoch().get(), event.final_sequence())
        });
    }

    #[inline(always)]
    pub fn host_native_owned_range_reset(event: super::NativeOwnedRangeReset) {
        carrick_usdt::host__native__owned__range__reset!(|| event.epoch().get());
    }

    #[inline(always)]
    pub fn host_native_owned_range_add(event: super::NativeOwnedRange) {
        carrick_usdt::host__native__owned__range__add!(|| {
            let range = event.range();
            (
                event.epoch().get(),
                event.sequence().get(),
                range.start.raw() as u64,
                range.end.raw() as u64,
            )
        });
    }

    #[inline(always)]
    pub fn host_native_owned_range_ready(event: super::NativeOwnedRangeReady) {
        carrick_usdt::host__native__owned__range__ready!(|| {
            (event.epoch().get(), event.final_sequence())
        });
    }

    #[inline(always)]
    pub fn dsr_cache_lifecycle(
        tid: i32,
        phase: super::DsrCacheLifecyclePhase,
        used_bytes: u64,
        block_count: u64,
        generation_count: u64,
    ) {
        carrick_usdt::dsr__cache__lifecycle!(|| {
            (tid, phase.raw(), used_bytes, block_count, generation_count)
        });
    }

    #[inline(always)]
    pub fn dsr_exec_map_detail(
        tid: i32,
        kind: super::DsrExecMapDetailKind,
        duration_ns: u64,
        bytes: u64,
        operations: u64,
    ) {
        carrick_usdt::dsr__exec__map__detail!(|| {
            (tid, kind.raw(), duration_ns, bytes, operations)
        });
    }

    pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
        carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
    }

    // For these helpers the PID read happens INSIDE the closure. usdt's
    // `probe!` macro only invokes the closure when the probe is enabled
    // (it gates on `is_enabled()` in asm before calling), so `getpid()`
    // is genuinely zero-cost when no DTrace consumer is attached.
    pub fn path_open(path: &str, result_size: u64, errno: i32) {
        carrick_usdt::path__open!(|| (std::process::id(), path, result_size, errno));
    }

    pub fn itimer_fire(signum: i32, generation: u64) {
        carrick_usdt::itimer__fire!(|| (std::process::id(), signum, generation));
    }

    pub fn futex_route(addr: u64, op: i32, shared: i32, host_addr: u64) {
        carrick_usdt::futex__route!(|| (std::process::id(), addr, op, shared, host_addr));
    }

    pub fn ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64) {
        carrick_usdt::ulock__wait!(|| (
            std::process::id(),
            host_addr,
            value,
            timeout_us,
            phase,
            rc
        ));
    }

    pub fn ulock_wake(host_addr: u64, iter: i32, rc: i64) {
        carrick_usdt::ulock__wake!(|| (std::process::id(), host_addr, iter, rc));
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct UlockRequeueWireProbe {
        pid: u64,
        phase: u64,
        from_key: u64,
        to_key: u64,
        wake_req: u64,
        requeue_req: u64,
        wake_ret: u64,
        requeue_ret: u64,
        from_count: u64,
        from_requeue_wake: u64,
        from_requeue_count: u64,
        from_logical_requeued: u64,
        from_logical_wake: u64,
        to_count: u64,
        to_requeue_wake: u64,
        to_requeue_count: u64,
        to_logical_requeued: u64,
        to_logical_wake: u64,
    }

    thread_local! {
        static ULOCK_REQUEUE_PROBE: std::cell::Cell<UlockRequeueWireProbe> =
            const { std::cell::Cell::new(UlockRequeueWireProbe {
                pid: 0,
                phase: 0,
                from_key: 0,
                to_key: 0,
                wake_req: 0,
                requeue_req: 0,
                wake_ret: 0,
                requeue_ret: 0,
                from_count: 0,
                from_requeue_wake: 0,
                from_requeue_count: 0,
                from_logical_requeued: 0,
                from_logical_wake: 0,
                to_count: 0,
                to_requeue_wake: 0,
                to_requeue_count: 0,
                to_logical_requeued: 0,
                to_logical_wake: 0,
            }) };
    }

    #[inline(never)]
    pub fn ulock_requeue(sample: super::UlockRequeueProbe) {
        let payload = UlockRequeueWireProbe {
            pid: std::process::id() as u64,
            phase: sample.phase as u64,
            from_key: sample.from_key,
            to_key: sample.to_key,
            wake_req: sample.wake_req as u64,
            requeue_req: sample.requeue_req as u64,
            wake_ret: sample.wake_ret as u64,
            requeue_ret: sample.requeue_ret as u64,
            from_count: sample.from_count as u64,
            from_requeue_wake: sample.from_requeue_wake as u64,
            from_requeue_count: sample.from_requeue_count as u64,
            from_logical_requeued: sample.from_logical_requeued as u64,
            from_logical_wake: sample.from_logical_wake as u64,
            to_count: sample.to_count as u64,
            to_requeue_wake: sample.to_requeue_wake as u64,
            to_requeue_count: sample.to_requeue_count as u64,
            to_logical_requeued: sample.to_logical_requeued as u64,
            to_logical_wake: sample.to_logical_wake as u64,
        };
        ULOCK_REQUEUE_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::ulock__requeue!(|| ptr);
        });
    }

    pub fn futex_unexpected_errno(host_addr: u64, errno: i32) {
        carrick_usdt::futex__unexpected__errno!(|| (std::process::id(), host_addr, errno));
    }

    pub fn guest_exit(code: i32) {
        carrick_usdt::guest__exit!(|| (std::process::id(), code));
    }

    pub fn mn_admit(tid: i32, slot: u32, budget: u32) {
        carrick_usdt::mn__admit!(|| (tid, slot, budget));
    }

    pub fn mn_reclaim(tid: i32, old_slot: u32, new_slot: u32, kind: i32) {
        carrick_usdt::mn__reclaim!(|| (tid, old_slot, new_slot, kind));
    }

    /// Per-run lifecycle phase markers (see the `lifecycle` provider doc). Fire one
    /// at each boundary so `carrick trace` can attribute the per-run wall-clock to
    /// startup / VM-create / guest-load / run / teardown phases.
    pub mod phase {
        pub const RUN_ENTRY: u32 = 0;
        pub const IMAGE_READY: u32 = 1;
        pub const VM_CREATED: u32 = 2;
        pub const GUEST_LOADED: u32 = 3;
        pub const FIRST_VCPU_RUN: u32 = 4;
        pub const VM_DESTROY_BEGIN: u32 = 5;
        pub const VM_DESTROY_END: u32 = 6;
    }

    pub fn lifecycle(phase: u32) {
        carrick_usdt::lifecycle!(|| phase);
    }

    #[inline(never)]
    pub fn hvpatch_guest_lifecycle(event: super::HvpatchGuestLifecycle) {
        // Identity first: a consumer that sees the lifecycle record is then
        // guaranteed to have already seen the serials that disambiguate it.
        carrick_usdt::hvpatch__guest__lifecycle__identity!(|| (
            event.pid(),
            event.task_serial(),
            event.parent_serial(),
            event.mm()
        ));
        carrick_usdt::hvpatch__guest__lifecycle!(|| (
            event.phase().raw(),
            event.pid(),
            event.ppid(),
            event.tid(),
            event.asid()
        ));
        if event.phase() == super::HvpatchGuestLifecyclePhase::ProcessExit {
            carrick_usdt::hvpatch__guest__exit!(|| (
                event.pid(),
                event.tid(),
                event.asid(),
                event.detail()
            ));
        }
    }

    #[inline(never)]
    pub fn hvpatch_guest_fault(event: super::HvpatchGuestFault) {
        carrick_usdt::hvpatch__guest__fault__asid!(|| (event.pid(), event.tid(), event.asid()));
        carrick_usdt::hvpatch__guest__fault!(|| (
            event.syndrome(),
            event.elr(),
            event.far(),
            event.pid(),
            event.tid()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_guest_address_space(event: super::HvpatchGuestAddressSpace) {
        carrick_usdt::hvpatch__guest__address__space!(|| (
            event.pid(),
            event.asid(),
            event.bank_base(),
            event.bank_size(),
            event.ttbr0()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_syscall_service_begin(
        event: super::HvpatchSyscallService,
        args: [u64; 6],
    ) -> Option<std::time::Instant> {
        let mut started = None;
        carrick_usdt::hvpatch__syscall__service__begin!(|| {
            started = Some(std::time::Instant::now());
            (event.pid(), event.tid(), event.asid(), event.number())
        });
        // Publish raw args only when the identity-bearing begin probe fired.
        // This guarantees that a consumer can join the companion on the same
        // host thread without ever receiving an identity-free args record.
        if started.is_some() {
            carrick_usdt::hvpatch__syscall__args!(|| (
                event.number(),
                args[0],
                args[1],
                args[2],
                args[3]
            ));
        }
        started
    }

    #[inline(never)]
    pub fn hvpatch_syscall_service(event: super::HvpatchSyscallService) {
        carrick_usdt::hvpatch__syscall__service!(|| (
            event.pid(),
            event.tid(),
            event.asid(),
            event.number(),
            event.duration_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_syscall_service_clear(event: super::HvpatchSyscallService) {
        carrick_usdt::hvpatch__syscall__service__clear!(|| (
            event.pid(),
            event.tid(),
            event.asid(),
            event.number()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_snapshot_begin(child_pid: i32, forking_tid: i32) {
        carrick_usdt::hvpatch__fork__snapshot__begin!(|| (child_pid, forking_tid));
    }

    #[inline(never)]
    pub fn hvpatch_fork_snapshot_end(
        child_pid: i32,
        local_regions: u64,
        candidate_regions: u64,
        added_regions: u64,
        added_bytes: u64,
    ) {
        carrick_usdt::hvpatch__fork__snapshot__end!(|| (
            child_pid,
            local_regions,
            candidate_regions,
            added_regions,
            added_bytes
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_snapshot_shape(
        child_pid: i32,
        private_added_regions: u64,
        shared_added_regions: u64,
        largest_added_bytes: u64,
        bank_used_bytes: u64,
    ) {
        carrick_usdt::hvpatch__fork__snapshot__shape!(|| (
            child_pid,
            private_added_regions,
            shared_added_regions,
            largest_added_bytes,
            bank_used_bytes
        ));
    }

    #[inline(never)]
    pub fn hvpatch_exec_bank_layout(event: super::HvpatchExecBankLayout) {
        carrick_usdt::hvpatch__exec__bank__layout!(|| (
            event.phase().raw(),
            event.bank_base(),
            event.mapping_count(),
            event.cache_entries(),
            event.elapsed_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_exec_backing(event: super::HvpatchExecBacking) {
        carrick_usdt::hvpatch__exec__backing!(|| (
            event.phase().raw(),
            event.guest_start(),
            event.ipa_start(),
            event.mapped_size(),
            event.elapsed_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_exec_stage2(event: super::HvpatchExecStage2) {
        carrick_usdt::hvpatch__exec__stage2!(|| (
            event.phase().raw(),
            event.ipa(),
            event.size(),
            event.guest_start(),
            event.rc()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_exec_replace_stage(event: super::HvpatchExecReplaceStage) {
        carrick_usdt::hvpatch__exec__replace__stage!(|| (
            event.phase().raw(),
            event.elapsed_ns(),
            event.mapping_count(),
            event.mapped_bytes()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_exec_runtime_stage(event: super::HvpatchExecRuntimeStage) {
        carrick_usdt::hvpatch__exec__runtime__stage!(|| (
            event.phase().raw(),
            event.elapsed_ns(),
            event.region_count(),
            event.mapped_bytes()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_topology_lock(event: super::HvpatchTopologyLock) {
        carrick_usdt::hvpatch__topology__lock!(|| (
            event.operation().raw(),
            event.phase().raw(),
            event.guest_pid(),
            event.guest_tid(),
            event.elapsed_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_runtime_stage(event: super::HvpatchForkRuntimeStage) {
        carrick_usdt::hvpatch__fork__runtime__stage!(|| (
            event.phase().raw(),
            event.parent_pid(),
            event.child_pid(),
            event.forking_tid(),
            event.elapsed_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_process_spec_stage(event: super::HvpatchForkProcessSpecStage) {
        carrick_usdt::hvpatch__fork__process__spec__stage!(|| (
            event.phase().raw(),
            event.child_pid(),
            event.forking_tid(),
            event.elapsed_ns(),
            event.units()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_private_snapshot(event: super::HvpatchForkPrivateSnapshot) {
        carrick_usdt::hvpatch__fork__private__snapshot!(|| (
            event.child_pid(),
            event.forking_tid(),
            event.guest_start(),
            event.mapped_size(),
            event.elapsed_ns()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_private_snapshot_outcome(event: super::HvpatchForkPrivateSnapshotOutcome) {
        carrick_usdt::hvpatch__fork__private__snapshot__outcome!(|| (
            event.child_pid(),
            event.forking_tid(),
            event.guest_start(),
            event.role().raw(),
            event.method().raw()
        ));
    }

    #[inline(never)]
    pub fn hvpatch_fork_quiesce(event: super::HvpatchForkQuiesce) {
        carrick_usdt::hvpatch__fork__quiesce!(|| (
            event.parent_pid(),
            event.forking_tid(),
            event.initial_siblings(),
            event.poll_iterations(),
            event.elapsed_ns()
        ));
    }

    pub fn vm_lifecycle(operation: u32, admission: i32) {
        crate::vm_lifecycle::record_raw(operation, admission);
        carrick_usdt::vm__lifecycle!(|| (operation, admission));
    }

    pub fn execve_argv(path: &str, argv: &[Vec<u8>]) {
        // argv items are opaque bytes (Linux ABI); lossily decode + join for the
        // trace (display only). `argv.join` allocates, so it can't move inside the
        // closure (the returned `&str` would dangle once the closure's local String
        // drops, before usdt serialises it). execve is rare, so the unconditional
        // join is acceptable; the hot paths above are zero-cost-when-disabled.
        let joined = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a))
            .collect::<Vec<_>>()
            .join(" ");
        carrick_usdt::execve__argv!(|| (std::process::id(), path, joined.as_str()));
    }

    /// Collect this process's carrick image base / ASLR slide for offline
    /// symbolication.
    ///
    /// Reports the HOST (carrick) image only. The inner guest image is a
    /// separate address range with a separate on-disk file, announced by
    /// [`guest_image_base`]; a consumer needs both, and conflating them
    /// resolves a guest PC against carrick's symbol table, which yields a
    /// plausible name that is simply wrong.
    #[cfg(target_os = "macos")]
    fn host_image_base_snapshot() -> HostImageBase {
        // Image 0 is the main executable. The mach_header address IS the
        // runtime __TEXT base, which is what `atos -l` wants; the slide is
        // reported alongside it so a consumer can convert either way, and the
        // path so nobody has to GUESS which binary to symbolicate against --
        // a rebuilt or stale `target/release/carrick` otherwise resolves to
        // confident nonsense rather than to an error.
        //
        // `mach2` rather than `libc`: libc deprecated these in its favour, and
        // the workspace denies warnings.
        //
        // SAFETY: all three are dyld queries taking an image index that is
        // always valid (index 0 exists in every Mach-O process). The header
        // pointer is only read as an integer, never dereferenced; the name is a
        // dyld-owned NUL-terminated string that lives as long as the image, so
        // the borrow taken here cannot dangle.
        // The probe macro expands to its own `unsafe`, so the FFI is scoped
        // tightly here rather than wrapping a later fire as well. Own the path:
        // its source is a temporary `CStr` borrow from dyld.
        let (base, slide, path) = unsafe {
            let name = mach2::dyld::_dyld_get_image_name(0);
            (
                mach2::dyld::_dyld_get_image_header(0) as usize as u64,
                mach2::dyld::_dyld_get_image_vmaddr_slide(0) as i64,
                if name.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(name)
                        .to_string_lossy()
                        .into_owned()
                },
            )
        };
        HostImageBase {
            pid: std::process::id(),
            base,
            slide,
            path,
        }
    }

    fn nul_terminated_wire(value: String) -> Box<[u8]> {
        let mut bytes = value.into_bytes();
        bytes.push(0);
        bytes.into_boxed_slice()
    }

    pub fn prepare_guest_image_path(path: String) -> PreparedGuestImagePath {
        PreparedGuestImagePath {
            wire: nul_terminated_wire(path),
        }
    }

    fn prepared_guest_image_path_arg(path: &PreparedGuestImagePath) -> *const u8 {
        path.wire.as_ptr()
    }

    /// Collect and publish this process's carrick image base immediately.
    /// Native exec handoff uses [`prepare_host_image_publication`] instead so
    /// allocation happens before its fatal-only boundary.
    pub fn host_image_base() {
        #[cfg(target_os = "macos")]
        carrick_usdt::host__image__base!(|| {
            // Keep every query INSIDE the probe closure: `usdt` invokes it
            // only when this probe is enabled, so Tier D can publish once per
            // process without adding dyld queries or a path allocation to an
            // untraced launch. Image zero and its name are dyld-owned for the
            // lifetime of the process; the consumer copies the path while the
            // probe fires, so the raw pointer cannot outlive its owner.
            // SAFETY: image zero exists in every Mach-O process. The header is
            // observed only as an integer and the name only as a probe arg.
            (
                std::process::id(),
                mach2::dyld::_dyld_get_image_header(0) as usize as u64,
                mach2::dyld::_dyld_get_image_vmaddr_slide(0) as i64,
                mach2::dyld::_dyld_get_image_name(0).cast::<u8>(),
            )
        });
        // Not macOS: dyld is the mechanism above, and only the Darwin native
        // lane self-reexecs its guest processes. Announcing a base we have not
        // actually queried would be worse than announcing none -- a consumer
        // cannot tell a fabricated base from a real one.
    }

    #[cfg(target_os = "macos")]
    fn runtime_address(vmaddr: u64, slide: isize) -> Option<u64> {
        if slide >= 0 {
            vmaddr.checked_add(slide as u64)
        } else {
            vmaddr.checked_sub(slide.unsigned_abs() as u64)
        }
    }

    /// Read one dyld image's executable Mach-O segments.
    ///
    /// # Safety
    ///
    /// `header` must be the live image header returned by dyld for `slide` and
    /// must remain mapped while this function walks its bounded load-command
    /// table.
    #[cfg(target_os = "macos")]
    unsafe fn executable_ranges(
        header: *const mach2::loader::mach_header,
        slide: isize,
        path: &str,
    ) -> Vec<HostImageRange> {
        if header.is_null() {
            return Vec::new();
        }
        // SAFETY: the caller's contract supplies a live dyld image header.
        let header_value = unsafe { std::ptr::read_unaligned(header) };
        if header_value.magic != libc::MH_MAGIC_64 {
            return Vec::new();
        }

        // `mach2::mach_header` models the common 28-byte prefix. A 64-bit
        // Mach-O header has one trailing reserved u32 before load commands.
        let commands = unsafe {
            header
                .cast::<u8>()
                .add(std::mem::size_of::<mach2::loader::mach_header>() + 4)
        };
        let command_bytes = header_value.sizeofcmds as usize;
        let mut offset = 0_usize;
        let mut ranges = Vec::new();
        for _ in 0..header_value.ncmds {
            if command_bytes.saturating_sub(offset) < std::mem::size_of::<libc::load_command>() {
                break;
            }
            // SAFETY: the size guard keeps the fixed command header in bounds.
            let command = unsafe {
                std::ptr::read_unaligned(commands.add(offset).cast::<libc::load_command>())
            };
            let command_size = command.cmdsize as usize;
            if command_size < std::mem::size_of::<libc::load_command>()
                || command_size > command_bytes.saturating_sub(offset)
            {
                break;
            }
            if command.cmd == libc::LC_SEGMENT_64
                && command_size >= std::mem::size_of::<libc::segment_command_64>()
            {
                // SAFETY: `cmdsize` proves the complete segment command is
                // inside dyld's load-command table.
                let segment = unsafe {
                    std::ptr::read_unaligned(
                        commands.add(offset).cast::<libc::segment_command_64>(),
                    )
                };
                if segment.initprot & libc::VM_PROT_EXECUTE != 0
                    && segment.vmsize != 0
                    && let Some(start) = runtime_address(segment.vmaddr, slide)
                    && let Some(end) = start.checked_add(segment.vmsize)
                {
                    ranges.push(HostImageRange {
                        start,
                        end,
                        path: path.to_owned(),
                    });
                }
            }
            offset += command_size;
        }
        ranges
    }

    #[cfg(target_os = "macos")]
    fn host_image_text_range_snapshot() -> (u32, u64, u64) {
        // SAFETY: dyld image zero is the live main executable for the process.
        // `executable_ranges` bounds its reads by that header's command table.
        let (header, slide) = unsafe {
            (
                mach2::dyld::_dyld_get_image_header(0),
                mach2::dyld::_dyld_get_image_vmaddr_slide(0),
            )
        };
        let base = header as usize as u64;
        let range = unsafe { executable_ranges(header, slide, "") }
            .into_iter()
            .find(|range| range.start <= base && base < range.end);
        range.map_or((std::process::id(), 0, 0), |range| {
            (std::process::id(), range.start, range.end)
        })
    }

    /// Publish the exact Carrick executable range without preparing a dyld
    /// catalog. The closure (including all dyld work) runs only when DTrace
    /// enables this probe.
    #[inline(always)]
    #[allow(
        clippy::redundant_closure,
        reason = "the generated USDT macro requires a closure argument"
    )]
    pub fn host_image_text_range() {
        #[cfg(target_os = "macos")]
        carrick_usdt::host__image__text__range!(|| host_image_text_range_snapshot());
    }

    #[cfg(target_os = "macos")]
    fn host_image_catalog_snapshot() -> HostImageCatalog {
        let mut ranges = Vec::new();
        // SAFETY: dyld owns the returned image table and its names/headers for
        // the process lifetime. The count bounds every query, and
        // `executable_ranges` bounds all reads by the header's command table.
        unsafe {
            for index in 0..mach2::dyld::_dyld_image_count() {
                let header = mach2::dyld::_dyld_get_image_header(index);
                let name = mach2::dyld::_dyld_get_image_name(index);
                let slide = mach2::dyld::_dyld_get_image_vmaddr_slide(index);
                let path = if name.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(name)
                        .to_string_lossy()
                        .into_owned()
                };
                if profile_runtime_image_path(&path) {
                    ranges.extend(executable_ranges(header, slide, &path));
                }
            }
        }
        ranges.sort_by_key(|range| range.start);
        HostImageCatalog {
            pid: std::process::id(),
            ranges,
        }
    }

    #[cfg(target_os = "macos")]
    fn profile_runtime_image_path(path: &str) -> bool {
        [
            "/usr/lib/system/",
            "/usr/lib/libSystem",
            "/usr/lib/libobjc",
            "/usr/lib/objc/",
            "/usr/lib/libc++",
            "/usr/lib/libdtrace",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    }

    /// Publish exact executable ranges for Darwin's process runtime images.
    ///
    /// This compatibility convenience prepares a complete one-shot wire
    /// buffer before firing. Native exec uses [`prepare_host_image_publication`]
    /// earlier, before its point of no return. Carrick's own text has a
    /// separate exact announcement; framework PCs outside this bounded catalog
    /// remain unresolved and count against the coverage gate.
    #[cfg(target_os = "macos")]
    pub fn host_image_catalog() {
        let catalog_wire = host_image_catalog_wire(&host_image_catalog_snapshot());
        let catalog = catalog_wire.as_ptr();
        carrick_usdt::host__image__catalog!(|| catalog);
        std::hint::black_box(&catalog_wire);
    }

    #[cfg(not(target_os = "macos"))]
    pub fn host_image_catalog() {}

    #[cfg(target_os = "macos")]
    fn host_image_catalog_wire(catalog: &HostImageCatalog) -> Box<[u8]> {
        let payload = match serde_json::to_string(catalog) {
            Ok(json) => format!("{{\"ok\":{json}}}"),
            Err(error) => format!("{{\"err\":\"{error}\"}}"),
        };
        nul_terminated_wire(payload)
    }

    #[cfg(target_os = "macos")]
    fn prepare_host_image_publication_from_snapshots(
        base: HostImageBase,
        catalog: HostImageCatalog,
    ) -> PreparedHostImagePublication {
        PreparedHostImagePublication {
            pid: base.pid,
            base: base.base,
            slide: base.slide,
            base_path_wire: nul_terminated_wire(base.path),
            catalog_wire: host_image_catalog_wire(&catalog),
        }
    }

    #[cfg(target_os = "macos")]
    fn prepared_host_image_base_args(
        prepared: &PreparedHostImagePublication,
    ) -> (u32, u64, i64, *const u8) {
        (
            prepared.pid,
            prepared.base,
            prepared.slide,
            prepared.base_path_wire.as_ptr(),
        )
    }

    #[cfg(target_os = "macos")]
    fn prepared_host_image_catalog_arg(prepared: &PreparedHostImagePublication) -> *const u8 {
        prepared.catalog_wire.as_ptr()
    }

    /// Collect every owned host-image value before a native exec retires its
    /// recoverable image. Paths are NUL-terminated and the catalog is wrapped
    /// in the exact legacy `{"ok":...}` JSON envelope here. The later probe
    /// fires only pass raw pointers, so activation through thread installation
    /// performs no dyld walk, serialization, path conversion, or allocation.
    #[cfg(target_os = "macos")]
    pub fn prepare_host_image_publication() -> PreparedHostImagePublication {
        prepare_host_image_publication_from_snapshots(
            host_image_base_snapshot(),
            host_image_catalog_snapshot(),
        )
    }

    #[cfg(not(target_os = "macos"))]
    pub fn prepare_host_image_publication() -> PreparedHostImagePublication {
        PreparedHostImagePublication
    }

    #[cfg(target_os = "macos")]
    pub fn publish_host_image_base(prepared: &PreparedHostImagePublication) {
        let args = prepared_host_image_base_args(prepared);
        carrick_usdt::host__image__base!(|| args);
        std::hint::black_box(&prepared.base_path_wire);
    }

    #[cfg(not(target_os = "macos"))]
    pub fn publish_host_image_base(_prepared: &PreparedHostImagePublication) {}

    #[cfg(target_os = "macos")]
    pub fn publish_host_image_catalog(prepared: &PreparedHostImagePublication) {
        let catalog = prepared_host_image_catalog_arg(prepared);
        carrick_usdt::host__image__catalog!(|| catalog);
        std::hint::black_box(&prepared.catalog_wire);
    }

    #[cfg(not(target_os = "macos"))]
    pub fn publish_host_image_catalog(_prepared: &PreparedHostImagePublication) {}

    /// Publish the INNER guest image: where the Linux binary this process is
    /// running got loaded, and which file it came from.
    ///
    /// The native lane maps guest text into the same address space as carrick's
    /// own code, so a sampled PC can land in either. Without this, guest-range
    /// PCs are indistinguishable from JIT output and get reported as unmapped.
    pub fn guest_image_base(base: u64, entry: u64, path: &PreparedGuestImagePath) {
        let path_arg = prepared_guest_image_path_arg(path);
        carrick_usdt::guest__image__base!(|| (std::process::id(), base, entry, path_arg));
        std::hint::black_box(&path.wire);
    }

    /// Publish the half-open executable range of this process's DSR code cache.
    pub fn host_jit_range(start: u64, end: u64) {
        carrick_usdt::host__jit__range!(|| (std::process::id(), start, end));
    }

    pub fn fs_op(op: &str, path: &str, errno: i32) {
        carrick_usdt::fs__op!(|| (std::process::id(), op, path, errno));
    }

    pub fn host_pipe_io(host_fd: i32, dir: i32, n: i64) {
        carrick_usdt::host__pipe__io!(|| (std::process::id(), host_fd, dir, n));
    }

    pub fn epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32) {
        carrick_usdt::epoll__ctl!(|| (epfd, op, fd, events, data, errno));
    }

    pub fn epoll_interest(
        epfd: i32,
        fd: i32,
        requested: u32,
        raw_ready: u32,
        last_ready: u32,
        ready: u32,
    ) {
        carrick_usdt::epoll__interest!(|| (epfd, fd, requested, raw_ready, last_ready, ready));
    }

    /// Raw-pointer payload for `epoll-masked`. Keep field order in sync with
    /// `scripts/dtrace/epoll-wait-debug.d`.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollMaskedWireProbe {
        origin: u64,
        fd: u64,
        host_fd: u64,
        requested: u64,
        raw_ready: u64,
        last_ready: u64,
        read_avail: u64,
        last_read_avail: u64,
    }

    thread_local! {
        static EPOLL_MASKED_PROBE: std::cell::Cell<EpollMaskedWireProbe> =
            const { std::cell::Cell::new(EpollMaskedWireProbe {
                origin: 0,
                fd: 0,
                host_fd: 0,
                requested: 0,
                raw_ready: 0,
                last_ready: 0,
                read_avail: 0,
                last_read_avail: 0,
            }) };
    }

    #[inline(never)]
    pub fn epoll_masked(sample: super::EpollMaskedProbe) {
        let payload = EpollMaskedWireProbe {
            origin: sample.origin as u64,
            fd: sample.fd as i64 as u64,
            host_fd: sample.host_fd as i64 as u64,
            requested: sample.requested as u64,
            raw_ready: sample.raw_ready as u64,
            last_ready: sample.last_ready as u64,
            read_avail: sample.read_avail,
            last_read_avail: sample.last_read_avail,
        };
        EPOLL_MASKED_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::epoll__masked!(|| ptr);
        });
    }

    /// Raw-pointer payload for `epoll-rebind`. Keep field order in sync with
    /// `scripts/dtrace/epoll-wait-debug.d`.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollRebindProbe {
        reason: u64,
        host_fd: u64,
        survivor_fd: u64,
        survivor_gen: u64,
        union_events: u64,
        effective: u64,
    }

    thread_local! {
        static EPOLL_REBIND_PROBE: std::cell::Cell<EpollRebindProbe> =
            const { std::cell::Cell::new(EpollRebindProbe {
                reason: 0,
                host_fd: 0,
                survivor_fd: 0,
                survivor_gen: 0,
                union_events: 0,
                effective: 0,
            }) };
    }

    #[inline(never)]
    pub fn epoll_rebind(
        reason: u32,
        host_fd: i32,
        survivor_fd: i32,
        survivor_gen: u32,
        union_events: u32,
        effective: u32,
    ) {
        let payload = EpollRebindProbe {
            reason: reason as u64,
            host_fd: host_fd as i64 as u64,
            survivor_fd: survivor_fd as i64 as u64,
            survivor_gen: survivor_gen as u64,
            union_events: union_events as u64,
            effective: effective as u64,
        };
        EPOLL_REBIND_PROBE.with(|slot| {
            slot.set(payload);
            let ptr = slot.as_ptr() as u64;
            carrick_usdt::epoll__rebind!(|| ptr);
        });
    }

    pub fn epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32) {
        carrick_usdt::epoll__wait__fd!(|| (epfd, fd, host_fd, poll_events, timeout_ms));
    }

    pub fn epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32) {
        carrick_usdt::epoll__result!(|| (epfd, ready_count, wait_count, timeout_ms, kind));
    }

    pub fn epoll_stale_edge(udata: u64, guest_fd: i32, generation: u32) {
        carrick_usdt::epoll__stale__edge!(|| (udata, guest_fd, generation));
    }

    pub fn io_wait_begin(
        tid: i32,
        fd_count: i32,
        timeout_ms: i64,
        fd0: i32,
        events0: i32,
        fd1: i32,
    ) {
        carrick_usdt::io__wait__begin!(|| (tid, fd_count, timeout_ms, fd0, events0, fd1));
    }

    pub fn io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32) {
        carrick_usdt::io__wait__end!(|| (tid, result, fd_count, fd0, fd1, fd2));
    }

    pub fn fork_quiesce(phase: i32, a: i64, b: i64, tid: i32) {
        carrick_usdt::fork__quiesce!(|| (phase, a, b, tid));
    }

    pub fn fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64) {
        carrick_usdt::fork__rebuild!(|| (role, phase, desc_count, map_count, elapsed_us));
    }

    pub fn fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64) {
        carrick_usdt::fork__lifecycle!(|| (role, phase, elapsed_us, a, b));
    }

    /// Typed native-lane (DSR) entry point to the same `fork-lifecycle` probe.
    ///
    /// The role is DERIVED from the phase (see [`super::NativeForkPhase::role`]),
    /// so the native fork path never names a role integer and cannot report a
    /// child phase under the parent role. Both ordinals are converted to the
    /// probe's `i32` wire form INSIDE the closure, which `usdt` invokes only
    /// when a consumer is attached.
    pub fn native_fork_lifecycle(phase: super::NativeForkPhase, elapsed_us: u64, a: i64, b: i64) {
        carrick_usdt::fork__lifecycle!(|| { (phase.role().raw(), phase.raw(), elapsed_us, a, b) });
    }

    /// [`native_fork_lifecycle`] for the one phase both processes fire
    /// ([`super::NativeForkPhase::HostFork`]): each side of `fork(2)` reports
    /// the same measured span under its OWN role, so the role is supplied by
    /// the call site rather than derived.
    pub fn native_fork_lifecycle_as(
        role: super::NativeForkRole,
        phase: super::NativeForkPhase,
        elapsed_us: u64,
        a: i64,
        b: i64,
    ) {
        carrick_usdt::fork__lifecycle!(|| (role.raw(), phase.raw(), elapsed_us, a, b));
    }

    pub fn fork_footprint(
        phase: i32,
        vm_region_count: u64,
        arena_high_water: u64,
        resident_bytes: u64,
        virtual_bytes: u64,
    ) {
        carrick_usdt::fork__footprint!(|| {
            (
                phase,
                vm_region_count,
                arena_high_water,
                resident_bytes,
                virtual_bytes,
            )
        });
    }

    pub fn fork_footprint_class(
        class_id: i32,
        region_count: u64,
        scan_bytes: u64,
        resident_bytes: u64,
        flags: u64,
    ) {
        carrick_usdt::fork__footprint__class!(|| {
            (class_id, region_count, scan_bytes, resident_bytes, flags)
        });
    }

    pub fn with_fork_footprint_class_probe<F>(emit: F)
    where
        F: FnOnce(),
    {
        let mut emit = Some(emit);
        carrick_usdt::fork__footprint__class!(|| {
            if let Some(emit) = emit.take() {
                emit();
            }
            (0, 0, 0, 0, 0)
        });
    }

    pub fn fork_post(pid: i32, pc: u64, elr: u64) {
        carrick_usdt::fork__post!(|| (pid, pc, elr));
    }

    pub fn signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64) {
        carrick_usdt::signal__inject!(|| (signum, saved_pc, new_sp, handler));
    }

    pub fn signal_restore(saved_pc: u64, sp: u64, magic: u64) {
        carrick_usdt::signal__restore!(|| (saved_pc, sp, magic));
    }

    pub fn kick_in_kernel(pc: u64, el: u32) {
        carrick_usdt::kick__in_kernel!(|| (pc, el));
    }

    pub fn kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64) {
        carrick_usdt::kick__stats!(|| (el1_resumed, kick_inject, inject_at_el1));
    }

    pub fn mem_watch(syscall_nr: u64, addr: u64, value: u64) {
        carrick_usdt::mem__watch!(|| (syscall_nr, addr, value));
    }

    pub fn sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64) {
        carrick_usdt::sigaction__read!(|| (signum, w0, w1, w2, w3));
    }

    pub fn supervisor_fork(child_pid: i32) {
        carrick_usdt::supervisor__fork!(|| child_pid);
    }

    pub fn supervisor_child_ready(runtime_pid: i32) {
        carrick_usdt::supervisor__child__ready!(|| runtime_pid);
    }

    pub fn supervisor_foreground_pgrp(pgid: i32, errno: i32) {
        carrick_usdt::supervisor__foreground__pgrp!(|| (pgid, errno));
    }

    pub fn supervisor_child_exit(pid: i32, status: i32) {
        carrick_usdt::supervisor__child__exit!(|| (pid, status));
    }

    pub fn pt_pause_begin(tid: i32, others_in_guest: i32, count: i32) {
        carrick_usdt::pt__pause__begin!(|| (tid, others_in_guest, count));
    }

    pub fn pt_pause_ready(tid: i32, spins: i32, wait_us: i64) {
        carrick_usdt::pt__pause__ready!(|| (tid, spins, wait_us));
    }

    pub fn pt_pause_timeout(tid: i32, wait_us: i64) {
        carrick_usdt::pt__pause__timeout!(|| (tid, wait_us));
    }

    pub fn pt_pause_end(tid: i32) {
        carrick_usdt::pt__pause__end!(|| tid);
    }

    pub fn pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32) {
        carrick_usdt::pt__pool!(|| (in_use, free_list, capacity, changed));
    }

    pub fn pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64) {
        carrick_usdt::pt__fault__walk!(|| (far, l0, l1, l2, l3));
    }

    pub mod guest_mem_dir {
        pub const READ_GUEST: u32 = 0;
        pub const WRITE_GUEST: u32 = 1;
        pub const WRITE_GUEST_CHECKED: u32 = 2;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct GuestMemProbeDigest {
        checksum: u64,
        nonzero: u64,
        head: u64,
        tail: u64,
    }

    fn guest_mem_probe_digest(bytes: &[u8]) -> GuestMemProbeDigest {
        let checksum = bytes
            .iter()
            .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)));
        GuestMemProbeDigest {
            checksum,
            nonzero: bytes.iter().filter(|byte| **byte != 0).count() as u64,
            head: guest_mem_probe_edge(bytes.iter().copied()),
            tail: if bytes.len() <= 8 {
                guest_mem_probe_edge(bytes.iter().copied())
            } else {
                guest_mem_probe_edge(bytes[bytes.len() - 8..].iter().copied())
            },
        }
    }

    fn guest_mem_probe_edge(bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes
            .into_iter()
            .take(8)
            .enumerate()
            .fold(0u64, |word, (idx, byte)| {
                word | (u64::from(byte) << (idx * 8))
            })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct GuestMemSubrangeConfig {
        offset: usize,
        length: usize,
    }

    fn guest_mem_subrange_config() -> Option<GuestMemSubrangeConfig> {
        static CONFIG: std::sync::OnceLock<Option<GuestMemSubrangeConfig>> =
            std::sync::OnceLock::new();

        *CONFIG.get_or_init(|| {
            let offset = parse_guest_mem_probe_usize_env("CARRICK_GUEST_MEM_SUB_OFFSET")?;
            let length = parse_guest_mem_probe_usize_env("CARRICK_GUEST_MEM_SUB_LEN")?;
            (length != 0).then_some(GuestMemSubrangeConfig { offset, length })
        })
    }

    fn parse_guest_mem_probe_usize_env(name: &str) -> Option<usize> {
        let value = std::env::var(name).ok()?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        if let Some(hex) = value.strip_prefix("0x") {
            usize::from_str_radix(hex, 16).ok()
        } else {
            value.parse::<usize>().ok()
        }
    }

    fn guest_mem_probe_subrange(
        bytes: &[u8],
        config: GuestMemSubrangeConfig,
    ) -> Option<(u64, GuestMemProbeDigest)> {
        let end = config.offset.checked_add(config.length)?;
        let subrange = bytes.get(config.offset..end)?;
        Some((config.offset as u64, guest_mem_probe_digest(subrange)))
    }

    pub fn guest_mem_probe_points(address: u64, length: usize) -> [Option<u64>; 5] {
        if length == 0 {
            return [None, None, None, None, None];
        }

        let length = length as u64;
        let three_quarter_offset = (length / 4) * 3 + ((length % 4) * 3) / 4;
        let candidates = [
            Some(address),
            address.checked_add(length / 4),
            address.checked_add(length / 2),
            address.checked_add(three_quarter_offset),
            address.checked_add(length - 1),
        ];
        let mut points = [None, None, None, None, None];
        let mut next = 0usize;
        for candidate in candidates.into_iter().flatten() {
            if points[..next].contains(&Some(candidate)) {
                continue;
            }
            points[next] = Some(candidate);
            next += 1;
        }
        points
    }

    pub fn guest_mem_copy(
        direction: u32,
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
        mapping_start: u64,
        mapping_end: u64,
        mapping_ipa: u64,
    ) {
        let stage1_ipa = stage1_ipa.unwrap_or(u64::MAX);
        carrick_usdt::guest__mem__copy!(|| (
            direction,
            address,
            length as u64,
            stage1_ipa,
            mapping_start
        ));
        carrick_usdt::guest__mem__region!(|| (
            direction,
            address,
            mapping_start,
            mapping_end,
            mapping_ipa
        ));
    }

    pub fn guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]) {
        carrick_usdt::guest__mem__bytes!(|| {
            let digest = guest_mem_probe_digest(bytes);
            (
                direction,
                address,
                bytes.len() as u64,
                digest.checksum,
                digest.head,
            )
        });
        carrick_usdt::guest__mem__tail!(|| (
            direction,
            address,
            bytes.len() as u64,
            guest_mem_probe_digest(bytes).tail
        ));
        if let Some(config) = guest_mem_subrange_config()
            && let Some((offset, digest)) = guest_mem_probe_subrange(bytes, config)
        {
            carrick_usdt::guest__mem__subrange!(|| (
                direction,
                address,
                offset,
                config.length as u64,
                digest.checksum,
            ));
            carrick_usdt::guest__mem__subedge!(|| (
                direction,
                address,
                offset,
                digest.head,
                digest.tail,
            ));
            carrick_usdt::guest__mem__subcount!(|| (direction, address, offset, digest.nonzero));
        }
    }

    pub fn guest_mem_point(
        direction: u32,
        address: u64,
        stage1_ipa: Option<u64>,
        mapping_start: u64,
        mapping_ipa: u64,
    ) {
        let va_offset = address.wrapping_sub(mapping_start);
        let ipa_offset = stage1_ipa
            .map(|ipa| ipa.wrapping_sub(mapping_ipa))
            .unwrap_or(u64::MAX);
        carrick_usdt::guest__mem__point!(|| (
            direction,
            address,
            va_offset,
            ipa_offset,
            stage1_ipa.unwrap_or(u64::MAX)
        ));
    }

    // `#[inline(never)]`: usdt embeds the probe site (an asm! anchor) in
    // the function body. If this gets inlined into multiple callers, each
    // copy becomes a SEPARATE DTrace probe site that fires independently
    // — so a single logical trap would fire `vcpu-trap` twice. Pinning the
    // function to one body keeps it a single, stable probe site.
    #[inline(never)]
    pub fn vcpu_trap(regs: &crate::compat::GuestRegs) {
        // Pass the struct's address; DTrace copyin's it. The reference is
        // live for the duration of this (inline(never)) function, which is
        // where usdt's synchronous probe fire happens, so the pointer is
        // valid when DTrace reads it.
        let ptr = regs as *const crate::compat::GuestRegs as u64;
        carrick_usdt::vcpu__trap!(|| ptr);
    }

    pub fn execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64) {
        carrick_usdt::execve__loaded!(|| (path, entry, initial_sp, mapping_count));
    }

    pub fn execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64) {
        carrick_usdt::execve__sysregs!(|| (sctlr, ttbr0, mair));
    }

    /// Fires on a fatal guest EL0 fault (instruction/data abort, undef). See the
    /// `vcpu__fault` provider doc. Cheap: only fires at the fault.
    pub fn vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32) {
        carrick_usdt::vcpu__fault!(|| (esr, elr, far, x30, sp, tid));
    }

    /// Emit the decoded fault diagnostics as scalars. See the `vcpu__fault__regs`
    /// provider doc. Scalars are captured at fire time, so this survives a fault
    /// that kills the process before DTrace's action runs. Fires only at the fault.
    pub fn vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64) {
        carrick_usdt::vcpu__fault__regs!(|| (esr, elr, far, insn, rn, xrn));
    }

    #[allow(clippy::too_many_arguments)]
    pub fn native_x86_fault(
        pc: u64,
        fault_address: u64,
        rsp: u64,
        rax: u64,
        rcx: u64,
        rdx: u64,
        rdi: u64,
        rsi: u64,
        r8: u64,
        rflags: u64,
    ) {
        let pid = std::process::id();
        carrick_usdt::native__x86__fault!(|| (pid, pc, fault_address, rsp, rcx, rflags));
        carrick_usdt::native__x86__fault__regs!(|| (pid, rax, rdx, rdi, rsi, r8));
    }

    pub fn native_x86_fault_stack(rbp: u64, stack_words: [u64; 4]) {
        let pid = std::process::id();
        carrick_usdt::native__x86__fault__stack!(|| (
            pid,
            stack_words[0],
            stack_words[1],
            stack_words[2],
            stack_words[3],
            rbp
        ));
    }

    pub fn native_x86_fault_history(pcs: [u64; 5]) {
        let pid = std::process::id();
        carrick_usdt::native__x86__fault__history!(|| (
            pid, pcs[0], pcs[1], pcs[2], pcs[3], pcs[4]
        ));
    }

    pub fn native_x86_pc(pc: u64, rsp: u64, rdi: u64, rbp: u64, stack_word: u64) {
        let pid = std::process::id();
        carrick_usdt::native__x86__pc!(|| (pid, pc, rsp, rdi, rbp, stack_word));
    }

    pub fn native_x86_resolve(source: u64, target: u64, rsp: u64, rdi: u64, rbp: u64) {
        let pid = std::process::id();
        carrick_usdt::native__x86__resolve!(|| (pid, source, target, rsp, rdi, rbp));
    }

    /// Scalar payload for the opt-in native-x86 xstate transition probes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NativeX86XstateProbe {
        pub source: u64,
        pub target: u64,
        pub event: u64,
        pub flags: u64,
        pub xstate_bv: u64,
        pub fcw: u16,
        pub mxcsr: u32,
        pub pkru: u32,
        pub legacy_hash: u64,
        pub ymm_hash: u64,
        pub opmask_zmm_hash: u64,
        pub extended_hash: u64,
    }

    pub fn native_x86_xstate_edge(probe: NativeX86XstateProbe) {
        let pid = std::process::id();
        carrick_usdt::native__x86__xstate__edge!(|| (
            pid,
            probe.source,
            probe.target,
            probe.event,
            probe.flags,
            probe.xstate_bv
        ));
    }

    pub fn native_x86_xstate(probe: NativeX86XstateProbe) {
        let pid = std::process::id();
        native_x86_xstate_edge(probe);
        carrick_usdt::native__x86__xstate__controls!(|| (
            pid,
            probe.source,
            u64::from(probe.fcw),
            u64::from(probe.mxcsr),
            u64::from(probe.pkru),
            probe.extended_hash
        ));
        carrick_usdt::native__x86__xstate__hashes!(|| (
            pid,
            probe.source,
            probe.legacy_hash,
            probe.ymm_hash,
            probe.opmask_zmm_hash,
            probe.extended_hash
        ));
    }

    /// Emit a high-VA alias page-table walk. See `pt__alias__walk`. `flag` bit0 =
    /// forked child, bit1 = the page-table build failed.
    pub fn pt_alias_walk(va: u64, descs: [u64; 4], flag: i32) {
        carrick_usdt::pt__alias__walk!(|| (va, descs[0], descs[1], descs[2], descs[3], flag));
    }

    /// Emit the stage-2 `hv_vm_map` result for an alias mapping. See
    /// `hv__vm__map__alias`. Fires right after the call, success or failure.
    pub fn hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32) {
        carrick_usdt::hv__vm__map__alias!(|| (va, ipa, size, rc, forked));
    }

    /// A signal was published for delivery. See `signal__publish`.
    pub fn signal_publish(target_tid: i32, signum: i32, kind: i32) {
        carrick_usdt::signal__publish!(|| (target_tid, signum, kind));
    }

    /// A `deliver_pending_signal` cycle ran. See `signal__deliver`.
    pub fn signal_deliver(tid: i32, pending: i32) {
        carrick_usdt::signal__deliver!(|| (tid, pending));
    }

    pub fn register_dtrace_probes() -> Result<(), super::ProbeRegistrationError> {
        // Install the compat reporter's per-event probe hook so every recorded
        // CompatEvent fires its DTrace probe. compat lives in the neutral
        // carrick-observability crate (no usdt dep) and only fires probes through
        // this hook; Linux/bhyve never install it. Idempotent (OnceLock).
        crate::compat::set_probe_hook(fire);
        // `usdt::Error`'s own Display text, verbatim — the callers only ever
        // render this, so the message is byte-identical to returning it directly.
        usdt::register_probes().map_err(|err| super::ProbeRegistrationError::new(err.to_string()))
    }

    pub fn fire(event: &CompatEvent) {
        fire_usdt(event);
    }

    fn fire_usdt(event: &CompatEvent) {
        match event {
            CompatEvent::SyscallEntry { number, name, args } => {
                // `args` lives in `event` for the duration of this synchronous
                // probe fire, so its address is valid when DTrace copyin's it.
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::syscall__entry!(|| (*number, name.as_ref(), args_ptr));
            }
            CompatEvent::SyscallReturn {
                number,
                name,
                retval,
                errno,
            } => {
                carrick_usdt::syscall__return!(|| {
                    (*number, name.as_ref(), *retval, errno.unwrap_or(0))
                });
            }
            CompatEvent::UnhandledSyscall { number, name, args } => {
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::unhandled__syscall!(|| (*number, name.as_str(), args_ptr));
            }
            CompatEvent::PartialSyscall {
                number,
                name,
                args,
                reason,
            } => {
                let args_ptr = args as *const SyscallArgs as u64;
                carrick_usdt::partial__syscall!(|| (
                    *number,
                    name.as_str(),
                    args_ptr,
                    reason.as_str()
                ));
            }
            CompatEvent::UnhandledIoctl { fd, request, arg } => {
                carrick_usdt::unhandled__ioctl!(|| (*fd, *request, *arg));
            }
            CompatEvent::ProcReadUnimplemented { path } => {
                carrick_usdt::proc__read__unimplemented!(|| path.as_str());
            }
            CompatEvent::SysReadUnimplemented { path } => {
                carrick_usdt::sys__read__unimplemented!(|| path.as_str());
            }
            CompatEvent::SignalUnsupported { signum, reason } => {
                carrick_usdt::signal__unsupported!(|| (*signum, reason.as_str()));
            }
            CompatEvent::UnknownSyscallFlags {
                number,
                name,
                argument,
                unknown_bits,
            } => {
                carrick_usdt::unknown__syscall__flags!(|| (
                    *number,
                    name.as_str(),
                    *argument,
                    *unknown_bits
                ));
            }
        }
    }

    #[allow(dead_code)]
    fn _assert_args_are_serializable(args: &SyscallArgs) -> &SyscallArgs {
        args
    }

    #[cfg(test)]
    mod tests {
        #[cfg(target_os = "macos")]
        #[test]
        fn host_image_catalog_contains_darwin_runtime() {
            let catalog = super::host_image_catalog_snapshot();

            assert_eq!(catalog.pid, std::process::id());
            assert!(catalog.ranges.iter().all(|range| range.start < range.end));
            assert!(
                catalog
                    .ranges
                    .windows(2)
                    .all(|pair| pair[0].end <= pair[1].start),
                "host image catalog is not sorted and non-overlapping"
            );
            assert!(
                catalog
                    .ranges
                    .iter()
                    .any(|range| range.path == "/usr/lib/system/libsystem_kernel.dylib"),
                "libsystem_kernel absent from {} runtime ranges",
                catalog.ranges.len()
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn profile_runtime_image_filter_is_bounded_and_explicit() {
            for accepted in [
                "/usr/lib/system/libsystem_kernel.dylib",
                "/usr/lib/libSystem.B.dylib",
                "/usr/lib/libobjc.A.dylib",
                "/usr/lib/objc/libobjcMsgSend.dylib",
                "/usr/lib/libc++.1.dylib",
                "/usr/lib/libdtrace.dylib",
            ] {
                assert!(super::profile_runtime_image_path(accepted), "{accepted}");
            }
            assert!(!super::profile_runtime_image_path(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            ));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn prepared_image_publication_retains_exact_usdt_wire_pointers_and_bytes() {
            let prepared = super::prepare_host_image_publication_from_snapshots(
                super::HostImageBase {
                    pid: 17,
                    base: 0x10_0000,
                    slide: -0x2000,
                    path: "/tmp/carrick".to_owned(),
                },
                super::HostImageCatalog {
                    pid: 17,
                    ranges: vec![super::HostImageRange {
                        start: 0x10_0000,
                        end: 0x10_4000,
                        path: "/tmp/\"carrick\\bin".to_owned(),
                    }],
                },
            );

            let (pid, base, slide, base_path) = super::prepared_host_image_base_args(&prepared);
            assert_eq!((pid, base, slide), (17, 0x10_0000, -0x2000));
            assert_eq!(base_path, prepared.base_path_wire.as_ptr());
            assert_eq!(prepared.base_path_wire.as_ref(), b"/tmp/carrick\0");

            let catalog = super::prepared_host_image_catalog_arg(&prepared);
            assert_eq!(catalog, prepared.catalog_wire.as_ptr());
            assert_eq!(
                prepared.catalog_wire.as_ref(),
                b"{\"ok\":{\"pid\":17,\"ranges\":[{\"start\":1048576,\"end\":1064960,\"path\":\"/tmp/\\\"carrick\\\\bin\"}]}}\0"
            );

            let guest = super::prepare_guest_image_path("/bin/guest".to_owned());
            let guest_path = super::prepared_guest_image_path_arg(&guest);
            assert_eq!(guest_path, guest.wire.as_ptr());
            assert_eq!(guest.wire.as_ref(), b"/bin/guest\0");
            assert_eq!(guest.as_str(), "/bin/guest");
            let moved_guest = guest;
            assert_eq!(
                super::prepared_guest_image_path_arg(&moved_guest),
                guest_path,
                "moving the owner changed its boxed wire pointer"
            );
        }

        #[test]
        fn guest_mem_probe_digest_reports_wrapping_sum_and_edges() {
            let bytes = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
                0x90, 0x80,
            ];

            let digest = super::guest_mem_probe_digest(&bytes);

            assert_eq!(digest.checksum, 0x5e4);
            assert_eq!(digest.nonzero, 16);
            assert_eq!(digest.head, 0x0807_0605_0403_0201);
            assert_eq!(digest.tail, 0x8090_a0b0_c0d0_e0f0);
        }

        #[test]
        fn guest_mem_probe_digest_zero_pads_short_edges() {
            let digest = super::guest_mem_probe_digest(&[0xaa, 0xbb, 0xcc]);

            assert_eq!(digest.checksum, 0x231);
            assert_eq!(digest.nonzero, 3);
            assert_eq!(digest.head, 0x00cc_bbaa);
            assert_eq!(digest.tail, 0x00cc_bbaa);
        }

        #[test]
        fn guest_mem_probe_subrange_reports_exact_window_digest() {
            let bytes = [0xaa, 0x00, 0xbb, 0xcc, 0x00, 0xdd];

            let (_, digest) = super::guest_mem_probe_subrange(
                &bytes,
                super::GuestMemSubrangeConfig {
                    offset: 1,
                    length: 4,
                },
            )
            .unwrap();

            assert_eq!(digest.checksum, 0x187);
            assert_eq!(digest.nonzero, 2);
            assert_eq!(digest.head, 0x00cc_bb00);
            assert_eq!(digest.tail, 0x00cc_bb00);
        }

        #[test]
        fn guest_mem_probe_points_cover_quarters_and_last_byte_without_duplicates() {
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 0),
                [None, None, None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 1),
                [Some(0x1000), None, None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x1000, 2),
                [Some(0x1000), Some(0x1001), None, None, None]
            );
            assert_eq!(
                super::guest_mem_probe_points(0x4590, 8192),
                [
                    Some(0x4590),
                    Some(0x4d90),
                    Some(0x5590),
                    Some(0x5d90),
                    Some(0x658f)
                ]
            );
        }

        #[test]
        fn guest_mem_probe_points_sample_inside_large_range_quarters() {
            let points = super::guest_mem_probe_points(0x4590, 8192);

            assert!(
                points.contains(&Some(0x5d90)),
                "expected 75% sample point in {points:?}"
            );
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        any(target_os = "linux", target_os = "freebsd"),
        target_arch = "x86_64"
    )
)))]
mod stub {
    //! No-op probe surface for the targets that link no `usdt` at all — NetBSD,
    //! plus aarch64 linux/freebsd (see the module header: usdt 0.6's SDT backend
    //! is x86-only, and its FreeBSD DTrace backend does not even compile on
    //! aarch64). Every public item the `real` module exports is mirrored
    //! here with an IDENTICAL signature and an empty body, so the dispatcher's
    //! `crate::probes::…` call sites compile unchanged. The three non-probe
    //! helpers (`guest_mem_probe_points`/`guest_mem_copy`/`guest_mem_point`) are
    //! plain logic, not probe fires, so they keep their REAL bodies — behaviour
    //! is identical to the real arm.

    #[derive(Debug)]
    pub struct PreparedHostImagePublication;

    #[derive(Debug, Eq, PartialEq)]
    pub struct PreparedGuestImagePath {
        wire: Box<[u8]>,
    }

    impl PreparedGuestImagePath {
        pub fn as_str(&self) -> &str {
            let path = &self.wire[..self.wire.len().saturating_sub(1)];
            // SAFETY: the only constructor consumes a valid `String` and
            // appends one byte; it never changes the original UTF-8 bytes.
            unsafe { std::str::from_utf8_unchecked(path) }
        }
    }

    pub fn prepare_guest_image_path(path: String) -> PreparedGuestImagePath {
        let mut wire = path.into_bytes();
        wire.push(0);
        PreparedGuestImagePath {
            wire: wire.into_boxed_slice(),
        }
    }

    pub fn prepare_host_image_publication() -> PreparedHostImagePublication {
        PreparedHostImagePublication
    }

    macro_rules! stub {
        ($name:ident($($param:ident: $ty:ty),* $(,)?) -> $return:ty => $value:expr) => {
            #[allow(dead_code, unused_variables)]
            #[inline(always)]
            pub fn $name($($param: $ty),*) -> $return { $value }
        };
        ($name:ident($($param:ident: $ty:ty),* $(,)?)) => {
            #[allow(dead_code, unused_variables)]
            #[inline(always)]
            pub fn $name($($param: $ty),*) {}
        };
    }

    stub!(dsr_prepare_begin(tid: i32, guest_pc: u64));
    stub!(native_syscall_service_entry(number: u64, name: &str));
    stub!(native_syscall_service_branch(kind: super::NativeSyscallBranchKind));
    stub!(native_syscall_service_end(number: u64, name: &str, outcome: super::NativeSyscallServiceOutcome));
    stub!(native_tierd_exception(phase: u32, a: u64, b: u64, c: u64, d: u64));
    stub!(native_tierd_unsupported(syscall: u64, detail: &str));
    stub!(hvf_syscall_transport(transport: u32, phase: u32, register_reads: u32, sysreg_reads: u32, register_writes: u32));
    stub!(dsr_prepare_end(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64, outcome: super::DsrPrepareOutcome));
    stub!(dsr_run_begin(tid: i32, guest_pc: u64, cache_pc: u64, generation: u64));
    stub!(dsr_run_end(tid: i32, kind: super::DsrExitKind, guest_pc: u64, target_pc: u64, status: i32));
    stub!(dsr_translate_begin(tid: i32, guest_pc: u64, generation: u64));
    stub!(dsr_translate_end(tid: i32, guest_pc: u64, cache_pc: u64, emitted_bytes: u64, outcome: super::DsrOperationOutcome));
    stub!(dsr_translate_subphase_begin(tid: i32, subphase: super::DsrTranslationSubphase, guest_pc: u64, generation: u64));
    stub!(dsr_translate_subphase_end(tid: i32, subphase: super::DsrTranslationSubphase, guest_pc: u64, generation: u64));
    stub!(dsr_synchronization_begin(kind: super::DsrSynchronizationKind));
    stub!(dsr_synchronization_end(kind: super::DsrSynchronizationKind));
    stub!(dsr_resolve_begin(tid: i32, kind: super::DsrResolveKind, source_pc: u64, target_pc: u64));
    stub!(dsr_resolve_end(tid: i32, kind: super::DsrResolveKind, source_pc: u64, target_pc: u64, outcome: super::DsrOperationOutcome));
    stub!(dsr_cache_event(tid: i32, kind: super::DsrCacheEventKind, guest_pc: u64, generation: u64, used_bytes: u64));
    stub!(dsr_cache_capacity(role: super::DsrCacheRole, capacity_bytes: u64));
    stub!(dsr_cache_bounds(base: u64, end: u64));
    stub!(host_process_birth(event: super::HostProcessBirth));
    stub!(host_process_birth_current());
    stub!(host_translated_range_reset(event: super::TranslatedRangeReset));
    stub!(host_translated_private_range(event: super::TranslatedPrivateRange));
    stub!(host_translated_shared_range(event: super::TranslatedSharedRange));
    stub!(host_translated_range_ready(event: super::TranslatedRangeReady));
    stub!(host_native_owned_range_reset(event: super::NativeOwnedRangeReset));
    stub!(host_native_owned_range_add(event: super::NativeOwnedRange));
    stub!(host_native_owned_range_ready(event: super::NativeOwnedRangeReady));
    stub!(dsr_cache_lifecycle(tid: i32, phase: super::DsrCacheLifecyclePhase, used_bytes: u64, block_count: u64, generation_count: u64));
    stub!(dsr_exec_map_detail(tid: i32, kind: super::DsrExecMapDetailKind, duration_ns: u64, bytes: u64, operations: u64));
    stub!(fork_pre(pc: u64, elr: u64, cpsr: u64));
    stub!(path_open(path: &str, result_size: u64, errno: i32));
    stub!(itimer_fire(signum: i32, generation: u64));
    stub!(futex_route(addr: u64, op: i32, shared: i32, host_addr: u64));
    stub!(ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64));
    stub!(ulock_wake(host_addr: u64, iter: i32, rc: i64));
    stub!(ulock_requeue(sample: super::UlockRequeueProbe));
    stub!(futex_unexpected_errno(host_addr: u64, errno: i32));
    stub!(guest_exit(code: i32));
    stub!(mn_admit(tid: i32, slot: u32, budget: u32));
    stub!(mn_reclaim(tid: i32, old_slot: u32, new_slot: u32, kind: i32));
    stub!(lifecycle(phase: u32));
    stub!(hvpatch_guest_lifecycle(event: super::HvpatchGuestLifecycle));
    stub!(hvpatch_guest_fault(event: super::HvpatchGuestFault));
    stub!(hvpatch_guest_address_space(event: super::HvpatchGuestAddressSpace));
    stub!(hvpatch_syscall_service_begin(event: super::HvpatchSyscallService, args: [u64; 6]) -> Option<std::time::Instant> => None);
    stub!(hvpatch_syscall_service(event: super::HvpatchSyscallService));
    stub!(hvpatch_syscall_service_clear(event: super::HvpatchSyscallService));
    stub!(hvpatch_fork_snapshot_begin(child_pid: i32, forking_tid: i32));
    stub!(hvpatch_fork_snapshot_end(child_pid: i32, local_regions: u64, candidate_regions: u64, added_regions: u64, added_bytes: u64));
    stub!(hvpatch_fork_snapshot_shape(child_pid: i32, private_added_regions: u64, shared_added_regions: u64, largest_added_bytes: u64, bank_used_bytes: u64));
    stub!(hvpatch_exec_bank_layout(event: super::HvpatchExecBankLayout));
    stub!(hvpatch_exec_backing(event: super::HvpatchExecBacking));
    stub!(hvpatch_exec_stage2(event: super::HvpatchExecStage2));
    stub!(hvpatch_exec_replace_stage(event: super::HvpatchExecReplaceStage));
    stub!(hvpatch_exec_runtime_stage(event: super::HvpatchExecRuntimeStage));
    stub!(hvpatch_topology_lock(event: super::HvpatchTopologyLock));
    stub!(hvpatch_fork_runtime_stage(event: super::HvpatchForkRuntimeStage));
    stub!(hvpatch_fork_process_spec_stage(event: super::HvpatchForkProcessSpecStage));
    stub!(hvpatch_fork_private_snapshot(event: super::HvpatchForkPrivateSnapshot));
    stub!(hvpatch_fork_private_snapshot_outcome(event: super::HvpatchForkPrivateSnapshotOutcome));
    stub!(hvpatch_fork_quiesce(event: super::HvpatchForkQuiesce));

    pub fn vm_lifecycle(operation: u32, admission: i32) {
        crate::vm_lifecycle::record_raw(operation, admission);
    }

    stub!(execve_argv(path: &str, argv: &[Vec<u8>]));
    stub!(host_image_base());
    stub!(host_image_text_range());
    stub!(host_image_catalog());
    stub!(publish_host_image_base(prepared: &PreparedHostImagePublication));
    stub!(publish_host_image_catalog(prepared: &PreparedHostImagePublication));
    stub!(guest_image_base(base: u64, entry: u64, path: &PreparedGuestImagePath));
    stub!(host_jit_range(start: u64, end: u64));
    stub!(fs_op(op: &str, path: &str, errno: i32));
    stub!(host_pipe_io(host_fd: i32, dir: i32, n: i64));
    stub!(epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32));
    stub!(epoll_interest(epfd: i32, fd: i32, requested: u32, raw_ready: u32, last_ready: u32, ready: u32));
    stub!(epoll_masked(sample: super::EpollMaskedProbe));
    stub!(epoll_rebind(reason: u32, host_fd: i32, survivor_fd: i32, survivor_gen: u32, union_events: u32, effective: u32));
    stub!(epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32));
    stub!(epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32));
    stub!(epoll_stale_edge(udata: u64, guest_fd: i32, generation: u32));
    stub!(io_wait_begin(tid: i32, fd_count: i32, timeout_ms: i64, fd0: i32, events0: i32, fd1: i32));
    stub!(io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32));
    stub!(fork_quiesce(phase: i32, a: i64, b: i64, tid: i32));
    stub!(fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64));
    stub!(fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64));
    stub!(native_fork_lifecycle(phase: super::NativeForkPhase, elapsed_us: u64, a: i64, b: i64));
    stub!(native_fork_lifecycle_as(role: super::NativeForkRole, phase: super::NativeForkPhase, elapsed_us: u64, a: i64, b: i64));
    stub!(fork_footprint(phase: i32, vm_region_count: u64, arena_high_water: u64, resident_bytes: u64, virtual_bytes: u64));
    stub!(fork_footprint_class(class_id: i32, region_count: u64, scan_bytes: u64, resident_bytes: u64, flags: u64));
    stub!(fork_post(pid: i32, pc: u64, elr: u64));
    stub!(signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64));
    stub!(signal_restore(saved_pc: u64, sp: u64, magic: u64));
    stub!(kick_in_kernel(pc: u64, el: u32));
    stub!(kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64));
    stub!(mem_watch(syscall_nr: u64, addr: u64, value: u64));
    stub!(sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64));
    stub!(supervisor_fork(child_pid: i32));
    stub!(supervisor_child_ready(runtime_pid: i32));
    stub!(supervisor_foreground_pgrp(pgid: i32, errno: i32));
    stub!(supervisor_child_exit(pid: i32, status: i32));
    stub!(pt_pause_begin(tid: i32, others_in_guest: i32, count: i32));
    stub!(pt_pause_ready(tid: i32, spins: i32, wait_us: i64));
    stub!(pt_pause_timeout(tid: i32, wait_us: i64));
    stub!(pt_pause_end(tid: i32));
    stub!(pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32));
    stub!(pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64));
    stub!(guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]));
    stub!(vcpu_trap(regs: &crate::compat::GuestRegs));
    stub!(execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64));
    stub!(execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64));
    stub!(vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32));
    stub!(vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64));
    stub!(pt_alias_walk(va: u64, descs: [u64; 4], flag: i32));
    stub!(hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32));
    stub!(signal_publish(target_tid: i32, signum: i32, kind: i32));
    stub!(signal_deliver(tid: i32, pending: i32));
    stub!(fire(event: &crate::compat::CompatEvent));

    // Native-x86 (DSR) run-loop probes — no-op mirror of `real`'s, so the shared
    // BSD native run loop (native_freebsd.rs, now compiled on NetBSD too, a
    // stub/usdt-less target) links unchanged. `NativeX86XstateProbe` is defined
    // here with the same public fields the run loop constructs.
    stub!(native_x86_fault_stack(rbp: u64, stack_words: [u64; 4]));
    stub!(native_x86_fault_history(pcs: [u64; 5]));
    stub!(native_x86_pc(pc: u64, rsp: u64, rdi: u64, rbp: u64, stack_word: u64));
    stub!(native_x86_resolve(source: u64, target: u64, rsp: u64, rdi: u64, rbp: u64));

    #[allow(clippy::too_many_arguments, dead_code, unused_variables)]
    #[inline(always)]
    pub fn native_x86_fault(
        pc: u64,
        fault_address: u64,
        rsp: u64,
        rax: u64,
        rcx: u64,
        rdx: u64,
        rdi: u64,
        rsi: u64,
        r8: u64,
        rflags: u64,
    ) {
    }

    /// Scalar payload for the opt-in native-x86 xstate transition probes
    /// (mirrors `real::NativeX86XstateProbe` field-for-field).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NativeX86XstateProbe {
        pub source: u64,
        pub target: u64,
        pub event: u64,
        pub flags: u64,
        pub xstate_bv: u64,
        pub fcw: u16,
        pub mxcsr: u32,
        pub pkru: u32,
        pub legacy_hash: u64,
        pub ymm_hash: u64,
        pub opmask_zmm_hash: u64,
        pub extended_hash: u64,
    }

    stub!(native_x86_xstate_edge(probe: NativeX86XstateProbe));
    stub!(native_x86_xstate(probe: NativeX86XstateProbe));

    pub fn with_fork_footprint_class_probe<F>(_emit: F)
    where
        F: FnOnce(),
    {
    }

    /// Per-run lifecycle phase markers (mirrors `real::phase`).
    pub mod phase {
        pub const RUN_ENTRY: u32 = 0;
        pub const IMAGE_READY: u32 = 1;
        pub const VM_CREATED: u32 = 2;
        pub const GUEST_LOADED: u32 = 3;
        pub const FIRST_VCPU_RUN: u32 = 4;
        pub const VM_DESTROY_BEGIN: u32 = 5;
        pub const VM_DESTROY_END: u32 = 6;
    }

    /// Guest-memory copy direction tags (mirrors `real::guest_mem_dir`).
    pub mod guest_mem_dir {
        pub const READ_GUEST: u32 = 0;
        pub const WRITE_GUEST: u32 = 1;
        pub const WRITE_GUEST_CHECKED: u32 = 2;
    }

    // The three non-probe helpers carry their REAL bodies (plain logic), so the
    // Linux/NetBSD arm computes identical results to the macOS/FreeBSD arm.

    pub fn guest_mem_probe_points(address: u64, length: usize) -> [Option<u64>; 5] {
        if length == 0 {
            return [None, None, None, None, None];
        }

        let length = length as u64;
        let three_quarter_offset = (length / 4) * 3 + ((length % 4) * 3) / 4;
        let candidates = [
            Some(address),
            address.checked_add(length / 4),
            address.checked_add(length / 2),
            address.checked_add(three_quarter_offset),
            address.checked_add(length - 1),
        ];
        let mut points = [None, None, None, None, None];
        let mut next = 0usize;
        for candidate in candidates.into_iter().flatten() {
            if points[..next].contains(&Some(candidate)) {
                continue;
            }
            points[next] = Some(candidate);
            next += 1;
        }
        points
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guest_mem_copy(
        _direction: u32,
        _address: u64,
        _length: usize,
        _stage1_ipa: Option<u64>,
        _mapping_start: u64,
        _mapping_end: u64,
        _mapping_ipa: u64,
    ) {
    }

    pub fn guest_mem_point(
        _direction: u32,
        _address: u64,
        _stage1_ipa: Option<u64>,
        _mapping_start: u64,
        _mapping_ipa: u64,
    ) {
    }

    pub fn register_dtrace_probes() -> Result<(), super::ProbeRegistrationError> {
        Ok(())
    }
}
