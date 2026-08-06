use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use carrick_host::clock::{TickScale, monotonic_ticks, tick_scale};
use carrick_host::host_proc::ThreadPort;

use crate::vocabulary::{ExclusiveFusionDisposition, ExclusiveFusionRejection, SensitiveKind};

pub const PROTOCOL_PREFIX: &str = "NATIVEPERF1";
pub const DARWIN_PIPE_BUF: usize = 512;

/// Reserved fail-closed identity. Valid exec epochs are `0..u64::MAX`; an
/// attempted increment from the final valid epoch publishes this sentinel and
/// invalidates profiling without affecting guest exec semantics.
const INVALID_EXEC_EPOCH: u64 = u64::MAX;
static PROFILE_EXEC_EPOCH: AtomicU64 = AtomicU64::new(0);

fn next_exec_epoch(current: u64) -> u64 {
    current.checked_add(1).unwrap_or(INVALID_EXEC_EPOCH)
}

pub fn next_profile_exec_epoch_for_reexec() -> u64 {
    next_exec_epoch(PROFILE_EXEC_EPOCH.load(Ordering::Acquire))
}

pub fn seed_profile_exec_epoch_after_reexec(epoch: u64) {
    PROFILE_EXEC_EPOCH.store(epoch, Ordering::Release);
}

pub fn reset_profile_exec_epoch_after_fork_child() {
    PROFILE_EXEC_EPOCH.store(0, Ordering::Release);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ExitClass {
    Syscall,
    ResolveDirect,
    ResolveIndirect,
    Sensitive,
    Fault,
    Kick,
    StaleGeneration,
    Unsupported,
}

impl ExitClass {
    pub const ALL: [Self; 8] = [
        Self::Syscall,
        Self::ResolveDirect,
        Self::ResolveIndirect,
        Self::Sensitive,
        Self::Fault,
        Self::Kick,
        Self::StaleGeneration,
        Self::Unsupported,
    ];
    pub const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    const fn field_name(self) -> &'static str {
        match self {
            Self::Syscall => "syscall",
            Self::ResolveDirect => "resolve_direct",
            Self::ResolveIndirect => "resolve_indirect",
            Self::Sensitive => "sensitive",
            Self::Fault => "fault",
            Self::Kick => "kick",
            Self::StaleGeneration => "stale_generation",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum SensitiveClass {
    Exclusive,
    ReadTpidr,
    WriteTpidr,
    ReadCounter,
    ReadCtr,
    ReadDczid,
    DcZva,
    DcCvau,
    IcIvau,
}

impl SensitiveClass {
    pub const ALL: [Self; 9] = [
        Self::Exclusive,
        Self::ReadTpidr,
        Self::WriteTpidr,
        Self::ReadCounter,
        Self::ReadCtr,
        Self::ReadDczid,
        Self::DcZva,
        Self::DcCvau,
        Self::IcIvau,
    ];
    pub const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    #[cfg(test)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::ReadTpidr => "read-tpidr",
            Self::WriteTpidr => "write-tpidr",
            Self::ReadCounter => "read-counter",
            Self::ReadCtr => "read-ctr",
            Self::ReadDczid => "read-dczid",
            Self::DcZva => "dc-zva",
            Self::DcCvau => "dc-cvau",
            Self::IcIvau => "ic-ivau",
        }
    }

    const fn field_name(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::ReadTpidr => "read_tpidr",
            Self::WriteTpidr => "write_tpidr",
            Self::ReadCounter => "read_counter",
            Self::ReadCtr => "read_ctr",
            Self::ReadDczid => "read_dczid",
            Self::DcZva => "dc_zva",
            Self::DcCvau => "dc_cvau",
            Self::IcIvau => "ic_ivau",
        }
    }
}

impl From<SensitiveKind> for SensitiveClass {
    fn from(kind: SensitiveKind) -> Self {
        kind.profile_class()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ExclusiveFusionClass {
    FusedDirect,
    FusedBiased,
    EligibleBackendDisabled,
    NotLoad,
    VirtualizedBase,
    VirtualizedOperand,
    PageBoundary,
    ScanLimitOrNoStore,
    MismatchedStore,
    UnsupportedBodyMemoryOrSensitive,
    UnsupportedControlFlow,
    InvalidRetryEdge,
    BiasedNoSafeScratch,
    BiasedAddressFormUnsupported,
    AnalysisUnavailable,
}

impl ExclusiveFusionClass {
    pub const ALL: [Self; 15] = [
        Self::FusedDirect,
        Self::FusedBiased,
        Self::EligibleBackendDisabled,
        Self::NotLoad,
        Self::VirtualizedBase,
        Self::VirtualizedOperand,
        Self::PageBoundary,
        Self::ScanLimitOrNoStore,
        Self::MismatchedStore,
        Self::UnsupportedBodyMemoryOrSensitive,
        Self::UnsupportedControlFlow,
        Self::InvalidRetryEdge,
        Self::BiasedNoSafeScratch,
        Self::BiasedAddressFormUnsupported,
        Self::AnalysisUnavailable,
    ];
    pub const COUNT: usize = Self::ALL.len();

    pub const fn index(self) -> usize {
        self as usize
    }

    const fn field_name(self) -> &'static str {
        match self {
            Self::FusedDirect => "fused_direct",
            Self::FusedBiased => "fused_biased",
            Self::EligibleBackendDisabled => "eligible_backend_disabled",
            Self::NotLoad => "not_load",
            Self::VirtualizedBase => "virtualized_base",
            Self::VirtualizedOperand => "virtualized_operand",
            Self::PageBoundary => "page_boundary",
            Self::ScanLimitOrNoStore => "scan_limit_or_no_store",
            Self::MismatchedStore => "mismatched_store",
            Self::UnsupportedBodyMemoryOrSensitive => "unsupported_body_memory_or_sensitive",
            Self::UnsupportedControlFlow => "unsupported_control_flow",
            Self::InvalidRetryEdge => "invalid_retry_edge",
            Self::BiasedNoSafeScratch => "biased_no_safe_scratch",
            Self::BiasedAddressFormUnsupported => "biased_address_form_unsupported",
            Self::AnalysisUnavailable => "analysis_unavailable",
        }
    }
}

impl From<ExclusiveFusionDisposition> for ExclusiveFusionClass {
    fn from(disposition: ExclusiveFusionDisposition) -> Self {
        match disposition {
            ExclusiveFusionDisposition::FusedDirect => Self::FusedDirect,
            ExclusiveFusionDisposition::FusedBiased => Self::FusedBiased,
            ExclusiveFusionDisposition::EligibleBackendDisabled => Self::EligibleBackendDisabled,
            ExclusiveFusionDisposition::Rejected(rejection) => match rejection {
                ExclusiveFusionRejection::NotLoad => Self::NotLoad,
                ExclusiveFusionRejection::VirtualizedBase => Self::VirtualizedBase,
                ExclusiveFusionRejection::VirtualizedOperand => Self::VirtualizedOperand,
                ExclusiveFusionRejection::PageBoundary => Self::PageBoundary,
                ExclusiveFusionRejection::ScanLimitOrNoStore => Self::ScanLimitOrNoStore,
                ExclusiveFusionRejection::MismatchedStore => Self::MismatchedStore,
                ExclusiveFusionRejection::UnsupportedBodyMemoryOrSensitive => {
                    Self::UnsupportedBodyMemoryOrSensitive
                }
                ExclusiveFusionRejection::UnsupportedControlFlow => Self::UnsupportedControlFlow,
                ExclusiveFusionRejection::InvalidRetryEdge => Self::InvalidRetryEdge,
                ExclusiveFusionRejection::BiasedNoSafeScratch => Self::BiasedNoSafeScratch,
                ExclusiveFusionRejection::BiasedAddressFormUnsupported => {
                    Self::BiasedAddressFormUnsupported
                }
                ExclusiveFusionRejection::AnalysisUnavailable => Self::AnalysisUnavailable,
            },
        }
    }
}

/// Why one live-arena consultation fell back to the private translator.
///
/// The counting vocabulary for `carrick_dsr_aarch64::translator::LiveFallback`,
/// with the arena's own named refusals EXPANDED rather than collapsed: "the
/// record is still BUILDING" and "the record failed validation" imply opposite
/// fixes, so folding them into one `arena` bucket would make a mis-attributed
/// fallback invisible — the exact defect Task 6F exists to remove.
///
/// The producer's mapping is an exhaustive match with no wildcard, so a new
/// fallback reason is a compile error here rather than a silent reuse of a
/// neighbouring class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum LiveLaneFallbackClass {
    Unconfigured,
    Regenerated,
    OutsideSegment,
    CrossPage,
    UnsupportedShape,
    SourceWordsUnavailable,
    PrepareRefused,
    UnresolvedEntry,
    ArenaBuilding,
    ArenaFailed,
    ArenaCasLost,
    ArenaInvalidRecord,
    ArenaCapacity,
    ArenaExhaustedProbes,
    ArenaKeyEncoding,
    ArenaWriteAttempted,
    ArenaUnknownState,
}

impl LiveLaneFallbackClass {
    pub const ALL: [Self; 17] = [
        Self::Unconfigured,
        Self::Regenerated,
        Self::OutsideSegment,
        Self::CrossPage,
        Self::UnsupportedShape,
        Self::SourceWordsUnavailable,
        Self::PrepareRefused,
        Self::UnresolvedEntry,
        Self::ArenaBuilding,
        Self::ArenaFailed,
        Self::ArenaCasLost,
        Self::ArenaInvalidRecord,
        Self::ArenaCapacity,
        Self::ArenaExhaustedProbes,
        Self::ArenaKeyEncoding,
        Self::ArenaWriteAttempted,
        Self::ArenaUnknownState,
    ];
    pub const COUNT: usize = Self::ALL.len();

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Regenerated => "regenerated",
            Self::OutsideSegment => "outside_segment",
            Self::CrossPage => "cross_page",
            Self::UnsupportedShape => "unsupported_shape",
            Self::SourceWordsUnavailable => "source_words_unavailable",
            Self::PrepareRefused => "prepare_refused",
            Self::UnresolvedEntry => "unresolved_entry",
            Self::ArenaBuilding => "arena_building",
            Self::ArenaFailed => "arena_failed",
            Self::ArenaCasLost => "arena_cas_lost",
            Self::ArenaInvalidRecord => "arena_invalid_record",
            Self::ArenaCapacity => "arena_capacity",
            Self::ArenaExhaustedProbes => "arena_exhausted_probes",
            Self::ArenaKeyEncoding => "arena_key_encoding",
            Self::ArenaWriteAttempted => "arena_write_attempted",
            Self::ArenaUnknownState => "arena_unknown_state",
        }
    }
}

/// `ALL` is the ordinal order, so `index()` is a valid slot in every
/// `[u64; COUNT]` counter array and the wire's three-frame split is a split of
/// that same order. A reordered or short `ALL` is a build failure, not a
/// silently mis-attributed counter.
const _: () = {
    let mut index = 0;
    while index < LiveLaneFallbackClass::COUNT {
        assert!(LiveLaneFallbackClass::ALL[index].index() == index);
        index += 1;
    }
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Phase {
    PrepareIndex,
    Translate,
    TranslatedRun,
    FinishExit,
    SensitiveEmulation,
    SyscallDispatch,
    LoopQuiesce,
    Blocked,
}

impl Phase {
    pub const ALL: [Self; 8] = [
        Self::PrepareIndex,
        Self::Translate,
        Self::TranslatedRun,
        Self::FinishExit,
        Self::SensitiveEmulation,
        Self::SyscallDispatch,
        Self::LoopQuiesce,
        Self::Blocked,
    ];
    pub const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareIndex => "prepare-index",
            Self::Translate => "translate",
            Self::TranslatedRun => "translated-run",
            Self::FinishExit => "finish-exit",
            Self::SensitiveEmulation => "sensitive-emulation",
            Self::SyscallDispatch => "syscall-dispatch",
            Self::LoopQuiesce => "loop-quiesce",
            Self::Blocked => "blocked",
        }
    }

    const fn field_name(self) -> &'static str {
        match self {
            Self::PrepareIndex => "prepare_index",
            Self::Translate => "translate",
            Self::TranslatedRun => "translated_run",
            Self::FinishExit => "finish_exit",
            Self::SensitiveEmulation => "sensitive_emulation",
            Self::SyscallDispatch => "syscall_dispatch",
            Self::LoopQuiesce => "loop_quiesce",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("profile counter overflow: {0}")]
    CounterOverflow(&'static str),
    #[error("profile counter regressed: {0}")]
    CounterUnderflow(&'static str),
    #[error(
        "gateway exits do not reconcile: gateway_entries={gateway_entries}, reconciled={reconciled_exits}"
    )]
    ExitMismatch {
        gateway_entries: u64,
        reconciled_exits: u64,
    },
    #[error("profile elapsed time overflow")]
    TimeOverflow,
    #[error("profile clock moved backwards")]
    ClockRegression,
    #[error("mach timebase is unavailable")]
    TimebaseUnavailable,
    #[error("profile dispatch blocked time exceeds total time")]
    DispatchTimeUnderflow,
    #[error("nested profile time exceeds its enclosing phase")]
    TimeOverlap,
    #[error("profile phase counts do not reconcile: {0}")]
    PhaseMismatch(&'static str),
    #[error("exclusive fusion counts do not reconcile")]
    ExclusiveFusionMismatch,
    #[error("profile protocol frame exceeds the atomic transport bound")]
    FrameTooLarge,
    #[error("profile blocked CPU time exceeds blocked wall time")]
    BlockedCpuExceedsWall,
    #[error("per-thread CPU usage is unavailable")]
    ThreadUsageUnavailable,
    #[error("process CPU usage is unavailable")]
    ProcessUsageUnavailable,
}

impl ProfileError {
    pub const fn protocol_reason(self) -> &'static str {
        match self {
            Self::CounterOverflow(_) => "counter-overflow",
            Self::CounterUnderflow(_) => "counter-underflow",
            Self::ExitMismatch { .. } => "exit-mismatch",
            Self::TimeOverflow => "time-overflow",
            Self::ClockRegression => "clock-regression",
            Self::TimebaseUnavailable => "timebase-unavailable",
            Self::DispatchTimeUnderflow => "dispatch-time-underflow",
            Self::TimeOverlap => "time-overlap",
            Self::PhaseMismatch(_) => "phase-mismatch",
            Self::ExclusiveFusionMismatch => "exclusive-fusion-mismatch",
            Self::FrameTooLarge => "frame-too-large",
            Self::BlockedCpuExceedsWall => "blocked-cpu-exceeds-wall",
            Self::ThreadUsageUnavailable => "thread-usage-unavailable",
            Self::ProcessUsageUnavailable => "process-usage-unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PhaseTimer {
    started: Option<u64>,
}

impl PhaseTimer {
    pub const fn disabled() -> Self {
        Self { started: None }
    }

    #[inline]
    pub fn start_if<const PROFILE: bool>() -> Self {
        if PROFILE {
            Self {
                started: Some(monotonic_ticks()),
            }
        } else {
            Self::disabled()
        }
    }

    pub fn elapsed_ns(self) -> Result<u64, ProfileError> {
        let Some(started) = self.started else {
            return Ok(0);
        };
        elapsed_ns_from_ticks(started, monotonic_ticks(), timebase())
    }
}

/// The host tick scale for [`monotonic_ticks`], memoized once per process.
/// Fail-closed: an unavailable timebase invalidates every measurement that
/// needs it (`TimebaseUnavailable`) rather than guessing a scale.
fn timebase() -> Result<TickScale, ProfileError> {
    static TIMEBASE: OnceLock<Result<TickScale, ProfileError>> = OnceLock::new();
    *TIMEBASE.get_or_init(|| tick_scale().ok_or(ProfileError::TimebaseUnavailable))
}

fn elapsed_ns_from_ticks(
    started: u64,
    ended: u64,
    timebase: Result<TickScale, ProfileError>,
) -> Result<u64, ProfileError> {
    let timebase = timebase?;
    let ticks = ended
        .checked_sub(started)
        .ok_or(ProfileError::ClockRegression)?;
    let ns = u128::from(ticks)
        .checked_mul(u128::from(timebase.numer))
        .ok_or(ProfileError::TimeOverflow)?
        / u128::from(timebase.denom);
    u64::try_from(ns).map_err(|_| ProfileError::TimeOverflow)
}

/// Total CPU (user + system) consumed by the CALLING thread, in nanoseconds.
/// Reads the host kernel's own per-thread accounting through the existing
/// `host_proc` helper (`thread_info(THREAD_BASIC_INFO)` on macOS); the µs
/// resolution of that interface is the measurement quantum for every consumer
/// in this file.
pub fn current_thread_cpu_total_ns() -> Result<u64, ProfileError> {
    let (user_us, system_us) = carrick_host::host_proc::self_thread_cpu_us()
        .ok_or(ProfileError::ThreadUsageUnavailable)?;
    user_us
        .checked_add(system_us)
        .and_then(|total_us| total_us.checked_mul(1_000))
        .ok_or(ProfileError::TimeOverflow)
}

/// Total CPU (user + system) consumed by THIS PROCESS, in nanoseconds, from
/// `getrusage(RUSAGE_SELF)`. Fork restarts this clock in the child; execve
/// preserves it — both facts are load-bearing for the startup gauge below.
pub fn process_cpu_total_ns() -> Result<u64, ProfileError> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage(RUSAGE_SELF) fills `usage` for this process; a zeroed
    // rusage is a valid out-buffer.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(ProfileError::ProcessUsageUnavailable);
    }
    let timeval_ns = |tv: libc::timeval| -> Option<u64> {
        u64::try_from(tv.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(tv.tv_usec).ok()?.checked_mul(1_000)?)
    };
    timeval_ns(usage.ru_utime)
        .zip(timeval_ns(usage.ru_stime))
        .and_then(|(user_ns, system_ns)| user_ns.checked_add(system_ns))
        .ok_or(ProfileError::TimeOverflow)
}

const STARTUP_UNARMED: u8 = 0;
const STARTUP_ARMED: u8 = 1;
const STARTUP_CLAIMING: u8 = 2;
const STARTUP_CLAIMED: u8 = 3;

/// One-per-process startup attribution window: from process runtime entry
/// (armed at bring-up) to the first gateway entry of any guest thread
/// (claimed exactly once). After the claim the pair is a GAUGE — every reader
/// observes the identical values, and every thread group of the pid repeats
/// them verbatim in its `process` frame.
///
/// Lock-free by design (no new locks solely to record a metric): a four-state
/// atomic word serializes the single claim; the `CLAIMING` window covers two
/// relaxed stores and is bridged with `spin_loop`.
pub struct StartupGauge {
    state: AtomicU8,
    entry_ticks: AtomicU64,
    entry_cpu_ns: AtomicU64,
    startup_wall_ns: AtomicU64,
    startup_cpu_ns: AtomicU64,
}

impl Default for StartupGauge {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupGauge {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STARTUP_UNARMED),
            entry_ticks: AtomicU64::new(0),
            entry_cpu_ns: AtomicU64::new(0),
            startup_wall_ns: AtomicU64::new(0),
            startup_cpu_ns: AtomicU64::new(0),
        }
    }

    /// Record the process runtime entry baseline. The first arm wins: the
    /// startup window is anchored at the earliest runtime entry of this
    /// process image, and re-anchoring after a claim would fork the gauge.
    pub fn arm(&self, entry_ticks: u64, entry_cpu_ns: u64) {
        if self
            .state
            .compare_exchange(
                STARTUP_UNARMED,
                STARTUP_CLAIMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.entry_ticks.store(entry_ticks, Ordering::Relaxed);
            self.entry_cpu_ns.store(entry_cpu_ns, Ordering::Relaxed);
            self.state.store(STARTUP_ARMED, Ordering::Release);
        }
    }

    /// Fork-child reset: the inherited claim describes the parent's startup,
    /// and the child's `getrusage(RUSAGE_SELF)` clock restarts at zero (an
    /// inherited CPU baseline would underflow). Restart the window at the
    /// fork boundary. Runs on the single surviving post-fork thread.
    pub fn rearm(&self, entry_ticks: u64, entry_cpu_ns: u64) {
        self.state.store(STARTUP_CLAIMING, Ordering::Release);
        self.entry_ticks.store(entry_ticks, Ordering::Relaxed);
        self.entry_cpu_ns.store(entry_cpu_ns, Ordering::Relaxed);
        self.startup_wall_ns.store(0, Ordering::Relaxed);
        self.startup_cpu_ns.store(0, Ordering::Relaxed);
        self.state.store(STARTUP_ARMED, Ordering::Release);
    }

    /// Republish a claim produced by the pre-exec image of the SAME pid (the
    /// host self-reexec transport): the pid's startup was already captured
    /// exactly once, so the post-exec image repeats it verbatim rather than
    /// measuring a second window under one pid.
    pub fn seed(&self, startup_wall_ns: u64, startup_cpu_ns: u64) {
        self.state.store(STARTUP_CLAIMING, Ordering::Release);
        self.startup_wall_ns
            .store(startup_wall_ns, Ordering::Relaxed);
        self.startup_cpu_ns.store(startup_cpu_ns, Ordering::Relaxed);
        self.state.store(STARTUP_CLAIMED, Ordering::Release);
    }

    pub fn is_claimed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STARTUP_CLAIMED
    }

    pub fn claimed(&self) -> Option<(u64, u64)> {
        self.is_claimed().then(|| {
            (
                self.startup_wall_ns.load(Ordering::Relaxed),
                self.startup_cpu_ns.load(Ordering::Relaxed),
            )
        })
    }

    /// Claim the startup window exactly once. Racing claimers and post-claim
    /// readers all observe the identical winning pair. An unarmed gauge
    /// (direct harness use without a bring-up mark) claims a zero-width
    /// window so every group still repeats one identical gauge.
    pub fn claim(&self, now_ticks: u64, cpu_now_ns: u64) -> Result<(u64, u64), ProfileError> {
        loop {
            match self.state.load(Ordering::Acquire) {
                STARTUP_CLAIMED => {
                    return Ok((
                        self.startup_wall_ns.load(Ordering::Relaxed),
                        self.startup_cpu_ns.load(Ordering::Relaxed),
                    ));
                }
                STARTUP_ARMED => {
                    // Compute the candidate BEFORE the state transition so an
                    // error can never strand the gauge in `CLAIMING`.
                    let entry_ticks = self.entry_ticks.load(Ordering::Acquire);
                    let entry_cpu_ns = self.entry_cpu_ns.load(Ordering::Acquire);
                    let wall_ns = elapsed_ns_from_ticks(entry_ticks, now_ticks, timebase())?;
                    let cpu_ns = cpu_now_ns
                        .checked_sub(entry_cpu_ns)
                        .ok_or(ProfileError::CounterUnderflow("startup_cpu_ns"))?;
                    if self
                        .state
                        .compare_exchange(
                            STARTUP_ARMED,
                            STARTUP_CLAIMING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.startup_wall_ns.store(wall_ns, Ordering::Relaxed);
                        self.startup_cpu_ns.store(cpu_ns, Ordering::Relaxed);
                        self.state.store(STARTUP_CLAIMED, Ordering::Release);
                        return Ok((wall_ns, cpu_ns));
                    }
                }
                STARTUP_UNARMED => {
                    if self
                        .state
                        .compare_exchange(
                            STARTUP_UNARMED,
                            STARTUP_CLAIMING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.startup_wall_ns.store(0, Ordering::Relaxed);
                        self.startup_cpu_ns.store(0, Ordering::Relaxed);
                        self.state.store(STARTUP_CLAIMED, Ordering::Release);
                        return Ok((0, 0));
                    }
                }
                _ => std::hint::spin_loop(),
            }
        }
    }
}

static PROCESS_STARTUP: StartupGauge = StartupGauge::new();

/// Anchor the process startup window at native runtime entry. Environment
/// gated: a profile-off run performs no timer or usage reads here.
pub fn mark_native_process_runtime_entry() {
    if std::env::var_os("CARRICK_DSR_PROFILE").is_none() {
        return;
    }
    let entry_ticks = monotonic_ticks();
    let Ok(entry_cpu_ns) = process_cpu_total_ns() else {
        // Leave the gauge unarmed: flushes then claim a visibly zero-width
        // window instead of publishing an unbaselined measurement.
        return;
    };
    PROCESS_STARTUP.arm(entry_ticks, entry_cpu_ns);
}

/// Fork-child reset for the process startup gauge (see [`StartupGauge::rearm`]).
/// Callers gate on profiling being enabled.
pub fn reset_process_startup_after_fork_child() {
    let entry_ticks = monotonic_ticks();
    let entry_cpu_ns = process_cpu_total_ns().unwrap_or(0);
    PROCESS_STARTUP.rearm(entry_ticks, entry_cpu_ns);
}

/// Republish a pre-exec claim across the host self-reexec (same pid).
pub fn seed_claimed_process_startup(startup_wall_ns: u64, startup_cpu_ns: u64) {
    PROCESS_STARTUP.seed(startup_wall_ns, startup_cpu_ns);
}

/// The claimed startup gauge, if the process has one (transported through the
/// self-reexec capsule so one pid never publishes two startup windows).
pub fn claimed_process_startup() -> Option<(u64, u64)> {
    PROCESS_STARTUP.claimed()
}

/// Sentinel for "no baseline installed": u64::MAX nanoseconds is ~584 years
/// of CPU time, not a realistic reading, so it safely distinguishes "unset"
/// from a genuine zero baseline (a surviving thread that had consumed no CPU
/// before the exec).
const NO_THREAD_CPU_BASELINE_NS: u64 = u64::MAX;

/// Baseline CPU (ns) for the ONE kernel thread that survives a PID-preserving
/// host self-reexec (see `resume_guest_from_capsule`). Real execve keeps the
/// calling thread's kernel CPU accounting intact — unlike fork, which starts
/// a fresh thread at a zero counter — so without this baseline the post-exec
/// era's flush would report the pre-exec era's CPU a second time (the
/// pre-exec image already flushed its own record for it). Installed exactly
/// once at post-exec runtime re-entry and consumed exactly once by the next
/// `ThreadBudget::from_environment` call: in a freshly execve'd process image
/// that is necessarily the surviving thread's own post-exec budget, since no
/// other thread runs before it.
static SURVIVING_THREAD_CPU_BASELINE_NS: AtomicU64 = AtomicU64::new(NO_THREAD_CPU_BASELINE_NS);

/// Per-era thread CPU: the calling thread's live cumulative CPU counter minus
/// whatever baseline was installed for this era (zero for a fresh kernel
/// thread, since it never installs one — the subtraction is then a no-op).
/// Saturates at zero so a measurement race that reads `current_thread_cpu_ns`
/// a hair below the baseline can never underflow into a huge unsigned wrap.
fn thread_cpu_since_baseline(current_thread_cpu_ns: u64, baseline_ns: u64) -> u64 {
    current_thread_cpu_ns.saturating_sub(baseline_ns)
}

/// Install the surviving thread's CPU baseline at runtime re-entry after a
/// PID-preserving host self-reexec. Environment gated like the sibling
/// startup-window marks: a profile-off run performs no usage read here.
pub fn install_surviving_thread_cpu_baseline_at_reexec_entry() {
    if std::env::var_os("CARRICK_DSR_PROFILE").is_none() {
        return;
    }
    if let Ok(baseline_ns) = current_thread_cpu_total_ns() {
        SURVIVING_THREAD_CPU_BASELINE_NS.store(baseline_ns, Ordering::Release);
    }
    // On a read failure, leave the slot unset: the surviving thread's budget
    // then reads a zero baseline (as if it were a fresh thread) instead of
    // stranding a half-written one. The same read failing again at that
    // thread's own flush already fails the record closed via
    // `ThreadUsageUnavailable`.
}

/// Consume (take) the installed baseline exactly once.
fn take_surviving_thread_cpu_baseline_ns() -> u64 {
    match SURVIVING_THREAD_CPU_BASELINE_NS.swap(NO_THREAD_CPU_BASELINE_NS, Ordering::AcqRel) {
        NO_THREAD_CPU_BASELINE_NS => 0,
        baseline_ns => baseline_ns,
    }
}

/// Claim the process startup window at a gateway entry. Cheap once claimed:
/// a single acquire load guards the usage/timer reads.
pub fn claim_process_startup() -> Result<(), ProfileError> {
    if PROCESS_STARTUP.is_claimed() {
        return Ok(());
    }
    let now_ticks = monotonic_ticks();
    let cpu_now_ns = process_cpu_total_ns()?;
    PROCESS_STARTUP.claim(now_ticks, cpu_now_ns).map(|_| ())
}

/// Point-in-time gauges sampled at one thread's profile flush: this thread's
/// total CPU, the process-wide CPU, and the once-claimed startup window.
#[derive(Clone, Copy, Debug, Default)]
pub struct FlushGauges {
    pub thread_cpu_ns: u64,
    pub startup_wall_ns: u64,
    pub startup_cpu_ns: u64,
    pub process_cpu_ns: u64,
}

/// Sample the flush-moment gauges for one thread group. Claims the startup
/// window if no gateway entry has (a flush before first guest entry ends the
/// window at the flush). `thread_cpu_baseline_ns` is the era baseline
/// installed on the flushing thread's `ThreadBudget` (zero for every thread
/// except the one surviving a PID-preserving host self-reexec): the reported
/// `thread_cpu_ns` is this era's OWN consumption, not the thread's lifetime
/// total.
pub fn flush_gauges(thread_cpu_baseline_ns: u64) -> Result<FlushGauges, ProfileError> {
    let thread_cpu_ns =
        thread_cpu_since_baseline(current_thread_cpu_total_ns()?, thread_cpu_baseline_ns);
    let process_cpu_ns = process_cpu_total_ns()?;
    let (startup_wall_ns, startup_cpu_ns) =
        PROCESS_STARTUP.claim(monotonic_ticks(), process_cpu_ns)?;
    Ok(FlushGauges {
        thread_cpu_ns,
        startup_wall_ns,
        startup_cpu_ns,
        process_cpu_ns,
    })
}

/// Total CPU (user + system) consumed by an ARBITRARY host thread of this
/// process, identified by the mach port it captured on itself (via
/// `carrick_host::host_proc::current_thread_port`) and published for a foreign
/// reader. Unlike `current_thread_cpu_total_ns`, this can be called from any
/// thread about ANY other -- it is how `exit_group`'s "last thread standing"
/// reads a still-running sibling's real, live CPU total instead of the
/// sibling's own (necessarily self-only) accounting.
pub fn thread_cpu_total_ns_for_port(port: ThreadPort) -> Result<u64, ProfileError> {
    let (user_us, system_us) = carrick_host::host_proc::thread_cpu_us_for_port(port)
        .ok_or(ProfileError::ThreadUsageUnavailable)?;
    user_us
        .checked_add(system_us)
        .and_then(|total_us| total_us.checked_mul(1_000))
        .ok_or(ProfileError::TimeOverflow)
}

/// Like [`flush_gauges`], but for a sibling thread this process is about to
/// lose to `exit_group`'s unconditional `libc::_exit()`: `thread_cpu_ns` is
/// read LIVE from the sibling's mach port (never stale, unlike the rest of
/// its record which comes from its last self-published snapshot -- see
/// `ThreadTranslator::publish_sibling_snapshot`), and the process/startup
/// gauges are the calling (foreign) thread's own live reads, exactly as any
/// other flush on this process would report them.
pub fn flush_gauges_for_port(
    port: ThreadPort,
    thread_cpu_baseline_ns: u64,
) -> Result<FlushGauges, ProfileError> {
    let thread_cpu_ns =
        thread_cpu_since_baseline(thread_cpu_total_ns_for_port(port)?, thread_cpu_baseline_ns);
    let process_cpu_ns = process_cpu_total_ns()?;
    let (startup_wall_ns, startup_cpu_ns) =
        PROCESS_STARTUP.claim(monotonic_ticks(), process_cpu_ns)?;
    Ok(FlushGauges {
        thread_cpu_ns,
        startup_wall_ns,
        startup_cpu_ns,
        process_cpu_ns,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProfileSnapshot {
    pub resolver_exits: u64,
    pub one_entry_hits: u64,
    pub translations: u64,
    pub optimistic_decode_discards: u64,
    pub optimistic_decode_discard_ns: u64,
    pub gateway_entries: u64,
    pub syscall_exits: u64,
    pub direct_resolver_exits: u64,
    pub cache_lookups: u64,
    pub cache_lookup_hits: u64,
    pub invalidated_blocks: u64,
    pub translation_ns: u64,
    pub translation_decode_ns: u64,
    pub translation_plan_ns: u64,
    pub translation_emit_ns: u64,
    pub translation_publication_ns: u64,
    pub nested_translation_ns: u64,
    pub cache_used_bytes: usize,
    pub cache_capacity_bytes: usize,
    /// Container-lifetime translation sharing. These existed in the resolver's
    /// own stats but were never PUBLISHED, so whether sharing ever hit was
    /// unobservable -- a four-arm bisect had to infer "no reuse" from
    /// translations failing to drop
    /// (docs/perf-results/2026-07-29-native-cpu-budget-evidence.md).
    pub shared_unit_lookups: u64,
    pub shared_unit_hits: u64,
    pub shared_unit_loads: u64,
    /// Blocks REPLAYED from attached units (each on its first lookup).
    pub shared_blocks_mapped: u64,
    pub shared_translations_avoided: u64,
    /// Blocks indexed at unit attach, available for lazy replay. The gap to
    /// `shared_blocks_mapped` is the replay work lazy install avoided.
    pub shared_blocks_attached: u64,
    /// Low-frequency mechanism evidence for loaded immutable translation
    /// metadata. These counters do not provide timing authority.
    pub shared_metadata_bytes_read: u64,
    pub shared_metadata_bytes_mapped: u64,
    pub shared_metadata_validation_ns: u64,
    pub shared_mapped_immutable_records: u64,
    pub shared_owned_immutable_records: u64,
    pub shared_guest_range_derivations: u64,
    pub shared_direct_edge_group_builds: u64,
    /// `ResolveDirect` exits classified by RANGE containment of the source and
    /// target guest PCs in shared-unit code. Thread-scoped deltas, summable.
    pub resolve_src_shared_tgt_shared: u64,
    pub resolve_src_shared_tgt_private: u64,
    pub resolve_src_private_tgt_shared: u64,
    pub resolve_src_private_tgt_private: u64,
    /// DISTINCT private -> shared edges seen by this thread.
    pub resolve_private_to_shared_distinct_edges: u64,
    /// Control for the above: distinct private -> private edges.
    pub resolve_private_to_private_distinct_edges: u64,
    /// Direct-binding registry counters. POINT-IN-TIME GAUGES on the process
    /// registry, never deltas -- like `cache_used_bytes`. Summing them across a
    /// process's thread records multiplies them by the reporting thread count;
    /// take the max per pid instead.
    pub direct_binding_owner_validation_failures: u64,
    pub direct_binding_authority_validation_failures: u64,
    pub direct_binding_cas_wins: u64,
    pub direct_binding_cas_losses: u64,
    pub direct_binding_stale_winner_clears: u64,
    pub direct_binding_publication_retries: u64,
    pub exclusive_fusion_sites: [u64; ExclusiveFusionClass::COUNT],
    /// Container-lifetime LIVE arena lane. Process-scoped like the
    /// `shared_*` counters above and published as the same claimed delta, so
    /// summing them across a process's thread records recovers the process
    /// total exactly once.
    ///
    /// `live_index_hits` is a repeat serve out of this process's own live
    /// index; `live_ready_hits` is a FRESH acquisition of another publisher's
    /// READY record; `live_publish_wins` is a block this process prepared
    /// itself; `live_publish_adoptions` is a race this process lost and was
    /// nevertheless served from the winner's record without preparing.
    pub live_index_hits: u64,
    pub live_ready_hits: u64,
    pub live_ready_misses: u64,
    pub live_publish_wins: u64,
    pub live_publish_adoptions: u64,
    pub live_blocks_installed: u64,
    /// Exact published extents of every live block this process installed.
    /// These are deliberately NOT folded into `cache_used_bytes`: that gauge
    /// is the PRIVATE bump cache's occupancy, and live code executes from the
    /// arena mapping instead.
    pub live_code_bytes: u64,
    pub live_hot_bytes: u64,
    pub live_cold_bytes: u64,
    /// Private direct-link sites waiting on a key a live installation
    /// published: patched to the arena entry, or left at the fall-into-stub
    /// because the arena is outside the ±128 MiB AArch64 branch reach.
    pub live_links_patched: u64,
    pub live_links_out_of_reach: u64,
    /// Winner-publication prebinding of shared→shared direct links (the
    /// realized `live_arena_shared_direct_links` design counter): bound into
    /// the still-staged source at publication, refused because the target
    /// was not an acquirable READY record (`unbound_state`), or refused by
    /// the emitter's AArch64 reach check (`unbound_reach` — structurally
    /// zero while the code payload is 64 MiB).
    pub live_links_prebound: u64,
    pub live_links_prebind_unbound_state: u64,
    pub live_links_prebind_unbound_reach: u64,
    /// Task 7's revocation seam, counted. `live_revoked_chunks` is exact
    /// 64 KiB local RX chunks this process protected `PROT_NONE` because a
    /// guest write, `mprotect`, `munmap`, or remap changed their source page;
    /// `live_stale_instruction_aborts` is instruction aborts inside one of
    /// those chunks that the exact classifier consumed and recovered
    /// privately. The pair is the only place the mutation cost of sharing is
    /// visible: a workload with many revocations is one where publication is
    /// being thrown away.
    pub live_revoked_chunks: u64,
    pub live_stale_instruction_aborts: u64,
    pub live_fallbacks: [u64; LiveLaneFallbackClass::COUNT],
}

#[derive(Clone, Debug)]
pub struct CompleteThreadRecord {
    pub pid: libc::pid_t,
    pub tid: i32,
    pub era: u64,
    pub exec_epoch: u64,
    pub gateway_entries: u64,
    pub reconciled_exits: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    exclusive_fusion: [u64; ExclusiveFusionClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
    blocked_cpu_ns: u64,
}

impl CompleteThreadRecord {
    pub fn to_protocol_line(&self, thread_cpu_ns: u64) -> String {
        let mut line = self.frame_header("core");
        let _ = write!(
            line,
            "|gateway_entries={}|reconciled_exits={}|overflowed=0|thread_cpu_ns={thread_cpu_ns}|exec_epoch={}",
            self.gateway_entries, self.reconciled_exits, self.exec_epoch
        );
        line
    }

    fn frame_header(&self, frame: &str) -> String {
        format!(
            "{PROTOCOL_PREFIX}|thread|complete=1|pid={}|tid={}|era={}|frame={frame}",
            self.pid, self.tid, self.era
        )
    }

    pub fn to_protocol_frames_with_resolver(
        &self,
        resolver: crate::profile::ProfileSnapshot,
        gauges: FlushGauges,
    ) -> Result<Vec<String>, ProfileError> {
        let mut frames = vec![self.to_protocol_line(gauges.thread_cpu_ns)];
        let mut exits = self.frame_header("exits");
        for class in ExitClass::ALL {
            let _ = write!(
                exits,
                "|exit_{}={}",
                class.field_name(),
                self.exits[class.index()]
            );
        }
        frames.push(exits);
        let mut sensitive = self.frame_header("sensitive");
        for class in SensitiveClass::ALL {
            let _ = write!(
                sensitive,
                "|sensitive_{}={}",
                class.field_name(),
                self.sensitive[class.index()]
            );
        }
        frames.push(sensitive);
        for (name, classes, values) in [
            (
                "fusion-exec-a",
                &ExclusiveFusionClass::ALL[..8],
                &self.exclusive_fusion,
            ),
            (
                "fusion-exec-b",
                &ExclusiveFusionClass::ALL[8..],
                &self.exclusive_fusion,
            ),
            (
                "fusion-sites-a",
                &ExclusiveFusionClass::ALL[..8],
                &resolver.exclusive_fusion_sites,
            ),
            (
                "fusion-sites-b",
                &ExclusiveFusionClass::ALL[8..],
                &resolver.exclusive_fusion_sites,
            ),
        ] {
            let mut frame = self.frame_header(name);
            for &class in classes {
                let _ = write!(
                    frame,
                    "|fusion_{}={}",
                    class.field_name(),
                    values[class.index()]
                );
            }
            frames.push(frame);
        }
        for (name, phases) in [
            ("phases-a", &Phase::ALL[..4]),
            ("phases-b", &Phase::ALL[4..]),
        ] {
            let mut frame = self.frame_header(name);
            for &phase in phases {
                let _ = write!(
                    frame,
                    "|phase_{}_ns={}|phase_{}_count={}",
                    phase.field_name(),
                    self.phase_ns[phase.index()],
                    phase.field_name(),
                    self.phase_counts[phase.index()]
                );
            }
            if name == "phases-b" {
                let _ = write!(frame, "|phase_blocked_cpu_ns={}", self.blocked_cpu_ns);
            }
            frames.push(frame);
        }
        let mut thread = self.frame_header("resolver-thread");
        let _ = write!(
            thread,
            "|translate_phase_nested_ns={}|resolver_exits={}|one_entry_hits={}|gateway_entries={}|syscall_exits={}|direct_resolver_exits={}",
            resolver.nested_translation_ns,
            resolver.resolver_exits,
            resolver.one_entry_hits,
            resolver.gateway_entries,
            resolver.syscall_exits,
            resolver.direct_resolver_exits,
        );
        frames.push(thread);
        let mut process = self.frame_header("resolver-process");
        let _ = write!(
            process,
            "|translations={}|optimistic_decode_discards={}|optimistic_decode_discard_ns={}|cache_lookups={}|cache_lookup_hits={}|invalidated_blocks={}",
            resolver.translations,
            resolver.optimistic_decode_discards,
            resolver.optimistic_decode_discard_ns,
            resolver.cache_lookups,
            resolver.cache_lookup_hits,
            resolver.invalidated_blocks,
        );
        frames.push(process);
        let mut times = self.frame_header("resolver-times");
        let _ = write!(
            times,
            "|nested_translation_ns={}|nested_translation_decode_ns={}|nested_translation_plan_ns={}|nested_translation_emit_ns={}|nested_translation_publication_ns={}",
            resolver.translation_ns,
            resolver.translation_decode_ns,
            resolver.translation_plan_ns,
            resolver.translation_emit_ns,
            resolver.translation_publication_ns,
        );
        frames.push(times);
        let mut shared = self.frame_header("resolver-shared");
        let _ = write!(
            shared,
            "|shared_unit_lookups={}|shared_unit_hits={}|shared_unit_loads={}|shared_blocks_mapped={}|shared_translations_avoided={}|shared_blocks_attached={}",
            resolver.shared_unit_lookups,
            resolver.shared_unit_hits,
            resolver.shared_unit_loads,
            resolver.shared_blocks_mapped,
            resolver.shared_translations_avoided,
            resolver.shared_blocks_attached,
        );
        frames.push(shared);
        let mut metadata = self.frame_header("resolver-metadata");
        let _ = write!(
            metadata,
            "|shared_metadata_bytes_read={}|shared_metadata_bytes_mapped={}|shared_metadata_validation_ns={}|shared_mapped_immutable_records={}|shared_owned_immutable_records={}|shared_guest_range_derivations={}|shared_direct_edge_group_builds={}",
            resolver.shared_metadata_bytes_read,
            resolver.shared_metadata_bytes_mapped,
            resolver.shared_metadata_validation_ns,
            resolver.shared_mapped_immutable_records,
            resolver.shared_owned_immutable_records,
            resolver.shared_guest_range_derivations,
            resolver.shared_direct_edge_group_builds,
        );
        frames.push(metadata);
        let mut resolve = self.frame_header("resolve-class");
        let _ = write!(
            resolve,
            "|resolve_src_shared_tgt_shared={}|resolve_src_shared_tgt_private={}|resolve_src_private_tgt_shared={}|resolve_src_private_tgt_private={}|resolve_private_to_shared_distinct_edges={}|resolve_private_to_private_distinct_edges={}",
            resolver.resolve_src_shared_tgt_shared,
            resolver.resolve_src_shared_tgt_private,
            resolver.resolve_src_private_tgt_shared,
            resolver.resolve_src_private_tgt_private,
            resolver.resolve_private_to_shared_distinct_edges,
            resolver.resolve_private_to_private_distinct_edges,
        );
        frames.push(resolve);
        let mut binding = self.frame_header("direct-binding-gauge");
        let _ = write!(
            binding,
            "|db_owner_validation_failures={}|db_authority_validation_failures={}|db_cas_wins={}|db_cas_losses={}|db_stale_winner_clears={}|db_publication_retries={}",
            resolver.direct_binding_owner_validation_failures,
            resolver.direct_binding_authority_validation_failures,
            resolver.direct_binding_cas_wins,
            resolver.direct_binding_cas_losses,
            resolver.direct_binding_stale_winner_clears,
            resolver.direct_binding_publication_retries,
        );
        frames.push(binding);
        let mut cache = self.frame_header("cache-gauge");
        let _ = write!(
            cache,
            "|cache_used_bytes={}|cache_capacity_bytes={}",
            resolver.cache_used_bytes, resolver.cache_capacity_bytes
        );
        frames.push(cache);
        let mut live = self.frame_header("live-lane");
        let _ = write!(
            live,
            "|live_index_hits={}|live_ready_hits={}|live_ready_misses={}|live_publish_wins={}|live_publish_adoptions={}|live_blocks_installed={}",
            resolver.live_index_hits,
            resolver.live_ready_hits,
            resolver.live_ready_misses,
            resolver.live_publish_wins,
            resolver.live_publish_adoptions,
            resolver.live_blocks_installed,
        );
        frames.push(live);
        // The live extents are their own frame, never folded into
        // `cache-gauge`: that frame is the private bump cache's occupancy.
        let mut live_bytes = self.frame_header("live-bytes");
        let _ = write!(
            live_bytes,
            "|live_code_bytes={}|live_hot_bytes={}|live_cold_bytes={}|live_links_patched={}|live_links_out_of_reach={}|live_links_prebound={}|live_links_prebind_unbound_state={}|live_links_prebind_unbound_reach={}",
            resolver.live_code_bytes,
            resolver.live_hot_bytes,
            resolver.live_cold_bytes,
            resolver.live_links_patched,
            resolver.live_links_out_of_reach,
            resolver.live_links_prebound,
            resolver.live_links_prebind_unbound_state,
            resolver.live_links_prebind_unbound_reach,
        );
        frames.push(live_bytes);
        // Revocation is its own frame rather than two more fields on
        // `live-lane`: it is the only live counter pair produced OUTSIDE the
        // translate path (the guest-write seam and the fault classifier), and
        // a reader that wants "was publication thrown away" wants exactly
        // these two together.
        let mut live_revoke = self.frame_header("live-revoke");
        let _ = write!(
            live_revoke,
            "|live_revoked_chunks={}|live_stale_instruction_aborts={}",
            resolver.live_revoked_chunks, resolver.live_stale_instruction_aborts,
        );
        frames.push(live_revoke);
        // Seventeen named fallback classes do not fit one PIPE_BUF-atomic
        // frame at u64::MAX, so they are split exactly like the fusion
        // classes are. The order within each frame is `ALL`'s order.
        for (name, classes) in [
            ("live-fallback-a", &LiveLaneFallbackClass::ALL[..6]),
            ("live-fallback-b", &LiveLaneFallbackClass::ALL[6..12]),
            ("live-fallback-c", &LiveLaneFallbackClass::ALL[12..]),
        ] {
            let mut frame = self.frame_header(name);
            for &class in classes {
                let _ = write!(
                    frame,
                    "|lfb_{}={}",
                    class.field_name(),
                    resolver.live_fallbacks[class.index()]
                );
            }
            frames.push(frame);
        }
        // Process attribution gauges: the once-claimed startup window repeats
        // identically on every thread group of this pid; process_cpu_ns is a
        // point-in-time gauge at THIS thread's flush (like cache-gauge, never
        // a delta — readers take the per-pid max).
        let mut process_gauges = self.frame_header("process");
        let _ = write!(
            process_gauges,
            "|startup_wall_ns={}|startup_cpu_ns={}|process_cpu_ns={}",
            gauges.startup_wall_ns, gauges.startup_cpu_ns, gauges.process_cpu_ns
        );
        frames.push(process_gauges);
        if frames.iter().any(|frame| {
            frame
                .len()
                .checked_add(1)
                .is_none_or(|len| len > DARWIN_PIPE_BUF)
        }) {
            return Err(ProfileError::FrameTooLarge);
        }
        Ok(frames)
    }
}

pub fn write_protocol_frames_to_fd(fd: libc::c_int, frames: &[String]) -> std::io::Result<()> {
    for frame in frames {
        let mut bytes = frame.as_bytes().to_vec();
        bytes.push(b'\n');
        if bytes.len() > DARWIN_PIPE_BUF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native performance frame exceeds PIPE_BUF",
            ));
        }
        loop {
            let rc = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if usize::try_from(rc).ok() != Some(bytes.len()) {
                return Err(if rc < 0 {
                    std::io::Error::last_os_error()
                } else {
                    std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short atomic native performance frame write",
                    )
                });
            }
            break;
        }
    }
    Ok(())
}

/// `Clone, Copy`: a `ThreadBudget` is a plain bag of counters (no handles, no
/// allocation), which is what lets a guest thread republish a cheap point-in-
/// time COPY of it into the cross-thread sibling registry every DSR loop
/// iteration (see `ThreadTranslator::publish_sibling_snapshot`) without
/// touching a lock any hotter than the registry's own.
#[derive(Clone, Copy)]
pub struct ThreadBudget {
    enabled: bool,
    pid: libc::pid_t,
    tid: i32,
    era: u64,
    exec_epoch: u64,
    gateway_entries: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    exclusive_fusion: [u64; ExclusiveFusionClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
    blocked_cpu_ns: u64,
    thread_cpu_baseline_ns: u64,
    invalid: Option<ProfileError>,
}

impl ThreadBudget {
    pub fn from_environment(tid: i32) -> Self {
        let enabled = std::env::var_os("CARRICK_DSR_PROFILE").is_some();
        let mut budget = Self::new(
            enabled,
            // SAFETY: `getpid` has no preconditions.
            unsafe { libc::getpid() },
            tid,
            PROFILE_EXEC_EPOCH.load(Ordering::Acquire),
        );
        if enabled {
            // Consume the baseline installed at post-exec runtime re-entry
            // (`install_surviving_thread_cpu_baseline_at_reexec_entry`). This
            // is the FIRST `ThreadBudget` built in a freshly execve'd process
            // image, so it is necessarily the surviving thread's own
            // post-exec budget; every later budget in this image (spawned
            // guest threads, or a process that never self-reexec'd) observes
            // the unset sentinel and gets zero.
            budget.thread_cpu_baseline_ns = take_surviving_thread_cpu_baseline_ns();
        }
        budget
    }

    fn new(enabled: bool, pid: libc::pid_t, tid: i32, exec_epoch: u64) -> Self {
        let mut budget = Self {
            enabled,
            pid,
            tid,
            era: if enabled { monotonic_ticks() } else { 0 },
            exec_epoch,
            gateway_entries: 0,
            exits: [0; ExitClass::COUNT],
            sensitive: [0; SensitiveClass::COUNT],
            exclusive_fusion: [0; ExclusiveFusionClass::COUNT],
            phase_ns: [0; Phase::COUNT],
            phase_counts: [0; Phase::COUNT],
            blocked_cpu_ns: 0,
            thread_cpu_baseline_ns: 0,
            invalid: None,
        };
        if enabled && exec_epoch == INVALID_EXEC_EPOCH {
            budget.invalid = Some(ProfileError::CounterOverflow("profile_exec_epoch"));
        }
        budget
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The guest tid this budget is accounted to. Only needed so a FOREIGN
    /// thread draining the sibling registry can name the thread it failed to
    /// reconstruct a record for in a diagnostic.
    pub fn tid(&self) -> i32 {
        self.tid
    }

    pub fn thread_cpu_baseline_ns(&self) -> u64 {
        self.thread_cpu_baseline_ns
    }

    pub fn record_gateway_entry(&mut self) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        match self.gateway_entries.checked_add(1) {
            Some(value) => {
                self.gateway_entries = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("gateway_entries"))),
        }
    }

    pub fn record_exit(&mut self, class: ExitClass) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        self.record_gateway_entry()?;
        let counter = &mut self.exits[class.index()];
        match counter.checked_add(1) {
            Some(value) => {
                *counter = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("exit"))),
        }
    }

    pub fn record_sensitive(&mut self, class: SensitiveClass) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        let counter = &mut self.sensitive[class.index()];
        match counter.checked_add(1) {
            Some(value) => {
                *counter = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("sensitive"))),
        }
    }

    pub fn record_exclusive_fusion(
        &mut self,
        class: ExclusiveFusionClass,
    ) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        let counter = &mut self.exclusive_fusion[class.index()];
        match counter.checked_add(1) {
            Some(value) => {
                *counter = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("exclusive_fusion"))),
        }
    }

    pub fn add_phase(&mut self, phase: Phase, elapsed_ns: u64) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        let ns = &mut self.phase_ns[phase.index()];
        let Some(next_ns) = ns.checked_add(elapsed_ns) else {
            return Err(self.invalidate(ProfileError::CounterOverflow("phase_ns")));
        };
        *ns = next_ns;
        let count = &mut self.phase_counts[phase.index()];
        match count.checked_add(1) {
            Some(value) => {
                *count = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("phase_count"))),
        }
    }

    /// Accumulate thread CPU consumed inside one blocked wait segment. The
    /// caller measures the segment (two per-thread usage reads around the
    /// wait closure) and the aggregate must never exceed the blocked wall
    /// phase — `complete_record` enforces that invariant.
    pub fn add_blocked_cpu_ns(&mut self, elapsed_ns: u64) -> Result<(), ProfileError> {
        if !self.enabled {
            return Ok(());
        }
        match self.blocked_cpu_ns.checked_add(elapsed_ns) {
            Some(value) => {
                self.blocked_cpu_ns = value;
                Ok(())
            }
            None => Err(self.invalidate(ProfileError::CounterOverflow("blocked_cpu_ns"))),
        }
    }

    pub fn complete_record(&self) -> Result<CompleteThreadRecord, ProfileError> {
        if let Some(error) = self.invalid {
            return Err(error);
        }
        let reconciled_exits = self.exits.into_iter().try_fold(0_u64, |sum, value| {
            sum.checked_add(value)
                .ok_or(ProfileError::CounterOverflow("reconciled_exits"))
        })?;
        if reconciled_exits != self.gateway_entries {
            return Err(ProfileError::ExitMismatch {
                gateway_entries: self.gateway_entries,
                reconciled_exits,
            });
        }
        let phase_samples = self
            .phase_counts
            .into_iter()
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(value)
                    .ok_or(ProfileError::CounterOverflow("phase_samples"))
            })?;
        if phase_samples != 0 {
            for phase in [
                Phase::PrepareIndex,
                Phase::TranslatedRun,
                Phase::FinishExit,
                Phase::LoopQuiesce,
            ] {
                if self.phase_counts[phase.index()] != self.gateway_entries {
                    return Err(ProfileError::PhaseMismatch(phase.as_str()));
                }
            }
            let syscalls = self.exits[ExitClass::Syscall.index()];
            if self.phase_counts[Phase::SyscallDispatch.index()] != syscalls
                || self.phase_counts[Phase::Blocked.index()] != syscalls
            {
                return Err(ProfileError::PhaseMismatch("syscall-dispatch"));
            }
            let sensitive_exits = self.exits[ExitClass::Sensitive.index()];
            let sensitive_classes = self.sensitive.into_iter().try_fold(0_u64, |sum, value| {
                sum.checked_add(value)
                    .ok_or(ProfileError::CounterOverflow("sensitive_classes"))
            })?;
            if self.phase_counts[Phase::SensitiveEmulation.index()] != sensitive_exits
                || sensitive_classes != sensitive_exits
            {
                return Err(ProfileError::PhaseMismatch("sensitive-emulation"));
            }
        }
        if self.blocked_cpu_ns > self.phase_ns[Phase::Blocked.index()] {
            return Err(ProfileError::BlockedCpuExceedsWall);
        }
        let exclusive_fusion =
            self.exclusive_fusion
                .into_iter()
                .try_fold(0_u64, |sum, value| {
                    sum.checked_add(value)
                        .ok_or(ProfileError::CounterOverflow("exclusive_fusion"))
                })?;
        if exclusive_fusion != self.sensitive[SensitiveClass::Exclusive.index()] {
            return Err(ProfileError::ExclusiveFusionMismatch);
        }
        Ok(CompleteThreadRecord {
            pid: self.pid,
            tid: self.tid,
            era: self.era,
            exec_epoch: self.exec_epoch,
            gateway_entries: self.gateway_entries,
            reconciled_exits,
            exits: self.exits,
            sensitive: self.sensitive,
            exclusive_fusion: self.exclusive_fusion,
            phase_ns: self.phase_ns,
            phase_counts: self.phase_counts,
            blocked_cpu_ns: self.blocked_cpu_ns,
        })
    }

    pub fn invalid_protocol_line(&self, error: ProfileError) -> String {
        format!(
            "{PROTOCOL_PREFIX}|invalid|complete=0|pid={}|tid={}|era={}|exec_epoch={}|reason={}",
            self.pid,
            self.tid,
            self.era,
            self.exec_epoch,
            error.protocol_reason()
        )
    }

    pub fn reset_after_fork_child(&mut self, tid: i32) {
        let enabled = self.enabled;
        *self = Self::new(
            enabled,
            // SAFETY: `getpid` has no preconditions.
            unsafe { libc::getpid() },
            tid,
            0,
        );
    }

    pub fn reset_after_exec(&mut self) {
        let next_exec_epoch = self.next_exec_epoch_after_reset();
        self.reset_profile_era(next_exec_epoch);
        if self.enabled {
            PROFILE_EXEC_EPOCH.store(next_exec_epoch, Ordering::Release);
        }
    }

    /// The exact checked/sentinel epoch that [`Self::reset_after_exec`] will
    /// install. Diagnostic companions use this before the result-free exec
    /// commit so their outgoing record and NATIVEPERF advance atomically.
    pub fn next_exec_epoch_after_reset(&self) -> u64 {
        next_exec_epoch(self.exec_epoch)
    }

    pub fn reset_same_image_profile_era(&mut self) {
        self.reset_profile_era(self.exec_epoch);
    }

    fn reset_profile_era(&mut self, exec_epoch: u64) {
        let enabled = self.enabled;
        let pid = self.pid;
        let tid = self.tid;
        let next_era = self.era.checked_add(1).map(|minimum| {
            if enabled {
                monotonic_ticks().max(minimum)
            } else {
                minimum
            }
        });
        *self = Self::new(enabled, pid, tid, exec_epoch);
        match next_era {
            Some(era) => self.era = era,
            None => {
                self.invalid = Some(ProfileError::CounterOverflow("profile_era"));
            }
        }
    }

    pub fn invalidate(&mut self, error: ProfileError) -> ProfileError {
        self.invalid.get_or_insert(error);
        error
    }

    // NOT #[cfg(test)]: the runtime's `native_darwin/dsr/mod.rs` tests build
    // budgets through these constructors, and a dependency crate's
    // `#[cfg(test)]` items are invisible to a dependent's test build.
    pub fn enabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        let mut budget = Self::new(true, pid, tid, 0);
        budget.era = 0;
        budget
    }

    pub fn disabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        Self::new(false, pid, tid, 0)
    }

    /// Directly install an era CPU baseline, bypassing the process-global
    /// single-shot slot that production code consumes through
    /// `from_environment`. Lets tests exercise the era-delta computation
    /// deterministically without racing a real self-reexec.
    // `test-hooks` (not bare `cfg(test)`): driven cross-crate by the
    // runtime's native test module — see `crate::test_hooks`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn install_thread_cpu_baseline_ns_for_test(&mut self, baseline_ns: u64) {
        self.thread_cpu_baseline_ns = baseline_ns;
    }

    #[cfg(test)]
    fn set_gateway_entries_for_test(&mut self, value: u64) {
        self.gateway_entries = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocabulary::SensitiveKind;
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;

    #[test]
    fn thread_budget_reconciles_every_gateway_exit() {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        for class in ExitClass::ALL {
            budget.record_exit(class).expect("count exit");
        }
        let record = budget.complete_record().expect("reconciled record");
        assert_eq!(record.gateway_entries, ExitClass::ALL.len() as u64);
        assert_eq!(record.reconciled_exits, record.gateway_entries);
        assert!(
            record
                .to_protocol_line(0)
                .starts_with("NATIVEPERF1|thread|")
        );
        assert!(record.to_protocol_line(0).contains("complete=1"));
        assert!(record.to_protocol_line(7).contains("|thread_cpu_ns=7"));
    }

    #[test]
    fn thread_budget_with_installed_baseline_reports_the_era_delta_and_saturates_at_zero() {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        // Fresh threads (the common case) never install a baseline.
        assert_eq!(budget.thread_cpu_baseline_ns(), 0);

        budget.install_thread_cpu_baseline_ns_for_test(500);
        assert_eq!(budget.thread_cpu_baseline_ns(), 500);

        // The surviving exec-calling thread's kernel CPU counter is
        // cumulative across the self-reexec: subtracting the baseline
        // installed at post-exec runtime re-entry yields only THIS era's
        // consumption.
        assert_eq!(
            thread_cpu_since_baseline(1_500, budget.thread_cpu_baseline_ns()),
            1_000
        );
        // A measurement race that reads the current counter a hair below the
        // installed baseline must saturate at zero instead of wrapping to a
        // huge unsigned value.
        assert_eq!(
            thread_cpu_since_baseline(100, budget.thread_cpu_baseline_ns()),
            0
        );
    }

    fn syscall_phase_budget(blocked_wall_ns: u64) -> ThreadBudget {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        budget.record_exit(ExitClass::Syscall).expect("count exit");
        for phase in [
            Phase::PrepareIndex,
            Phase::TranslatedRun,
            Phase::FinishExit,
            Phase::LoopQuiesce,
            Phase::SyscallDispatch,
        ] {
            budget.add_phase(phase, 0).expect("count phase");
        }
        budget
            .add_phase(Phase::Blocked, blocked_wall_ns)
            .expect("count blocked wall");
        budget
    }

    #[test]
    fn blocked_cpu_exceeding_blocked_wall_invalidates_the_record() {
        let mut budget = syscall_phase_budget(10);
        budget
            .add_blocked_cpu_ns(11)
            .expect("accumulate blocked cpu");
        assert!(matches!(
            budget.complete_record(),
            Err(ProfileError::BlockedCpuExceedsWall)
        ));
    }

    #[test]
    fn blocked_cpu_within_blocked_wall_reaches_the_phases_frame() {
        let mut budget = syscall_phase_budget(10);
        budget
            .add_blocked_cpu_ns(7)
            .expect("accumulate blocked cpu");
        let record = budget.complete_record().expect("reconciled record");
        let frames = record
            .to_protocol_frames_with_resolver(
                crate::profile::ProfileSnapshot::default(),
                FlushGauges::default(),
            )
            .expect("bounded frames");
        let phases_b = frames
            .iter()
            .find(|frame| frame.contains("|frame=phases-b|"))
            .expect("phases-b frame");
        assert!(phases_b.contains("|phase_blocked_ns=10|"));
        assert!(phases_b.contains("|phase_blocked_cpu_ns=7"));
    }

    #[test]
    fn process_frame_repeats_startup_and_process_gauges() {
        let budget = ThreadBudget::enabled_for_test(41, 42);
        let record = budget.complete_record().expect("empty record");
        let frames = record
            .to_protocol_frames_with_resolver(
                crate::profile::ProfileSnapshot::default(),
                FlushGauges {
                    thread_cpu_ns: 5,
                    startup_wall_ns: 9,
                    startup_cpu_ns: 3,
                    process_cpu_ns: 8,
                },
            )
            .expect("bounded frames");
        assert_eq!(frames.len(), 24);
        assert!(frames[0].contains("|frame=core|"));
        assert!(frames[0].contains("|thread_cpu_ns=5"));
        let process = frames
            .iter()
            .find(|frame| frame.contains("|frame=process|"))
            .expect("process frame");
        assert!(process.contains("|startup_wall_ns=9|startup_cpu_ns=3|process_cpu_ns=8"));
    }

    /// Every live counter must appear EXACTLY once across the record. A
    /// counter emitted twice is double-counted the moment a reader sums the
    /// per-thread frames into a process total, and a counter emitted zero
    /// times is a metric nobody can run — the failure 6F existed to remove.
    #[test]
    fn the_live_revocation_counters_appear_once_and_round_trip() {
        let budget = ThreadBudget::enabled_for_test(41, 42);
        let record = budget.complete_record().expect("empty record");
        let frames = record
            .to_protocol_frames_with_resolver(
                crate::profile::ProfileSnapshot {
                    live_revoked_chunks: 9,
                    live_stale_instruction_aborts: 2,
                    ..Default::default()
                },
                FlushGauges {
                    thread_cpu_ns: 5,
                    startup_wall_ns: 9,
                    startup_cpu_ns: 3,
                    process_cpu_ns: 8,
                },
            )
            .expect("bounded frames");
        for field in ["live_revoked_chunks", "live_stale_instruction_aborts"] {
            let marker = format!("|{field}=");
            assert_eq!(
                frames
                    .iter()
                    .filter(|frame| frame.contains(&marker))
                    .count(),
                1,
                "{field} must be published exactly once per record"
            );
        }
        let revoke = frames
            .iter()
            .find(|frame| frame.contains("|frame=live-revoke|"))
            .expect("live-revoke frame");
        assert!(
            revoke.contains("|live_revoked_chunks=9|live_stale_instruction_aborts=2"),
            "the revocation frame must round-trip its exact values: {revoke}"
        );
        // The revocation pair is deliberately NOT folded into the serve /
        // publish frame or the byte frame: those are translate-path counters.
        for other in ["live-lane", "live-bytes"] {
            let frame = frames
                .iter()
                .find(|frame| frame.contains(&format!("|frame={other}|")))
                .expect("live frame");
            assert!(!frame.contains("live_revoked_chunks"));
            assert!(!frame.contains("live_stale_instruction_aborts"));
        }
    }

    /// The prebind triple rides the `live-bytes` frame — beside the two
    /// private→live link counters it complements — exactly once, exact
    /// values.
    #[test]
    fn the_prebind_counters_ride_the_live_bytes_frame_and_round_trip() {
        let budget = ThreadBudget::enabled_for_test(41, 42);
        let record = budget.complete_record().expect("empty record");
        let frames = record
            .to_protocol_frames_with_resolver(
                crate::profile::ProfileSnapshot {
                    live_links_prebound: 7,
                    live_links_prebind_unbound_state: 5,
                    live_links_prebind_unbound_reach: 1,
                    ..Default::default()
                },
                FlushGauges {
                    thread_cpu_ns: 5,
                    startup_wall_ns: 9,
                    startup_cpu_ns: 3,
                    process_cpu_ns: 8,
                },
            )
            .expect("bounded frames");
        for field in [
            "live_links_prebound",
            "live_links_prebind_unbound_state",
            "live_links_prebind_unbound_reach",
        ] {
            let marker = format!("|{field}=");
            assert_eq!(
                frames
                    .iter()
                    .filter(|frame| frame.contains(&marker))
                    .count(),
                1,
                "{field} must be published exactly once per record"
            );
        }
        let bytes = frames
            .iter()
            .find(|frame| frame.contains("|frame=live-bytes|"))
            .expect("live-bytes frame");
        assert!(
            bytes.contains(
                "|live_links_prebound=7|live_links_prebind_unbound_state=5|live_links_prebind_unbound_reach=1"
            ),
            "the byte frame must round-trip the exact prebind values: {bytes}"
        );
    }

    #[test]
    fn exclusive_fusion_frames_reconcile_and_fit_pipe_buf() {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        budget
            .record_exit(ExitClass::Sensitive)
            .expect("sensitive exit");
        budget
            .record_sensitive(SensitiveClass::Exclusive)
            .expect("exclusive");
        budget
            .record_exclusive_fusion(ExclusiveFusionClass::EligibleBackendDisabled)
            .expect("fusion disposition");
        let record = budget.complete_record().expect("complete record");
        let mut snapshot = crate::profile::ProfileSnapshot::default();
        snapshot.exclusive_fusion_sites[ExclusiveFusionClass::EligibleBackendDisabled.index()] = 1;
        let frames = record
            .to_protocol_frames_with_resolver(snapshot, FlushGauges::default())
            .expect("serialize frames");
        assert!(frames.iter().all(|frame| frame.len() < DARWIN_PIPE_BUF));
        assert!(frames.iter().any(|frame| {
            frame.contains("frame=fusion-exec-a")
                && frame.contains("fusion_eligible_backend_disabled=1")
        }));
    }

    #[test]
    fn startup_gauge_claims_exactly_once_and_repeats_identically() {
        let gauge = StartupGauge::new();
        gauge.arm(1_000, 500);
        let first = gauge.claim(51_000, 800).expect("first claim");
        assert_eq!(first.1, 300);
        assert_eq!(
            first.0,
            elapsed_ns_from_ticks(1_000, 51_000, timebase()).expect("tick conversion")
        );
        // Later claims repeat the first claim verbatim: the startup window is
        // captured exactly once per process and republished as a gauge.
        assert_eq!(gauge.claim(999_000, 9_999).expect("repeat claim"), first);
        assert_eq!(gauge.claimed(), Some(first));
    }

    #[test]
    fn startup_gauge_concurrent_claims_agree() {
        let gauge = StartupGauge::new();
        gauge.arm(0, 0);
        let claims = std::thread::scope(|scope| {
            let gauge = &gauge;
            (1..=8_u64)
                .map(|index| {
                    scope.spawn(move || gauge.claim(index * 1_000, index * 10).expect("claim"))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("join claimer"))
                .collect::<Vec<_>>()
        });
        assert!(claims.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn startup_gauge_unarmed_claim_is_zero_and_fork_rearm_restarts_the_window() {
        let gauge = StartupGauge::new();
        assert_eq!(gauge.claimed(), None);
        assert_eq!(gauge.claim(123, 456).expect("unarmed claim"), (0, 0));
        // A fork child discards the inherited claim: its rusage restarts at
        // zero, so the startup window restarts at the fork boundary.
        gauge.rearm(10_000, 100);
        assert_eq!(gauge.claimed(), None);
        let claimed = gauge.claim(10_000, 400).expect("re-claim after fork");
        assert_eq!(claimed, (0, 300));
    }

    #[test]
    fn startup_gauge_seed_republishes_the_producer_claim() {
        let gauge = StartupGauge::new();
        gauge.seed(77, 33);
        assert_eq!(gauge.claimed(), Some((77, 33)));
        // The seeded gauge wins over any later measurement input.
        assert_eq!(
            gauge.claim(999_999, 999_999).expect("seeded claim"),
            (77, 33)
        );
    }

    #[test]
    fn thread_budget_rejects_missing_exit_and_overflow() {
        let mut missing = ThreadBudget::enabled_for_test(41, 42);
        missing.record_gateway_entry().expect("gateway");
        assert!(matches!(
            missing.complete_record(),
            Err(ProfileError::ExitMismatch { .. })
        ));

        let mut overflow = ThreadBudget::enabled_for_test(41, 42);
        overflow.set_gateway_entries_for_test(u64::MAX);
        assert!(matches!(
            overflow.record_gateway_entry(),
            Err(ProfileError::CounterOverflow("gateway_entries"))
        ));
    }

    #[test]
    fn exec_epoch_exhaustion_invalidates_profile_without_wrapping_identity() {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        budget.exec_epoch = u64::MAX - 1;

        budget.reset_after_exec();

        assert_eq!(budget.exec_epoch, INVALID_EXEC_EPOCH);
        assert!(matches!(
            budget.complete_record(),
            Err(ProfileError::CounterOverflow("profile_exec_epoch"))
        ));
        assert!(
            budget
                .invalid_protocol_line(ProfileError::CounterOverflow("profile_exec_epoch"))
                .contains("|exec_epoch=18446744073709551615|reason=counter-overflow")
        );
    }

    #[test]
    fn sensitive_classes_have_stable_protocol_names() {
        assert_eq!(
            SensitiveClass::from(SensitiveKind::Exclusive(0)).as_str(),
            "exclusive"
        );
        assert_eq!(
            SensitiveClass::from(SensitiveKind::DcZva).as_str(),
            "dc-zva"
        );
        assert_eq!(
            SensitiveClass::from(SensitiveKind::ReadCounter).as_str(),
            "read-counter"
        );
        assert_eq!(SensitiveClass::ALL.len(), 9);
    }

    #[test]
    fn timer_rejects_timebase_failure_and_regressing_ticks() {
        assert_eq!(
            elapsed_ns_from_ticks(100, 200, Err(ProfileError::TimebaseUnavailable)),
            Err(ProfileError::TimebaseUnavailable)
        );
        assert_eq!(
            elapsed_ns_from_ticks(200, 100, Ok(TickScale { numer: 1, denom: 1 })),
            Err(ProfileError::ClockRegression)
        );
    }

    #[test]
    fn complete_records_use_pipe_atomic_bounded_frames() {
        // Worst-case identity and counter widths: every field at its maximum
        // decimal width must still fit one atomic PIPE_BUF write per frame.
        let record = CompleteThreadRecord {
            pid: libc::pid_t::MIN,
            tid: i32::MIN,
            era: u64::MAX,
            exec_epoch: u64::MAX - 1,
            gateway_entries: u64::MAX,
            reconciled_exits: u64::MAX,
            exits: [u64::MAX; ExitClass::COUNT],
            sensitive: [u64::MAX; SensitiveClass::COUNT],
            exclusive_fusion: [u64::MAX; ExclusiveFusionClass::COUNT],
            phase_ns: [u64::MAX; Phase::COUNT],
            phase_counts: [u64::MAX; Phase::COUNT],
            blocked_cpu_ns: u64::MAX,
        };
        let gauges = FlushGauges {
            thread_cpu_ns: u64::MAX,
            startup_wall_ns: u64::MAX,
            startup_cpu_ns: u64::MAX,
            process_cpu_ns: u64::MAX,
        };
        let frames = record
            .to_protocol_frames_with_resolver(
                crate::profile::ProfileSnapshot {
                    direct_binding_owner_validation_failures: u64::MAX,
                    direct_binding_authority_validation_failures: u64::MAX,
                    direct_binding_cas_wins: u64::MAX,
                    direct_binding_cas_losses: u64::MAX,
                    direct_binding_stale_winner_clears: u64::MAX,
                    direct_binding_publication_retries: u64::MAX,
                    resolve_src_shared_tgt_shared: u64::MAX,
                    resolve_src_shared_tgt_private: u64::MAX,
                    resolve_src_private_tgt_shared: u64::MAX,
                    resolve_src_private_tgt_private: u64::MAX,
                    resolve_private_to_shared_distinct_edges: u64::MAX,
                    resolve_private_to_private_distinct_edges: u64::MAX,
                    shared_unit_lookups: u64::MAX,
                    shared_unit_hits: u64::MAX,
                    shared_unit_loads: u64::MAX,
                    shared_blocks_mapped: u64::MAX,
                    shared_translations_avoided: u64::MAX,
                    shared_blocks_attached: u64::MAX,
                    shared_metadata_bytes_read: u64::MAX,
                    shared_metadata_bytes_mapped: u64::MAX,
                    shared_metadata_validation_ns: u64::MAX,
                    shared_mapped_immutable_records: u64::MAX,
                    shared_owned_immutable_records: u64::MAX,
                    shared_guest_range_derivations: u64::MAX,
                    shared_direct_edge_group_builds: u64::MAX,
                    resolver_exits: u64::MAX,
                    one_entry_hits: u64::MAX,
                    translations: u64::MAX,
                    optimistic_decode_discards: u64::MAX,
                    optimistic_decode_discard_ns: u64::MAX,
                    gateway_entries: u64::MAX,
                    syscall_exits: u64::MAX,
                    direct_resolver_exits: u64::MAX,
                    cache_lookups: u64::MAX,
                    cache_lookup_hits: u64::MAX,
                    invalidated_blocks: u64::MAX,
                    translation_ns: u64::MAX,
                    translation_decode_ns: u64::MAX,
                    translation_plan_ns: u64::MAX,
                    translation_emit_ns: u64::MAX,
                    translation_publication_ns: u64::MAX,
                    nested_translation_ns: u64::MAX,
                    cache_used_bytes: usize::MAX,
                    cache_capacity_bytes: usize::MAX,
                    exclusive_fusion_sites: [u64::MAX; ExclusiveFusionClass::COUNT],
                    live_index_hits: u64::MAX,
                    live_ready_hits: u64::MAX,
                    live_ready_misses: u64::MAX,
                    live_publish_wins: u64::MAX,
                    live_publish_adoptions: u64::MAX,
                    live_blocks_installed: u64::MAX,
                    live_code_bytes: u64::MAX,
                    live_hot_bytes: u64::MAX,
                    live_cold_bytes: u64::MAX,
                    live_links_patched: u64::MAX,
                    live_links_out_of_reach: u64::MAX,
                    live_links_prebound: u64::MAX,
                    live_links_prebind_unbound_state: u64::MAX,
                    live_links_prebind_unbound_reach: u64::MAX,
                    live_revoked_chunks: u64::MAX,
                    live_stale_instruction_aborts: u64::MAX,
                    live_fallbacks: [u64::MAX; LiveLaneFallbackClass::COUNT],
                },
                gauges,
            )
            .expect("bounded frames");
        assert_eq!(frames.len(), 24);
        for frame in frames {
            let transport_len = frame.len().checked_add(1).expect("newline length");
            assert!(
                transport_len <= DARWIN_PIPE_BUF,
                "oversized frame: {} bytes",
                transport_len
            );
        }
    }

    #[test]
    fn atomic_frames_survive_twenty_four_concurrent_writers() {
        const WRITERS: i32 = 24;
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "create pipe");
        let read_fd = pipe[0];
        let write_fd = pipe[1];
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            file.read_to_string(&mut text).expect("read frames");
            text
        });
        let writers = (0..WRITERS)
            .map(|tid| {
                std::thread::spawn(move || {
                    let budget = ThreadBudget::enabled_for_test(41, tid);
                    let record = budget.complete_record().expect("empty complete record");
                    let frames = record
                        .to_protocol_frames_with_resolver(
                            crate::profile::ProfileSnapshot::default(),
                            FlushGauges::default(),
                        )
                        .expect("bounded frames");
                    write_protocol_frames_to_fd(write_fd, &frames).expect("write frames");
                    frames.len()
                })
            })
            .collect::<Vec<_>>();
        let expected_frames = writers
            .into_iter()
            .map(|writer| writer.join().expect("join writer"))
            .sum::<usize>();
        assert_eq!(unsafe { libc::close(write_fd) }, 0, "close writer");
        let text = reader.join().expect("join reader");
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), expected_frames);
        assert!(lines.iter().all(|line| {
            let transport_len = line.len().checked_add(1).expect("newline length");
            line.starts_with("NATIVEPERF1|thread|") && transport_len <= DARWIN_PIPE_BUF
        }));
        let mut parsed_frames = std::collections::BTreeSet::new();
        for line in &lines {
            let tid = line
                .split('|')
                .find_map(|field| field.strip_prefix("tid="))
                .and_then(|value| value.parse::<i32>().ok())
                .expect("parse tid");
            let frame = line
                .split('|')
                .find_map(|field| field.strip_prefix("frame="))
                .expect("parse frame");
            assert!(
                parsed_frames.insert((tid, frame.to_owned())),
                "duplicate or interleaved frame for tid={tid} frame={frame}"
            );
        }
        for tid in 0..WRITERS {
            let needle = format!("|tid={tid}|");
            assert!(lines.iter().any(|line| line.contains(&needle)));
        }
        assert_eq!(parsed_frames.len(), expected_frames);
    }
}
