use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use super::types::{ExclusiveFusionDisposition, ExclusiveFusionRejection, SensitiveKind};

pub(super) const PROTOCOL_PREFIX: &str = "NATIVEPERF1";
pub(super) const DARWIN_PIPE_BUF: usize = 512;

/// Reserved fail-closed identity. Valid exec epochs are `0..u64::MAX`; an
/// attempted increment from the final valid epoch publishes this sentinel and
/// invalidates profiling without affecting guest exec semantics.
const INVALID_EXEC_EPOCH: u64 = u64::MAX;
static PROFILE_EXEC_EPOCH: AtomicU64 = AtomicU64::new(0);

fn next_exec_epoch(current: u64) -> u64 {
    current.checked_add(1).unwrap_or(INVALID_EXEC_EPOCH)
}

pub(in crate::native_darwin) fn next_profile_exec_epoch_for_reexec() -> u64 {
    next_exec_epoch(PROFILE_EXEC_EPOCH.load(Ordering::Acquire))
}

pub(in crate::native_darwin) fn seed_profile_exec_epoch_after_reexec(epoch: u64) {
    PROFILE_EXEC_EPOCH.store(epoch, Ordering::Release);
}

pub(super) fn reset_profile_exec_epoch_after_fork_child() {
    PROFILE_EXEC_EPOCH.store(0, Ordering::Release);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(in crate::native_darwin) enum ExitClass {
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
    pub(super) const ALL: [Self; 8] = [
        Self::Syscall,
        Self::ResolveDirect,
        Self::ResolveIndirect,
        Self::Sensitive,
        Self::Fault,
        Self::Kick,
        Self::StaleGeneration,
        Self::Unsupported,
    ];
    pub(super) const COUNT: usize = Self::ALL.len();

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
pub(in crate::native_darwin) enum SensitiveClass {
    Exclusive,
    ReadTpidr,
    WriteTpidr,
    ReadCtr,
    ReadDczid,
    DcZva,
    DcCvau,
    IcIvau,
}

impl SensitiveClass {
    pub(super) const ALL: [Self; 8] = [
        Self::Exclusive,
        Self::ReadTpidr,
        Self::WriteTpidr,
        Self::ReadCtr,
        Self::ReadDczid,
        Self::DcZva,
        Self::DcCvau,
        Self::IcIvau,
    ];
    pub(super) const COUNT: usize = Self::ALL.len();

    const fn index(self) -> usize {
        self as usize
    }

    #[cfg(test)]
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::ReadTpidr => "read-tpidr",
            Self::WriteTpidr => "write-tpidr",
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
pub(in crate::native_darwin) enum ExclusiveFusionClass {
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
    pub(super) const ALL: [Self; 15] = [
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
    pub(super) const COUNT: usize = Self::ALL.len();

    pub(super) const fn index(self) -> usize {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(in crate::native_darwin) enum Phase {
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
    pub(super) const ALL: [Self; 8] = [
        Self::PrepareIndex,
        Self::Translate,
        Self::TranslatedRun,
        Self::FinishExit,
        Self::SensitiveEmulation,
        Self::SyscallDispatch,
        Self::LoopQuiesce,
        Self::Blocked,
    ];
    pub(super) const COUNT: usize = Self::ALL.len();

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
pub(in crate::native_darwin) enum ProfileError {
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
    pub(super) const fn protocol_reason(self) -> &'static str {
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
pub(in crate::native_darwin) struct PhaseTimer {
    started: Option<u64>,
}

impl PhaseTimer {
    pub(super) const fn disabled() -> Self {
        Self { started: None }
    }

    #[inline]
    pub(in crate::native_darwin) fn start_if<const PROFILE: bool>() -> Self {
        if PROFILE {
            Self {
                started: Some(monotonic_ticks()),
            }
        } else {
            Self::disabled()
        }
    }

    pub(in crate::native_darwin) fn elapsed_ns(self) -> Result<u64, ProfileError> {
        let Some(started) = self.started else {
            return Ok(0);
        };
        elapsed_ns_from_ticks(started, monotonic_ticks(), timebase())
    }
}

#[inline]
#[allow(deprecated)]
fn monotonic_ticks() -> u64 {
    // SAFETY: `mach_absolute_time` has no arguments and returns the monotonic
    // host uptime counter.
    unsafe { libc::mach_absolute_time() }
}

#[allow(deprecated)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Timebase {
    numer: u32,
    denom: u32,
}

#[allow(deprecated)]
fn timebase() -> Result<Timebase, ProfileError> {
    static TIMEBASE: OnceLock<Result<Timebase, ProfileError>> = OnceLock::new();
    *TIMEBASE.get_or_init(|| {
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: the call initializes the fixed-size out parameter.
        if unsafe { libc::mach_timebase_info(&mut info) } != libc::KERN_SUCCESS || info.denom == 0 {
            Err(ProfileError::TimebaseUnavailable)
        } else {
            Ok(Timebase {
                numer: info.numer,
                denom: info.denom,
            })
        }
    })
}

fn elapsed_ns_from_ticks(
    started: u64,
    ended: u64,
    timebase: Result<Timebase, ProfileError>,
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
pub(in crate::native_darwin) fn current_thread_cpu_total_ns() -> Result<u64, ProfileError> {
    let (user_us, system_us) =
        crate::host_proc::self_thread_cpu_us().ok_or(ProfileError::ThreadUsageUnavailable)?;
    user_us
        .checked_add(system_us)
        .and_then(|total_us| total_us.checked_mul(1_000))
        .ok_or(ProfileError::TimeOverflow)
}

/// Total CPU (user + system) consumed by THIS PROCESS, in nanoseconds, from
/// `getrusage(RUSAGE_SELF)`. Fork restarts this clock in the child; execve
/// preserves it — both facts are load-bearing for the startup gauge below.
pub(in crate::native_darwin) fn process_cpu_total_ns() -> Result<u64, ProfileError> {
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
pub(super) struct StartupGauge {
    state: AtomicU8,
    entry_ticks: AtomicU64,
    entry_cpu_ns: AtomicU64,
    startup_wall_ns: AtomicU64,
    startup_cpu_ns: AtomicU64,
}

impl StartupGauge {
    pub(super) const fn new() -> Self {
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
    pub(super) fn arm(&self, entry_ticks: u64, entry_cpu_ns: u64) {
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
    pub(super) fn rearm(&self, entry_ticks: u64, entry_cpu_ns: u64) {
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
    pub(super) fn seed(&self, startup_wall_ns: u64, startup_cpu_ns: u64) {
        self.state.store(STARTUP_CLAIMING, Ordering::Release);
        self.startup_wall_ns
            .store(startup_wall_ns, Ordering::Relaxed);
        self.startup_cpu_ns.store(startup_cpu_ns, Ordering::Relaxed);
        self.state.store(STARTUP_CLAIMED, Ordering::Release);
    }

    pub(super) fn is_claimed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STARTUP_CLAIMED
    }

    pub(super) fn claimed(&self) -> Option<(u64, u64)> {
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
    pub(super) fn claim(
        &self,
        now_ticks: u64,
        cpu_now_ns: u64,
    ) -> Result<(u64, u64), ProfileError> {
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
pub(in crate::native_darwin) fn mark_native_process_runtime_entry() {
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
pub(super) fn reset_process_startup_after_fork_child() {
    let entry_ticks = monotonic_ticks();
    let entry_cpu_ns = process_cpu_total_ns().unwrap_or(0);
    PROCESS_STARTUP.rearm(entry_ticks, entry_cpu_ns);
}

/// Republish a pre-exec claim across the host self-reexec (same pid).
pub(in crate::native_darwin) fn seed_claimed_process_startup(
    startup_wall_ns: u64,
    startup_cpu_ns: u64,
) {
    PROCESS_STARTUP.seed(startup_wall_ns, startup_cpu_ns);
}

/// The claimed startup gauge, if the process has one (transported through the
/// self-reexec capsule so one pid never publishes two startup windows).
pub(in crate::native_darwin) fn claimed_process_startup() -> Option<(u64, u64)> {
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
pub(in crate::native_darwin) fn install_surviving_thread_cpu_baseline_at_reexec_entry() {
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
pub(super) fn claim_process_startup() -> Result<(), ProfileError> {
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
pub(super) struct FlushGauges {
    pub(super) thread_cpu_ns: u64,
    pub(super) startup_wall_ns: u64,
    pub(super) startup_cpu_ns: u64,
    pub(super) process_cpu_ns: u64,
}

/// Sample the flush-moment gauges for one thread group. Claims the startup
/// window if no gateway entry has (a flush before first guest entry ends the
/// window at the flush). `thread_cpu_baseline_ns` is the era baseline
/// installed on the flushing thread's `ThreadBudget` (zero for every thread
/// except the one surviving a PID-preserving host self-reexec): the reported
/// `thread_cpu_ns` is this era's OWN consumption, not the thread's lifetime
/// total.
pub(super) fn flush_gauges(thread_cpu_baseline_ns: u64) -> Result<FlushGauges, ProfileError> {
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
/// `crate::host_proc::current_thread_port`) and published for a foreign
/// reader. Unlike `current_thread_cpu_total_ns`, this can be called from any
/// thread about ANY other -- it is how `exit_group`'s "last thread standing"
/// reads a still-running sibling's real, live CPU total instead of the
/// sibling's own (necessarily self-only) accounting.
pub(in crate::native_darwin) fn thread_cpu_total_ns_for_port(
    port: libc::mach_port_t,
) -> Result<u64, ProfileError> {
    let (user_us, system_us) = crate::host_proc::thread_cpu_us_for_port(port)
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
pub(super) fn flush_gauges_for_port(
    port: libc::mach_port_t,
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

#[derive(Clone, Debug)]
pub(super) struct CompleteThreadRecord {
    pub(super) pid: libc::pid_t,
    pub(super) tid: i32,
    pub(super) era: u64,
    pub(super) exec_epoch: u64,
    pub(super) gateway_entries: u64,
    pub(super) reconciled_exits: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    exclusive_fusion: [u64; ExclusiveFusionClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
    blocked_cpu_ns: u64,
}

impl CompleteThreadRecord {
    pub(super) fn to_protocol_line(&self, thread_cpu_ns: u64) -> String {
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

    pub(super) fn to_protocol_frames_with_resolver(
        &self,
        resolver: super::ProfileSnapshot,
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
            "|translations={}|duplicate_publications={}|cache_lookups={}|cache_lookup_hits={}|invalidated_blocks={}",
            resolver.translations,
            resolver.duplicate_publications,
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
        let mut cache = self.frame_header("cache-gauge");
        let _ = write!(
            cache,
            "|cache_used_bytes={}|cache_capacity_bytes={}",
            resolver.cache_used_bytes, resolver.cache_capacity_bytes
        );
        frames.push(cache);
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

pub(super) fn write_protocol_frames_to_fd(
    fd: libc::c_int,
    frames: &[String],
) -> std::io::Result<()> {
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
pub(super) struct ThreadBudget {
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
    pub(super) fn from_environment(tid: i32) -> Self {
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

    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    /// The guest tid this budget is accounted to. Only needed so a FOREIGN
    /// thread draining the sibling registry can name the thread it failed to
    /// reconstruct a record for in a diagnostic.
    pub(super) fn tid(&self) -> i32 {
        self.tid
    }

    pub(super) fn thread_cpu_baseline_ns(&self) -> u64 {
        self.thread_cpu_baseline_ns
    }

    pub(super) fn record_gateway_entry(&mut self) -> Result<(), ProfileError> {
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

    pub(super) fn record_exit(&mut self, class: ExitClass) -> Result<(), ProfileError> {
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

    pub(super) fn record_sensitive(&mut self, class: SensitiveClass) -> Result<(), ProfileError> {
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

    pub(super) fn record_exclusive_fusion(
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

    pub(super) fn add_phase(&mut self, phase: Phase, elapsed_ns: u64) -> Result<(), ProfileError> {
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
    pub(super) fn add_blocked_cpu_ns(&mut self, elapsed_ns: u64) -> Result<(), ProfileError> {
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

    pub(super) fn complete_record(&self) -> Result<CompleteThreadRecord, ProfileError> {
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

    pub(super) fn invalid_protocol_line(&self, error: ProfileError) -> String {
        format!(
            "{PROTOCOL_PREFIX}|invalid|complete=0|pid={}|tid={}|era={}|exec_epoch={}|reason={}",
            self.pid,
            self.tid,
            self.era,
            self.exec_epoch,
            error.protocol_reason()
        )
    }

    pub(super) fn reset_after_fork_child(&mut self, tid: i32) {
        let enabled = self.enabled;
        *self = Self::new(
            enabled,
            // SAFETY: `getpid` has no preconditions.
            unsafe { libc::getpid() },
            tid,
            0,
        );
    }

    pub(super) fn reset_after_exec(&mut self) {
        let enabled = self.enabled;
        let pid = self.pid;
        let tid = self.tid;
        let next_exec_epoch = next_exec_epoch(self.exec_epoch);
        let next_era = self.era.checked_add(1).map(|minimum| {
            if enabled {
                monotonic_ticks().max(minimum)
            } else {
                minimum
            }
        });
        *self = Self::new(enabled, pid, tid, next_exec_epoch);
        if enabled {
            PROFILE_EXEC_EPOCH.store(next_exec_epoch, Ordering::Release);
        }
        match next_era {
            Some(era) => self.era = era,
            None => {
                self.invalid = Some(ProfileError::CounterOverflow("profile_era"));
            }
        }
    }

    pub(super) fn invalidate(&mut self, error: ProfileError) -> ProfileError {
        self.invalid.get_or_insert(error);
        error
    }

    #[cfg(test)]
    pub(super) fn enabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        let mut budget = Self::new(true, pid, tid, 0);
        budget.era = 0;
        budget
    }

    #[cfg(test)]
    pub(super) fn disabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        Self::new(false, pid, tid, 0)
    }

    /// Directly install an era CPU baseline, bypassing the process-global
    /// single-shot slot that production code consumes through
    /// `from_environment`. Lets tests exercise the era-delta computation
    /// deterministically without racing a real self-reexec.
    #[cfg(test)]
    pub(super) fn install_thread_cpu_baseline_ns_for_test(&mut self, baseline_ns: u64) {
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
    use crate::native_darwin::dsr::types::SensitiveKind;
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
                super::super::ProfileSnapshot::default(),
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
                super::super::ProfileSnapshot::default(),
                FlushGauges {
                    thread_cpu_ns: 5,
                    startup_wall_ns: 9,
                    startup_cpu_ns: 3,
                    process_cpu_ns: 8,
                },
            )
            .expect("bounded frames");
        assert_eq!(frames.len(), 14);
        assert!(frames[0].contains("|frame=core|"));
        assert!(frames[0].contains("|thread_cpu_ns=5"));
        let process = frames
            .iter()
            .find(|frame| frame.contains("|frame=process|"))
            .expect("process frame");
        assert!(process.contains("|startup_wall_ns=9|startup_cpu_ns=3|process_cpu_ns=8"));
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
        let mut snapshot = super::super::ProfileSnapshot::default();
        snapshot.exclusive_fusion_sites[ExclusiveFusionClass::EligibleBackendDisabled.index()] = 1;
        let frames = record
            .to_protocol_frames_with_resolver(snapshot, FlushGauges::default())
            .expect("serialize frames");
        assert!(
            frames
                .iter()
                .all(|frame| frame.len() + 1 <= DARWIN_PIPE_BUF)
        );
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
        assert_eq!(SensitiveClass::ALL.len(), 8);
    }

    #[test]
    fn timer_rejects_timebase_failure_and_regressing_ticks() {
        assert_eq!(
            elapsed_ns_from_ticks(100, 200, Err(ProfileError::TimebaseUnavailable)),
            Err(ProfileError::TimebaseUnavailable)
        );
        assert_eq!(
            elapsed_ns_from_ticks(200, 100, Ok(Timebase { numer: 1, denom: 1 })),
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
                super::super::ProfileSnapshot {
                    resolver_exits: u64::MAX,
                    one_entry_hits: u64::MAX,
                    translations: u64::MAX,
                    duplicate_publications: u64::MAX,
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
                },
                gauges,
            )
            .expect("bounded frames");
        assert_eq!(frames.len(), 14);
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
                            super::super::ProfileSnapshot::default(),
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
