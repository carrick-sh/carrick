use std::fmt::Write as _;
use std::sync::OnceLock;

use super::types::SensitiveKind;

pub(super) const PROTOCOL_PREFIX: &str = "NATIVEPERF1";

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
    #[error(
        "gateway exits do not reconcile: gateway_entries={gateway_entries}, reconciled={reconciled_exits}"
    )]
    ExitMismatch {
        gateway_entries: u64,
        reconciled_exits: u64,
    },
    #[error("profile elapsed time overflow")]
    TimeOverflow,
    #[error("profile dispatch blocked time exceeds total time")]
    DispatchTimeUnderflow,
    #[error("nested profile time exceeds its enclosing phase")]
    TimeOverlap,
    #[error("profile phase counts do not reconcile: {0}")]
    PhaseMismatch(&'static str),
}

impl ProfileError {
    pub(super) const fn protocol_reason(self) -> &'static str {
        match self {
            Self::CounterOverflow(_) => "counter-overflow",
            Self::ExitMismatch { .. } => "exit-mismatch",
            Self::TimeOverflow => "time-overflow",
            Self::DispatchTimeUnderflow => "dispatch-time-underflow",
            Self::TimeOverlap => "time-overlap",
            Self::PhaseMismatch(_) => "phase-mismatch",
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
        ticks_to_ns(monotonic_ticks().wrapping_sub(started))
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
fn ticks_to_ns(ticks: u64) -> Result<u64, ProfileError> {
    static TIMEBASE: OnceLock<(u32, u32)> = OnceLock::new();
    let (numer, denom) = *TIMEBASE.get_or_init(|| {
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: the call initializes the fixed-size out parameter. A failed
        // query uses identity conversion so profiling becomes conservative
        // rather than dividing by zero.
        if unsafe { libc::mach_timebase_info(&mut info) } != libc::KERN_SUCCESS || info.denom == 0 {
            (1, 1)
        } else {
            (info.numer, info.denom)
        }
    });
    let ns = u128::from(ticks)
        .checked_mul(u128::from(numer))
        .ok_or(ProfileError::TimeOverflow)?
        / u128::from(denom);
    u64::try_from(ns).map_err(|_| ProfileError::TimeOverflow)
}

#[derive(Clone, Debug)]
pub(super) struct CompleteThreadRecord {
    pub(super) pid: libc::pid_t,
    pub(super) tid: i32,
    pub(super) gateway_entries: u64,
    pub(super) reconciled_exits: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
}

impl CompleteThreadRecord {
    pub(super) fn to_protocol_line(&self) -> String {
        let mut line = format!(
            "{PROTOCOL_PREFIX}|thread|complete=1|pid={}|tid={}|gateway_entries={}|reconciled_exits={}",
            self.pid, self.tid, self.gateway_entries, self.reconciled_exits
        );
        for class in ExitClass::ALL {
            let _ = write!(
                line,
                "|exit_{}={}",
                class.field_name(),
                self.exits[class.index()]
            );
        }
        for class in SensitiveClass::ALL {
            let _ = write!(
                line,
                "|sensitive_{}={}",
                class.field_name(),
                self.sensitive[class.index()]
            );
        }
        for phase in Phase::ALL {
            let _ = write!(
                line,
                "|phase_{}_ns={}|phase_{}_count={}",
                phase.field_name(),
                self.phase_ns[phase.index()],
                phase.field_name(),
                self.phase_counts[phase.index()]
            );
        }
        line.push_str("|overflowed=0");
        line
    }

    pub(super) fn to_protocol_line_with_resolver(
        &self,
        resolver: super::ProfileSnapshot,
    ) -> String {
        let mut line = self.to_protocol_line();
        let _ = write!(
            line,
            "|nested_translation_ns={}|nested_translation_decode_ns={}|nested_translation_plan_ns={}|nested_translation_emit_ns={}|nested_translation_publication_ns={}|resolver_exits={}|one_entry_hits={}|translations={}|duplicate_publications={}|cache_lookups={}|cache_lookup_hits={}|invalidated_blocks={}|cache_used_bytes={}|cache_capacity_bytes={}",
            resolver.translation_ns,
            resolver.translation_decode_ns,
            resolver.translation_plan_ns,
            resolver.translation_emit_ns,
            resolver.translation_publication_ns,
            resolver.resolver_exits,
            resolver.one_entry_hits,
            resolver.translations,
            resolver.duplicate_publications,
            resolver.cache_lookups,
            resolver.cache_lookup_hits,
            resolver.invalidated_blocks,
            resolver.cache_used_bytes,
            resolver.cache_capacity_bytes,
        );
        line
    }
}

pub(super) struct ThreadBudget {
    enabled: bool,
    pid: libc::pid_t,
    tid: i32,
    gateway_entries: u64,
    exits: [u64; ExitClass::COUNT],
    sensitive: [u64; SensitiveClass::COUNT],
    phase_ns: [u64; Phase::COUNT],
    phase_counts: [u64; Phase::COUNT],
    invalid: Option<ProfileError>,
}

impl ThreadBudget {
    pub(super) fn from_environment(tid: i32) -> Self {
        Self::new(
            std::env::var_os("CARRICK_DSR_PROFILE").is_some(),
            // SAFETY: `getpid` has no preconditions.
            unsafe { libc::getpid() },
            tid,
        )
    }

    fn new(enabled: bool, pid: libc::pid_t, tid: i32) -> Self {
        Self {
            enabled,
            pid,
            tid,
            gateway_entries: 0,
            exits: [0; ExitClass::COUNT],
            sensitive: [0; SensitiveClass::COUNT],
            phase_ns: [0; Phase::COUNT],
            phase_counts: [0; Phase::COUNT],
            invalid: None,
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.enabled
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
        Ok(CompleteThreadRecord {
            pid: self.pid,
            tid: self.tid,
            gateway_entries: self.gateway_entries,
            reconciled_exits,
            exits: self.exits,
            sensitive: self.sensitive,
            phase_ns: self.phase_ns,
            phase_counts: self.phase_counts,
        })
    }

    pub(super) fn invalid_protocol_line(&self, error: ProfileError) -> String {
        format!(
            "{PROTOCOL_PREFIX}|invalid|complete=0|pid={}|tid={}|reason={}",
            self.pid,
            self.tid,
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
        );
    }

    pub(super) fn invalidate(&mut self, error: ProfileError) -> ProfileError {
        self.invalid.get_or_insert(error);
        error
    }

    #[cfg(test)]
    pub(super) fn enabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        Self::new(true, pid, tid)
    }

    #[cfg(test)]
    pub(super) fn disabled_for_test(pid: libc::pid_t, tid: i32) -> Self {
        Self::new(false, pid, tid)
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

    #[test]
    fn thread_budget_reconciles_every_gateway_exit() {
        let mut budget = ThreadBudget::enabled_for_test(41, 42);
        for class in ExitClass::ALL {
            budget.record_exit(class).expect("count exit");
        }
        let record = budget.complete_record().expect("reconciled record");
        assert_eq!(record.gateway_entries, ExitClass::ALL.len() as u64);
        assert_eq!(record.reconciled_exits, record.gateway_entries);
        assert!(record.to_protocol_line().starts_with("NATIVEPERF1|thread|"));
        assert!(record.to_protocol_line().contains("complete=1"));
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
}
