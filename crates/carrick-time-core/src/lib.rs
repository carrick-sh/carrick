//! Shared Linux clock-discipline state and transitions.
//!
//! This crate owns neither a clock nor guest memory. The caller retains the
//! clock authority's lock and prepares output before applying a validated
//! adjustment. Physical sampling, clock-change notification and offset steps
//! remain with that authority. Both host and ring clients can use these same
//! transitions without copying the Linux interpretation.
#![no_std]

use carrick_abi::{
    LINUX_TIME_DEL, LINUX_TIME_ERROR, LINUX_TIME_INS, LINUX_TIME_OK, LinuxTimeval, LinuxTimex,
    LinuxTimexModes, LinuxTimexStatus,
};
use core::time::Duration;

/// Time discipline state modeled for this clock domain per `struct timex`.
///
/// Deliberate approximations:
/// - Frequency adjustments (`freq`, `tick`) are recorded and reported faithfully
///   through `adjtimex` and `clock_adjtime`, but do not alter the virtual clock rate.
/// - `maxerror` remains static between calls unless explicitly updated via `ADJ_MAXERROR`.
/// - `ADJ_OFFSET_SINGLESHOT` is modeled as an immediate step applied to the domain's
///   virtual realtime offset rather than an ongoing linear slew or PLL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjtimexState {
    pub offset: i64,
    pub freq: i64,
    pub maxerror: i64,
    pub esterror: i64,
    pub status: i32,
    pub constant: i64,
    pub tick: i64,
    pub tai: i32,
    pub singleshot_offset: i64,
}

impl Default for AdjtimexState {
    fn default() -> Self {
        Self {
            offset: 0,
            freq: 0,
            maxerror: 16_000_000,
            esterror: 16_000_000,
            status: 0,
            constant: 2,
            tick: 10_000,
            tai: 0,
            singleshot_offset: 0,
        }
    }
}

pub fn linux_time_state_from_status(status: LinuxTimexStatus) -> i64 {
    if status.contains(LinuxTimexStatus::UNSYNC) {
        LINUX_TIME_ERROR
    } else if status.contains(LinuxTimexStatus::INS) {
        LINUX_TIME_INS
    } else if status.contains(LinuxTimexStatus::DEL) {
        LINUX_TIME_DEL
    } else {
        LINUX_TIME_OK
    }
}

pub fn linux_timex_from_state(time: LinuxTimeval, state: &AdjtimexState) -> LinuxTimex {
    LinuxTimex {
        modes: 0,
        _pad0: 0,
        offset: state.offset,
        freq: state.freq,
        maxerror: state.maxerror,
        esterror: state.esterror,
        status: state.status,
        _pad1: 0,
        constant: state.constant,
        precision: 1,
        tolerance: 32_768_000,
        time,
        tick: state.tick,
        ppsfreq: 0,
        jitter: 0,
        shift: 0,
        _pad2: 0,
        stabil: 0,
        jitcnt: 0,
        calcnt: 0,
        errcnt: 0,
        stbcnt: 0,
        tai: state.tai,
        _pad3: [0; 11],
    }
}

pub fn linux_timex_time(duration: Duration, status: LinuxTimexStatus) -> LinuxTimeval {
    let sub = if status.contains(LinuxTimexStatus::NANO) {
        i64::from(duration.subsec_nanos())
    } else {
        i64::from(duration.subsec_micros())
    };
    LinuxTimeval::new(duration.as_secs() as i64, sub)
}

/// Apply the state fields of an already validated adjustment.
///
/// The caller must hold the clock authority's mutation lock. This does not
/// validate credentials, prepare guest output or apply the realtime offset:
/// those obligations must precede this transition, as in the host dispatcher.
/// It performs bounded work with no allocation or physical clock reads.
fn apply_timex_fields(state: &mut AdjtimexState, timex: &LinuxTimex) {
    let modes = LinuxTimexModes::from_bits_retain(timex.modes);
    if modes.contains(LinuxTimexModes::OFFSET) {
        if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG) {
            state.offset = 0;
        } else {
            state.offset = timex.offset;
        }
    }
    if modes.contains(LinuxTimexModes::FREQUENCY) {
        // Linux clamps to +/-MAXFREQ (scaled ppm) instead of refusing.
        state.freq = timex.freq.clamp(-32_768_000, 32_768_000);
    }
    if modes.contains(LinuxTimexModes::MAXERROR) {
        state.maxerror = timex.maxerror;
    }
    if modes.contains(LinuxTimexModes::ESTERROR) {
        state.esterror = timex.esterror;
    }
    if modes.contains(LinuxTimexModes::STATUS) {
        let current_status = LinuxTimexStatus::from_bits_retain(state.status);
        // `from_bits_truncate`: bits Linux does not define are dropped,
        // not refused (the oracle accepts `1 << 20`).
        let requested_status = LinuxTimexStatus::from_bits_truncate(timex.status);
        let merged = (current_status & LinuxTimexStatus::RONLY)
            | (requested_status & !LinuxTimexStatus::RONLY);
        state.status = merged.bits();
    }
    if modes.contains(LinuxTimexModes::NANO) {
        let mut s = LinuxTimexStatus::from_bits_retain(state.status);
        s.insert(LinuxTimexStatus::NANO);
        state.status = s.bits();
    }
    if modes.contains(LinuxTimexModes::MICRO) {
        let mut s = LinuxTimexStatus::from_bits_retain(state.status);
        s.remove(LinuxTimexStatus::NANO);
        state.status = s.bits();
    }
    if modes.contains(LinuxTimexModes::TIMECONST) {
        state.constant = timex.constant;
    }
    if modes.contains(LinuxTimexModes::TAI) {
        state.tai = timex.constant as i32;
    }
    if modes.contains(LinuxTimexModes::TICK) {
        state.tick = timex.tick;
    }
}

/// The caller's already authenticated Linux clock-adjustment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimexAccess {
    ReadOnly,
    Adjust,
}

/// Validation has one unusual Linux result: a malformed singleshot mode
/// writes a defined error record before returning EINVAL. Keep that effect
/// distinct from a refusal that must leave user memory untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimexValidationError {
    InvalidModeOutput,
    Errno(carrick_abi::LinuxErrno),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimexKind {
    Read,
    ReadSingleshot,
    Adjust,
}

/// A borrowed, validated Linux request. No ABI-sized value is copied onto
/// the kernel stack. State-dependent offset interpretation still belongs
/// inside the clock authority's transaction, via `realtime_step`.
pub struct TimexRequest<'a> {
    input: &'a LinuxTimex,
    kind: TimexKind,
}

impl<'a> TimexRequest<'a> {
    pub fn validate(
        input: &'a LinuxTimex,
        access: TimexAccess,
    ) -> Result<Self, TimexValidationError> {
        use carrick_abi::{LINUX_CLK_TCK, LINUX_EINVAL, LINUX_EPERM};
        let modes = LinuxTimexModes::from_bits_retain(input.modes);
        if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
            && !modes.contains(LinuxTimexModes::OFFSET)
        {
            return Err(TimexValidationError::InvalidModeOutput);
        }
        let kind = if input.modes == 0 {
            TimexKind::Read
        } else if modes == LinuxTimexModes::OFFSET_SS_READ {
            TimexKind::ReadSingleshot
        } else {
            // Preserve Linux's permission-before-adjustment-validation order.
            if access != TimexAccess::Adjust {
                return Err(TimexValidationError::Errno(LINUX_EPERM));
            }
            // The native ARM64 adjtimexmodel oracle accepts MICRO|NANO
            // and TAI|TIMECONST together. The later field update wins.
            // Frequency is clamped and unknown status bits are dropped by
            // the transition, rather than rejected here.
            const KNOWN_MODES: u32 = LinuxTimexModes::IDEMPOTENT_SUPPORTED.bits()
                | LinuxTimexModes::OFFSET_SINGLESHOT_FLAG.bits();
            let tick = input.tick;
            let offset = input.offset;
            if (input.modes & !KNOWN_MODES) != 0
                || (modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
                    && modes != LinuxTimexModes::OFFSET_SINGLESHOT)
                || (modes.contains(LinuxTimexModes::TICK)
                    && !(900_000 / LINUX_CLK_TCK..=1_100_000 / LINUX_CLK_TCK).contains(&tick))
                || (modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
                    && !(-131_071..=131_071).contains(&offset))
            {
                return Err(TimexValidationError::Errno(LINUX_EINVAL));
            }
            TimexKind::Adjust
        };
        Ok(Self { input, kind })
    }

    pub fn modifies(&self) -> bool {
        self.kind == TimexKind::Adjust
    }

    /// Compute a step against the state held by the clock's mutation owner.
    /// This never changes state, including on overflow or an invalid subsecond.
    pub fn realtime_step(
        &self,
        status: impl FnOnce() -> LinuxTimexStatus,
    ) -> Result<Option<i64>, carrick_abi::LinuxErrno> {
        use carrick_abi::LINUX_EINVAL;
        if !self.modifies() {
            return Ok(None);
        }
        let modes = LinuxTimexModes::from_bits_retain(self.input.modes);
        if modes.contains(LinuxTimexModes::SETOFFSET) {
            let is_nano = if modes.contains(LinuxTimexModes::NANO) {
                true
            } else if modes.contains(LinuxTimexModes::MICRO) {
                false
            } else {
                status().contains(LinuxTimexStatus::NANO)
            };
            let max_sub = if is_nano { 1_000_000_000 } else { 1_000_000 };
            if self.input.time.tv_usec < 0 || self.input.time.tv_usec >= max_sub {
                return Err(LINUX_EINVAL);
            }
            let sec_ns = self
                .input
                .time
                .tv_sec
                .checked_mul(1_000_000_000)
                .ok_or(LINUX_EINVAL)?;
            let sub_ns = if is_nano {
                self.input.time.tv_usec
            } else {
                self.input.time.tv_usec.saturating_mul(1_000)
            };
            Ok(Some(sec_ns.checked_add(sub_ns).ok_or(LINUX_EINVAL)?))
        } else if modes == LinuxTimexModes::OFFSET_SINGLESHOT {
            Ok(Some(
                self.input.offset.checked_mul(1_000).ok_or(LINUX_EINVAL)?,
            ))
        } else {
            Ok(None)
        }
    }

    /// Apply only the discipline fields, after output preparation and a
    /// successful step, under the same authority as `realtime_step`.
    pub fn apply_fields(&self, state: &mut AdjtimexState) {
        if self.modifies() {
            apply_timex_fields(state, self.input);
        }
    }

    /// Fill caller-owned storage so ring callers need no large return value.
    pub fn write_reply(
        &self,
        state: &AdjtimexState,
        now: Duration,
        output: &mut LinuxTimex,
    ) -> i64 {
        let status = LinuxTimexStatus::from_bits_retain(state.status);
        *output = linux_timex_from_state(linux_timex_time(now, status), state);
        if self.kind != TimexKind::Read {
            output.modes = self.input.modes;
        }
        if self.kind == TimexKind::ReadSingleshot {
            output.offset = 0;
        }
        linux_time_state_from_status(status)
    }
}
