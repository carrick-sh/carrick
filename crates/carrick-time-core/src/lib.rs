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
pub fn apply_timex_fields(state: &mut AdjtimexState, timex: &LinuxTimex) {
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
