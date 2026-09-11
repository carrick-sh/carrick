//! Time, clock, and timer serialization and conversion helpers.

use core::time::Duration;

pub(crate) use carrick_abi::{
    LINUX_CLK_TCK, LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME, LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE,
    LINUX_CLOCK_RESOLUTION_NSEC, LINUX_CLOCK_TAI, LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EAGAIN,
    LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_EOPNOTSUPP, LINUX_EPERM, LINUX_ITIMER_PROF,
    LINUX_ITIMER_REAL, LINUX_ITIMER_VIRTUAL, LINUX_TIME_DEL, LINUX_TIME_ERROR, LINUX_TIME_INS,
    LINUX_TIME_OK, LINUX_UTIME_NOW, LINUX_UTIME_OMIT, LinuxItimerspec, LinuxItimerval,
    LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimex, LinuxTimexModes,
    LinuxTimexStatus, LinuxTimezone, LinuxTms,
};
use carrick_guest_mem::CurrentMmMemory;

use crate::linux_abi::LinuxErrno;

use super::fd_table::{TimerFdInner, TimerFdState};
use super::{
    DispatchOutcome, GuestPtr, read_kernel_struct, time, write_kernel_struct,
    write_kernel_struct_raw,
};

pub(crate) enum DynamicCpuClock {
    /// Per-thread CPU clock → target thread kernel CPU accounting.
    PerThread,
    /// Per-process CPU clock → target task kernel CPU accounting.
    PerProcess,
}

pub(crate) fn dynamic_cpu_clock(clock_id: u64) -> Option<DynamicCpuClock> {
    // clockid_t is a 32-bit `int`; the guest may zero- OR sign-extend it into
    // x0 (the vDSO __kernel_clock_gettime fast-path loads only w0, so a dynamic
    // id arrives as a LARGE positive u64, not sign-extended). Interpret as i32:
    // static CLOCK_* ids are small non-negative; dynamic per-task ids are
    // negative. Bit layout (clean-room from clock_getcpuclockid(3) + observed
    // Docker encodings): low 2 bits = clock type (SCHED=2), low 3 bits == 3 is
    // CPUCLOCK_FD (not a CPU clock), bit 2 (mask 4) = CPUCLOCK_PERTHREAD.
    if (clock_id as i32) >= 0 {
        return None;
    }
    if (clock_id & 0b11) as u8 == 3 {
        return None;
    }
    if clock_id & 0b100 != 0 {
        Some(DynamicCpuClock::PerThread)
    } else {
        Some(DynamicCpuClock::PerProcess)
    }
}

pub(crate) fn linux_clock_duration(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Some(clock.realtime_now()),
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW | LINUX_CLOCK_MONOTONIC_COARSE => {
            Some(clock.monotonic_now())
        }
        // BOOTTIME includes suspend time; on macOS that is CLOCK_MONOTONIC.
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => Some(clock.boottime_now()),
        LINUX_CLOCK_PROCESS_CPUTIME_ID => Some(Duration::from_nanos(time::task_process_cpu_ns())),
        LINUX_CLOCK_THREAD_CPUTIME_ID => Some(Duration::from_nanos(time::task_thread_cpu_ns())),
        // A dynamic per-task CPU-clock id (negative) → current thread/process CPU time.
        _ => match dynamic_cpu_clock(clock_id)? {
            DynamicCpuClock::PerThread => Some(Duration::from_nanos(time::task_thread_cpu_ns())),
            DynamicCpuClock::PerProcess => Some(Duration::from_nanos(time::task_process_cpu_ns())),
        },
    }
}

pub(super) fn linux_clock_nanosleep_now(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Result<Duration, LinuxErrno> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP);
    }
    linux_clock_duration(clock, clock_id).ok_or(LINUX_EINVAL)
}

/// Linux clock_getres resolution in nanoseconds, selected per clock id.
///
/// The exact value is NOT a host-portable invariant: a CONFIG_HIGH_RES_TIMERS
/// kernel reports 1ns for the hrtimer-backed clocks, but a low-res kernel —
/// e.g. Docker Desktop's LinuxKit VM at CONFIG_HZ=1000 — reports TICK_NSEC =
/// 1ms for ALL of them (verified live: clock_getres on REALTIME/MONOTONIC/
/// MONOTONIC_RAW/BOOTTIME returns tv_nsec==1000000 under `gcc:13` linux/arm64).
/// carrick therefore reports the 1ms stand-in (LINUX_CLOCK_RESOLUTION_NSEC),
/// which matches the Docker oracle on these hosts. The clockgetres probe
/// asserts only the portable invariant (rc==0, tv_sec==0). The per-clock match
/// is retained so a future CONFIG_HZ/hrtimer-aware value can be wired in here
/// without re-plumbing the call site. Only clocks `linux_clock_duration`
/// returns Some for reach this (clock_getres rejects unknown ids with EINVAL
/// before the write).
pub(super) fn linux_clock_getres_nsec(clock_id: u64) -> i64 {
    match clock_id {
        // hrtimer-backed hi-res clocks (1ns on a CONFIG_HIGH_RES_TIMERS
        // kernel) and the posix CPU clocks. The 1ms stand-in is what the
        // low-res Docker host kernels actually report; the value is not
        // probe-asserted, so this stays host-portable.
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_BOOTTIME
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_BOOTTIME_ALARM
        | LINUX_CLOCK_TAI
        | LINUX_CLOCK_PROCESS_CPUTIME_ID
        | LINUX_CLOCK_THREAD_CPUTIME_ID => LINUX_CLOCK_RESOLUTION_NSEC,
        // COARSE clocks report TICK_NSEC (CONFIG_HZ-dependent, NOT
        // host-portable). Same 1ms stand-in; not probe-asserted.
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE => LINUX_CLOCK_RESOLUTION_NSEC,
        _ => LINUX_CLOCK_RESOLUTION_NSEC,
    }
}

pub(super) fn linux_clock_is_known(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
            | LINUX_CLOCK_TAI
    )
}

/// Clocks a `timerfd` can be armed on.
///
/// Strictly smaller than [`linux_clock_is_known`]: the CPU-time clocks and the
/// coarse/raw variants are readable through `clock_gettime` but cannot back a
/// timer. carrick admitted anything it could read, so
/// `timerfd_create(CLOCK_PROCESS_CPUTIME_ID)` returned a working fd where
/// Linux answers EINVAL (`eventwaitmatrix` `timerfd_create_cputime_einval`).
pub(super) fn linux_timerfd_clock_is_supported(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
    )
}

pub(super) fn linux_clock_is_settable(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM | LINUX_CLOCK_TAI
    )
}

pub(super) fn linux_itimer_which_is_valid(which: u64) -> bool {
    matches!(
        which,
        LINUX_ITIMER_REAL | LINUX_ITIMER_VIRTUAL | LINUX_ITIMER_PROF
    )
}

pub(super) fn linux_timeval_usec_is_valid(tv: LinuxTimeval) -> bool {
    let usec = tv.tv_usec;
    (0..1_000_000).contains(&usec)
}

pub(super) fn linux_time_state_from_status(status: LinuxTimexStatus) -> i64 {
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

pub(super) fn linux_timex_from_state(
    time: LinuxTimeval,
    state: &crate::kernel::container::AdjtimexState,
) -> LinuxTimex {
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

pub(super) fn linux_timex_time(duration: Duration, status: LinuxTimexStatus) -> LinuxTimeval {
    let sub = if status.contains(LinuxTimexStatus::NANO) {
        i64::from(duration.subsec_nanos())
    } else {
        i64::from(duration.subsec_micros())
    };
    LinuxTimeval::new(duration.as_secs() as i64, sub)
}

pub(super) fn adjtimex_bootstrap(
    clock: &crate::kernel::container::ClockDomain,
    memory: &mut impl CurrentMmMemory,
    address: u64,
    can_adjust: bool,
) -> DispatchOutcome {
    let timex = match read_kernel_struct::<LinuxTimex>(memory, address) {
        Ok(timex) => timex,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };
    let modes = LinuxTimexModes::from_bits_retain(timex.modes);
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
        && !modes.contains(LinuxTimexModes::OFFSET)
    {
        let invalid = LinuxTimex::invalid_mode_error_state();
        return match write_kernel_struct(memory, address, &invalid) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
            other => other,
        };
    }
    if timex.modes == 0 {
        let state = clock.adjtimex_state();
        let status = LinuxTimexStatus::from_bits_retain(state.status);
        let now = clock.realtime_now();
        let time = linux_timex_time(now, status);
        let current = linux_timex_from_state(time, &state);
        let value = linux_time_state_from_status(status);
        return match write_kernel_struct(memory, address, &current) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
            other => other,
        };
    }
    if modes == LinuxTimexModes::OFFSET_SS_READ {
        let state = clock.adjtimex_state();
        let status = LinuxTimexStatus::from_bits_retain(state.status);
        let now = clock.realtime_now();
        let time = linux_timex_time(now, status);
        let mut current = linux_timex_from_state(time, &state);
        current.modes = timex.modes;
        current.offset = 0;
        let value = linux_time_state_from_status(status);
        return match write_kernel_struct(memory, address, &current) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
            other => other,
        };
    }
    if !can_adjust {
        return DispatchOutcome::Errno { errno: LINUX_EPERM };
    }

    const KNOWN_MODES: u32 = LinuxTimexModes::IDEMPOTENT_SUPPORTED.bits()
        | LinuxTimexModes::OFFSET_SINGLESHOT_FLAG.bits();
    if (timex.modes & !KNOWN_MODES) != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    // ADJ_MICRO|ADJ_NANO together and ADJ_TAI|ADJ_TIMECONST together are
    // ACCEPTED by Linux (native arm64 oracle, probe `adjtimexmodel`
    // `micro_nano_together_accepted` / `tai_timeconst_together_accepted`);
    // the later of the two stores simply wins.
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
        && modes != LinuxTimexModes::OFFSET_SINGLESHOT
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    if modes.contains(LinuxTimexModes::TICK) {
        let minimum = 900_000 / LINUX_CLK_TCK;
        let maximum = 1_100_000 / LINUX_CLK_TCK;
        let requested_tick = timex.tick;
        if !(minimum..=maximum).contains(&requested_tick) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
    }
    // An out-of-range `freq` is CLAMPED to +/-MAXFREQ, not refused: the
    // native arm64 oracle accepts 35_000_000 (probe `adjtimexmodel`,
    // `oversized_freq_accepted`). The clamp happens where the value is stored.
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG) {
        let requested_offset = timex.offset;
        if !(-131_071..=131_071).contains(&requested_offset) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
    }
    // Unknown `status` bits are ignored, not refused: the oracle accepts
    // `1 << 20` (`unknown_status_bits_accepted`). Only the defined, writable
    // bits are stored where the value lands.

    let mut step_realtime_ns: Option<i64> = None;
    if modes.contains(LinuxTimexModes::SETOFFSET) {
        let is_nano = if modes.contains(LinuxTimexModes::NANO) {
            true
        } else if modes.contains(LinuxTimexModes::MICRO) {
            false
        } else {
            LinuxTimexStatus::from_bits_retain(clock.adjtimex_state().status)
                .contains(LinuxTimexStatus::NANO)
        };
        let max_sub = if is_nano { 1_000_000_000 } else { 1_000_000 };
        if timex.time.tv_usec < 0 || timex.time.tv_usec >= max_sub {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let sec_ns = match timex.time.tv_sec.checked_mul(1_000_000_000) {
            Some(s) => s,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        let sub_ns = if is_nano {
            timex.time.tv_usec
        } else {
            timex.time.tv_usec.saturating_mul(1_000)
        };
        let delta_ns = match sec_ns.checked_add(sub_ns) {
            Some(d) => d,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        step_realtime_ns = Some(delta_ns);
    } else if modes == LinuxTimexModes::OFFSET_SINGLESHOT {
        let delta_ns = match timex.offset.checked_mul(1_000) {
            Some(ns) => ns,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        step_realtime_ns = Some(delta_ns);
    }

    if let Some(delta_ns) = step_realtime_ns {
        if let Err(errno) = clock.try_step_realtime_offset_ns(delta_ns) {
            return DispatchOutcome::Errno { errno };
        }
    }

    let updated_state = clock.with_adjtimex_mut(|state| {
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
        state.clone()
    });

    let status = LinuxTimexStatus::from_bits_retain(updated_state.status);
    let now = clock.realtime_now();
    let time = linux_timex_time(now, status);
    let mut current = linux_timex_from_state(time, &updated_state);
    current.modes = timex.modes;
    let value = linux_time_state_from_status(status);
    match write_kernel_struct(memory, address, &current) {
        DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
        other => other,
    }
}

/// Read a host (macOS) POSIX clock via `libc::clock_gettime`. `clock_id`
/// MUST be a host symbolic `libc::CLOCK_*` constant (Linux numbering
/// differs and is mapped by callers). Returns `None` only on failure.
pub(crate) fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, properly-aligned timespec we own.
    let rc = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

pub(crate) fn monotonic_duration() -> Duration {
    // On a Linux host the guest's CLOCK_MONOTONIC IS the host's — read the host
    // CLOCK_MONOTONIC (NOT CLOCK_MONOTONIC_RAW). RAW is the un-virtualized
    // hardware clock; inside a time-namespace (LXC/containers) it is NOT offset
    // by the namespace's boottime delta while CLOCK_MONOTONIC and CLOCK_BOOTTIME
    // ARE, so a RAW monotonic can exceed the virtualized BOOTTIME and break the
    // BOOTTIME >= MONOTONIC invariant. Keeping both on the virtualized family
    // makes the invariant hold; it also matches what the guest asked for.
    #[cfg(target_os = "linux")]
    {
        return host_clock_duration(libc::CLOCK_MONOTONIC).unwrap_or(Duration::ZERO);
    }
    // Linux CLOCK_MONOTONIC does NOT advance while the system is suspended.
    // On macOS that is CLOCK_UPTIME_RAW (mach_absolute_time) — NOT macOS
    // CLOCK_MONOTONIC, which (unlike Linux) keeps counting through sleep and
    // therefore corresponds to Linux CLOCK_BOOTTIME (see `boottime_duration`).
    #[cfg(not(target_os = "linux"))]
    {
        host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW).unwrap_or(Duration::ZERO)
    }
}

/// The guest's `CLOCK_BOOTTIME`. Also THE authority for `/proc/uptime` field 1
/// and `/proc/stat`'s `btime`, which Linux derives from this same clock — see
/// `crate::vfs::proc`.
pub(crate) fn boottime_duration() -> Duration {
    // On a Linux host the guest's CLOCK_BOOTTIME IS the host's — read it natively
    // so it shares the same (time-namespace-virtualized) epoch family as
    // monotonic_duration above; BOOTTIME = MONOTONIC + suspend, so the
    // BOOTTIME >= MONOTONIC invariant holds.
    #[cfg(target_os = "linux")]
    {
        return host_clock_duration(libc::CLOCK_BOOTTIME).unwrap_or_else(monotonic_duration);
    }
    // On macOS/HVF the guest's BOOTTIME must MATCH its own vDSO fast path, which
    // serves CLOCK_BOOTTIME (clock id 7) as the bare guest CNTVCT/freq — i.e.
    // suspend-EXCLUDING, identical to MONOTONIC (vdso_fns.s clock-7 path). HVF
    // gives the guest a virtual counter aligned to CLOCK_UPTIME_RAW that does NOT
    // advance through host sleep (trap.rs documents the guest CNTVCT tracks
    // CLOCK_UPTIME_RAW while the raw hardware MRS runs hours ahead after suspend),
    // so the guest's timeline never "suspends" in its own frame. Reading
    // mach_continuous_time (macOS CLOCK_MONOTONIC, suspend-INCLUDING) here made
    // the trapping syscall disagree with the vDSO by the host's accumulated sleep
    // (seconds) — LTP clock_gettime04 reads BOTH paths and sees time travel
    // backwards. Use the SAME suspend-excluding base as monotonic_duration so the
    // two paths agree and BOOTTIME >= MONOTONIC holds (as equality). The Linux
    // branch keeps native CLOCK_BOOTTIME (true suspend-inclusive, time-ns aware).
    #[cfg(not(target_os = "linux"))]
    {
        host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW).unwrap_or_else(monotonic_duration)
    }
}

pub(super) fn linux_timespec_from_duration(duration: Duration) -> LinuxTimespec {
    LinuxTimespec::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_nanos()),
    )
}

pub(crate) fn complete_interrupted_sleep(
    memory: &mut impl CurrentMmMemory,
    remaining: Option<GuestPtr>,
    duration: Duration,
) -> DispatchOutcome {
    if let Some(address) = remaining {
        let rem = linux_timespec_from_duration(duration);
        match write_kernel_struct(memory, address.0, &rem) {
            DispatchOutcome::Returned { value: 0 } => {}
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        }
    }
    DispatchOutcome::Errno { errno: LINUX_EINTR }
}

pub(super) fn linux_timeval_from_duration(duration: Duration) -> LinuxTimeval {
    LinuxTimeval::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_micros()),
    )
}

pub(super) fn read_timerfd(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    length: usize,
    state: &TimerFdState,
    nonblocking: bool,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxTimerfdExpirations>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let mut timer = state.inner.lock();
    loop {
        let ready = refresh_timerfd_locked(&state.clock, &mut timer);
        if ready > 0 {
            let value = LinuxTimerfdExpirations {
                expirations: timer.expirations,
            };
            if write_kernel_struct_raw(memory, address, &value).is_err() {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
            timer.expirations = 0;
            return DispatchOutcome::returned_len_or_errno(core::mem::size_of::<
                LinuxTimerfdExpirations,
            >());
        }

        if nonblocking {
            return DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            };
        }

        let Some(deadline) = timer.deadline else {
            state.changed.wait(&mut timer);
            continue;
        };
        let Some(now) = linux_clock_duration(&state.clock, timer.clock_id) else {
            state.changed.wait(&mut timer);
            continue;
        };
        let wait = deadline.saturating_sub(now);
        if wait.is_zero() {
            continue;
        }
        state.changed.wait_for(&mut timer, wait);
    }
}

pub(super) fn refresh_timerfd_locked(
    clock: &crate::kernel::container::ClockDomain,
    timer: &mut TimerFdInner,
) -> u64 {
    let (ready, next_deadline) = timerfd_expirations(
        clock,
        timer.clock_id,
        timer.interval,
        timer.deadline,
        timer.expirations,
    );
    timer.expirations = ready;
    timer.deadline = next_deadline;
    ready
}

pub(super) fn timerfd_ready_count(state: &TimerFdState) -> u64 {
    let mut timer = state.inner.lock();
    refresh_timerfd_locked(&state.clock, &mut timer)
}

pub(super) fn timerfd_itimerspec(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
) -> LinuxItimerspec {
    let now = linux_clock_duration(clock, clock_id).unwrap_or(Duration::ZERO);
    let remaining = deadline.map(|deadline| deadline.saturating_sub(now));
    LinuxItimerspec::new(
        linux_timespec_from_optional_duration(interval),
        linux_timespec_from_optional_duration(remaining),
    )
}

pub(super) fn timerfd_expirations(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = linux_clock_duration(clock, clock_id) else {
        return (expirations, Some(deadline));
    };
    if now < deadline {
        return (expirations, Some(deadline));
    }
    let Some(interval) = interval else {
        return (expirations.saturating_add(1), None);
    };
    if interval.is_zero() {
        return (expirations.saturating_add(1), None);
    }

    let now_nanos = duration_to_nanos(now);
    let deadline_nanos = duration_to_nanos(deadline);
    let interval_nanos = duration_to_nanos(interval);
    let elapsed_periods = ((now_nanos - deadline_nanos) / interval_nanos).saturating_add(1);
    let count = u64::try_from(elapsed_periods).unwrap_or(u64::MAX);
    let next_deadline_nanos =
        deadline_nanos.saturating_add(interval_nanos.saturating_mul(elapsed_periods));
    (
        expirations.saturating_add(count),
        Some(duration_from_nanos_saturating(next_deadline_nanos)),
    )
}

pub(super) fn itimerspec_durations(
    spec: LinuxItimerspec,
) -> Result<(Option<Duration>, Option<Duration>), LinuxErrno> {
    let interval = spec.it_interval;
    let value = spec.it_value;
    Ok((
        duration_from_linux_timespec(interval)?,
        duration_from_linux_timespec(value)?,
    ))
}

pub(super) fn duration_from_linux_timespec(
    timespec: LinuxTimespec,
) -> Result<Option<Duration>, LinuxErrno> {
    let seconds = timespec.tv_sec;
    let nanoseconds = timespec.tv_nsec;
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(LINUX_EINVAL);
    }
    if seconds == 0 && nanoseconds == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::new(seconds as u64, nanoseconds as u32)))
}

pub(super) fn linux_timespec_from_optional_duration(duration: Option<Duration>) -> LinuxTimespec {
    duration.map_or(LinuxTimespec::new(0, 0), linux_timespec_from_duration)
}

pub(super) fn duration_to_nanos(duration: Duration) -> u128 {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    u128::from(duration.as_secs()) * NANOS_PER_SEC + u128::from(duration.subsec_nanos())
}

pub(super) fn duration_from_nanos_saturating(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let seconds = nanos / NANOS_PER_SEC;
    if seconds > u128::from(u64::MAX) {
        return Duration::new(u64::MAX, 999_999_999);
    }
    Duration::new(seconds as u64, (nanos % NANOS_PER_SEC) as u32)
}

pub(super) fn read_itimerspec(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxItimerspec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

pub(super) fn read_itimerval(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxItimerval, LinuxErrno> {
    read_kernel_struct(memory, address)
}

pub(super) fn read_timespec(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxTimespec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

/// A `struct timespec` used as a syscall TIMEOUT: non-negative seconds and
/// `tv_nsec` in `[0, 1e9)`. Linux answers EINVAL otherwise, before it waits.
///
/// `ppoll` accepted both a negative `tv_nsec` and one at or past a full second
/// and silently folded them into a millisecond count, so a request Linux
/// rejects outright became a long sleep (`eventwaitmatrix`
/// `ppoll_negative_nsec_einval` / `ppoll_overflow_nsec_einval`).
pub(crate) fn linux_timeout_timespec_is_valid(timespec: LinuxTimespec) -> bool {
    // Copied out: `LinuxTimespec` is packed, so a reference to a field would
    // be unaligned.
    let (tv_sec, tv_nsec) = (timespec.tv_sec, timespec.tv_nsec);
    tv_sec >= 0 && (0..1_000_000_000).contains(&tv_nsec)
}

pub(super) fn linux_utimensat_timespec_is_valid(timespec: LinuxTimespec) -> bool {
    let nsec = timespec.tv_nsec;
    if nsec == LINUX_UTIME_NOW || nsec == LINUX_UTIME_OMIT {
        return true;
    }
    (0..1_000_000_000).contains(&nsec)
}

/// Resolve a validated utimensat timespec into the (sec, nsec) the backend
/// should write, or `None` to leave the time untouched (UTIME_OMIT).
/// UTIME_NOW resolves to the current wall-clock time.
pub(super) fn resolve_utimensat_timespec(
    clock: &crate::kernel::container::ClockDomain,
    timespec: LinuxTimespec,
) -> Option<(i64, i64)> {
    // Copy out of the packed struct before matching (taking a reference to
    // a packed field is UB).
    let nsec = timespec.tv_nsec;
    let sec = timespec.tv_sec;
    if nsec == LINUX_UTIME_OMIT {
        None
    } else if nsec == LINUX_UTIME_NOW {
        Some(now_realtime_timespec(clock))
    } else {
        Some((sec, nsec))
    }
}

/// The guest's current CLOCK_REALTIME as a (sec, nsec) pair, for UTIME_NOW /
/// NULL times.
pub(super) fn now_realtime_timespec(clock: &crate::kernel::container::ClockDomain) -> (i64, i64) {
    let now = clock.realtime_now();
    (now.as_secs() as i64, i64::from(now.subsec_nanos()))
}
