//! Clocks, sleeps, interval timers, and POSIX per-process timers.
//!
//! # Theory of operation
//!
//! Time is one place where Linux and macOS genuinely differ at the ABI level,
//! so this file is a translation layer over the host clocks rather than a
//! reimplementation. The pivot is `linux_clock_duration` (in [`super`]): it maps
//! a Linux `clock_id` to a host clock and returns a `Duration`; handlers either
//! use it directly or add syscall-specific capability checks around it. Three
//! things make that non-trivial:
//!
//!   - **The clock-id numbers differ.** Linux and macOS do NOT agree on the
//!     numeric `CLOCK_*` constants, so the Linux ids are matched explicitly and
//!     mapped to the host's symbolic `libc::CLOCK_*` — never passed through. An
//!     unrecognised id is EINVAL, exactly when `linux_clock_duration` returns
//!     `None`, which is why every handler checks it first.
//!   - **Some Linux clocks have no host analogue.** CLOCK_BOOTTIME (which
//!     includes suspend) is approximated by CLOCK_MONOTONIC; the REALTIME
//!     variants (COARSE/ALARM/TAI) collapse onto realtime; the per-task
//!     CPU-time clocks (the negative dynamic ids) map to the host
//!     thread/process CPU clocks best-effort.
//!   - **Resolution is not portable.** `clock_getres` reports a chosen
//!     stand-in (carrick does not coarsen waits), documented at the call site.
//!
//! ## Two timer families
//!
//! Interval timers (`getitimer`/`setitimer`, and glibc's `alarm()` which is
//! `setitimer(ITIMER_REAL, …)`) keep their state in the proc subsystem's
//! `ProcState::itimers`; the POSIX per-process timers
//! (`timer_create`/`timer_settime`/…) live in
//! `crate::posix_timer`. Both share one delivery mechanism the dispatcher
//! cannot perform itself: the expiry SIGNAL is raised by an `EVFILT_TIMER`
//! event on the signal pump's kqueue (see `crate::itimer`), because firing a
//! signal requires reaching the vCPU, which the syscall handler cannot. The
//! handlers here therefore only ARM/DISARM and report time-remaining; the
//! actual SIGALRM/SIGVTALRM/SIGPROF/`sigev_signo` delivery is the runtime's.
//! `timerfd_create`/`timerfd_settime` are the fd-based variant — a readable
//! `TimerFd` instead of a signal — and integrate with the epoll/poll readiness
//! model (see [`super::net`]).
//!
//! `gettimeofday`/`settimeofday`/`times`/`adjtimex` round out the file. A guest
//! is not allowed to reset the host wall clock: `settimeofday` returns EPERM
//! and `adjtimex`/`clock_adjtime` report timex state without changing it.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table.
use carrick_timer_core::TimerSpecNs;

use super::*;

syscall_table! {
    /// Per-module syscall routing for the `time` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `time` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_time;
    85 => timerfd_create,
    86 => timerfd_settime,
    87 => timerfd_gettime,
    101 => nanosleep,
    102 => getitimer,
    103 => setitimer,
    107 => timer_create,
    108 => timer_gettime,
    109 => timer_getoverrun,
    110 => timer_settime,
    111 => timer_delete,
    112 => clock_settime,
    113 => clock_gettime,
    114 => clock_getres,
    115 => clock_nanosleep,
    carrick_abi::CARRICK_PRIVATE_X86_ALARM => x86_alarm,
    153 => times,
    163 => getrlimit,
    165 => getrusage,
    169 => gettimeofday,
    170 => settimeofday,
    171 => adjtimex,
    179 => sysinfo,
    261 => prlimit64,
    266 => clock_adjtime,
}

/// Pack a timer's `(value, interval)` ns pair into a `LinuxItimerspec` (the
/// Linux kernel ABI `struct __kernel_itimerspec`). Used by `timer_settime`'s
/// `old_value` and `timer_gettime`'s `cur_value` writes.
fn build_itimerspec_ns(spec: TimerSpecNs) -> LinuxItimerspec {
    let split = |ns: u64| LinuxTimespec {
        tv_sec: i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(ns % 1_000_000_000).unwrap_or(0),
    };
    // WIRE order: `LinuxItimerspec::new(it_interval, it_value)` — interval
    // FIRST, matching the struct's field order. Taking the typed pair means no
    // caller ever has to re-perform (and possibly re-swap) that transposition.
    LinuxItimerspec::new(split(spec.interval), split(spec.value))
}

impl SyscallDispatcher {
    pub(crate) fn effective_resource_limit(&self, resource: u64) -> LinuxRlimit {
        let nofile_soft = self
            .io
            .nofile_soft
            .load(std::sync::atomic::Ordering::Relaxed);
        effective_rlimit(resource, nofile_soft, &self.proc.lock().rlimit_overrides)
    }

    define_syscall! {
        fn timerfd_create(this, cx, clock_id: u64, flags: u64) {
            if linux_clock_duration(clock_id).is_none()
                || flags & !(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC) != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let description = OpenDescription::TimerFd {
                state: Arc::new(TimerFdState::new(clock_id)),
                base: OpenDescriptionBase::new(flags & LINUX_TFD_NONBLOCK),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
        }

        fn timerfd_settime(this, cx, fd: Fd, flags: u64, new_value: u64, old_value: u64) {
            let memory = &mut *cx.memory;
            if flags & !LINUX_TIMER_ABSTIME != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let spec = read_itimerspec(memory, new_value)?;
            let (next_interval, next_value) = itimerspec_durations(spec)?;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            let OpenDescription::TimerFd { state, .. } = &*open else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let state = Arc::clone(state);
            drop(open);
            let mut timer = state.inner.lock();

            if old_value != 0 {
                let previous = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
                if write_kernel_struct_raw(memory, old_value, &previous).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }

            let now = linux_clock_duration(timer.clock_id).unwrap_or(Duration::ZERO);
            timer.interval = next_interval;
            timer.deadline = next_value.map(|value| {
                if flags & LINUX_TIMER_ABSTIME != 0 {
                    value
                } else {
                    now.saturating_add(value)
                }
            });
            timer.expirations = 0;
            state.changed.notify_all();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn timerfd_gettime(this, cx, fd: Fd, current_value: u64) {
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let open = open_file.description.read();
            let OpenDescription::TimerFd { state, .. } = &*open else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let mut timer = state.inner.lock();
            refresh_timerfd_locked(&mut timer);
            let current = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
            Ok(write_kernel_struct(memory, current_value, &current))
        }

        fn nanosleep(this, cx, request_address: GuestPtr, rem_ptr: GuestPtr) {
            let memory = &*cx.memory;
            let timespec = read_timespec(memory, request_address.0)?;
            let duration = duration_from_linux_timespec(timespec)?;
            // Hand the sleep to the run loop (DispatchOutcome::WaitOnSleep) so it
            // waits via the per-thread waiter instead of a blocking host
            // nanosleep inside the dispatcher: a synchronous host sleep never
            // reaches the run-loop top, so a sleeping sibling would deadlock a
            // multithreaded fork-quiesce. The run loop owns EINTR completion, so
            // carry the optional `rem` pointer there for remaining-time copyout.
            let remaining = (rem_ptr.0 != 0).then_some(rem_ptr);
            match duration {
                Some(duration) => Ok(DispatchOutcome::WaitOnSleep {
                    duration,
                    remaining,
                }),
                None => Ok(DispatchOutcome::Returned { value: 0 }),
            }
        }

        fn clock_nanosleep(this, cx, clock_id: u64, flags: u64, request_address: GuestPtr, rem_ptr: GuestPtr) {
            let memory = &*cx.memory;
            if flags & !LINUX_TIMER_ABSTIME != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let now = match linux_clock_nanosleep_now(clock_id) {
                Ok(now) => now,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let timespec = read_timespec(memory, request_address.0)?;
            let requested = match duration_from_linux_timespec(timespec) {
                Ok(duration) => duration.unwrap_or(Duration::ZERO),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let sleep_duration = if flags & LINUX_TIMER_ABSTIME != 0 {
                requested.saturating_sub(now)
            } else {
                requested
            };
            // See nanosleep: the run loop performs the timed wait (WaitOnSleep)
            // so it is fork-quiesce-parkable. ABSTIME is pre-converted to the
            // relative `sleep_duration` here; on a quiesce re-dispatch the run
            // loop keeps the original deadline, so it stays absolute-correct.
            let remaining = (flags & LINUX_TIMER_ABSTIME == 0 && rem_ptr.0 != 0).then_some(rem_ptr);
            if sleep_duration.is_zero() {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(DispatchOutcome::WaitOnSleep {
                duration: sleep_duration,
                remaining,
            })
        }

        fn clock_gettime(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &mut *cx.memory;
            let Some(duration) = linux_clock_duration(clock_id) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let timespec = linux_timespec_from_duration(duration);
            Ok(write_kernel_struct(memory, address.0, &timespec))
        }

        fn clock_getres(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &mut *cx.memory;
            if linux_clock_duration(clock_id).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if address.0 == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(write_packed(
                memory,
                address.0,
                // Resolution is host-kernel-dependent and NOT a host-portable
                // invariant: a CONFIG_HIGH_RES_TIMERS kernel reports 1ns, but a
                // low-res kernel (e.g. Docker Desktop's LinuxKit VM at
                // CONFIG_HZ=1000) reports TICK_NSEC = 1ms. carrick reports the
                // 1ms stand-in (LINUX_CLOCK_RESOLUTION_NSEC), which is what the
                // Docker oracle on these hosts actually returns; the clockgetres
                // probe asserts only rc==0 + tv_sec==0 (sub-second resolution).
                LinuxTimespec::new(0, linux_clock_getres_nsec(clock_id)).as_bytes(),
            ))
        }

        fn clock_settime(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &*cx.memory;
            if !linux_clock_is_known(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let timespec = read_timespec(memory, address.0)?;
            let tv_nsec = timespec.tv_nsec;
            if !(0..1_000_000_000).contains(&tv_nsec) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !linux_clock_is_settable(clock_id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }

        fn getitimer(this, cx, which: u64, address: GuestPtr) {
            let memory = &mut *cx.memory;
            if !linux_itimer_which_is_valid(which) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if address.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let current = itimerval_from_state(this.proc.lock().itimers[which as usize]);
            Ok(write_kernel_struct(memory, address.0, &current))
        }

        fn setitimer(this, cx, which: u64, new_address: GuestPtr, old_address: GuestPtr) {
            let memory = &mut *cx.memory;
            if !linux_itimer_which_is_valid(which) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let new_value = if new_address.0 != 0 {
                let v = read_itimerval(memory, new_address.0)?;
                if !linux_timeval_usec_is_valid(v.it_interval)
                    || !linux_timeval_usec_is_valid(v.it_value)
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                Some(v)
            } else {
                None
            };

            let idx = which as usize;
            if old_address.0 != 0 {
                let prev = itimerval_from_state(this.proc.lock().itimers[idx]);
                let outcome = write_kernel_struct(memory, old_address.0, &prev);
                if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                    return Ok(outcome);
                }
            }
            if let Some(v) = new_value {
                let value = duration_from_timeval(v.it_value);
                let interval = duration_from_timeval(v.it_interval);
                this.proc.lock().itimers[idx] = if value.is_zero() {
                    None
                } else {
                    Some(crate::dispatch::proc::ItimerState {
                        set_at: std::time::Instant::now(),
                        value,
                        interval,
                    })
                };

                if value.is_zero() {
                    // Disarm: clear the slot + tear down backend delivery (HVF
                    // deletes the EVFILT_TIMER; KVM just clears the slot). No
                    // registered backend (a backing-loop-less unit test) → just
                    // clear the neutral slot.
                    match crate::timer_delivery::delivery() {
                        Some(d) => d.disarm_itimer(idx),
                        None => crate::itimer::disarm(idx),
                    }
                } else {
                    let spec_ns = TimerSpecNs::from_durations(value, interval);
                    let needs_periodic = !interval.is_zero() && value != interval;
                    // Write the neutral slot state FIRST (timer-core), then ask
                    // the backend to initiate delivery.
                    let generation = crate::itimer::arm(idx, spec_ns, needs_periodic);

                    let signum = crate::itimer::signum_for(idx);
                    let signal_name = match signum {
                        crate::linux_abi::LINUX_SIGVTALRM => "SIGVTALRM",
                        crate::linux_abi::LINUX_SIGPROF => "SIGPROF",
                        _ => "SIGALRM",
                    };
                    cx.reporter
                        .record(crate::compat::CompatEvent::partial_syscall(
                            103,
                            "setitimer",
                            cx.raw_args(),
                            format!(
                                "setitimer delivery is emulated with an EVFILT_TIMER on the signal pump kqueue and {signal_name}"
                            ),
                        ));
                    // `arm_itimer` returns true if the backend owns delivery
                    // (HVF armed an EVFILT_TIMER on the pump kq); false → spawn
                    // the shared wall-clock fallback thread (KVM, or an HVF
                    // process with no pump kqueue yet). No registered backend (a
                    // backing-loop-less unit test) also falls back.
                    let owned = crate::timer_delivery::delivery()
                        .is_some_and(|d| d.arm_itimer(idx, spec_ns, needs_periodic, signum));
                    if !owned {
                        crate::itimer::spawn_fallback_timer(idx, generation, spec_ns);
                    }
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// x86_64 `alarm(seconds)`: legacy syscall with no asm-generic
        /// canonical number. It is equivalent to arming/disarming
        /// `ITIMER_REAL` with zero interval and returns the previous timer's
        /// remaining seconds.
        fn x86_alarm(this, cx, seconds: u64) {
            let idx = LINUX_ITIMER_REAL as usize;
            let previous = x86_alarm_remaining_seconds(this.proc.lock().itimers[idx]);
            if seconds == 0 {
                this.proc.lock().itimers[idx] = None;
                match crate::timer_delivery::delivery() {
                    Some(d) => d.disarm_itimer(idx),
                    None => crate::itimer::disarm(idx),
                }
                return Ok(DispatchOutcome::Returned {
                    value: previous.min(i64::MAX as u64) as i64,
                });
            }

            let value = Duration::from_secs(seconds);
            let interval = Duration::ZERO;
            this.proc.lock().itimers[idx] = Some(crate::dispatch::proc::ItimerState {
                set_at: std::time::Instant::now(),
                value,
                interval,
            });

            let spec_ns = TimerSpecNs::from_durations(value, interval);
            let generation = crate::itimer::arm(idx, spec_ns, false);
            let signum = crate::itimer::signum_for(idx);
            let owned = crate::timer_delivery::delivery()
                .is_some_and(|d| d.arm_itimer(idx, spec_ns, false, signum));
            if !owned {
                crate::itimer::spawn_fallback_timer(idx, generation, spec_ns);
            }

            Ok(DispatchOutcome::Returned {
                value: previous.min(i64::MAX as u64) as i64,
            })
        }

        /// `timer_create(clock_id, sevp, &id)`: allocate a per-process timer.
        /// `sevp == NULL` means "default: deliver SIGALRM via SIGEV_SIGNAL".
        /// Only SIGEV_SIGNAL (and NULL default) are implemented; SIGEV_THREAD
        /// would require synthesising a guest thread we can't create from the
        /// host. Linux sigevent layout: si_value (8) | sigev_signo (4) |
        /// sigev_notify (4) | _sigev_un (48) = 64 bytes total.
        fn timer_create(this, cx, clock_id: u64, sevp: GuestPtr, id_out: GuestPtr) {
            let memory = &mut *cx.memory;
            // Validate the clock — we only support the same set as clock_gettime.
            if linux_clock_duration(clock_id).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if id_out.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let mut signum = crate::linux_abi::LINUX_SIGALRM;
            if sevp.0 != 0 {
                let bytes = memory.read_bytes(sevp.0, 16)?;
                let signo = i32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
                let notify = i32::from_le_bytes(bytes[12..16].try_into().unwrap_or([0; 4]));
                const LINUX_SIGEV_SIGNAL: i32 = 0;
                const LINUX_SIGEV_NONE: i32 = 1;
                const LINUX_SIGEV_THREAD: i32 = 2;
                const LINUX_SIGEV_THREAD_ID: i32 = 4;
                if notify == LINUX_SIGEV_NONE {
                    // Accept but never fires a signal; we just track for
                    // settime/gettime/delete bookkeeping.
                    signum = 0;
                } else if notify == LINUX_SIGEV_SIGNAL
                    || notify == LINUX_SIGEV_THREAD_ID
                {
                    // SIGEV_THREAD_ID is the kernel's "deliver to a specific
                    // tid via _sigev_un.tid" variant — glibc compiles
                    // SIGEV_THREAD down to SIGEV_THREAD_ID + an internal helper
                    // thread. Carrick does not yet have per-guest-thread CPU
                    // timer accounting; accepting CLOCK_THREAD_CPUTIME_ID here
                    // would turn Go's per-M profiler timers into wall-clock
                    // process SIGPROF streams. Report unsupported so runtimes
                    // use their process-timer fallback instead.
                    if notify == LINUX_SIGEV_THREAD_ID
                        && clock_id == LINUX_CLOCK_THREAD_CPUTIME_ID
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if !(1..=64).contains(&signo) {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    signum = signo;
                } else if notify == LINUX_SIGEV_THREAD {
                    // SIGEV_THREAD: never seen by the kernel on real Linux
                    // (glibc swaps it for SIGEV_THREAD_ID). A raw syscall
                    // passing it gets EINVAL.
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                } else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            let timer_id = crate::posix_timer::create(clock_id as i32, signum);
            // Linux uses an opaque pointer-sized `timer_t`; we hand back the
            // small integer id widened to 64 bits.
            let id_bytes = (timer_id as i64 as u64).to_le_bytes();
            if memory.write_bytes(id_out.0, &id_bytes).is_err() {
                let _ = crate::posix_timer::delete(timer_id);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `timer_settime(id, flags, new, old)`: arm / disarm the timer.
        /// `flags` of 0 = relative `it_value`; TIMER_ABSTIME = an absolute
        /// deadline on the timer's clock, converted to a relative interval here.
        /// `old` (NULL allowed) receives the previous spec.
        fn timer_settime(this, cx, timer_id: u64, flags: u64, new_ptr: GuestPtr, old_ptr: GuestPtr) {
            let memory = &mut *cx.memory;
            let id = timer_id as i64 as i32;
            if !crate::posix_timer::exists(id) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Only TIMER_ABSTIME is a valid flag; reject any other bit. (audit M4)
            if flags & !LINUX_TIMER_ABSTIME != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if new_ptr.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let spec = read_itimerspec(memory, new_ptr.0)?;
            // Validate the timespec (EINVAL on tv_nsec>=1e9 or negative) via the
            // shared helper, exactly like timerfd_settime. (audit M4)
            let (interval_dur, value_dur) = itimerspec_durations(spec)?;
            let interval_ns =
                interval_dur.map_or(0, |d| u64::try_from(duration_to_nanos(d)).unwrap_or(u64::MAX));
            // Not `TimerSpecNs::from_durations`: the value leg has its own
            // shape (None disarms; a TIMER_ABSTIME deadline becomes a relative
            // interval floored at 1ns), so it can't share the plain
            // Duration-pair saturation.
            let value_ns = match value_dur {
                None => 0, // all-zero it_value disarms (Linux semantics)
                Some(deadline) => {
                    if flags & LINUX_TIMER_ABSTIME != 0 {
                        // Absolute deadline on the timer's clock -> relative.
                        let now =
                            linux_clock_duration(crate::posix_timer::clock_id(id) as u64)
                                .unwrap_or(Duration::ZERO);
                        // A now/past deadline must still arm-and-fire; arm() uses
                        // value_ns==0 as the DISARM sentinel, so floor at 1ns.
                        let rel = deadline.saturating_sub(now);
                        u64::try_from(duration_to_nanos(rel)).unwrap_or(u64::MAX).max(1)
                    } else {
                        u64::try_from(duration_to_nanos(deadline)).unwrap_or(u64::MAX)
                    }
                }
            };
            let spec_ns = TimerSpecNs {
                value: value_ns,
                interval: interval_ns,
            };
            // Route the arm through the backend `TimerDelivery` (HVF/KVM each
            // spawn their own firing mechanism; signum/si_value were captured at
            // timer_create and live on the slot, so only value/interval pass). No
            // registered backend (a backing-loop-less unit test) → arm the
            // neutral registry directly (no firing thread, matching the old
            // pump-less path).
            let old = match crate::timer_delivery::delivery() {
                Some(d) => d.arm_posix(id, spec_ns),
                None => crate::posix_timer::arm(id, spec_ns),
            };
            if old_ptr.0 != 0 {
                let prev = old.unwrap_or(crate::posix_timer::PosixTimerSpec {
                    signum: 0,
                    spec: TimerSpecNs::DISARM,
                    si_value: 0,
                });
                let old_spec = build_itimerspec_ns(prev.spec);
                if memory
                    .write_bytes(old_ptr.0, old_spec.as_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `timer_gettime(id, cur)`: write the remaining time + interval.
        fn timer_gettime(this, cx, timer_id: u64, cur_ptr: GuestPtr) {
            let memory = &mut *cx.memory;
            let id = timer_id as i64 as i32;
            let Some(remaining) = crate::posix_timer::remaining(id) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if cur_ptr.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let spec = build_itimerspec_ns(remaining);
            memory.write_bytes(cur_ptr.0, spec.as_bytes())?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `timer_delete(id)`: tear down a timer.
        fn timer_delete(this, cx, timer_id: u64) {
            let id = timer_id as i64 as i32;
            if crate::posix_timer::delete(id) {
                Ok(DispatchOutcome::Returned { value: 0 })
            } else {
                Ok(DispatchOutcome::errno(LINUX_EINVAL))
            }
        }

        /// `timer_getoverrun(id)`: number of missed expiries since last query.
        fn timer_getoverrun(this, cx, timer_id: u64) {
            let id = timer_id as i64 as i32;
            match crate::posix_timer::getoverrun(id) {
                Some(n) => Ok(DispatchOutcome::Returned { value: n as i64 }),
                None => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        }

        fn adjtimex(this, cx, address: GuestPtr) {
            Ok(adjtimex_bootstrap(&mut *cx.memory, address.0))
        }

        fn clock_adjtime(this, cx, clock_id: u64, address: GuestPtr) {
            let memory = &mut *cx.memory;
            if clock_id != LINUX_CLOCK_REALTIME {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(adjtimex_bootstrap(memory, address.0))
        }

        fn gettimeofday(this, cx, timeval: GuestPtr, timezone: GuestPtr) {
            let memory = &mut *cx.memory;
            let now = realtime_duration();
            if timeval.0 != 0 {
                let tv = linux_timeval_from_duration(now);
                if memory
                    .write_bytes(timeval.0, tv.as_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            if timezone.0 != 0
                && memory
                    .write_bytes(timezone.0, LinuxTimezone::utc().abi_bytes())
                    .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn settimeofday(this, cx, _timeval: GuestPtr, _timezone: GuestPtr) {
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }

        fn sysinfo(this, cx, info_ptr: GuestPtr) {
            let memory = &mut *cx.memory;
            let info = LinuxSysinfo {
                uptime: host_uptime_secs(),
                loads: [0; 3],
                totalram: 16 * 1024 * 1024 * 1024,
                freeram: 16 * 1024 * 1024 * 1024,
                sharedram: 0,
                bufferram: 0,
                totalswap: 0,
                freeswap: 0,
                procs: 1,
                totalhigh: 0,
                freehigh: 0,
                mem_unit: 1,
                pad: 0,
                _pad_align: [0; 4],
                _f: [0; 4],
            };
            if write_kernel_struct_raw(memory, info_ptr.0, &info).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn times(this, cx, buf: GuestPtr) {
            let memory = &mut *cx.memory;
            let secs = realtime_duration().as_secs();
            let clock = i64::try_from(secs)
                .ok()
                .and_then(|s| s.checked_mul(LINUX_CLK_TCK))
                .unwrap_or(i64::MAX);
            // On macOS, `self_resource_usage` sources guest CPU from
            // `proc_pid_rusage` + HVF exec-time correction (see host_proc.rs).
            // On Linux/KVM, it returns `None` because Darwin libproc is
            // unavailable; fall back to the cross-platform
            // `guest_cpu::total_us()` table that is now populated by the
            // `begin_active`/`finish_active` wrap around KVM_RUN.
            let (user_us, system_us) = crate::host_proc::self_resource_usage()
                .map(|h| (h.user_us, h.system_us))
                .unwrap_or_else(|| (crate::guest_cpu::total_us(), 0));
            let to_ticks = |us: u64| (us as i64).saturating_mul(LINUX_CLK_TCK) / 1_000_000;
            let tms = LinuxTms {
                tms_utime: to_ticks(user_us),
                tms_stime: to_ticks(system_us),
                tms_cutime: to_ticks(crate::guest_cpu::child_user_us()),
                tms_cstime: to_ticks(crate::guest_cpu::child_system_us()),
            };
            if buf.0 != 0 && memory.write_bytes(buf.0, tms.abi_bytes()).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: clock })
        }

        fn getrusage(this, cx, who: u64, usage: GuestPtr) {
            let memory = &mut *cx.memory;
            let who = who as i32;
            match who {
                LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD => {}
                _ => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            if usage.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let host = crate::host_proc::self_resource_usage().unwrap_or_default();
            // On Linux/KVM, `self_resource_usage` is a no-op stub; source the
            // guest's user CPU from the cross-platform `guest_cpu` table instead
            // (populated by begin_active/finish_active around KVM_RUN).
            let self_user_us = if host.user_us > 0 {
                host.user_us
            } else {
                crate::guest_cpu::total_us()
            };
            let rusage = match who {
                LINUX_RUSAGE_THREAD => {
                    // Per-thread guest CPU: the guest's getrusage traps out and runs
                    // this dispatch ON its own vCPU thread, so guest_cpu's per-thread
                    // slot IS this thread's user CPU. Guest cycles (HVF/KVM/bhyve)
                    // don't accrue to the host thread's rusage, so self_thread_cpu_us
                    // is only carrick-side overhead — take the larger.
                    let (host_user, system_us) =
                        crate::host_proc::self_thread_cpu_us().unwrap_or((0, 0));
                    let user_us = crate::guest_cpu::this_thread_us().max(host_user);
                    rusage_from(user_us, system_us, host.maxrss_bytes, host.majflt)
                }
                LINUX_RUSAGE_CHILDREN => rusage_from(
                    crate::guest_cpu::child_user_us(),
                    crate::guest_cpu::child_system_us(),
                    host.maxrss_bytes,
                    0,
                ),
                _ => rusage_from(self_user_us, host.system_us, host.maxrss_bytes, host.majflt),
            };
            memory.write_bytes(usage.0, rusage.abi_bytes())?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        // getrlimit(2) (syscall 163) — the older 2-arg form glibc and Apple
        // Rosetta still use. Equivalent to prlimit64 reading the current limit.
        fn getrlimit(this, cx, resource: u64, rlimit: GuestPtr) {
            if resource >= LINUX_RLIM_NLIMITS {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let nofile_soft = this.io.nofile_soft.load(std::sync::atomic::Ordering::Relaxed);
            let limit = effective_rlimit(resource, nofile_soft, &this.proc.lock().rlimit_overrides);
            let memory = &mut *cx.memory;
            if rlimit.0 != 0 && write_kernel_struct_raw(memory, rlimit.0, &limit).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn prlimit64(this, cx, pid: Pid, resource: u64, new_limit: GuestPtr, old_limit: GuestPtr) {
            let memory = &mut *cx.memory;
            // The pid arg selects the target process: 0 names the caller, any
            // other pid names another task that must EXIST or the call is ESRCH
            // (CPython test_resource.test_prlimit: prlimit(-1)→ESRCH,
            // prlimit(0)→ok, prlimit(999999)→ESRCH). carrick's getpid returns the
            // host pid, so the guest's "own pid" is std::process::id(); any other
            // pid is probed via kill(pid,0) — rc==0 (signalable) or EPERM (exists,
            // foreign owner, e.g. launchd) means it exists, ESRCH means it does
            // not. A negative or out-of-range pid is never a real task → ESRCH.
            {
                let pid = i64::from(pid.0);
                let self_pid = std::process::id() as i64;
                if pid != 0 && pid != self_pid {
                    let exists = pid > 0
                        && pid <= i32::MAX as i64
                        && {
                            let rc = unsafe { libc::kill(pid as i32, 0) };
                            rc == 0
                                || std::io::Error::last_os_error().raw_os_error()
                                    == Some(libc::EPERM)
                        };
                    if !exists {
                        return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                    }
                }
            }
            // An invalid resource (>= RLIM_NLIMITS) is EINVAL, checked before any
            // limit read/write (LTP getrlimit02 invalid-resource-type case).
            // Valid resources are 0..=15 (RLIMIT_CPU..RLIMIT_RTTIME); carrick
            // previously treated unknown resources as RLIM_INFINITY and
            // "succeeded".
            if resource >= LINUX_RLIM_NLIMITS {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let nofile_soft = this.io.nofile_soft.load(std::sync::atomic::Ordering::Relaxed);
            // The old (current) limit is reported BEFORE the new one is applied.
            let old = effective_rlimit(resource, nofile_soft, &this.proc.lock().rlimit_overrides);
            if old_limit.0 != 0 && write_kernel_struct_raw(memory, old_limit.0, &old).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if new_limit.0 != 0 {
                let bytes = match memory.read_bytes(new_limit.0, 16) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let rlim_cur = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                let rlim_max = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                if rlim_cur > rlim_max {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // Raising a (previously-lowered) hard limit needs CAP_SYS_RESOURCE,
                // which carrick models as euid==0 (the default guest identity is
                // root). A privileged guest may raise it; the store path below
                // then persists the new hard cap. An unprivileged guest still gets
                // EPERM (matches real Linux). Reverts commit 13873aa3's
                // unconditional denial.
                if rlim_max > old.rlim_max && this.cred_snapshot().euid != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
                if resource == LINUX_RLIMIT_NOFILE {
                    // Honor the guest raising (or lowering) its fd soft limit,
                    // clamped to the hard limit we expose. The fd allocator
                    // (first_free_fd) and dup3's range check read this. RLIM_
                    // INFINITY soft is clamped to the hard cap.
                    let soft = rlim_cur.min(1024 * 1024);
                    this.io
                        .nofile_soft
                        .store(soft, std::sync::atomic::Ordering::Relaxed);
                } else {
                    // Every other resource round-trips through the per-process
                    // override table so a subsequent get reads back what was set.
                    if let Some(slot) = this.proc.lock().rlimit_overrides.get_mut(resource as usize)
                    {
                        *slot = Some(LinuxRlimit::new(rlim_cur, rlim_max));
                    }
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }
    }
}

/// The resource limit carrick reports for `getrlimit`/`prlimit64`, honoring any
/// `setrlimit` override. NOFILE is always derived from `nofile_soft` (so it
/// stays consistent with the fd allocator), so it is never stored in the
/// per-resource override table; every other resource returns its stored
/// override if one was set, else the carrick default.
fn effective_rlimit(
    resource: u64,
    nofile_soft: u64,
    overrides: &[Option<LinuxRlimit>; 16],
) -> LinuxRlimit {
    // RLIMIT_NOFILE's soft cap is authoritative in io.nofile_soft.
    if resource != LINUX_RLIMIT_NOFILE
        && let Some(Some(limit)) = overrides.get(resource as usize)
    {
        return *limit;
    }
    rlimit_for_resource(resource, nofile_soft)
}

/// The DEFAULT resource limit carrick reports for a resource with no override.
/// Shared so the old 2-arg and new 4-arg forms agree. `nofile_soft` is threaded
/// in because RLIMIT_NOFILE's soft cap is dynamic (set via setrlimit).
fn rlimit_for_resource(resource: u64, nofile_soft: u64) -> LinuxRlimit {
    // The fd hard cap carrick exposes; mirrors fs::state::NOFILE_HARD (private).
    const NOFILE_HARD: u64 = 1024 * 1024;
    match resource {
        LINUX_RLIMIT_NOFILE => LinuxRlimit::new(nofile_soft, NOFILE_HARD),
        LINUX_RLIMIT_NPROC => LinuxRlimit::new(8192, 8192),
        LINUX_RLIMIT_STACK => {
            // Linux's default 8 MiB soft RLIMIT_STACK, unlimited hard limit.
            // CPython (and other runtimes) calibrate their main-thread
            // C-recursion guard to this value, so it must match the size of
            // the guest stack carrick actually backs (LINUX_STACK_SIZE) or
            // deep C recursion overflows the real stack before the guard
            // fires. Kept as its own constant (rather than reusing
            // LINUX_STACK_SIZE directly) so the reported limit and the
            // backed region can diverge if we ever add guard-page slack.
            LinuxRlimit::new(crate::memory::LINUX_RLIMIT_STACK_SOFT, LINUX_RLIM_INFINITY)
        }
        LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
            LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
        }
        _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
    }
}

fn host_uptime_secs() -> i64 {
    #[cfg(target_os = "macos")]
    {
        let mut boot = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        let mut len = core::mem::size_of::<libc::timeval>();
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut boot as *mut _ as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0
            && boot.tv_sec > 0
            && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
        {
            return now.as_secs().saturating_sub(boot.tv_sec as u64) as i64;
        }
    }
    0
}

/// Convert a Linux `timeval` to a `Duration` (saturating; negative components,
/// already rejected by `linux_timeval_usec_is_valid`, clamp to zero).
fn duration_from_timeval(tv: crate::linux_abi::LinuxTimeval) -> std::time::Duration {
    let secs = tv.tv_sec.max(0) as u64;
    let usecs = tv.tv_usec.clamp(0, 999_999) as u32;
    std::time::Duration::new(secs, usecs * 1000)
}

/// Build a `timeval` from a `Duration`.
fn timeval_from_duration(d: std::time::Duration) -> crate::linux_abi::LinuxTimeval {
    crate::linux_abi::LinuxTimeval {
        tv_sec: d.as_secs() as i64,
        tv_usec: i64::from(d.subsec_micros()),
    }
}

/// Build a `LinuxRusage` from CPU times (microseconds), peak RSS (bytes), and a
/// major-fault count. `ru_maxrss` is reported in KiB, as Linux does. Fields we
/// do not yet account (ixrss/idrss/swaps/blocks/context switches) stay zero.
fn rusage_from(user_us: u64, system_us: u64, maxrss_bytes: u64, majflt: u64) -> LinuxRusage {
    let timeval = |us: u64| crate::linux_abi::LinuxTimeval {
        tv_sec: (us / 1_000_000) as i64,
        tv_usec: (us % 1_000_000) as i64,
    };
    let mut ru = LinuxRusage::zeroed();
    ru.ru_utime = timeval(user_us);
    ru.ru_stime = timeval(system_us);
    ru.ru_maxrss = (maxrss_bytes / 1024) as i64;
    ru.ru_majflt = majflt as i64;
    ru
}

/// Render an interval-timer's state as an `itimerval`, computing the time
/// remaining (`value - elapsed`, saturating to zero on/after expiry). A
/// disarmed timer (`None`) is the zeroed struct.
fn itimerval_from_state(
    state: Option<crate::dispatch::proc::ItimerState>,
) -> crate::linux_abi::LinuxItimerval {
    match state {
        Some(t) => {
            let remaining = t.value.saturating_sub(t.set_at.elapsed());
            crate::linux_abi::LinuxItimerval {
                it_interval: timeval_from_duration(t.interval),
                it_value: timeval_from_duration(remaining),
            }
        }
        None => crate::linux_abi::LinuxItimerval::zeroed(),
    }
}

fn x86_alarm_remaining_seconds(state: Option<crate::dispatch::proc::ItimerState>) -> u64 {
    let Some(timer) = state else {
        return 0;
    };
    let remaining = timer.value.saturating_sub(timer.set_at.elapsed());
    if remaining.is_zero() {
        0
    } else {
        remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0)
    }
}

// `nanosleep`/`clock_nanosleep` now return `DispatchOutcome::WaitOnSleep` and
// the run loop performs the timed wait via the per-thread waiter (so it is
// fork-quiesce-parkable). The former in-dispatcher `host_sleep_interruptible`
// blocking host nanosleep was removed: a sibling stuck in it never reached the
// run-loop top and deadlocked multithreaded fork.

#[cfg(test)]
mod rlimit_tests {
    use super::*;
    #[test]
    fn nofile_uses_dynamic_soft_cap() {
        let r = rlimit_for_resource(7, 2048); // RLIMIT_NOFILE
        // `LinuxRlimit` is `#[repr(C, packed)]`, so copy the fields to locals
        // before asserting to avoid taking references to unaligned fields.
        let (cur, max) = (r.rlim_cur, r.rlim_max);
        assert_eq!(cur, 2048);
        assert_eq!(max, 1024 * 1024);
    }
    #[test]
    fn unknown_resource_is_infinity() {
        let r = rlimit_for_resource(99, 1024);
        let cur = r.rlim_cur;
        assert_eq!(cur, LINUX_RLIM_INFINITY);
    }
}
