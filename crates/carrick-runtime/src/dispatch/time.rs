//! time syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

impl SyscallDispatcher {
define_syscall! {
    fn timerfd_create(this, cx, clock_id: u64, flags: u64) {
        if linux_clock_duration(clock_id).is_none()
            || flags & !(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC) != 0
        {
            return Ok(LINUX_EINVAL.into());
        }
        let description = OpenDescription::TimerFd {
            state: Arc::new(TimerFdState::new(clock_id)),
            status_flags: flags & LINUX_TFD_NONBLOCK,
        };
        Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    fn timerfd_settime(this, cx, fd: Fd, flags: u64, new_value: u64, old_value: u64) {
        let memory = &mut *cx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        let spec = match read_itimerspec(memory, new_value) {
            Ok(spec) => spec,
            Err(errno) => return Ok(errno.into()),
        };
        let (next_interval, next_value) = match itimerspec_durations(spec) {
            Ok(value) => value,
            Err(errno) => return Ok(errno.into()),
        };
        let Some(open_file) = this.open_file(fd.0) else {
            return Ok(LINUX_EBADF.into());
        };
        let open = open_file.description.read();
        let OpenDescription::TimerFd { state, .. } = &*open else {
            return Ok(LINUX_EINVAL.into());
        };
        let state = Arc::clone(state);
        drop(open);
        let mut timer = state.inner.lock();

        if old_value != 0 {
            let previous = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
            if write_kernel_struct_raw(memory, old_value, &previous).is_err() {
                return Ok(LINUX_EFAULT.into());
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
            return Ok(LINUX_EBADF.into());
        };
        let open = open_file.description.read();
        let OpenDescription::TimerFd { state, .. } = &*open else {
            return Ok(LINUX_EINVAL.into());
        };
        let mut timer = state.inner.lock();
        refresh_timerfd_locked(&mut timer);
        let current = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
        Ok(write_kernel_struct(memory, current_value, &current))
    }

    fn nanosleep(this, cx, request_address: GuestPtr, rem_ptr: GuestPtr) {
        let memory = &*cx.memory;
        let timespec = match read_timespec(memory, request_address.0) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(errno.into()),
        };
        let duration = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration,
            Err(errno) => return Ok(errno.into()),
        };
        if let Some(duration) = duration {
            if let Some(remaining) = host_sleep_interruptible(duration) {
                if rem_ptr.0 != 0 {
                    let memory = &mut *cx.memory;
                    let ts = linux_timespec_from_duration(remaining);
                    let _ = write_kernel_struct(memory, rem_ptr.0, &ts);
                }
                return Ok(LINUX_EINTR.into());
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn clock_nanosleep(this, cx, clock_id: u64, flags: u64, request_address: GuestPtr, rem_ptr: GuestPtr) {
        let memory = &*cx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        let Some(now) = linux_clock_duration(clock_id) else {
            return Ok(LINUX_EINVAL.into());
        };
        let timespec = match read_timespec(memory, request_address.0) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(errno.into()),
        };
        let requested = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration.unwrap_or(Duration::ZERO),
            Err(errno) => return Ok(errno.into()),
        };
        let sleep_duration = if flags & LINUX_TIMER_ABSTIME != 0 {
            requested.saturating_sub(now)
        } else {
            requested
        };
        if !sleep_duration.is_zero() {
            if let Some(remaining) = host_sleep_interruptible(sleep_duration) {
                if flags & LINUX_TIMER_ABSTIME == 0 {
                    if rem_ptr.0 != 0 {
                        let memory = &mut *cx.memory;
                        let ts = linux_timespec_from_duration(remaining);
                        let _ = write_kernel_struct(memory, rem_ptr.0, &ts);
                    }
                }
                return Ok(LINUX_EINTR.into());
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn clock_gettime(this, cx, clock_id: u64, address: GuestPtr) {
        let memory = &mut *cx.memory;
        let Some(duration) = linux_clock_duration(clock_id) else {
            return Ok(LINUX_EINVAL.into());
        };
        let timespec = linux_timespec_from_duration(duration);
        Ok(write_kernel_struct(memory, address.0, &timespec))
    }

    fn clock_getres(this, cx, clock_id: u64, address: GuestPtr) {
        let memory = &mut *cx.memory;
        if linux_clock_duration(clock_id).is_none() {
            return Ok(LINUX_EINVAL.into());
        }
        if address.0 == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        Ok(write_packed(
            memory,
            address.0,
            LinuxTimespec::new(0, LINUX_CLOCK_RESOLUTION_NSEC).as_bytes(),
        ))
    }

    fn clock_settime(this, cx, clock_id: u64, address: GuestPtr) {
        let memory = &*cx.memory;
        if !linux_clock_is_known(clock_id) {
            return Ok(LINUX_EINVAL.into());
        }
        let timespec = match read_timespec(memory, address.0) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(errno.into()),
        };
        let tv_nsec = timespec.tv_nsec;
        if !(0..1_000_000_000).contains(&tv_nsec) {
            return Ok(LINUX_EINVAL.into());
        }
        if !linux_clock_is_settable(clock_id) {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(LINUX_EPERM.into())
    }

    fn getitimer(this, cx, which: u64, address: GuestPtr) {
        let memory = &mut *cx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(LINUX_EINVAL.into());
        }
        if address.0 == 0 {
            return Ok(LINUX_EFAULT.into());
        }
        let current = itimerval_from_state(this.proc.lock().itimers[which as usize]);
        Ok(write_kernel_struct(memory, address.0, &current))
    }

    fn setitimer(this, cx, which: u64, new_address: GuestPtr, old_address: GuestPtr) {
        let memory = &mut *cx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(LINUX_EINVAL.into());
        }
        let new_value = if new_address.0 != 0 {
            let v = match read_itimerval(memory, new_address.0) {
                Ok(value) => value,
                Err(errno) => return Ok(errno.into()),
            };
            if !linux_timeval_usec_is_valid(v.it_interval)
                || !linux_timeval_usec_is_valid(v.it_value)
            {
                return Ok(LINUX_EINVAL.into());
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

            let ident = crate::itimer::ident_for(idx);
            let kq = crate::host_signal::pump_kqueue();
            if value.is_zero() {
                crate::itimer::disarm(idx);
                if kq >= 0 {
                    let _ = crate::darwin_kqueue::apply_changes(
                        kq,
                        &[crate::darwin_kqueue::Kevent::timer(
                            ident,
                            libc::EV_DELETE,
                            0,
                        )],
                    );
                }
            } else {
                let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
                let value_ns = i64::try_from(value.as_nanos()).unwrap_or(i64::MAX);
                let interval_value_ns = i64::try_from(interval.as_nanos()).unwrap_or(i64::MAX);
                let periodic = !interval.is_zero() && value == interval;
                let needs_periodic = !interval.is_zero() && value != interval;
                crate::itimer::arm(idx, interval_ns, needs_periodic);

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
                if kq >= 0 {
                    let (flags, data) = if periodic {
                        (libc::EV_ADD, interval_value_ns)
                    } else {
                        (libc::EV_ADD | libc::EV_ONESHOT, value_ns)
                    };
                    let _ = crate::darwin_kqueue::apply_changes(
                        kq,
                        &[crate::darwin_kqueue::Kevent::timer(ident, flags, data)],
                    );
                }
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn adjtimex(this, cx, address: GuestPtr) {
        Ok(adjtimex_bootstrap(&*cx.memory, address.0))
    }

    fn clock_adjtime(this, cx, clock_id: u64, address: GuestPtr) {
        let memory = &*cx.memory;
        if clock_id != LINUX_CLOCK_REALTIME {
            return Ok(LINUX_EINVAL.into());
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
                return Ok(LINUX_EFAULT.into());
            }
        }
        if timezone.0 != 0
            && memory
                .write_bytes(timezone.0, LinuxTimezone::utc().abi_bytes())
                .is_err()
        {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn settimeofday(this, cx, _timeval: GuestPtr, _timezone: GuestPtr) {
        Ok(LINUX_EPERM.into())
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
            _padding: [0; 8],
        };
        if write_kernel_struct_raw(memory, info_ptr.0, &info).is_err() {
            return Ok(LINUX_EFAULT.into());
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
        let host = crate::host_proc::self_resource_usage().unwrap_or_default();
        let to_ticks = |us: u64| (us as i64).saturating_mul(LINUX_CLK_TCK) / 1_000_000;
        let tms = LinuxTms {
            tms_utime: to_ticks(host.user_us),
            tms_stime: to_ticks(host.system_us),
            tms_cutime: to_ticks(crate::guest_cpu::child_user_us()),
            tms_cstime: to_ticks(crate::guest_cpu::child_system_us()),
        };
        if buf.0 != 0 && memory.write_bytes(buf.0, tms.abi_bytes()).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: clock })
    }

    fn getrusage(this, cx, who: u64, usage: GuestPtr) {
        let memory = &mut *cx.memory;
        let who = who as i32;
        match who {
            LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD => {}
            _ => {
                return Ok(LINUX_EINVAL.into());
            }
        }
        if usage.0 == 0 {
            return Ok(LINUX_EFAULT.into());
        }
        let host = crate::host_proc::self_resource_usage().unwrap_or_default();
        let rusage = match who {
            LINUX_RUSAGE_THREAD => {
                let (user_us, system_us) = crate::host_proc::self_thread_cpu_us().unwrap_or((0, 0));
                rusage_from(user_us, system_us, host.maxrss_bytes, host.majflt)
            }
            LINUX_RUSAGE_CHILDREN => rusage_from(
                crate::guest_cpu::child_user_us(),
                crate::guest_cpu::child_system_us(),
                host.maxrss_bytes,
                0,
            ),
            _ => rusage_from(host.user_us, host.system_us, host.maxrss_bytes, host.majflt),
        };
        if memory.write_bytes(usage.0, rusage.abi_bytes()).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn prlimit64(this, cx, pid: Pid, resource: u64, new_limit: GuestPtr, old_limit: GuestPtr) {
        let memory = &mut *cx.memory;
        const LINUX_RLIMIT_NOFILE: u64 = 7;
        const LINUX_RLIMIT_NPROC: u64 = 6;
        const LINUX_RLIMIT_STACK: u64 = 3;
        const LINUX_RLIMIT_AS: u64 = 9;
        const LINUX_RLIMIT_DATA: u64 = 2;
        let limit = match resource {
            LINUX_RLIMIT_NOFILE => LinuxRlimit::new(1024, 1024 * 1024),
            LINUX_RLIMIT_NPROC => LinuxRlimit::new(8192, 8192),
            LINUX_RLIMIT_STACK => {
                LinuxRlimit::new(crate::memory::LINUX_STACK_SIZE, LINUX_RLIM_INFINITY)
            }
            LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
                LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
            }
            _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
        };
        if old_limit.0 != 0 && write_kernel_struct_raw(memory, old_limit.0, &limit).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        if new_limit.0 != 0 {
            let bytes = match memory.read_bytes(new_limit.0, 16) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            let rlim_cur = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
            let rlim_max = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
            if rlim_cur > rlim_max {
                return Ok(LINUX_EINVAL.into());
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }
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

/// Sleep on the host for `duration`, interruptible by a pending guest signal.
///
/// Unlike `std::thread::sleep` — whose internal `assert_eq!(errno, EINTR)`
/// panics the whole process when carrick's signal machinery leaves a different
/// errno on the thread (observed crashing forked guest children on Ctrl-C) —
/// this issues `nanosleep(2)` directly. On a genuine interruption (a
/// process-directed guest signal such as SIGINT is pending) it returns the
/// unslept `Some(remaining)` so the caller can return `EINTR` and let the trap
/// loop deliver the signal. Spurious wakeups (internal vCPU kicks, SIGCHLD…)
/// resume sleeping for the remaining time, matching Linux's restart behaviour.
fn host_sleep_interruptible(duration: Duration) -> Option<Duration> {
    let mut req = libc::timespec {
        tv_sec: duration.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    };
    loop {
        let mut rem = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `req` and `rem` are valid, distinct, fully-initialised
        // timespecs for the duration of the call.
        let r = unsafe { libc::nanosleep(&req, &mut rem) };
        if r == 0 {
            return None;
        }
        // Interrupted. Surface EINTR only if the guest has a signal it can
        // actually take; otherwise resume sleeping for the remaining time.
        if crate::host_signal::has_process_pending() {
            return Some(Duration::new(
                rem.tv_sec.max(0) as u64,
                rem.tv_nsec.max(0) as u32,
            ));
        }
        if rem.tv_sec <= 0 && rem.tv_nsec <= 0 {
            return None;
        }
        req = rem;
    }
}
