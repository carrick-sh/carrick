//! time syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

impl SyscallDispatcher {
    pub(super) fn timerfd_create<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let flags = ctx.arg(1);
        if linux_clock_duration(clock_id).is_none()
            || flags & !(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC) != 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::TimerFd {
            clock_id,
            interval: None,
            deadline: None,
            expirations: 0,
            status_flags: flags & LINUX_TFD_NONBLOCK,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    pub(super) fn timerfd_settime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let flags = ctx.arg(1);
        let new_value = ctx.arg(2);
        let old_value = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let spec = match read_itimerspec(memory, new_value) {
            Ok(spec) => spec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (next_interval, next_value) = match itimerspec_durations(spec) {
            Ok(value) => value,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::TimerFd {
            clock_id,
            interval,
            deadline,
            expirations,
            ..
        } = &mut *open
        else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };

        if old_value != 0 {
            let previous = timerfd_itimerspec(*clock_id, *interval, *deadline);
            if write_kernel_struct_raw(memory, old_value, &previous).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }

        let now = linux_clock_duration(*clock_id).unwrap_or(Duration::ZERO);
        *interval = next_interval;
        *deadline = next_value.map(|value| {
            if flags & LINUX_TIMER_ABSTIME != 0 {
                value
            } else {
                now.saturating_add(value)
            }
        });
        *expirations = 0;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn timerfd_gettime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let current_value = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.io.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        let OpenDescription::TimerFd {
            clock_id,
            interval,
            deadline,
            ..
        } = &*open
        else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let current = timerfd_itimerspec(*clock_id, *interval, *deadline);
        Ok(write_kernel_struct(memory, current_value, &current))
    }

    pub(super) fn nanosleep<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request_address = ctx.arg(0);
        let memory = &*ctx.memory;
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let duration = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(duration) = duration {
            std::thread::sleep(duration);
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn clock_nanosleep<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let flags = ctx.arg(1);
        let request_address = ctx.arg(2);
        let memory = &*ctx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(now) = linux_clock_duration(clock_id) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let requested = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration.unwrap_or(Duration::ZERO),
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let sleep_duration = if flags & LINUX_TIMER_ABSTIME != 0 {
            requested.saturating_sub(now)
        } else {
            requested
        };
        if !sleep_duration.is_zero() {
            std::thread::sleep(sleep_duration);
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn clock_gettime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let Some(duration) = linux_clock_duration(clock_id) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let timespec = linux_timespec_from_duration(duration);
        Ok(write_kernel_struct(memory, address, &timespec))
    }

    pub(super) fn clock_getres<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if linux_clock_duration(clock_id).is_none() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if address == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        Ok(write_packed(
            memory,
            address,
            LinuxTimespec::new(0, LINUX_CLOCK_RESOLUTION_NSEC).as_bytes(),
        ))
    }

    pub(super) fn clock_settime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &*ctx.memory;
        if !linux_clock_is_known(clock_id) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Reading the timespec lets us surface EFAULT for bad pointers and
        // EINVAL for invalid tv_nsec, matching the order real Linux performs
        // these checks before the privilege check kicks in for unsupported
        // clocks.
        let timespec = match read_timespec(memory, address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let tv_nsec = timespec.tv_nsec;
        if !(0..1_000_000_000).contains(&tv_nsec) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Monotonic-family clocks can never be set; report EINVAL like the
        // real kernel.
        if !linux_clock_is_settable(clock_id) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // For settable clocks (CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_TAI)
        // we still refuse: we are not root and we do not actually mutate the
        // host clock.
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn getitimer<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if address == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        // Only ITIMER_REAL is tracked; VIRTUAL/PROF report disarmed.
        let current = if which == LINUX_ITIMER_REAL {
            itimerval_from_real(self.proc.itimer_real)
        } else {
            LinuxItimerval::zeroed()
        };
        Ok(write_kernel_struct(memory, address, &current))
    }

    pub(super) fn setitimer<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let new_address = ctx.arg(1);
        let old_address = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Read+validate the new value first (so an EINVAL/EFAULT doesn't
        // disturb the currently-armed timer or the old_value out-param).
        let new_value = if new_address != 0 {
            let v = match read_itimerval(memory, new_address) {
                Ok(value) => value,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            if !linux_timeval_usec_is_valid(v.it_interval)
                || !linux_timeval_usec_is_valid(v.it_value)
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            Some(v)
        } else {
            None
        };

        // ITIMER_REAL is tracked so glibc's alarm() can read back the previous
        // timer's remaining seconds; VIRTUAL/PROF stay disarmed (zeroed).
        let is_real = which == LINUX_ITIMER_REAL;
        if old_address != 0 {
            let prev = if is_real {
                itimerval_from_real(self.proc.itimer_real)
            } else {
                LinuxItimerval::zeroed()
            };
            let outcome = write_kernel_struct(memory, old_address, &prev);
            if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                return Ok(outcome);
            }
        }
        if is_real && let Some(v) = new_value {
            let value = duration_from_timeval(v.it_value);
            let interval = duration_from_timeval(v.it_interval);
            // A zero it_value disarms the timer (matching the kernel).
            self.proc.itimer_real = if value.is_zero() {
                None
            } else {
                Some(crate::dispatch::proc::ItimerReal {
                    set_at: std::time::Instant::now(),
                    value,
                    interval,
                })
            };
            ctx.reporter.record(CompatEvent::partial_syscall(
                ctx.request.number,
                "setitimer",
                ctx.request.args,
                "ITIMER_REAL tracked for alarm() accounting; no SIGALRM delivery yet",
            ));
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn adjtimex<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        Ok(adjtimex_bootstrap(&*ctx.memory, address))
    }

    pub(super) fn clock_adjtime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &*ctx.memory;
        // Linux only accepts CLOCK_REALTIME for unprivileged callers (and
        // generally only CLOCK_REALTIME at all for adjtime semantics); anything
        // else is EINVAL.
        if clock_id != LINUX_CLOCK_REALTIME {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(adjtimex_bootstrap(memory, address))
    }

    pub(super) fn gettimeofday<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let timeval = ctx.request.arg(0);
        let timezone = ctx.request.arg(1);
        let now = realtime_duration();
        if timeval != 0 {
            let timeval = linux_timeval_from_duration(now);
            if memory
                .write_bytes(ctx.request.arg(0), timeval.as_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        if timezone != 0
            && memory
                .write_bytes(timezone, LinuxTimezone::utc().abi_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn settimeofday<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn sysinfo<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let info = LinuxSysinfo {
            uptime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
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
        if write_kernel_struct_raw(memory, ctx.request.arg(0), &info).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn times<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let buf = ctx.request.arg(0);
        let secs = realtime_duration().as_secs();
        let clock = i64::try_from(secs)
            .ok()
            .and_then(|s| s.checked_mul(LINUX_CLK_TCK))
            .unwrap_or(i64::MAX);
        if buf != 0
            && memory
                .write_bytes(buf, LinuxTms::zeroed().abi_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: clock })
    }

    pub(super) fn getrusage<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let who = ctx.request.arg(0) as i32;
        let usage = ctx.request.arg(1);
        match who {
            LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD => {}
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if usage == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if memory
            .write_bytes(usage, LinuxRusage::zeroed().abi_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn prlimit64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let resource = ctx.arg(1);
        let new_limit = ctx.arg(2);
        let old_limit = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if new_limit != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if old_limit != 0 {
            // Per-resource values matched to a sensible Linux default.
            // Returning RLIM_INFINITY for ALL resources crashes apt:
            // its pre-fork "set CLOEXEC on every fd" loop iterates
            // 3..rlim_cur and so spins for u64::MAX cycles. RLIMIT_NOFILE
            // in particular needs a real bound.
            // Resource numbers from include/uapi/asm-generic/resource.h.
            const LINUX_RLIMIT_NOFILE: u64 = 7;
            const LINUX_RLIMIT_NPROC: u64 = 6;
            const LINUX_RLIMIT_STACK: u64 = 3;
            const LINUX_RLIMIT_AS: u64 = 9;
            const LINUX_RLIMIT_DATA: u64 = 2;
            let limit = match resource {
                LINUX_RLIMIT_NOFILE => LinuxRlimit::new(1024, 1024 * 1024),
                LINUX_RLIMIT_NPROC => LinuxRlimit::new(8192, 8192),
                LINUX_RLIMIT_STACK => LinuxRlimit::new(
                    crate::memory::LINUX_STACK_SIZE,
                    LINUX_RLIM_INFINITY,
                ),
                LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
                    LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
                }
                _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
            };
            if write_kernel_struct_raw(memory, old_limit, &limit).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }
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

/// Render the current ITIMER_REAL state as an `itimerval`, computing the time
/// remaining (`value - elapsed`, saturating to zero on/after expiry). A
/// disarmed timer (`None`) is the zeroed struct.
fn itimerval_from_real(
    state: Option<crate::dispatch::proc::ItimerReal>,
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
