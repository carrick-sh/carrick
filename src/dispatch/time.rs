//! time syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

impl SyscallDispatcher {
    pub(super) fn dispatch_threaded_time<M: GuestMemory>(
        &self,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !syscall_handler_is(request.number, SyscallHandler::Time) {
            return None;
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let mut ctx = SyscallCtx {
            request,
            memory,
            reporter,
            thread: None,
        };
        let outcome = match match request.number {
            85 => self.timerfd_create(&mut ctx),
            86 => self.timerfd_settime(&mut ctx),
            87 => self.timerfd_gettime(&mut ctx),
            101 => self.nanosleep(&mut ctx),
            102 => self.getitimer(&mut ctx),
            103 => self.setitimer(&mut ctx),
            112 => self.clock_settime(&mut ctx),
            113 => self.clock_gettime(&mut ctx),
            114 => self.clock_getres(&mut ctx),
            115 => self.clock_nanosleep(&mut ctx),
            153 => self.times(&mut ctx),
            165 => self.getrusage(&mut ctx),
            169 => self.gettimeofday(&mut ctx),
            170 => self.settimeofday(&mut ctx),
            171 => self.adjtimex(&mut ctx),
            179 => self.sysinfo(&mut ctx),
            261 => self.prlimit64(&mut ctx),
            266 => self.clock_adjtime(&mut ctx),
            _ => unreachable!("unsupported threaded time syscall"),
        } {
            Ok(outcome) => outcome,
            Err(error) => return Some(Err(error)),
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            retval,
            errno,
        });

        Some(Ok(outcome))
    }

    pub(super) fn timerfd_create<M: GuestMemory>(
        &self,
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
            state: Arc::new(TimerFdState::new(clock_id)),
            status_flags: flags & LINUX_TFD_NONBLOCK,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    pub(super) fn timerfd_settime<M: GuestMemory>(
        &self,
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
        let Some(open_file) = self.open_file(fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.read();
        let OpenDescription::TimerFd { state, .. } = &*open else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let state = Arc::clone(state);
        drop(open);
        let mut timer = state.inner.lock();

        if old_value != 0 {
            let previous = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
            if write_kernel_struct_raw(memory, old_value, &previous).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
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

    pub(super) fn timerfd_gettime<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let current_value = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.open_file(fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.read();
        let OpenDescription::TimerFd { state, .. } = &*open else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let mut timer = state.inner.lock();
        refresh_timerfd_locked(&mut timer);
        let current = timerfd_itimerspec(timer.clock_id, timer.interval, timer.deadline);
        Ok(write_kernel_struct(memory, current_value, &current))
    }

    pub(super) fn nanosleep<M: GuestMemory>(
        &self,
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
            if let Some(remaining) = host_sleep_interruptible(duration) {
                // Interrupted by a pending signal: report the unslept remainder
                // (if the guest passed a `rem` pointer) and return EINTR so the
                // trap loop delivers the signal. nanosleep(2)'s `rem` is arg1.
                let rem_ptr = ctx.arg(1);
                if rem_ptr != 0 {
                    let memory = &mut *ctx.memory;
                    let ts = linux_timespec_from_duration(remaining);
                    let _ = write_kernel_struct(memory, rem_ptr, &ts);
                }
                return Ok(DispatchOutcome::Errno { errno: LINUX_EINTR });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn clock_nanosleep<M: GuestMemory>(
        &self,
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
            if let Some(remaining) = host_sleep_interruptible(sleep_duration) {
                // Relative sleeps report the unslept remainder via arg3;
                // absolute (TIMER_ABSTIME) sleeps do not. Return EINTR either
                // way so the trap loop delivers the pending signal.
                if flags & LINUX_TIMER_ABSTIME == 0 {
                    let rem_ptr = ctx.arg(3);
                    if rem_ptr != 0 {
                        let memory = &mut *ctx.memory;
                        let ts = linux_timespec_from_duration(remaining);
                        let _ = write_kernel_struct(memory, rem_ptr, &ts);
                    }
                }
                return Ok(DispatchOutcome::Errno { errno: LINUX_EINTR });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn clock_gettime<M: GuestMemory>(
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        let current = itimerval_from_state(self.proc.lock().itimers[which as usize]);
        Ok(write_kernel_struct(memory, address, &current))
    }

    pub(super) fn setitimer<M: GuestMemory>(
        &self,
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

        let idx = which as usize;
        // Write the old value before applying the new one (the kernel does the
        // same, so a read-modify-write sees the prior timer).
        if old_address != 0 {
            let prev = itimerval_from_state(self.proc.lock().itimers[idx]);
            let outcome = write_kernel_struct(memory, old_address, &prev);
            if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                return Ok(outcome);
            }
        }
        if let Some(v) = new_value {
            let value = duration_from_timeval(v.it_value);
            let interval = duration_from_timeval(v.it_interval);
            // Bump this timer's generation: any in-flight timer thread for it
            // now sees a stale generation and exits without firing (this both
            // disarms a running timer and supersedes it on re-arm).
            let gen_arc = self.proc.lock().itimer_gen.clone();
            let my_gen = gen_arc[idx].fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            // A zero it_value disarms the timer (matching the kernel).
            self.proc.lock().itimers[idx] = if value.is_zero() {
                None
            } else {
                Some(crate::dispatch::proc::ItimerState {
                    set_at: std::time::Instant::now(),
                    value,
                    interval,
                })
            };
            if !value.is_zero() {
                let signum = match which {
                    LINUX_ITIMER_VIRTUAL => crate::linux_abi::LINUX_SIGVTALRM,
                    LINUX_ITIMER_PROF => crate::linux_abi::LINUX_SIGPROF,
                    _ => crate::linux_abi::LINUX_SIGALRM,
                };
                let signal_name = match signum {
                    crate::linux_abi::LINUX_SIGVTALRM => "SIGVTALRM",
                    crate::linux_abi::LINUX_SIGPROF => "SIGPROF",
                    _ => "SIGALRM",
                };
                ctx.reporter
                    .record(crate::compat::CompatEvent::partial_syscall(
                        103,
                        "setitimer",
                        ctx.request.args,
                        format!(
                            "setitimer delivery is emulated with host timer thread and {signal_name}"
                        ),
                    ));
                spawn_itimer_thread(gen_arc, idx, my_gen, value, interval, signum);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn adjtimex<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        Ok(adjtimex_bootstrap(&*ctx.memory, address))
    }

    pub(super) fn clock_adjtime<M: GuestMemory>(
        &self,
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
        &self,
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
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn sysinfo<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
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
        if write_kernel_struct_raw(memory, ctx.request.arg(0), &info).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn times<M: GuestMemory>(
        &self,
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
        &self,
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
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let resource = ctx.arg(1);
        let new_limit = ctx.arg(2);
        let old_limit = ctx.arg(3);
        let memory = &mut *ctx.memory;
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
            LINUX_RLIMIT_STACK => {
                LinuxRlimit::new(crate::memory::LINUX_STACK_SIZE, LINUX_RLIM_INFINITY)
            }
            LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
                LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
            }
            _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
        };
        // prlimit64 writes the OLD limit before applying the new one, so a
        // read-modify-write (both pointers set) sees the prior value.
        if old_limit != 0 && write_kernel_struct_raw(memory, old_limit, &limit).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        // Setting a limit: validate and accept. carrick does not enforce most
        // resource limits (RLIMIT_CORE/CPU/etc. are advisory here), but a
        // blanket EINVAL broke every caller that legitimately lowers a limit —
        // notably LTP's tst_coredump, which sets RLIMIT_CORE and TBROKs the
        // whole test (setitimer01, getitimer01, …) when the set fails.
        if new_limit != 0 {
            let bytes = match memory.read_bytes(new_limit, 16) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let rlim_cur = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
            let rlim_max = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
            // RLIM_INFINITY (u64::MAX) is the maximum; a soft limit above the
            // hard limit is EINVAL.
            if rlim_cur > rlim_max {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
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

/// Spawn the per-arm interval-timer thread. After the initial `value` delay it
/// publishes `signum` (SIGALRM/SIGVTALRM/SIGPROF) to the guest and, if an
/// `interval` is set, keeps re-firing. Before each fire it checks the timer's
/// generation: if `setitimer` re-armed or disarmed this `which` in the
/// meantime, `gen[idx]` no longer equals `my_gen` and the thread exits without
/// firing. The thread holds only an `Arc` to the generation array, so it never
/// outlives the process (and forked children never inherit it — threads don't
/// survive fork).
fn spawn_itimer_thread(
    gen_arc: std::sync::Arc<[std::sync::atomic::AtomicU64; 3]>,
    idx: usize,
    my_gen: u64,
    value: std::time::Duration,
    interval: std::time::Duration,
    signum: i32,
) {
    use std::sync::atomic::Ordering;
    let _ = std::thread::Builder::new()
        .name("carrick-itimer".to_owned())
        .spawn(move || {
            std::thread::sleep(value);
            loop {
                if gen_arc[idx].load(Ordering::SeqCst) != my_gen {
                    return;
                }
                crate::probes::itimer_fire(signum, my_gen);
                crate::host_signal::publish_process_signal(signum);
                if interval.is_zero() {
                    return;
                }
                std::thread::sleep(interval);
            }
        });
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
