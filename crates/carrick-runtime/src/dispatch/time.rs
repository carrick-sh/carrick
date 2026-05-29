//! time syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Pack a `(value_ns, interval_ns)` pair into a `LinuxItimerspec` (the Linux
/// kernel ABI `struct __kernel_itimerspec`). Used by `timer_settime`'s
/// `old_value` and `timer_gettime`'s `cur_value` writes.
fn build_itimerspec_ns(value_ns: u64, interval_ns: u64) -> LinuxItimerspec {
    let split = |ns: u64| LinuxTimespec {
        tv_sec: i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(ns % 1_000_000_000).unwrap_or(0),
    };
    LinuxItimerspec::new(split(interval_ns), split(value_ns))
}

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
                base: OpenDescriptionBase::new(flags & LINUX_TFD_NONBLOCK),
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
                    let arm_value_ns = u64::try_from(value.as_nanos()).unwrap_or(u64::MAX);
                    let value_ns = i64::try_from(value.as_nanos()).unwrap_or(i64::MAX);
                    let interval_value_ns = i64::try_from(interval.as_nanos()).unwrap_or(i64::MAX);
                    let periodic = !interval.is_zero() && value == interval;
                    let needs_periodic = !interval.is_zero() && value != interval;
                    let generation =
                        crate::itimer::arm(idx, arm_value_ns, interval_ns, needs_periodic);

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
                    let mut armed_on_kqueue = false;
                    if kq >= 0 {
                        let (flags, data) = if periodic {
                            (libc::EV_ADD, interval_value_ns)
                        } else {
                            (libc::EV_ADD | libc::EV_ONESHOT, value_ns)
                        };
                        armed_on_kqueue = crate::darwin_kqueue::apply_changes(
                            kq,
                            &[crate::darwin_kqueue::Kevent::timer(ident, flags, data)],
                        )
                        .is_ok();
                    }
                    if !armed_on_kqueue {
                        crate::itimer::spawn_fallback_timer(idx, generation, value, interval);
                    }
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
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
                return Ok(LINUX_EINVAL.into());
            }
            if id_out.0 == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            let mut signum = crate::linux_abi::LINUX_SIGALRM;
            if sevp.0 != 0 {
                let bytes = match memory.read_bytes(sevp.0, 16) {
                    Ok(b) => b,
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                };
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
                    // SIGEV_THREAD down to SIGEV_THREAD_ID + an internal
                    // helper thread. For our purposes the delivery still
                    // routes through the posix_timer fallback-thread, which
                    // raises against the process; the *test contract* the
                    // LTP suites check is just that timer_create succeeds.
                    if !(1..=64).contains(&signo) {
                        return Ok(LINUX_EINVAL.into());
                    }
                    signum = signo;
                } else if notify == LINUX_SIGEV_THREAD {
                    // SIGEV_THREAD: never seen by the kernel on real Linux
                    // (glibc swaps it for SIGEV_THREAD_ID). A raw syscall
                    // passing it gets EINVAL.
                    return Ok(LINUX_EINVAL.into());
                } else {
                    return Ok(LINUX_EINVAL.into());
                }
            }
            let timer_id = crate::posix_timer::create(clock_id as i32, signum);
            // Linux uses an opaque pointer-sized `timer_t`; we hand back the
            // small integer id widened to 64 bits.
            let id_bytes = (timer_id as i64 as u64).to_le_bytes();
            if memory.write_bytes(id_out.0, &id_bytes).is_err() {
                let _ = crate::posix_timer::delete(timer_id);
                return Ok(LINUX_EFAULT.into());
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
                return Ok(LINUX_EINVAL.into());
            }
            // Only TIMER_ABSTIME is a valid flag; reject any other bit. (audit M4)
            if flags & !LINUX_TIMER_ABSTIME != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if new_ptr.0 == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            let spec = match read_itimerspec(memory, new_ptr.0) {
                Ok(spec) => spec,
                Err(errno) => return Ok(errno.into()),
            };
            // Validate the timespec (EINVAL on tv_nsec>=1e9 or negative) via the
            // shared helper, exactly like timerfd_settime. (audit M4)
            let (interval_dur, value_dur) = match itimerspec_durations(spec) {
                Ok(durations) => durations,
                Err(errno) => return Ok(errno.into()),
            };
            let interval_ns =
                interval_dur.map_or(0, |d| u64::try_from(duration_to_nanos(d)).unwrap_or(u64::MAX));
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
            let old = crate::posix_timer::arm(id, value_ns, interval_ns);
            if old_ptr.0 != 0 {
                let prev = old.unwrap_or(crate::posix_timer::TimerSpec {
                    signum: 0,
                    value_ns: 0,
                    interval_ns: 0,
                });
                let old_spec = build_itimerspec_ns(prev.value_ns, prev.interval_ns);
                if memory
                    .write_bytes(old_ptr.0, old_spec.as_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `timer_gettime(id, cur)`: write the remaining time + interval.
        fn timer_gettime(this, cx, timer_id: u64, cur_ptr: GuestPtr) {
            let memory = &mut *cx.memory;
            let id = timer_id as i64 as i32;
            let Some((value_ns, interval_ns)) = crate::posix_timer::remaining(id) else {
                return Ok(LINUX_EINVAL.into());
            };
            if cur_ptr.0 == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            let spec = build_itimerspec_ns(value_ns, interval_ns);
            if memory.write_bytes(cur_ptr.0, spec.as_bytes()).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `timer_delete(id)`: tear down a timer.
        fn timer_delete(this, cx, timer_id: u64) {
            let id = timer_id as i64 as i32;
            if crate::posix_timer::delete(id) {
                Ok(DispatchOutcome::Returned { value: 0 })
            } else {
                Ok(LINUX_EINVAL.into())
            }
        }

        /// `timer_getoverrun(id)`: number of missed expiries since last query.
        fn timer_getoverrun(this, cx, timer_id: u64) {
            let id = timer_id as i64 as i32;
            match crate::posix_timer::getoverrun(id) {
                Some(n) => Ok(DispatchOutcome::Returned { value: n as i64 }),
                None => Ok(LINUX_EINVAL.into()),
            }
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
                pad: 0,
                _pad_align: [0; 4],
                _f: [0; 4],
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
            // An invalid resource (>= RLIM_NLIMITS) is EINVAL, checked before any
            // limit read/write (LTP getrlimit02 invalid-resource-type case).
            // Valid resources are 0..=15 (RLIMIT_CPU..RLIMIT_RTTIME); carrick
            // previously treated unknown resources as RLIM_INFINITY and
            // "succeeded".
            const LINUX_RLIM_NLIMITS: u64 = 16;
            if resource >= LINUX_RLIM_NLIMITS {
                return Ok(LINUX_EINVAL.into());
            }
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
