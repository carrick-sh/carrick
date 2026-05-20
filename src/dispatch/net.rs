//! net syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

impl SyscallDispatcher {
    pub(super) fn eventfd2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let initial_value = ctx.arg(0);
        let flags = ctx.arg(1);
        if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::EventFd {
            counter: initial_value,
            semaphore: flags & LINUX_EFD_SEMAPHORE != 0,
            status_flags: flags & LINUX_EFD_NONBLOCK,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    pub(super) fn epoll_create1<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(0);
        if flags & !LINUX_EPOLL_CLOEXEC != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::Epoll {
            interest: HashMap::new(),
            status_flags: 0,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    pub(super) fn epoll_ctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let epfd = ctx.arg(0) as i32;
        let operation = ctx.arg(1);
        let fd = ctx.arg(2) as i32;
        let event_address = ctx.arg(3);
        if epfd == fd || !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        let Some(open_file) = self.open_files.get(&epfd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::Epoll { interest, .. } = &mut *open else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };

        match operation {
            LINUX_EPOLL_CTL_ADD => {
                let event = match read_epoll_event(memory, event_address) {
                    Ok(event) => event,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                if interest.contains_key(&fd) {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                interest.insert(fd, event);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_EPOLL_CTL_MOD => {
                let event = match read_epoll_event(memory, event_address) {
                    Ok(event) => event,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                let Some(slot) = interest.get_mut(&fd) else {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOENT,
                    });
                };
                *slot = event;
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_EPOLL_CTL_DEL => {
                if interest.remove(&fd).is_some() {
                    Ok(DispatchOutcome::Returned { value: 0 })
                } else {
                    Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOENT,
                    })
                }
            }
            _ => Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            }),
        }
    }

    pub(super) fn epoll_pwait<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let epfd = ctx.arg(0) as i32;
        let events_address = ctx.arg(1);
        let max_events = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        if max_events == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let Some(open_file) = self.open_files.get(&epfd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let interests = {
            let open = open_file.description.borrow();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            };
            interest
                .iter()
                .map(|(fd, event)| (*fd, *event))
                .collect::<Vec<_>>()
        };

        let mut ready = Vec::new();
        for (fd, event) in interests {
            let requested_events = event.events;
            let ready_events = self.epoll_ready_events(fd, requested_events);
            if ready_events != 0 {
                ready.push(LinuxEpollEvent {
                    events: ready_events,
                    data: event.data,
                });
                if ready.len() == max_events {
                    break;
                }
            }
        }

        let event_size = core::mem::size_of::<LinuxEpollEvent>();
        for (index, event) in ready.iter().enumerate() {
            let offset = index
                .checked_mul(event_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let address = events_address.checked_add(offset).ok_or(LINUX_EFAULT);
            let Ok(address) = address else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            };
            if write_kernel_struct_raw(memory, address, event).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }

        Ok(DispatchOutcome::Returned {
            value: ready.len() as i64,
        })
    }

    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_files.get(&fd) else {
            return 0;
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::EventFd { counter, .. }
                if *counter > 0 && requested_events & LINUX_EPOLLIN != 0 =>
            {
                LINUX_EPOLLIN
            }
            OpenDescription::PipeReader { pipe, .. } if requested_events & LINUX_EPOLLIN != 0 => {
                let pipe = pipe.borrow();
                if !pipe.buffer.is_empty() || pipe.writers == 0 {
                    LINUX_EPOLLIN
                } else {
                    0
                }
            }
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                ..
            } if requested_events & LINUX_EPOLLIN != 0
                && timerfd_expirations(*clock_id, *interval, *deadline, *expirations).0 > 0 =>
            {
                LINUX_EPOLLIN
            }
            _ => {
                // For host-backed descriptions (HostPipe/HostSocket/HostFile/
                // stdio) the in-memory arms above don't apply: readiness lives
                // in the real kernel object. Mirror what poll()/ppoll() do —
                // map the guest fd to its host fd and do a non-blocking
                // libc::poll(timeout 0), then translate revents → epoll events.
                drop(open);
                let Some(host_fd) = self.host_fd_for_poll(fd) else {
                    return 0;
                };
                let mut interest: i16 = 0;
                if requested_events & LINUX_EPOLLIN != 0 {
                    interest |= libc::POLLIN;
                }
                if requested_events & LINUX_EPOLLOUT != 0 {
                    interest |= libc::POLLOUT;
                }
                if requested_events & LINUX_EPOLLPRI != 0 {
                    interest |= libc::POLLPRI;
                }
                let mut pfd = libc::pollfd {
                    fd: host_fd,
                    events: interest,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                if rc <= 0 {
                    return 0;
                }
                let mut ready = 0u32;
                if pfd.revents & libc::POLLIN != 0 {
                    ready |= LINUX_EPOLLIN;
                }
                if pfd.revents & libc::POLLOUT != 0 {
                    ready |= LINUX_EPOLLOUT;
                }
                if pfd.revents & libc::POLLPRI != 0 {
                    ready |= LINUX_EPOLLPRI;
                }
                if pfd.revents & libc::POLLHUP != 0 {
                    ready |= LINUX_EPOLLHUP;
                }
                if pfd.revents & libc::POLLERR != 0 {
                    ready |= LINUX_EPOLLERR;
                }
                // Only report events the caller is watching, plus the
                // always-reported HUP/ERR conditions Linux delivers regardless.
                ready & (requested_events | LINUX_EPOLLHUP | LINUX_EPOLLERR)
            }
        }
    }

    pub(super) fn pselect6<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nfds = usize::try_from(ctx.arg(0))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(0)))?;
        let readfds_addr = ctx.arg(1);
        let writefds_addr = ctx.arg(2);
        let exceptfds_addr = ctx.arg(3);
        let timeout_addr = ctx.arg(4);
        let request = &ctx.request;
        let memory = &mut *ctx.memory;
        let reporter = &mut *ctx.reporter;

        // Decode timespec → millis for libc::poll. NULL = block forever (-1).
        let timeout_ms: i32 = if timeout_addr == 0 {
            -1
        } else {
            match memory.read_bytes(timeout_addr, 16) {
                Ok(b) if b.len() == 16 => {
                    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
                    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
                    let ms = sec
                        .saturating_mul(1000)
                        .saturating_add(nsec / 1_000_000);
                    if ms <= 0 {
                        0
                    } else if ms > i32::MAX as i64 {
                        i32::MAX
                    } else {
                        ms as i32
                    }
                }
                _ => 0,
            }
        };

        // Pull each fd_set into memory.
        let read_set = match self.read_optional_fd_set(memory, readfds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let write_set = match self.read_optional_fd_set(memory, writefds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let except_set = match self.read_optional_fd_set(memory, exceptfds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        // Collect the union of the three sets into per-fd entries, and try to
        // map each guest fd to a real host fd. Then route exactly like ppoll:
        //   - all fds host-backed → one libc::poll (kernel blocks efficiently);
        //   - any fd synthetic (eventfd/timerfd/epoll/in-memory pipe) → the
        //     poll_ready_events readiness loop, which is correct for those.
        // The old code unwrap_or'd synthetic fds into the guest fd *number* and
        // polled that as a host fd — which blocks on carrick's own fds and
        // deadlocks. Each fd gets POLLIN/POLLOUT/POLLPRI per its set membership.
        let mut owners: Vec<(i32, i16)> = Vec::new(); // (fd, requested_mask)
        let mut events_list: Vec<i16> = Vec::new();
        let mut host_map: Vec<Option<i32>> = Vec::new();
        for fd in 0..nfds {
            let r = read_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            let w = write_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            let e = except_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            if !(r || w || e) {
                continue;
            }
            let fd_i32 = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
            if !self.fd_is_valid(fd_i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let mut events: i16 = 0;
            if r { events |= libc::POLLIN; }
            if w { events |= libc::POLLOUT; }
            if e { events |= libc::POLLPRI; }
            let mut req_mask: i16 = 0;
            if r { req_mask |= 0x01; }
            if w { req_mask |= 0x02; }
            if e { req_mask |= 0x04; }
            owners.push((fd_i32, req_mask));
            events_list.push(events);
            host_map.push(self.host_fd_for_poll(fd_i32));
        }

        // revents per entry, filled by whichever path runs.
        let mut revents: Vec<i16> = vec![0; owners.len()];
        let all_host: Option<Vec<i32>> = host_map.iter().copied().collect();

        if owners.is_empty() {
            if timeout_ms > 0 {
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: (timeout_ms / 1000) as libc::time_t,
                        tv_nsec: ((timeout_ms % 1000) as i64 * 1_000_000) as libc::c_long,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
            }
        } else if let Some(host_fds) = all_host {
            let mut pollfds: Vec<libc::pollfd> = host_fds
                .iter()
                .zip(events_list.iter())
                .map(|(hf, ev)| libc::pollfd { fd: *hf, events: *ev, revents: 0 })
                .collect();
            let n = unsafe {
                libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            for (slot, p) in revents.iter_mut().zip(pollfds.iter()) {
                *slot = p.revents;
            }
        } else {
            // Mixed/synthetic: per-fd readiness with nanosleep slicing.
            let mut deadline_attempts = 0u32;
            loop {
                let mut any = false;
                for (i, (fd, _)) in owners.iter().enumerate() {
                    let rev = self.poll_ready_events(*fd, events_list[i]);
                    revents[i] = rev;
                    if rev != 0 {
                        any = true;
                    }
                }
                if any || timeout_ms == 0 {
                    break;
                }
                const SLICE_MS: u32 = 10;
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: (SLICE_MS as i64) * 1_000_000,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
                deadline_attempts += 1;
                if timeout_ms > 0 {
                    if deadline_attempts.saturating_mul(SLICE_MS) as i32 >= timeout_ms {
                        break;
                    }
                } else if deadline_attempts > 6000 {
                    // Blocked ~60 s with no fd ever ready: almost certainly a
                    // missing readiness signal, not a real idle wait. Make it
                    // loud in `carrick trace` instead of silently returning 0.
                    reporter.record(CompatEvent::partial_syscall(
                        request.number,
                        "pselect6",
                        request.args,
                        "blocked ~60s with no fd ready (possible poll deadlock)",
                    ));
                    break;
                }
            }
        }

        // Adapter so the writeback below reads `p.revents` uniformly.
        let pollfds: Vec<libc::pollfd> = owners
            .iter()
            .zip(revents.iter())
            .map(|((fd, _), rev)| libc::pollfd { fd: *fd, events: 0, revents: *rev })
            .collect();

        // Write back ready bits. Start with fully-cleared sets and only
        // set bits for fds that fired.
        let mut new_read = read_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut new_write = write_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut new_except = except_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut ready = 0i64;
        for ((fd, req_mask), p) in owners.iter().zip(pollfds.iter()) {
            let fd_usize = *fd as usize;
            let revs = p.revents;
            let mut fired = false;
            if (req_mask & 0x01) != 0 && (revs & (libc::POLLIN | libc::POLLHUP)) != 0 {
                if let Some(ref mut set) = new_read { fd_set_set(set, fd_usize); fired = true; }
            }
            if (req_mask & 0x02) != 0 && (revs & libc::POLLOUT) != 0 {
                if let Some(ref mut set) = new_write { fd_set_set(set, fd_usize); fired = true; }
            }
            if (req_mask & 0x04) != 0 && (revs & (libc::POLLPRI | libc::POLLERR)) != 0 {
                if let Some(ref mut set) = new_except { fd_set_set(set, fd_usize); fired = true; }
            }
            if fired { ready += 1; }
        }
        if let Some(s) = &new_read {
            if memory.write_bytes(readfds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if let Some(s) = &new_write {
            if memory.write_bytes(writefds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if let Some(s) = &new_except {
            if memory.write_bytes(exceptfds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: ready })
    }

    fn read_optional_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
    ) -> Result<Result<Option<Vec<u8>>, i32>, DispatchError> {
        if address == 0 {
            return Ok(Ok(None));
        }
        match read_fd_set(memory, address, nfds) {
            Ok(s) => Ok(Ok(Some(s))),
            Err(errno) => Ok(Err(errno)),
        }
    }

    fn filter_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
        interest: PollInterest,
    ) -> Result<Result<usize, i32>, DispatchError> {
        if address == 0 {
            return Ok(Ok(0));
        }
        let mut fd_set = match read_fd_set(memory, address, nfds) {
            Ok(fd_set) => fd_set,
            Err(errno) => return Ok(Err(errno)),
        };
        let mut ready_count = 0usize;
        for fd in 0..nfds {
            if !fd_set_contains(&fd_set, fd) {
                continue;
            }
            let fd = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
            if !self.fd_is_valid(fd) {
                return Ok(Err(LINUX_EBADF));
            }
            if self.poll_ready_events(fd, interest.poll_events()) & interest.poll_events() == 0 {
                fd_set_clear(&mut fd_set, fd as usize);
            } else {
                ready_count += 1;
            }
        }
        if memory.write_bytes(address, &fd_set).is_err() {
            return Ok(Err(LINUX_EFAULT));
        }
        Ok(Ok(ready_count))
    }

    pub(super) fn ppoll<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pollfds_address = ctx.arg(0);
        let nfds = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let timeout_address = ctx.arg(2);
        let request = &ctx.request;
        let memory = &mut *ctx.memory;
        let reporter = &mut *ctx.reporter;

        // Decode timeout. NULL pointer means block forever; non-NULL points
        // to a `struct timespec { i64 tv_sec; i64 tv_nsec; }`. We translate
        // to milliseconds for libc::poll (-1 = forever, 0 = immediate).
        let timeout_ms: i32 = if timeout_address == 0 {
            -1
        } else {
            match memory.read_bytes(timeout_address, 16) {
                Ok(b) if b.len() == 16 => {
                    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
                    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
                    let ms = sec
                        .saturating_mul(1000)
                        .saturating_add(nsec / 1_000_000);
                    if ms <= 0 {
                        0
                    } else if ms > i32::MAX as i64 {
                        i32::MAX
                    } else {
                        ms as i32
                    }
                }
                _ => 0,
            }
        };

        // Read all the pollfds up front so we can route them. Fast path:
        // every fd in the set maps to a host fd (stdio bare, HostPipe, or
        // HostSocket) → call libc::poll once with the requested timeout
        // and let the kernel block efficiently instead of pseudo-polling
        // in a 10 ms-slice loop.
        let pollfd_size = core::mem::size_of::<LinuxPollFd>();
        let mut fds: Vec<LinuxPollFd> = Vec::with_capacity(nfds);
        let mut addresses: Vec<u64> = Vec::with_capacity(nfds);
        for index in 0..nfds {
            let offset = index
                .checked_mul(pollfd_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let address = pollfds_address
                .checked_add(offset)
                .ok_or(LINUX_EFAULT);
            let address = match address {
                Ok(a) => a,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            };
            let pollfd = match read_pollfd(memory, address) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            fds.push(pollfd);
            addresses.push(address);
        }
        // Map guest fds → host fds where possible. Fast path requires
        // every fd be host-backed (stdio bare, HostPipe, HostSocket).
        let host_fds: Option<Vec<i32>> = fds
            .iter()
            .map(|p| self.host_fd_for_poll(p.fd))
            .collect();
        if let Some(host_fds) = host_fds {
            let mut sys_pollfds: Vec<libc::pollfd> = fds
                .iter()
                .zip(host_fds.iter())
                .map(|(p, hf)| libc::pollfd {
                    fd: *hf,
                    events: p.events as i16,
                    revents: 0,
                })
                .collect();
            let n = unsafe {
                libc::poll(
                    sys_pollfds.as_mut_ptr(),
                    sys_pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: host_errno(),
                });
            }
            let mut ready = 0i64;
            for (i, p) in sys_pollfds.iter().enumerate() {
                let mut pollfd = fds[i];
                pollfd.revents = p.revents as i16;
                if pollfd.revents != 0 {
                    ready += 1;
                }
                if write_kernel_struct_raw(memory, addresses[i], &pollfd).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            }
            return Ok(DispatchOutcome::Returned { value: ready });
        }

        // Mixed / synthetic fds: fall back to the per-fd readiness check
        // loop. Slow because of nanosleep slicing but correct.
        let mut ready = 0i64;
        let mut deadline_attempts = 0u32;
        loop {
            ready = 0;
            for (index, pollfd) in fds.iter_mut().enumerate() {
                pollfd.revents = self.poll_ready_events(pollfd.fd, pollfd.events);
                if pollfd.revents != 0 {
                    ready += 1;
                }
                if write_kernel_struct_raw(memory, addresses[index], pollfd).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            }
            if ready > 0 || timeout_ms == 0 {
                break;
            }
            const SLICE_MS: u32 = 10;
            unsafe {
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: (SLICE_MS as i64) * 1_000_000,
                };
                libc::nanosleep(&ts, std::ptr::null_mut());
            }
            deadline_attempts += 1;
            if timeout_ms > 0 {
                let elapsed_ms = deadline_attempts.saturating_mul(SLICE_MS);
                if elapsed_ms as i32 >= timeout_ms {
                    break;
                }
            } else if deadline_attempts > 6000 {
                // ~60 s ceiling for "block forever" callers. Reaching it means
                // no fd ever became ready — surface it loudly in carrick trace
                // rather than silently returning 0 (a likely poll deadlock).
                reporter.record(CompatEvent::partial_syscall(
                    request.number,
                    "ppoll",
                    request.args,
                    "blocked ~60s with no fd ready (possible poll deadlock)",
                ));
                break;
            }
        }

        Ok(DispatchOutcome::Returned { value: ready })
    }

    /// Return the host fd backing a guest fd for ppoll's fast path.
    /// `Some(host_fd)` means we can hand this off to libc::poll.
    /// `None` means it's synthetic (epoll/eventfd/timerfd/in-memory pipe)
    /// and ppoll has to fall back to the per-fd readiness loop.
    fn host_fd_for_poll(&self, fd: i32) -> Option<i32> {
        if fd < 0 {
            // Negative fd in a pollfd entry: libc::poll ignores it
            // (revents=0), which is the right semantic. Pass it through.
            return Some(fd);
        }
        if let Some(open_file) = self.open_files.get(&fd) {
            let open = open_file.description.borrow();
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
                _ => None,
            };
        }
        if is_stdio_fd(fd) {
            return Some(fd);
        }
        // Unknown fd: do NOT pass the guest fd number through as a host fd
        // (host fds 3,4,5… belong to carrick itself — the cap-std rootfs dir,
        // the HVF device, etc., so polling them blocks on the wrong object).
        // Route to the synthetic readiness path instead.
        None
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return if is_stdio_fd(fd) {
                // fd 1/2 are always writable (we either buffer or stream
                // straight to host write). For fd 0 we have to actually
                // poll the host because the guest's read(0,...) ultimately
                // calls libc::read(0,...); without a real readiness check,
                // ppoll would always return POLLOUT only and never POLLIN,
                // breaking interactive shells that ppoll(stdin) before
                // each prompt.
                let mut revents = requested_events & LINUX_POLLOUT;
                if fd == 0 && (requested_events & LINUX_POLLIN) != 0 {
                    let mut pfd = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let n = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                    if n > 0 {
                        if pfd.revents & libc::POLLIN != 0 {
                            revents |= LINUX_POLLIN;
                        }
                        if pfd.revents & libc::POLLHUP != 0 {
                            revents |= LINUX_POLLHUP;
                        }
                    }
                }
                revents
            } else {
                LINUX_POLLNVAL
            };
        };
        let open = open_file.description.borrow();
        let mut ready = 0;
        match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            // Regular files are always ready for read and write.
            OpenDescription::HostFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::Directory { .. } => {}
            OpenDescription::EventFd { counter, .. } => {
                if requested_events & LINUX_POLLIN != 0 && *counter > 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                ..
            } => {
                if requested_events & LINUX_POLLIN != 0
                    && timerfd_expirations(*clock_id, *interval, *deadline, *expirations).0 > 0
                {
                    ready |= LINUX_POLLIN;
                }
            }
            OpenDescription::Epoll { .. } => {}
            OpenDescription::PipeReader { pipe, .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    let pipe = pipe.borrow();
                    if !pipe.buffer.is_empty() {
                        ready |= LINUX_POLLIN;
                    }
                    if pipe.writers == 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let pipe = pipe.borrow();
                if pipe.readers == 0 {
                    ready |= LINUX_POLLERR;
                } else if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::HostPipe { .. } => {
                // Polling host pipes correctly requires poll(2) on the
                // host fd. For now report nothing ready and let the
                // guest block in a real read/write.
            }
            OpenDescription::HostSocket { host_fd, .. } => {
                // Poll the real host fd so the guest's poll loop reflects
                // actual kernel readiness for the socket.
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::Netlink { recv_queue, .. } => {
                // A netlink socket is "readable" once a dump response has
                // been queued (by a prior sendto/sendmsg), and always
                // writable (the kernel never blocks rtnetlink requests).
                if requested_events & LINUX_POLLIN != 0 && !recv_queue.is_empty() {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
        }
        ready
    }

    pub(super) fn socket<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let family = ctx.arg(0) as i32;
        let type_ = ctx.arg(1) as i32;
        let protocol = ctx.arg(2) as i32;
        // AF_NETLINK has no macOS equivalent, so we can't back it with a
        // host socket. Model a synthetic netlink fd instead (see the
        // `OpenDescription::Netlink` docs) so glibc's __check_pf /
        // getaddrinfo and `ip`/`ss` get a valid fd rather than
        // EAFNOSUPPORT.
        if family == LINUX_AF_NETLINK {
            return Ok(self.netlink_socket(type_, protocol));
        }
        Ok(self.host_socket_install(family, type_, protocol))
    }

    /// Create a synthetic AF_NETLINK socket. Linux accepts SOCK_RAW and
    /// SOCK_DGRAM for netlink (they're equivalent there); other socket
    /// types are rejected with ESOCKTNOSUPPORT, matching the kernel.
    fn netlink_socket(&mut self, type_: i32, protocol: i32) -> DispatchOutcome {
        let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
        let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
        let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
        if base_type != LINUX_SOCK_RAW && base_type != LINUX_SOCK_DGRAM {
            return DispatchOutcome::Errno {
                errno: LINUX_ESOCKTNOSUPPORT,
            };
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        self.install_fd(
            OpenDescription::Netlink {
                protocol,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                status_flags,
            },
            fd_flags,
        )
    }

    fn host_socket_install(
        &mut self,
        family: i32,
        type_: i32,
        protocol: i32,
    ) -> DispatchOutcome {
        // Strip the Linux-only SOCK_NONBLOCK / SOCK_CLOEXEC bits before
        // we hand the type to macOS, then set them on the resulting fd
        // by hand.
        let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
        let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
        let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
        let host_family = linux_to_host_af(family);
        let host_type = linux_to_host_socktype(base_type);
        let host_fd = unsafe { libc::socket(host_family, host_type, protocol) };
        if host_fd < 0 {
            return DispatchOutcome::Errno { errno: host_errno() };
        }
        if nonblock {
            unsafe {
                let flags = libc::fcntl(host_fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(host_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(linux_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(host_fd); }
            return DispatchOutcome::Errno { errno: LINUX_EINVAL };
        };
        self.insert_open_file(
            linux_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: linux_fd as i64 }
    }

    pub(super) fn socketpair<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let family = ctx.request.arg(0) as i32;
        let type_ = ctx.request.arg(1) as i32;
        let protocol = ctx.request.arg(2) as i32;
        let sv_addr = ctx.request.arg(3);
        let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
        let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
        let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
        let host_family = linux_to_host_af(family);
        let host_type = linux_to_host_socktype(base_type);

        let mut host_fds: [i32; 2] = [-1, -1];
        let rc = unsafe {
            libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr())
        };
        if rc != 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if nonblock {
            for fd in &host_fds {
                unsafe {
                    let flags = libc::fcntl(*fd, libc::F_GETFL);
                    if flags >= 0 {
                        libc::fcntl(*fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(read_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: host_fds[0],
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        self.insert_open_file(
            write_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: host_fds[1],
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// Pull a (host_fd, family) pair out of the dispatcher's fd table.
    fn host_socket_lookup(&self, fd: i32) -> Result<(i32, i32), i32> {
        let Some(open_file) = self.open_files.get(&fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::HostSocket { host_fd, family, .. } => Ok((*host_fd, *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    /// True iff `fd` refers to a synthetic AF_NETLINK socket.
    fn fd_is_netlink(&self, fd: i32) -> bool {
        self.open_files.get(&fd).is_some_and(|of| {
            matches!(&*of.description.borrow(), OpenDescription::Netlink { .. })
        })
    }

    /// Handle a netlink "send": parse the request and queue a synthetic
    /// rtnetlink dump reply (or a bare NLMSG_DONE for requests we don't
    /// specifically model). Returns the number of bytes "sent".
    fn netlink_send(&mut self, fd: i32, request: &[u8]) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let reply = {
            let open = open_file.description.borrow();
            let OpenDescription::Netlink { pid, .. } = &*open else {
                return DispatchOutcome::Errno { errno: LINUX_ENOTSOCK };
            };
            let dest_pid = if *pid != 0 { *pid } else { std::process::id() };
            build_netlink_reply(request, dest_pid)
        };
        if let OpenDescription::Netlink { recv_queue, .. } =
            &mut *open_file.description.borrow_mut()
        {
            recv_queue.extend(reply);
        }
        DispatchOutcome::Returned {
            value: request.len() as i64,
        }
    }

    /// recvfrom path for netlink: drain queued reply bytes into guest memory.
    fn netlink_recv(
        &mut self,
        fd: i32,
        buf_addr: u64,
        len: usize,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let chunk = self.netlink_drain(fd, len);
        if !chunk.is_empty() && memory.write_bytes(buf_addr, &chunk).is_err() {
            return DispatchOutcome::Errno { errno: LINUX_EFAULT };
        }
        DispatchOutcome::Returned {
            value: chunk.len() as i64,
        }
    }

    /// Pop up to `max` bytes from the netlink recv queue. Our synthetic
    /// reply is built as one contiguous dump, so a single drain that fits
    /// the caller's buffer returns the whole thing.
    fn netlink_drain(&mut self, fd: i32, max: usize) -> Vec<u8> {
        let Some(open_file) = self.open_files.get(&fd) else {
            return Vec::new();
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Vec::new();
        };
        let take = recv_queue.len().min(max);
        recv_queue.drain(..take).collect()
    }

    pub(super) fn bind<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen = ctx.request.arg(2) as u32;
        // AF_NETLINK bind: read the (optional) sockaddr_nl to pick up the
        // requested pid/groups, then assign a pid (the guest's own pid
        // when the caller passed 0, i.e. "let the kernel choose").
        if let Some(open_file) = self.open_files.get(&fd) {
            if let OpenDescription::Netlink {
                pid: nl_pid,
                groups: nl_groups,
                ..
            } = &mut *open_file.description.borrow_mut()
            {
                let (req_pid, req_groups) = read_sockaddr_nl(memory, addr_addr, addrlen);
                *nl_pid = if req_pid != 0 {
                    req_pid
                } else {
                    std::process::id()
                };
                *nl_groups = req_groups;
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
        }
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // AF_UNIX pathname sockets are bound at a stable host path (see
        // unix_socket_host_path). The guest's unlink only tombstones a VFS
        // overlay entry, so it can't clear a real host socket left by a
        // prior run — which would make bind() fail with EADDRINUSE. Mirror
        // Linux's unlink-then-bind by removing a stale *socket* node here
        // before binding (only if it is actually a socket, never a regular
        // file or directory, to stay safe).
        if family == libc::AF_UNIX && host_addr.len() > 2 && host_addr[2] != 0 {
            let path_end = host_addr[2..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| 2 + p)
                .unwrap_or(host_addr.len());
            if let Ok(path) = std::str::from_utf8(&host_addr[2..path_end]) {
                if let Ok(md) = std::fs::symlink_metadata(path) {
                    use std::os::unix::fs::FileTypeExt;
                    if md.file_type().is_socket() {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
        }
        let rc = unsafe {
            libc::bind(host_fd, host_addr.as_ptr() as *const _, host_addr.len() as u32)
        };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    pub(super) fn listen<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let backlog = ctx.arg(1) as i32;
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe { libc::listen(host_fd, backlog) };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    pub(super) fn accept<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request = ctx.request;
        Ok(self.accept_common(request, &mut *ctx.memory, 0))
    }

    pub(super) fn accept4<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(3) as i32;
        let request = ctx.request;
        Ok(self.accept_common(request, &mut *ctx.memory, flags))
    }

    fn accept_common(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let addr_addr = request.arg(1);
        let addrlen_addr = request.arg(2);
        let (host_fd, family, type_) = {
            let Some(open_file) = self.open_files.get(&fd) else {
                return DispatchOutcome::Errno { errno: LINUX_EBADF };
            };
            match &*open_file.description.borrow() {
                OpenDescription::HostSocket { host_fd, family, type_, .. } => {
                    (*host_fd, *family, *type_)
                }
                _ => return DispatchOutcome::Errno { errno: LINUX_ENOTSOCK },
            }
        };
        let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
        let new_host = unsafe {
            libc::accept(
                host_fd,
                sa_storage.as_mut_ptr() as *mut _,
                &mut sa_len as *mut _,
            )
        };
        if new_host < 0 {
            return DispatchOutcome::Errno { errno: host_errno() };
        }
        let nonblock = accept4_flags & LINUX_SOCK_NONBLOCK as i32 != 0;
        let cloexec = accept4_flags & LINUX_SOCK_CLOEXEC as i32 != 0;
        if nonblock {
            unsafe {
                let flags = libc::fcntl(new_host, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(new_host, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        if addr_addr != 0 && addrlen_addr != 0 {
            let used = (sa_len as usize).min(sa_storage.len());
            let linux_bytes = host_to_linux_sockaddr(&sa_storage[..used], family);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                unsafe { libc::close(new_host); }
                return DispatchOutcome::Errno { errno: LINUX_EFAULT };
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(linux_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(new_host); }
            return DispatchOutcome::Errno { errno: LINUX_EINVAL };
        };
        self.insert_open_file(
            linux_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: new_host,
                    family,
                    type_,
                    status_flags,
                })),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: linux_fd as i64 }
    }

    pub(super) fn connect<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen = ctx.request.arg(2) as u32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe {
            libc::connect(host_fd, host_addr.as_ptr() as *const _, host_addr.len() as u32)
        };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    pub(super) fn getsockname<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen_addr = ctx.request.arg(2);
        // AF_NETLINK getsockname: hand back a sockaddr_nl carrying the
        // bound pid/groups (or pid=0 if the socket was never bound).
        if let Some(open_file) = self.open_files.get(&fd) {
            if let OpenDescription::Netlink { pid, groups, .. } =
                &*open_file.description.borrow()
            {
                let nl = sockaddr_nl_bytes(*pid, *groups);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &nl).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
        }
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockname(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _)
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (sa_len as usize).min(sa.len());
        let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpeername<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen_addr = ctx.request.arg(2);
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _)
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (sa_len as usize).min(sa.len());
        let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sendto<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let buf_addr = ctx.request.arg(1);
        let len = ctx.request.arg(2) as usize;
        let flags = ctx.request.arg(3) as i32;
        let dest_addr = ctx.request.arg(4);
        let dest_len = ctx.request.arg(5) as u32;
        // AF_NETLINK send: treat the payload as an rtnetlink request and
        // queue a synthetic dump reply for the next recv.
        if self.fd_is_netlink(fd) {
            let bytes = match memory.read_bytes(buf_addr, len) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            };
            return Ok(self.netlink_send(fd, &bytes));
        }
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match memory.read_bytes(buf_addr, len) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        let host_flags = linux_to_host_msg_flags(flags);
        let n = if dest_addr == 0 {
            unsafe {
                libc::sendto(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    host_flags,
                    std::ptr::null(),
                    0,
                )
            }
        } else {
            let host_addr = match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                Ok(b) => b,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            unsafe {
                libc::sendto(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    host_flags,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            }
        };
        Ok(if n < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: n as i64 }
        })
    }

    pub(super) fn recvfrom<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let buf_addr = ctx.request.arg(1);
        let len = ctx.request.arg(2) as usize;
        let flags = ctx.request.arg(3) as i32;
        let src_addr = ctx.request.arg(4);
        let src_len_addr = ctx.request.arg(5);
        // AF_NETLINK recv: drain the queued dump reply. The source address
        // (if requested) is the kernel: sockaddr_nl with pid=0.
        if self.fd_is_netlink(fd) {
            let drained = self.netlink_recv(fd, buf_addr, len, memory);
            if let DispatchOutcome::Returned { .. } = drained {
                if src_addr != 0 && src_len_addr != 0 {
                    let nl = sockaddr_nl_bytes(0, 0);
                    let _ = write_linux_sockaddr(memory, src_addr, src_len_addr, &nl);
                }
            }
            return Ok(drained);
        }
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_flags = linux_to_host_msg_flags(flags);
        let mut buf = vec![0u8; len];
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let (n, used_addr) = if src_addr == 0 {
            let n = unsafe {
                libc::recvfrom(
                    host_fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    host_flags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            (n, false)
        } else {
            let n = unsafe {
                libc::recvfrom(
                    host_fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    host_flags,
                    sa.as_mut_ptr() as *mut _,
                    &mut sa_len as *mut _,
                )
            };
            (n, true)
        };
        if n < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if n > 0 {
            let bytes = &buf[..n as usize];
            if memory.write_bytes(buf_addr, bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if used_addr && src_addr != 0 && src_len_addr != 0 {
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
            if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: n as i64 })
    }

    pub(super) fn setsockopt<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let level = ctx.request.arg(1) as i32;
        let optname = ctx.request.arg(2) as i32;
        let optval_addr = ctx.request.arg(3);
        let optlen = ctx.request.arg(4) as u32;
        // AF_NETLINK setsockopt: glibc/`ip` set SO_RCVBUF / SO_SNDBUF and
        // netlink-specific options (NETLINK_*). We don't model buffer
        // pressure, so just accept them.
        if self.fd_is_netlink(fd) {
            let _ = (level, optname, optval_addr, optlen);
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
            Some(t) => t,
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_ENOPROTOOPT }),
        };
        let bytes = if optval_addr == 0 || optlen == 0 {
            Vec::new()
        } else {
            match memory.read_bytes(optval_addr, optlen as usize) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            }
        };
        let rc = unsafe {
            libc::setsockopt(
                host_fd,
                host_level,
                host_opt,
                if bytes.is_empty() {
                    std::ptr::null()
                } else {
                    bytes.as_ptr() as *const _
                },
                bytes.len() as u32,
            )
        };
        Ok(if rc < 0 {
            // Linux apps frequently set options that aren't supported on
            // macOS (eg IP_MTU_DISCOVER); swallow ENOPROTOOPT silently
            // when the equivalent option simply doesn't exist on macOS.
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    pub(super) fn getsockopt<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let level = ctx.request.arg(1) as i32;
        let optname = ctx.request.arg(2) as i32;
        let optval_addr = ctx.request.arg(3);
        let optlen_addr = ctx.request.arg(4);
        // AF_NETLINK getsockopt: answer the common SO_TYPE query (callers
        // verify the socket is SOCK_RAW); everything else returns 0.
        if self.fd_is_netlink(fd) {
            let val: i32 = if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE {
                LINUX_SOCK_RAW
            } else {
                0
            };
            let _ = memory.write_bytes(optval_addr, &val.to_ne_bytes());
            let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
            Some(t) => t,
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_ENOPROTOOPT }),
        };
        // Read the guest's reported optlen so we don't overflow.
        let optlen_bytes = match memory.read_bytes(optlen_addr, 4) {
            Ok(b) => b,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        let mut optlen = u32::from_ne_bytes([
            optlen_bytes[0], optlen_bytes[1], optlen_bytes[2], optlen_bytes[3],
        ]);
        let cap = optlen.min(256) as usize;
        let mut buf = vec![0u8; cap];
        let rc = unsafe {
            libc::getsockopt(
                host_fd,
                host_level,
                host_opt,
                buf.as_mut_ptr() as *mut _,
                &mut optlen as *mut _,
            )
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (optlen as usize).min(buf.len());
        if optval_addr != 0 && used > 0 {
            if memory.write_bytes(optval_addr, &buf[..used]).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if memory.write_bytes(optlen_addr, &optlen.to_ne_bytes()).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn shutdown<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let how = ctx.arg(1) as i32;
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe { libc::shutdown(host_fd, how) };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    pub(super) fn sendmsg<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let msg_addr = ctx.request.arg(1);
        let flags = ctx.request.arg(3) as i32;
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (-1, LINUX_AF_NETLINK)
        } else {
            match self.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            }
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Pack iovecs into a single contiguous send. Simple and avoids
        // having to keep guest pointers alive across the FFI call.
        let mut data = Vec::new();
        for iov in iovecs {
            let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            };
            data.extend_from_slice(&chunk);
        }
        // AF_NETLINK: parse the assembled request and queue a synthetic
        // dump reply, ignoring the destination sockaddr (always the kernel).
        if is_netlink {
            return Ok(self.netlink_send(fd, &data));
        }
        let host_flags = linux_to_host_msg_flags(flags);
        let n = if msg.name == 0 || msg.namelen == 0 {
            unsafe {
                libc::sendto(
                    host_fd,
                    data.as_ptr() as *const _,
                    data.len(),
                    host_flags,
                    std::ptr::null(),
                    0,
                )
            }
        } else {
            let host_addr = match read_linux_sockaddr(memory, msg.name, msg.namelen, family) {
                Ok(b) => b,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            unsafe {
                libc::sendto(
                    host_fd,
                    data.as_ptr() as *const _,
                    data.len(),
                    host_flags,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            }
        };
        Ok(if n < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: n as i64 }
        })
    }

    pub(super) fn recvmsg<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let msg_addr = ctx.request.arg(1);
        let flags = ctx.request.arg(2) as i32;
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (-1, LINUX_AF_NETLINK)
        } else {
            match self.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            }
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // AF_NETLINK: drain the queued dump reply into the iovecs, fill in
        // the source sockaddr_nl (kernel; pid=0), and zero controllen/flags.
        if is_netlink {
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            let chunk = self.netlink_drain(fd, total);
            let n = chunk.len();
            let mut remaining = n;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(iov.iov_len as usize);
                if take > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &chunk[cursor..cursor + take])
                        .is_err()
                    {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                    }
                    cursor += take;
                    remaining -= take;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let nl = sockaddr_nl_bytes(0, 0);
                let write_len = (nl.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &nl[..write_len as usize])
                        .is_err()
                {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                let _ = memory.write_bytes(msg_addr + 8, &(nl.len() as u32).to_ne_bytes());
            }
            let _ = memory.write_bytes(msg_addr + 40, &0u64.to_ne_bytes());
            let _ = memory.write_bytes(msg_addr + 48, &0i32.to_ne_bytes());
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        let mut buf = vec![0u8; total];
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                host_fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                linux_to_host_msg_flags(flags),
                if msg.name == 0 { std::ptr::null_mut() } else { sa.as_mut_ptr() as *mut _ },
                if msg.name == 0 { std::ptr::null_mut() } else { &mut sa_len as *mut _ },
            )
        };
        if n < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        // Scatter the received bytes back into the guest's iovecs.
        let mut remaining = n as usize;
        let mut cursor = 0usize;
        for iov in iovecs {
            if remaining == 0 {
                break;
            }
            let chunk = remaining.min(iov.iov_len as usize);
            if chunk > 0 {
                if memory.write_bytes(iov.iov_base, &buf[cursor..cursor + chunk]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                cursor += chunk;
                remaining -= chunk;
            }
        }
        if msg.name != 0 && msg.namelen != 0 {
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
            // Write up to msg.namelen, then update the namelen field
            // inside the msghdr.
            let write_len = (linux_bytes.len() as u32).min(msg.namelen);
            if write_len > 0 {
                if memory.write_bytes(msg.name, &linux_bytes[..write_len as usize]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
            }
            // namelen lives at offset 8 (after the 8-byte name pointer).
            if memory
                .write_bytes(msg_addr + 8, &(linux_bytes.len() as u32).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        // We don't translate ancillary data; report controllen=0.
        if memory
            .write_bytes(msg_addr + 40, &0u64.to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        // msg_flags lives at offset 48 (just after controllen).
        if memory
            .write_bytes(msg_addr + 48, &0i32.to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: n as i64 })
    }

    /// `sendmmsg(sockfd, msgvec, vlen, flags)` — Linux's batched
    /// sendmsg. glibc's getaddrinfo uses sendmmsg for DNS queries even
    /// when only a single message is sent; without this handler the
    /// guest sees ENOSYS and bails with "Temporary failure resolving".
    /// Implemented as a loop over single sendmsgs, writing each entry's
    /// msg_len field with the bytes-sent on success.
    fn sendmmsg(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let msgvec = request.arg(1);
        let vlen = request.arg(2) as u32;
        let flags = request.arg(3) as i32;
        // mmsghdr = msghdr (56 bytes) + msg_len:u32 (4) + pad (4) = 64.
        const MMSGHDR_SIZE: u64 = 64;
        const MSG_LEN_OFFSET: u64 = 56;
        let mut sent: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
            };
            // Build a synthetic sendmsg request that points at this
            // entry's msg_hdr (which is the first 56 bytes of the
            // mmsghdr). Reusing sendmsg keeps the iovec-pack + sockaddr-
            // translate logic in one place.
            let inner_req = SyscallRequest::new(
                211, // sendmsg
                SyscallArgs([fd as u64, entry, 0, flags as u64, 0, 0]),
            );
            let mut inner_reporter = CompatReporter::default();
            let outcome = {
                let mut inner_ctx = SyscallCtx {
                    request: inner_req,
                    memory: &mut *memory,
                    reporter: &mut inner_reporter,
                };
                match self.sendmsg(&mut inner_ctx) {
                    Ok(o) => o,
                    // sendmsg never produces a DispatchError; surface it
                    // as EFAULT to keep this helper's bare-outcome contract.
                    Err(_) => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::Errno { errno: LINUX_EFAULT };
                    }
                    sent += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if sent > 0 {
                        // At least one message went out — Linux returns
                        // the count of successful sends, and the errno
                        // surfaces on the next call.
                        return DispatchOutcome::Returned { value: sent as i64 };
                    }
                    return DispatchOutcome::Errno { errno };
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: sent as i64 }
    }

    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` — Linux's
    /// batched recvmsg. Same shape as sendmmsg: loop over entries,
    /// call single recvmsg for each, fill msg_len on success.
    /// The timeout argument is best-effort — we fall through to a
    /// single libc::poll up front if it's non-NULL and at least one
    /// message is wanted before blocking.
    fn recvmmsg(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let msgvec = request.arg(1);
        let vlen = request.arg(2) as u32;
        let flags = request.arg(3) as i32;
        const MMSGHDR_SIZE: u64 = 64;
        const MSG_LEN_OFFSET: u64 = 56;
        let mut received: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
            };
            // After the first successful recvmsg, switch to non-blocking
            // so we drain whatever else is in the queue without waiting.
            let entry_flags = if received > 0 {
                flags | (libc::MSG_DONTWAIT as i32)
            } else {
                flags
            };
            let inner_req = SyscallRequest::new(
                212, // recvmsg
                SyscallArgs([fd as u64, entry, entry_flags as u64, 0, 0, 0]),
            );
            let mut inner_reporter = CompatReporter::default();
            let outcome = {
                let mut inner_ctx = SyscallCtx {
                    request: inner_req,
                    memory: &mut *memory,
                    reporter: &mut inner_reporter,
                };
                match self.recvmsg(&mut inner_ctx) {
                    Ok(o) => o,
                    // recvmsg never produces a DispatchError; surface it
                    // as EFAULT to keep this helper's bare-outcome contract.
                    Err(_) => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::Errno { errno: LINUX_EFAULT };
                    }
                    received += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if received > 0 {
                        return DispatchOutcome::Returned { value: received as i64 };
                    }
                    return DispatchOutcome::Errno { errno };
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: received as i64 }
    }

    pub(super) fn sys_recvmmsg<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.recvmmsg(ctx.request, ctx.memory))
    }

    pub(super) fn sys_sendmmsg<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.sendmmsg(ctx.request, ctx.memory))
    }
}

fn read_epoll_event(memory: &impl GuestMemory, address: u64) -> Result<LinuxEpollEvent, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxEpollEvent>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxEpollEvent::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_pollfd(memory: &impl GuestMemory, address: u64) -> Result<LinuxPollFd, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxPollFd>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxPollFd::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_fd_set(memory: &impl GuestMemory, address: u64, nfds: usize) -> Result<Vec<u8>, i32> {
    let length = linux_fd_set_len(nfds).ok_or(LINUX_EINVAL)?;
    memory.read_bytes(address, length).map_err(|_| LINUX_EFAULT)
}

fn fd_set_contains(fd_set: &[u8], fd: usize) -> bool {
    fd_set
        .get(fd / 8)
        .is_some_and(|byte| byte & (1 << (fd % 8)) != 0)
}

fn fd_set_clear(fd_set: &mut [u8], fd: usize) {
    if let Some(byte) = fd_set.get_mut(fd / 8) {
        *byte &= !(1 << (fd % 8));
    }
}

fn fd_set_set(fd_set: &mut [u8], fd: usize) {
    if let Some(byte) = fd_set.get_mut(fd / 8) {
        *byte |= 1 << (fd % 8);
    }
}

fn linux_fd_set_len(nfds: usize) -> Option<usize> {
    nfds.checked_add(63)?.checked_div(64)?.checked_mul(8)
}

fn linux_to_host_af(family: i32) -> i32 {
    match family {
        LINUX_AF_UNSPEC => libc::AF_UNSPEC,
        LINUX_AF_UNIX => libc::AF_UNIX,
        LINUX_AF_INET => libc::AF_INET,
        LINUX_AF_INET6 => libc::AF_INET6,
        // Linux-only families. macOS doesn't have AF_NETLINK / AF_PACKET;
        // pass through whatever number was given so the host socket()
        // call returns EAFNOSUPPORT naturally.
        _ => family,
    }
}

fn host_to_linux_af(host_family: u16) -> u16 {
    match host_family as i32 {
        libc::AF_UNSPEC => LINUX_AF_UNSPEC as u16,
        libc::AF_UNIX => LINUX_AF_UNIX as u16,
        libc::AF_INET => LINUX_AF_INET as u16,
        libc::AF_INET6 => LINUX_AF_INET6 as u16,
        _ => host_family,
    }
}

fn linux_to_host_socktype(t: i32) -> i32 {
    // Linux and macOS agree on the numeric values for the BSD socket
    // types we care about (1=STREAM, 2=DGRAM, 3=RAW, 5=SEQPACKET).
    match t {
        LINUX_SOCK_STREAM => libc::SOCK_STREAM,
        LINUX_SOCK_DGRAM => libc::SOCK_DGRAM,
        LINUX_SOCK_RAW => libc::SOCK_RAW,
        LINUX_SOCK_SEQPACKET => libc::SOCK_SEQPACKET,
        _ => t,
    }
}

/// Parse a Linux `sockaddr_nl` (family(2) pad(2) pid(4) groups(4) = 12 bytes)
/// from guest memory, returning `(nl_pid, nl_groups)`. Missing / short
/// addresses yield zeros (kernel treats pid=0 as "auto-assign").
fn read_sockaddr_nl(memory: &impl GuestMemory, addr: u64, addrlen: u32) -> (u32, u32) {
    if addr == 0 || addrlen < 12 {
        return (0, 0);
    }
    match memory.read_bytes(addr, 12) {
        Ok(b) => {
            let pid = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
            let groups = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
            (pid, groups)
        }
        Err(_) => (0, 0),
    }
}

/// Build a Linux `sockaddr_nl` byte buffer for getsockname / recv source.
fn sockaddr_nl_bytes(pid: u32, groups: u32) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0..2].copy_from_slice(&(LINUX_AF_NETLINK as u16).to_ne_bytes());
    // bytes 2..4 are nl_pad (zero)
    out[4..8].copy_from_slice(&pid.to_ne_bytes());
    out[8..12].copy_from_slice(&groups.to_ne_bytes());
    out
}

/// Generic read(2)-style drain of a netlink recv queue into guest memory.
pub(super) fn drain_netlink_queue(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    queue: &mut VecDeque<u8>,
) -> DispatchOutcome {
    let take = queue.len().min(length);
    if take == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let chunk: Vec<u8> = queue.drain(..take).collect();
    if memory.write_bytes(address, &chunk).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    DispatchOutcome::Returned {
        value: chunk.len() as i64,
    }
}

/// Append a 4-byte-aligned rtattr (TLV) to `buf`.
fn push_rtattr(buf: &mut Vec<u8>, rta_type: u16, payload: &[u8]) {
    let rta_len = (std::mem::size_of::<LinuxRtAttr>() + payload.len()) as u16;
    let hdr = LinuxRtAttr { rta_len, rta_type };
    buf.extend_from_slice(hdr.as_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % NLMSG_ALIGNTO != 0 {
        buf.push(0);
    }
}

/// Wrap an already-built payload (header struct + attributes) in an
/// `nlmsghdr` and append it to `out`, 4-byte aligned. `nlmsg_len` covers
/// the header plus payload (unaligned, per the kernel).
fn push_nlmsg(out: &mut Vec<u8>, nlmsg_type: u16, seq: u32, pid: u32, payload: &[u8]) {
    let hdr_size = std::mem::size_of::<LinuxNlMsgHdr>();
    let nlmsg_len = (hdr_size + payload.len()) as u32;
    let hdr = LinuxNlMsgHdr {
        nlmsg_len,
        nlmsg_type,
        nlmsg_flags: LINUX_NLM_F_MULTI,
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(payload);
    while out.len() % NLMSG_ALIGNTO != 0 {
        out.push(0);
    }
}

/// Append a terminating NLMSG_DONE to `out`.
fn push_nlmsg_done(out: &mut Vec<u8>, seq: u32, pid: u32) {
    // NLMSG_DONE carries a 4-byte error/return code payload (0 = success).
    push_nlmsg(out, LINUX_NLMSG_DONE, seq, pid, &0i32.to_ne_bytes());
}

/// Build the synthetic rtnetlink reply for a guest's request. We inspect
/// the leading nlmsghdr's `nlmsg_type`:
///   - RTM_GETLINK  -> one RTM_NEWLINK for `lo`, then NLMSG_DONE
///   - RTM_GETADDR  -> one RTM_NEWADDR for `lo` (127.0.0.1/8), then NLMSG_DONE
///   - anything else -> a bare NLMSG_DONE (the dump is "empty")
/// All replies are NLM_F_MULTI dumps terminated by NLMSG_DONE, which is
/// what glibc's __check_pf and `ip` expect.
fn build_netlink_reply(request: &[u8], pid: u32) -> Vec<u8> {
    let hdr_size = std::mem::size_of::<LinuxNlMsgHdr>();
    let (req_type, seq) = if request.len() >= hdr_size {
        match LinuxNlMsgHdr::read_from_prefix(request) {
            Ok((h, _)) => (h.nlmsg_type, h.nlmsg_seq),
            Err(_) => (0u16, 0u32),
        }
    } else {
        (0, 0)
    };

    let mut out = Vec::new();
    match req_type {
        LINUX_RTM_GETLINK => {
            let mut payload = Vec::new();
            let ifi = LinuxIfInfoMsg {
                ifi_family: 0, // AF_UNSPEC
                ifi_pad: 0,
                ifi_type: LINUX_ARPHRD_LOOPBACK,
                ifi_index: 1,
                ifi_flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
                ifi_change: 0,
            };
            payload.extend_from_slice(ifi.as_bytes());
            // IFLA_IFNAME is a NUL-terminated string.
            push_rtattr(&mut payload, LINUX_IFLA_IFNAME, b"lo\0");
            // IFLA_ADDRESS: loopback hardware address (6 zero bytes).
            push_rtattr(&mut payload, LINUX_IFLA_ADDRESS, &[0u8; 6]);
            push_nlmsg(&mut out, LINUX_RTM_NEWLINK, seq, pid, &payload);
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETADDR => {
            let mut payload = Vec::new();
            let ifa = LinuxIfAddrMsg {
                ifa_family: LINUX_AF_INET as u8,
                ifa_prefixlen: 8,
                ifa_flags: 0,
                ifa_scope: 254, // RT_SCOPE_HOST
                ifa_index: 1,
            };
            payload.extend_from_slice(ifa.as_bytes());
            let loopback = [127u8, 0, 0, 1];
            push_rtattr(&mut payload, LINUX_IFA_ADDRESS, &loopback);
            push_rtattr(&mut payload, LINUX_IFA_LOCAL, &loopback);
            push_rtattr(&mut payload, LINUX_IFA_LABEL, b"lo\0");
            push_nlmsg(&mut out, LINUX_RTM_NEWADDR, seq, pid, &payload);
            push_nlmsg_done(&mut out, seq, pid);
        }
        _ => {
            // Unmodelled request (e.g. RTM_GETROUTE, RTM_GETNEIGH): return
            // an empty dump so the caller's enumeration loop terminates
            // cleanly rather than blocking.
            push_nlmsg_done(&mut out, seq, pid);
        }
    }
    out
}

fn linux_to_host_msg_flags(flags: i32) -> i32 {
    let mut out = 0;
    if flags & LINUX_MSG_OOB != 0 { out |= libc::MSG_OOB; }
    if flags & LINUX_MSG_PEEK != 0 { out |= libc::MSG_PEEK; }
    if flags & LINUX_MSG_DONTROUTE != 0 { out |= libc::MSG_DONTROUTE; }
    if flags & LINUX_MSG_TRUNC != 0 { out |= libc::MSG_TRUNC; }
    if flags & LINUX_MSG_DONTWAIT != 0 { out |= libc::MSG_DONTWAIT; }
    if flags & LINUX_MSG_EOR != 0 { out |= libc::MSG_EOR; }
    if flags & LINUX_MSG_WAITALL != 0 { out |= libc::MSG_WAITALL; }
    // MSG_NOSIGNAL is Linux-only. macOS expresses the equivalent via
    // SO_NOSIGPIPE on the socket; ignoring the flag is the best we can
    // do here. Likewise MSG_CMSG_CLOEXEC has no macOS equivalent.
    let _ = (LINUX_MSG_NOSIGNAL, LINUX_MSG_CMSG_CLOEXEC);
    out
}

fn linux_to_host_sockopt(level: i32, optname: i32) -> Option<(i32, i32)> {
    match level {
        LINUX_SOL_SOCKET => {
            let host_opt = match optname {
                LINUX_SO_DEBUG => libc::SO_DEBUG,
                LINUX_SO_REUSEADDR => libc::SO_REUSEADDR,
                LINUX_SO_TYPE => libc::SO_TYPE,
                LINUX_SO_ERROR => libc::SO_ERROR,
                LINUX_SO_DONTROUTE => libc::SO_DONTROUTE,
                LINUX_SO_BROADCAST => libc::SO_BROADCAST,
                LINUX_SO_SNDBUF => libc::SO_SNDBUF,
                LINUX_SO_RCVBUF => libc::SO_RCVBUF,
                LINUX_SO_KEEPALIVE => libc::SO_KEEPALIVE,
                LINUX_SO_OOBINLINE => libc::SO_OOBINLINE,
                LINUX_SO_LINGER => libc::SO_LINGER,
                LINUX_SO_REUSEPORT => libc::SO_REUSEPORT,
                LINUX_SO_RCVTIMEO => libc::SO_RCVTIMEO,
                LINUX_SO_SNDTIMEO => libc::SO_SNDTIMEO,
                LINUX_SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
                _ => return None,
            };
            Some((libc::SOL_SOCKET, host_opt))
        }
        LINUX_SOL_IP => Some((libc::IPPROTO_IP, optname)),
        LINUX_SOL_TCP => Some((libc::IPPROTO_TCP, optname)),
        LINUX_SOL_UDP => Some((libc::IPPROTO_UDP, optname)),
        LINUX_SOL_IPV6 => Some((libc::IPPROTO_IPV6, optname)),
        _ => None,
    }
}

/// Map a guest AF_UNIX *pathname* socket path to a stable host path.
///
/// Under `--fs host` the guest's view of the filesystem is a cap-std
/// sandboxed scratch dir; a guest path like `/tmp/net_bind.sock` is NOT a
/// real host path, and the guest's `unlink` only tombstones a VFS overlay
/// entry — it never touches a real host socket file. If `bind` handed the
/// raw guest path to `libc::bind` the macOS kernel would create the socket
/// at that literal host location, decoupled from the guest's unlink, so a
/// stale socket from a prior run yields EADDRINUSE.
///
/// To keep bind/connect/getsockname consistent (and let the probe's
/// unlink-then-bind work like Linux, with bind clearing any stale node),
/// every pathname socket is deterministically mapped into a single
/// per-run host directory. The mapping is a pure function of the guest
/// path, so a `connect` to the same guest path resolves to the same host
/// socket a prior `bind` created — including across forked children, which
/// inherit the same derivation. macOS `sun_path` is only 104 bytes, so the
/// host name is a short hash rather than the (possibly long) guest path.
///
/// Abstract-namespace sockets (Linux: leading NUL in sun_path) are NOT
/// pathname sockets and are returned unchanged.
fn unix_socket_host_dir() -> std::path::PathBuf {
    // One directory per host boot/run, shared by all forked guest
    // processes. TMPDIR keeps the absolute path short enough for sun_path.
    let base = std::env::temp_dir();
    base.join("carrick-unix-sockets")
}

/// Given the raw guest `sun_path` bytes (everything after the 2-byte
/// family), return the host pathname to bind/connect on, or `None` for an
/// abstract-namespace / autobind address (which we pass through verbatim).
fn unix_socket_host_path(sun_path: &[u8]) -> Option<std::path::PathBuf> {
    // Empty (autobind) or abstract (leading NUL): not a filesystem path.
    if sun_path.is_empty() || sun_path[0] == 0 {
        return None;
    }
    // Pathname socket: bytes up to the first NUL.
    let nul = sun_path.iter().position(|&b| b == 0).unwrap_or(sun_path.len());
    let guest_path = &sun_path[..nul];
    if guest_path.is_empty() {
        return None;
    }
    let dir = unix_socket_host_dir();
    let _ = std::fs::create_dir_all(&dir);
    // Short, collision-resistant, deterministic name derived from the guest
    // path so bind and connect agree and the result fits macOS sun_path.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in guest_path {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Some(dir.join(format!("{hash:016x}.sock")))
}

/// Translate a Linux-formatted sockaddr (read from guest memory) into the
/// macOS BSD form. Returns the host-formatted bytes ready to hand to
/// libc::bind/connect/sendto.
fn read_linux_sockaddr(
    memory: &impl GuestMemory,
    addr: u64,
    addrlen: u32,
    _family_hint: i32,
) -> Result<Vec<u8>, i32> {
    if addr == 0 || addrlen < 2 {
        return Err(LINUX_EINVAL);
    }
    let len = addrlen as usize;
    let bytes = memory.read_bytes(addr, len).map_err(|_| LINUX_EFAULT)?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        LINUX_AF_INET => {
            // sockaddr_in: family(2) port(2) addr(4) zero(8) = 16 bytes
            if len < 8 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 16];
            out[0] = 16; // sin_len
            out[1] = libc::AF_INET as u8; // sin_family
            out[2..4].copy_from_slice(&bytes[2..4]); // sin_port (network)
            out[4..8].copy_from_slice(&bytes[4..8]); // sin_addr
            Ok(out)
        }
        LINUX_AF_INET6 => {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4) = 28
            if len < 24 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 28];
            out[0] = 28;
            out[1] = libc::AF_INET6 as u8;
            out[2..4].copy_from_slice(&bytes[2..4]); // port
            out[4..8].copy_from_slice(&bytes[4..8]); // flowinfo
            out[8..24].copy_from_slice(&bytes[8..24]); // addr
            if len >= 28 {
                out[24..28].copy_from_slice(&bytes[24..28]); // scope_id
            }
            Ok(out)
        }
        LINUX_AF_UNIX => {
            // Linux sockaddr_un: family(2) sun_path[108]. macOS sockaddr_un
            // is sun_len(1) sun_family(1) sun_path[104].
            if len < 2 {
                return Err(LINUX_EINVAL);
            }
            let sun_path = &bytes[2..];
            match unix_socket_host_path(sun_path) {
                // Pathname socket: bind/connect on a stable host path so the
                // guest's filesystem view (and its unlink) doesn't have to
                // own the real socket node. See unix_socket_host_path.
                Some(host_path) => {
                    let p = host_path.to_string_lossy();
                    let pbytes = p.as_bytes();
                    // sun_path is fixed-size; macOS allows up to 104 bytes
                    // including the trailing NUL.
                    if pbytes.len() >= 104 {
                        return Err(LINUX_ENAMETOOLONG);
                    }
                    let mut out = vec![0u8; 2 + pbytes.len() + 1];
                    out[0] = out.len().min(255) as u8;
                    out[1] = libc::AF_UNIX as u8;
                    out[2..2 + pbytes.len()].copy_from_slice(pbytes);
                    Ok(out)
                }
                // Abstract / autobind: pass the raw bytes through unchanged.
                None => {
                    let path_len = len.saturating_sub(2);
                    let mut out = vec![0u8; 2 + path_len];
                    out[0] = (2 + path_len).min(255) as u8;
                    out[1] = libc::AF_UNIX as u8;
                    out[2..].copy_from_slice(&bytes[2..2 + path_len]);
                    Ok(out)
                }
            }
        }
        _ => Err(LINUX_EAFNOSUPPORT),
    }
}

/// Translate a macOS BSD sockaddr (as returned by accept/getsockname/...
/// into Linux-formatted bytes suitable for the guest to consume.
fn host_to_linux_sockaddr(bytes: &[u8], _family_hint: i32) -> Vec<u8> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    // macOS layout: sa_len(1) sa_family(1) ...
    let host_family = bytes[1] as u16;
    let linux_family = host_to_linux_af(host_family);
    match host_family as i32 {
        libc::AF_INET => {
            // Linux sockaddr_in: family(2) port(2) addr(4) zero(8) = 16
            let mut out = vec![0u8; 16];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            if bytes.len() >= 8 {
                out[2..4].copy_from_slice(&bytes[2..4]); // port
                out[4..8].copy_from_slice(&bytes[4..8]); // addr
            }
            out
        }
        libc::AF_INET6 => {
            let mut out = vec![0u8; 28];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            let take = bytes.len().min(28);
            if take > 2 {
                out[2..take].copy_from_slice(&bytes[2..take]);
            }
            out
        }
        libc::AF_UNIX => {
            // Linux sockaddr_un is family(2) path[108]. macOS path starts
            // at offset 2; skip the host's sun_len byte at offset 0.
            let path_len = bytes.len().saturating_sub(2);
            let mut out = vec![0u8; 2 + path_len];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            if path_len > 0 {
                out[2..].copy_from_slice(&bytes[2..2 + path_len]);
            }
            out
        }
        _ => {
            let mut out = bytes.to_vec();
            if out.len() >= 2 {
                out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            }
            out
        }
    }
}

/// Write a Linux-formatted sockaddr back into guest memory, respecting
/// the caller's `addrlen` (Linux truncates when the buffer is too small
/// and writes the full required length into `*addrlen_addr`).
fn write_linux_sockaddr(
    memory: &mut impl GuestMemory,
    addr: u64,
    addrlen_addr: u64,
    bytes: &[u8],
) -> Result<(), ()> {
    if addrlen_addr == 0 {
        return Err(());
    }
    let cur_bytes = memory.read_bytes(addrlen_addr, 4).map_err(|_| ())?;
    let cur = u32::from_ne_bytes([
        cur_bytes[0], cur_bytes[1], cur_bytes[2], cur_bytes[3],
    ]) as usize;
    let write_len = cur.min(bytes.len());
    if addr != 0 && write_len > 0 {
        memory.write_bytes(addr, &bytes[..write_len]).map_err(|_| ())?;
    }
    memory
        .write_bytes(addrlen_addr, &(bytes.len() as u32).to_ne_bytes())
        .map_err(|_| ())
}

#[derive(Debug, Clone, Copy)]
struct LinuxMsghdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
}

fn read_linux_msghdr(memory: &impl GuestMemory, addr: u64) -> Result<LinuxMsghdr, i32> {
    if addr == 0 {
        return Err(LINUX_EFAULT);
    }
    // Linux msghdr (LP64): name(8) namelen(4) pad(4) iov(8) iovlen(8)
    //                      control(8) controllen(8) flags(4)
    let bytes = memory.read_bytes(addr, 56).map_err(|_| LINUX_EFAULT)?;
    // INVARIANT: read_bytes(_, 56) returns exactly 56 bytes on Ok, so every
    // fixed-offset sub-slice below (max end 32) always converts into its array.
    #[allow(clippy::unwrap_used)]
    let name = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    #[allow(clippy::unwrap_used)]
    let namelen = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    #[allow(clippy::unwrap_used)]
    let iov = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
    #[allow(clippy::unwrap_used)]
    let iovlen = u64::from_ne_bytes(bytes[24..32].try_into().unwrap());
    Ok(LinuxMsghdr { name, namelen, iov, iovlen })
}
