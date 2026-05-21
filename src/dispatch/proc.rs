//! proc syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Owned process-subsystem state. Split out of `SyscallDispatcher`.
pub(super) struct ProcState {
    /// Path of the currently-running executable, surfaced via
    /// `/proc/self/exe`, `/proc/self/cmdline`, `/proc/self/comm`, etc.
    pub executable_path: String,
    /// `personality(2)` execution-domain flags, recorded and echoed back.
    pub personality: u64,
    /// `prctl(PR_SET_DUMPABLE)` flag (default 1).
    pub dumpable: i64,
    /// `prctl(PR_SET_NAME)` task comm name (16 bytes, NUL-padded).
    pub task_name: [u8; LINUX_TASK_COMM_LEN],
    /// `prctl(PR_SET_PDEATHSIG)` parent-death signal (0 = none). Recorded and
    /// echoed back via PR_GET_PDEATHSIG; not yet delivered on parent exit.
    pub pdeathsig: i64,
    /// Host pid of the ROOT guest process, captured at construction — before
    /// any guest `fork(2)`. Carrick forks each guest process as a real host
    /// child, so the host process tree mirrors the guest tree. A forked child
    /// inherits this value through the copied address space and can tell it is
    /// NOT the root by comparing it to its own (now-different) pid. Used by
    /// `getppid`: the root reports the stable bootstrap parent (init), while a
    /// forked child reports its real host parent — which, because the trees
    /// mirror, IS its parent guest process. See `sys_getppid`.
    pub bootstrap_host_pid: u32,
}

impl ProcState {
    pub(super) fn new() -> Self {
        Self {
            executable_path: "/proc/self/exe".to_owned(),
            personality: 0,
            dumpable: 1,
            task_name: linux_task_name_from_bytes(b"carrick"),
            pdeathsig: 0,
            bootstrap_host_pid: std::process::id(),
        }
    }
}

impl SyscallDispatcher {
    pub(super) fn personality<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let previous = self.proc.personality;
        if requested != LINUX_PERSONALITY_QUERY {
            self.proc.personality = requested;
        }
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    pub(super) fn prctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let option = ctx.request.arg(0);
        Ok(match option {
            LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                value: self.proc.dumpable,
            },
            LINUX_PR_SET_DUMPABLE => {
                let value = ctx.request.arg(1);
                if value > 1 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
                self.proc.dumpable = value as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_NAME => {
                let address = ctx.request.arg(1);
                let Ok(bytes) = memory.read_bytes(address, LINUX_TASK_COMM_LEN) else {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                };
                self.proc.task_name = linux_task_name_from_bytes(&bytes);
                // Reflect the guest's chosen name into the host
                // process/thread name as `carrick: <name>`, so `ps -M`
                // / Activity Monitor / lldb show which guest each
                // carrick host process is running.
                set_host_process_name(&self.proc.task_name);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_NAME => {
                let address = ctx.request.arg(1);
                if memory.write_bytes(address, &self.proc.task_name).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_PDEATHSIG => {
                // arg1 is a signal number: 0 clears, 1..=64 is valid, anything
                // else is EINVAL (what the kernel returns).
                let sig = ctx.request.arg(1);
                if sig > 64 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
                self.proc.pdeathsig = sig as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_PDEATHSIG => {
                let address = ctx.request.arg(1);
                if memory
                    .write_bytes(address, &(self.proc.pdeathsig as i32).to_ne_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    pub(super) fn getcpu<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let cpu_address = ctx.request.arg(0);
        let node_address = ctx.request.arg(1);
        let bootstrap_value = 0u32.to_ne_bytes();

        if cpu_address != 0 && memory.write_bytes(cpu_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if node_address != 0 && memory.write_bytes(node_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// gettid(2). In the multi-threaded runtime each guest thread has its
    /// own tid (allocated by the ThreadRegistry); fall back to the pid for
    /// the single-threaded path.
    pub(super) fn gettid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        if let Some(t) = ctx.thread {
            // Linux: in a single-threaded process gettid()==getpid(). Our
            // main thread's tid is seeded from getpid AT PROCESS START, but a
            // forked child gets a fresh host pid while keeping the inherited
            // main_tid — so returning the stale tid would break the
            // gettid==getpid invariant. While this is the sole live thread,
            // answer with the live getpid; only once siblings exist do we
            // hand out the distinct per-thread tid.
            if t.registry.live_count() > 1 {
                return Ok(DispatchOutcome::Returned { value: t.tid as i64 });
            }
        }
        Ok(self.getpid())
    }

    /// set_tid_address(addr). Records `addr` as this thread's
    /// CLONE_CHILD_CLEARTID word (zeroed + FUTEX_WAKE'd on thread exit) and
    /// returns the caller's tid. Single-threaded path just returns pid.
    pub(super) fn set_tid_address<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let addr = ctx.arg(0);
        if let Some(t) = ctx.thread {
            t.registry.set_clear_child_tid(t.tid, addr);
            return Ok(DispatchOutcome::Returned { value: t.tid as i64 });
        }
        Ok(self.getpid())
    }

    pub(super) fn set_robust_list<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let len = ctx.arg(1);
        if len == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_yield<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        std::thread::yield_now();
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_getaffinity<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0);
        let size = ctx.arg(1);
        let address = ctx.arg(2);
        let memory = &mut *ctx.memory;
        let current_pid = std::process::id() as u64;

        if pid != 0 && pid != current_pid {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if size < LINUX_BOOTSTRAP_AFFINITY_BYTES as u64 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let mut mask = [0_u8; LINUX_BOOTSTRAP_AFFINITY_BYTES];
        mask[0] = 1;
        if memory.write_bytes(address, &mask).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: LINUX_BOOTSTRAP_AFFINITY_BYTES as i64,
        })
    }

    pub(super) fn futex<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let operation = ctx.arg(1);
        let value = ctx.arg(2) as u32;
        let timeout_address = ctx.arg(3);
        let args = ctx.request.args;
        let thread = ctx.thread;
        let memory = &*ctx.memory;
        // FUTEX_*_BITSET (9/10) are the bitset variants glibc uses for
        // pthread join/condvar; we treat them as their plain WAIT/WAKE
        // counterparts (match-all bitset). CLOCK_REALTIME is accepted (we
        // service the wait with a relative timeout regardless).
        const LINUX_FUTEX_WAIT_BITSET: u64 = 9;
        const LINUX_FUTEX_WAKE_BITSET: u64 = 10;
        let raw_command = operation & LINUX_FUTEX_CMD_MASK;
        let command = match raw_command {
            LINUX_FUTEX_WAIT_BITSET => LINUX_FUTEX_WAIT,
            LINUX_FUTEX_WAKE_BITSET => LINUX_FUTEX_WAKE,
            other => other,
        };
        let flags = operation & !LINUX_FUTEX_CMD_MASK;
        if flags & !(LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let word = match read_u32(memory, address) {
            Ok(word) => word,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        // Single-threaded path (no ThreadCtx): keep the prior best-effort
        // behaviour — WAKE is a no-op success, WAIT either EAGAINs (value
        // mismatch / no timeout) or sleeps then ETIMEDOUTs. apt's update
        // stage runs single-threaded and tolerates this.
        let Some(thread) = thread else {
            return Ok(match command {
                LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
                LINUX_FUTEX_WAIT => {
                    if word != value || timeout_address == 0 {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EAGAIN });
                    }
                    let timespec = match read_timespec(memory, timeout_address) {
                        Ok(t) => t,
                        Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    };
                    let timeout = match duration_from_linux_timespec(timespec) {
                        Ok(t) => t,
                        Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    };
                    if let Some(timeout) = timeout {
                        std::thread::sleep(timeout);
                    }
                    DispatchOutcome::Errno { errno: LINUX_ETIMEDOUT }
                }
                _ => DispatchOutcome::Errno { errno: LINUX_ENOSYS },
            });
        };

        // Multi-threaded path: real cross-thread WAIT/WAKE via the shared
        // FutexTable. We support private futexes; shared-flag futexes use the
        // same table here (the address space is shared within the process,
        // so the keying is identical) — note it via a partial-syscall probe.
        if flags & LINUX_FUTEX_PRIVATE_FLAG == 0 {
            ctx.reporter.record(crate::compat::CompatEvent::partial_syscall(
                98,
                "futex",
                args,
                "non-private futex treated as private (shared address space)",
            ));
        }

        Ok(match command {
            LINUX_FUTEX_WAKE => {
                let n = thread.futex.wake(address, value);
                DispatchOutcome::Returned { value: i64::from(n) }
            }
            LINUX_FUTEX_WAIT => {
                // Re-check *uaddr under the kernel lock. If it changed since
                // the guest's last read, don't block (EAGAIN). Otherwise the
                // runtime must block with the lock RELEASED, so surface a
                // FutexWait outcome instead of sleeping here.
                if word != value {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EAGAIN });
                }
                let timeout = if timeout_address == 0 {
                    None
                } else {
                    let timespec = match read_timespec(memory, timeout_address) {
                        Ok(t) => t,
                        Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    };
                    match duration_from_linux_timespec(timespec) {
                        Ok(t) => t,
                        Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    }
                };
                DispatchOutcome::FutexWait {
                    addr: address,
                    timeout,
                }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        })
    }

    pub(super) fn uname<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let address = ctx.request.arg(0);
        if memory
            .write_bytes(address, LinuxUtsname::carrick_aarch64().abi_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn ptrace<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Bootstrap: no debugger surface yet. Linux returns ENOSYS when ptrace
        // is built out of the kernel; we surface the same answer so glibc /
        // gdb fall back cleanly.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    pub(super) fn reboot<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // We're not root and we wouldn't honour the request anyway.
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn sethostname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    pub(super) fn setdomainname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    // Process-group / session calls delegate to the host. Guest pids equal
    // host pids (getpid mirrors std::process::id), and carrick forks each
    // guest process as a real host child, so the host process tree mirrors the
    // guest tree — host pgid/sid state is therefore consistent across
    // getpgid/getsid/setsid for the whole guest process group. The previous
    // stubs assumed "the guest is always pid 1" and returned a constant 1,
    // which broke getpgid(0)==getpid() (getpid now returns the real host pid)
    // and let setsid() spuriously succeed for a group leader.
    pub(super) fn setpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as libc::pid_t;
        let pgid = ctx.arg(1) as libc::pid_t;
        // SAFETY: setpgid has no memory side effects; errors surface via errno.
        if unsafe { libc::setpgid(pid, pgid) } < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as libc::pid_t;
        let r = unsafe { libc::getpgid(pid) };
        if r < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        Ok(DispatchOutcome::Returned { value: i64::from(r) })
    }

    pub(super) fn getsid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as libc::pid_t;
        let r = unsafe { libc::getsid(pid) };
        if r < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        Ok(DispatchOutcome::Returned { value: i64::from(r) })
    }

    pub(super) fn setsid<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = unsafe { libc::setsid() };
        if r < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        Ok(DispatchOutcome::Returned { value: i64::from(r) })
    }

    pub(super) fn waitid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let idtype = ctx.arg(0);
        let options = ctx.arg(3);
        match idtype {
            LINUX_P_ALL | LINUX_P_PID | LINUX_P_PGID | LINUX_P_PIDFD => {}
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if options & LINUX_WAITID_STATE_MASK == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        })
    }

    pub(super) fn wait4<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let wstatus_addr = ctx.arg(1);
        let options = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        }
        // Linux WNOHANG = 1; macOS WNOHANG = 1. Same bit, pass through.
        let mut host_status: i32 = 0;
        let result = unsafe { libc::waitpid(pid, &mut host_status, options as i32) };
        if result < 0 {
            // ECHILD on macOS == ECHILD on Linux (10).
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if result == 0 {
            // WNOHANG and no child ready.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Linux and Darwin agree on the wstatus LAYOUT (low 7 bits = signal,
        // bit 7 = core flag, bits 8..15 = exit code) but NOT on signal
        // NUMBERS, so a signal-death's termsig must be translated host->Linux
        // (e.g. a child killed by SIGUSR1 dies as host signal 30; the guest
        // must read WTERMSIG == 10). The exit-status byte is untouched.
        let host_status = translate_wait_status(host_status);
        if wstatus_addr != 0 {
            let bytes = host_status.to_ne_bytes();
            if memory.write_bytes(wstatus_addr, &bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: i64::from(result) })
    }

    /// Linux `execve(2)` (aarch64 syscall 221). Reads pathname, argv,
    /// and envp from guest memory, then surfaces `DispatchOutcome::Execve`
    /// so the runtime can tear down the guest address space and load
    /// the new image. Returns the usual errno on the failure paths
    /// (EFAULT on bad pointers, ENAMETOOLONG on oversized strings).
    pub(super) fn execve<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname_addr = ctx.arg(0);
        let argv_addr = ctx.arg(1);
        let envp_addr = ctx.arg(2);
        let memory = &*ctx.memory;

        let path = match read_guest_c_string(memory, pathname_addr) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let argv = match read_guest_string_array(memory, argv_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let env = match read_guest_string_array(memory, envp_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        Ok(DispatchOutcome::Execve { path, argv, env })
    }

    /// Linux `clone(2)` (aarch64 syscall 220). Real fork delegation:
    /// the dispatcher recognises clone, returns `DispatchOutcome::Fork`,
    /// and the runtime asks the trap engine to do a real macOS fork
    /// against the live HVF state.
    ///
    /// Thread-create flags (CLONE_VM | CLONE_THREAD etc.) now emit
    /// `DispatchOutcome::CloneThread` so the runtime can spin up a new
    /// vCPU sharing the same address space.  All other flags (including
    /// the SIGCHLD-only fork case) still return `DispatchOutcome::Fork`.
    ///
    /// aarch64 clone ABI: clone(flags, stack, parent_tid, tls, child_tid)
    pub(super) fn clone<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;
        const CLONE_SETTLS: u64 = 0x00080000;
        const CLONE_PARENT_SETTID: u64 = 0x00100000;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        let flags = ctx.arg(0);
        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            // aarch64 ABI: clone(flags, stack, parent_tid, tls, child_tid)
            let stack = ctx.arg(1);
            let parent_tid_addr = if flags & CLONE_PARENT_SETTID != 0 { ctx.arg(2) } else { 0 };
            let tls = if flags & CLONE_SETTLS != 0 { ctx.arg(3) } else { 0 };
            let child_tid_addr = if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 {
                ctx.arg(4)
            } else {
                0
            };
            return Ok(DispatchOutcome::CloneThread {
                stack,
                tls,
                flags,
                parent_tid_addr,
                child_tid_addr,
            });
        }

        // Anything else (including the SIGCHLD-only fork case) → real fork.
        Ok(DispatchOutcome::Fork)
    }

    /// clone3(2): like clone, but flags and the rest of the parameters live in
    /// a `struct clone_args` pointed to by arg0 (arg1 is its size). glibc's
    /// posix_spawn/fork now prefer clone3; without it apt-get's worker spawn
    /// silently failed and the parent deadlocked waiting on a child that never
    /// came up.
    ///
    /// clone_args layout (little-endian u64s):
    ///   flags@0, pidfd@8, child_tid@16, parent_tid@24, exit_signal@32,
    ///   stack@40, stack_size@48, tls@56
    ///
    /// Thread-create flags now emit `DispatchOutcome::CloneThread`.
    /// Fork-like flags still return `DispatchOutcome::Fork`.
    fn clone3(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;
        const CLONE_SETTLS: u64 = 0x00080000;
        const CLONE_PARENT_SETTID: u64 = 0x00100000;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        let args_ptr = request.arg(0);
        let args_size = request.arg(1);
        // clone_args is at least flags(8)+pidfd(8)+child_tid(8)+parent_tid(8)
        // +exit_signal(8) = 40 bytes; flags is the first field.
        if args_size < 8 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }

        // Read up to the full struct (64 bytes through tls@56). glibc always
        // passes the complete struct; if the caller passes a truncated struct
        // with thread flags set we fall back to ENOSYS with a note below.
        let read_len = args_size.min(64) as usize;
        let bytes = match memory.read_bytes(args_ptr, read_len) {
            Ok(b) => b,
            Err(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        };

        // INVARIANT: read_len >= 8 (guarded above) so slice [0..8] is valid.
        #[allow(clippy::unwrap_used)]
        let flags = u64::from_le_bytes(bytes[..8].try_into().unwrap());

        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            // glibc always passes the full struct (64 bytes); if for some reason
            // the caller passes a short struct with thread flags, return ENOSYS
            // rather than misreading uninitialised fields.
            if args_size < 64 {
                return DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS,
                };
            }

            // All fields are little-endian u64; offsets from the layout above.
            #[allow(clippy::unwrap_used)]
            let read_u64_at = |off: usize| -> u64 {
                u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
            };
            let child_tid_ptr = read_u64_at(16);  // child_tid@16
            let parent_tid_ptr = read_u64_at(24); // parent_tid@24
            let stack = read_u64_at(40);           // stack@40
            let stack_size = read_u64_at(48);      // stack_size@48
            let tls_val = read_u64_at(56);         // tls@56

            // child SP = stack base + stack_size (stack grows down on aarch64)
            let child_sp = stack + stack_size;
            let tls = if flags & CLONE_SETTLS != 0 { tls_val } else { 0 };
            let parent_tid_addr =
                if flags & CLONE_PARENT_SETTID != 0 { parent_tid_ptr } else { 0 };
            let child_tid_addr =
                if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 {
                    child_tid_ptr
                } else {
                    0
                };

            return DispatchOutcome::CloneThread {
                stack: child_sp,
                tls,
                flags,
                parent_tid_addr,
                child_tid_addr,
            };
        }

        // posix_spawn's CLONE_VM|CLONE_VFORK|SIGCHLD and plain SIGCHLD forks
        // both land here. A real fork is a valid implementation of vfork (the
        // child execs or _exits immediately), so route to the same path.
        DispatchOutcome::Fork
    }

    pub(super) fn getrandom<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let memory = &mut *ctx.memory;
        let mut bytes = vec![0; length];
        if getrandom::fill(&mut bytes).is_err() {
            fill_deterministic_bootstrap_random(&mut bytes);
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    pub(super) fn sys_exit<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        let code = ctx.request.arg(0) as i32;
        // exit_group(94) always tears down the whole process. exit(93) ends
        // just this thread IF siblings are still live; with only one live
        // thread (or no ThreadCtx) it's equivalent to whole-process exit.
        if ctx.request.number == 93
            && let Some(t) = ctx.thread
                && t.registry.live_count() > 1 {
                    return Ok(DispatchOutcome::ThreadExit { code });
                }
        Ok(DispatchOutcome::Exit { code })
    }

    pub(super) fn sys_clone3<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.clone3(ctx.request, &*ctx.memory))
    }

    pub(super) fn sys_rseq<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.rseq())
    }

}

fn fill_deterministic_bootstrap_random(bytes: &mut [u8]) {
    let mut state = 0x00ca_221c_u64;
    for byte in bytes {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *byte = state as u8;
    }
}

/// Translate a host `waitpid` status so a signal-death's termsig uses Linux
/// numbering. The wstatus layout is shared (low 7 bits = signal, bit 7 = core
/// dump flag, bits 8..15 = exit code); only the signal NUMBER differs between
/// macOS and Linux. Exited children (low 7 bits == 0) and stopped children
/// (low byte == 0x7f) are returned unchanged.
fn translate_wait_status(status: i32) -> i32 {
    let low = status & 0x7f;
    if low != 0 && low != 0x7f {
        let core = status & 0x80;
        let linux_sig = crate::host_signal::host_to_linux_signum(low);
        (linux_sig & 0x7f) | core
    } else {
        status
    }
}
