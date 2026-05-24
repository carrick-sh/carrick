//! proc syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Owned process-subsystem state. Split out of `SyscallDispatcher`.
pub(super) struct ProcState {
    /// Path of the currently-running executable, surfaced via
    /// `/proc/self/exe`, `/proc/self/cmdline`, `/proc/self/comm`, etc.
    pub executable_path: String,
    /// Current guest argv, surfaced as NUL-separated bytes through
    /// `/proc/self/cmdline`.
    pub argv: Vec<String>,
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
    /// Interval-timer state for `[ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF]`,
    /// indexed by the `which` value. Anchored to the monotonic clock so
    /// setitimer/getitimer report the time remaining; `None` = disarmed.
    /// glibc's `alarm()` is `setitimer(ITIMER_REAL, …)` and returns the
    /// previous timer's remaining seconds. The matching expiry signal
    /// (SIGALRM/SIGVTALRM/SIGPROF) is delivered by an EVFILT_TIMER event on the
    /// signal pump's kqueue (see crate::itimer). VIRTUAL/PROF are approximated
    /// with a wall-clock timer (carrick has no per-process CPU-time accounting).
    pub itimers: [Option<ItimerState>; 3],
    /// CPU affinity mask, one bit per Linux-visible logical CPU (word 0 holds
    /// CPUs 0..64). Seeded to "all online CPUs" from `host_facts` so
    /// `sched_getaffinity` reports Carrick's effective vCPU capacity — the Go
    /// runtime sizes `GOMAXPROCS` from its population count, and `nproc`/OpenMP
    /// read it too.
    /// `sched_setaffinity` updates it (intersected with the online set) so a
    /// set→get round-trips; Apple Silicon scheduling is advisory, so we honour
    /// the observable mask without physically pinning the host thread. Affinity
    /// is inherited across `fork`, which the address-space copy gives us for
    /// free. See [[host_facts]].
    pub affinity: Vec<u64>,
}

/// Default affinity mask for `ncpu` logical CPUs: the low `ncpu` bits set
/// across `ceil(ncpu/64)` 64-bit words.
pub(super) fn default_affinity(ncpu: usize) -> Vec<u64> {
    let words = ncpu.div_ceil(64).max(1);
    let mut mask = vec![0u64; words];
    for cpu in 0..ncpu {
        mask[cpu / 64] |= 1u64 << (cpu % 64);
    }
    mask
}

/// Serialize an affinity word-mask into exactly `out_len` little-endian bytes
/// (the kernel's `cpumask_size`), truncating or zero-padding as needed.
pub(super) fn affinity_to_bytes(mask: &[u64], out_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; out_len];
    for (i, word) in mask.iter().enumerate() {
        let off = i * 8;
        if off >= out_len {
            break;
        }
        let wb = word.to_le_bytes();
        let n = (out_len - off).min(8);
        buf[off..off + n].copy_from_slice(&wb[..n]);
    }
    buf
}

/// Classification of a sched_*affinity `pid` argument relative to the caller.
enum AffinityTarget {
    /// 0 or the caller's own pid.
    SelfProc,
    /// Another process/thread in the guest tree.
    OtherGuest,
    /// No such guest task — ESRCH.
    NotFound,
}

/// Build a `LinuxRusage` carrying just CPU time (user/system microseconds);
/// other fields stay zero. Used for the `wait4` rusage out-param.
fn rusage_from_us(user_us: u64, system_us: u64) -> LinuxRusage {
    let tv = |us: u64| crate::linux_abi::LinuxTimeval {
        tv_sec: (us / 1_000_000) as i64,
        tv_usec: (us % 1_000_000) as i64,
    };
    let mut ru = LinuxRusage::zeroed();
    ru.ru_utime = tv(user_us);
    ru.ru_stime = tv(system_us);
    ru
}

/// Lowest CPU index set in a word-mask, or `None` if empty.
pub(super) fn lowest_set_cpu(mask: &[u64]) -> Option<u32> {
    for (i, word) in mask.iter().enumerate() {
        if *word != 0 {
            return Some((i as u32) * 64 + word.trailing_zeros());
        }
    }
    None
}

/// Parse a little-endian CPU bitmask from user bytes into `words` 64-bit words.
pub(super) fn affinity_from_bytes(bytes: &[u8], words: usize) -> Vec<u64> {
    let mut mask = vec![0u64; words.max(1)];
    for (i, w) in mask.iter_mut().enumerate() {
        let off = i * 8;
        if off >= bytes.len() {
            break;
        }
        let mut wb = [0u8; 8];
        let n = (bytes.len() - off).min(8);
        wb[..n].copy_from_slice(&bytes[off..off + n]);
        *w = u64::from_le_bytes(wb);
    }
    mask
}

/// Armed interval timer. `value`/`interval` are the configured initial
/// expiration and reload period; `set_at` anchors `value` to the monotonic
/// clock so the remaining time is `value - set_at.elapsed()` (saturating).
#[derive(Clone, Copy)]
pub(super) struct ItimerState {
    pub set_at: std::time::Instant,
    pub value: std::time::Duration,
    pub interval: std::time::Duration,
}

impl ProcState {
    pub(super) fn new() -> Self {
        Self {
            executable_path: "/proc/self/exe".to_owned(),
            argv: vec!["/proc/self/exe".to_owned()],
            personality: 0,
            dumpable: 1,
            task_name: linux_task_name_from_bytes(b"carrick"),
            pdeathsig: 0,
            bootstrap_host_pid: std::process::id(),
            itimers: [None, None, None],
            affinity: default_affinity(crate::host_facts::logical_cpu_count()),
        }
    }
}

impl SyscallDispatcher {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_threaded_lifecycle<M: GuestMemory>(
        &self,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !syscall_handler_is(request.number, SyscallHandler::Lifecycle) {
            return None;
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let thread = Some(ThreadCtx {
            tid,
            registry,
            futex,
        });
        let mut ctx = SyscallCtx {
            request,
            memory,
            reporter,
            thread,
        };
        let outcome = match match request.number {
            93 | 94 => self.sys_exit(&mut ctx),
            220 => self.clone(&mut ctx),
            221 => self.execve(&mut ctx),
            260 => self.wait4(&mut ctx),
            435 => self.sys_clone3(&mut ctx),
            _ => unreachable!("unsupported threaded lifecycle syscall"),
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

    pub(super) fn personality<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let mut proc = self.proc.lock();
        let previous = proc.personality;
        if requested != LINUX_PERSONALITY_QUERY {
            proc.personality = requested;
        }
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    pub(super) fn prctl<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let option = ctx.request.arg(0);
        Ok(match option {
            LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                value: self.proc.lock().dumpable,
            },
            LINUX_PR_SET_DUMPABLE => {
                let value = ctx.request.arg(1);
                if value > 1 {
                    return Ok(LINUX_EINVAL.into());
                }
                self.proc.lock().dumpable = value as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_NAME => {
                let address = ctx.request.arg(1);
                let Ok(bytes) = memory.read_bytes(address, LINUX_TASK_COMM_LEN) else {
                    return Ok(LINUX_EFAULT.into());
                };
                let task_name = linux_task_name_from_bytes(&bytes);
                self.proc.lock().task_name = task_name;
                // Reflect the guest's chosen name into the host
                // process/thread name as `carrick: <name>`, so `ps -M`
                // / Activity Monitor / lldb show which guest each
                // carrick host process is running.
                set_host_process_name(&task_name);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_NAME => {
                let address = ctx.request.arg(1);
                let task_name = self.proc.lock().task_name;
                if memory.write_bytes(address, &task_name).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_PDEATHSIG => {
                // arg1 is a signal number: 0 clears, 1..=64 is valid, anything
                // else is EINVAL (what the kernel returns).
                let sig = ctx.request.arg(1);
                if sig > 64 {
                    return Ok(LINUX_EINVAL.into());
                }
                self.proc.lock().pdeathsig = sig as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_PDEATHSIG => {
                let address = ctx.request.arg(1);
                let pdeathsig = self.proc.lock().pdeathsig;
                if memory
                    .write_bytes(address, &(pdeathsig as i32).to_ne_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::errno(LINUX_EINVAL),
        })
    }

    pub(super) fn getcpu<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let cpu_address = ctx.request.arg(0);
        let node_address = ctx.request.arg(1);
        // Report the lowest CPU in this process's affinity mask. macOS has no
        // portable "which CPU am I on" query, but a task pinned to a single
        // CPU (sched_setaffinity to one bit) must observe getcpu() returning
        // that CPU — LTP getcpu01 pins to CPU n-1 then expects it back. The
        // lowest set bit equals the pinned CPU when restricted, and is always
        // a valid online CPU otherwise. Single NUMA node (0).
        let cpu = lowest_set_cpu(&self.proc.lock().affinity).unwrap_or(0);
        let cpu_value = cpu.to_ne_bytes();
        let node_value = 0u32.to_ne_bytes();

        if cpu_address != 0 && memory.write_bytes(cpu_address, &cpu_value).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        if node_address != 0 && memory.write_bytes(node_address, &node_value).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// gettid(2). In the multi-threaded runtime each guest thread has its
    /// own tid (allocated by the ThreadRegistry); fall back to the pid for
    /// the single-threaded path.
    pub(super) fn gettid<M: GuestMemory>(
        &self,
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
                return Ok(DispatchOutcome::Returned {
                    value: t.tid as i64,
                });
            }
        }
        Ok(self.getpid())
    }

    /// set_tid_address(addr). Records `addr` as this thread's
    /// CLONE_CHILD_CLEARTID word (zeroed + FUTEX_WAKE'd on thread exit) and
    /// returns the caller's tid. Single-threaded path just returns pid.
    pub(super) fn set_tid_address<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let addr = ctx.arg(0);
        if let Some(t) = ctx.thread {
            t.registry.set_clear_child_tid(t.tid, addr);
            return Ok(DispatchOutcome::Returned {
                value: t.tid as i64,
            });
        }
        Ok(self.getpid())
    }

    pub(super) fn set_robust_list<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let len = ctx.arg(1);
        if len == 0 {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_yield<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        std::thread::yield_now();
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn sched_getaffinity<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0);
        let size = ctx.arg(1) as usize;
        let address = ctx.arg(2);
        let memory = &mut *ctx.memory;

        if matches!(self.resolve_affinity_target(pid), AffinityTarget::NotFound) {
            return Ok(LINUX_ESRCH.into());
        }
        // The kernel copies (and returns) `cpumask_size()` bytes — one `long`
        // per 64 CPUs — and requires the user buffer to be at least that big.
        let kernel_bytes = crate::host_facts::logical_cpu_count().div_ceil(64) * 8;
        if size < kernel_bytes {
            return Ok(LINUX_EINVAL.into());
        }
        let mask = self.proc.lock().affinity.clone();
        let buf = affinity_to_bytes(&mask, kernel_bytes);
        if memory.write_bytes(address, &buf).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned {
            value: kernel_bytes as i64,
        })
    }

    /// sched_setaffinity(pid, size, mask). Honours the requested CPU mask
    /// (intersected with the online set) so a set→get round-trips; macOS
    /// thread scheduling is advisory so no physical pin is performed. An empty
    /// effective mask is rejected with EINVAL, matching Linux ("no online CPU
    /// in the set"). Affinity is per-process and inherited across fork.
    pub(super) fn sched_setaffinity<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0);
        let size = ctx.arg(1) as usize;
        let address = ctx.arg(2);
        let memory = &*ctx.memory;

        // Linux order: copy the mask from user (EFAULT) → find the task
        // (ESRCH) → permission check (EPERM) → apply (EINVAL on empty set).
        let read_len = size.min(128);
        let bytes = match memory.read_bytes(address, read_len) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(LINUX_EFAULT.into()),
        };
        let target = self.resolve_affinity_target(pid);
        if matches!(target, AffinityTarget::NotFound) {
            return Ok(LINUX_ESRCH.into());
        }
        // Setting ANOTHER process's affinity requires owning it or CAP_SYS_NICE.
        // carrick models a single guest credential set and can't read a peer
        // process's owner across the fork boundary, so it approximates the
        // kernel's same-owner-or-capable rule: only the (root, euid 0) guest
        // may target another process; a process that has dropped privileges
        // gets EPERM. Setting one's OWN affinity is always permitted.
        if matches!(target, AffinityTarget::OtherGuest) && self.creds.lock().euid != 0 {
            return Ok(LINUX_EPERM.into());
        }
        // Intersect the requested mask with the online set. An empty result is
        // EINVAL, exactly as Linux rejects a mask naming no usable CPU.
        let ncpu = crate::host_facts::logical_cpu_count();
        let online = default_affinity(ncpu);
        let requested = affinity_from_bytes(&bytes, online.len());
        let effective: Vec<u64> = online
            .iter()
            .zip(requested.iter())
            .map(|(o, r)| o & r)
            .collect();
        if effective.iter().all(|w| *w == 0) {
            return Ok(LINUX_EINVAL.into());
        }
        // We can only mutate our own mask; setting a peer's is a permitted
        // no-op (macOS scheduling is advisory regardless).
        if matches!(target, AffinityTarget::SelfProc) {
            self.proc.lock().affinity = effective;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// Resolve an affinity pid argument. 0 or our own pid is `SelfProc`; any
    /// other thread/process in the guest tree is `OtherGuest`; anything else
    /// is `NotFound` (ESRCH).
    fn resolve_affinity_target(&self, pid: u64) -> AffinityTarget {
        if pid == 0 || pid == std::process::id() as u64 {
            AffinityTarget::SelfProc
        } else if crate::host_proc::is_guest_process(pid as u32) {
            AffinityTarget::OtherGuest
        } else {
            AffinityTarget::NotFound
        }
    }

    pub(super) fn futex<M: GuestMemory>(
        &self,
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
        let futex_flags = LinuxFutexFlags::from_bits_retain(flags);
        if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        let word = match read_u32(memory, address) {
            Ok(word) => word,
            Err(errno) => return Ok(errno.into()),
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
                        return Ok(LINUX_EAGAIN.into());
                    }
                    let timespec = match read_timespec(memory, timeout_address) {
                        Ok(t) => t,
                        Err(errno) => return Ok(errno.into()),
                    };
                    let timeout = match duration_from_linux_timespec(timespec) {
                        Ok(t) => t,
                        Err(errno) => return Ok(errno.into()),
                    };
                    if let Some(timeout) = timeout {
                        std::thread::sleep(timeout);
                    }
                    DispatchOutcome::errno(LINUX_ETIMEDOUT)
                }
                _ => DispatchOutcome::errno(LINUX_ENOSYS),
            });
        };

        // Multi-threaded path: real cross-thread WAIT/WAKE via the shared
        // FutexTable. We support private futexes; shared-flag futexes use the
        // same table here (the address space is shared within the process,
        // so the keying is identical) — note it via a partial-syscall probe.
        if !futex_flags.contains(LinuxFutexFlags::PRIVATE) {
            ctx.reporter
                .record(crate::compat::CompatEvent::partial_syscall(
                    98,
                    "futex",
                    args,
                    "non-private futex treated as private (shared address space)",
                ));
        }

        Ok(match command {
            LINUX_FUTEX_WAKE => {
                let n = thread.futex.wake(address, value);
                DispatchOutcome::Returned {
                    value: i64::from(n),
                }
            }
            LINUX_FUTEX_WAIT => {
                // Re-check *uaddr under the dispatcher lock. If it changed since
                // the guest's last read, don't block (EAGAIN). Otherwise the
                // runtime must block with the lock RELEASED, so surface a
                // FutexWait outcome instead of sleeping here.
                if word != value {
                    return Ok(LINUX_EAGAIN.into());
                }
                let timeout = if timeout_address == 0 {
                    None
                } else {
                    let timespec = match read_timespec(memory, timeout_address) {
                        Ok(t) => t,
                        Err(errno) => return Ok(errno.into()),
                    };
                    match duration_from_linux_timespec(timespec) {
                        Ok(t) => t,
                        Err(errno) => return Ok(errno.into()),
                    }
                };
                DispatchOutcome::FutexWait {
                    wait: thread.futex.prepare_wait(address),
                    timeout,
                }
            }
            _ => DispatchOutcome::errno(LINUX_ENOSYS),
        })
    }

    pub(super) fn uname<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let address = ctx.request.arg(0);
        if memory
            .write_bytes(address, LinuxUtsname::carrick_aarch64().abi_bytes())
            .is_err()
        {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn ptrace<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Bootstrap: no debugger surface yet. Linux returns ENOSYS when ptrace
        // is built out of the kernel; we surface the same answer so glibc /
        // gdb fall back cleanly.
        Ok(LINUX_ENOSYS.into())
    }

    pub(super) fn reboot<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // We're not root and we wouldn't honour the request anyway.
        Ok(LINUX_EPERM.into())
    }

    pub(super) fn sethostname<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(LINUX_EPERM.into())
    }

    pub(super) fn setdomainname<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(LINUX_EPERM.into())
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
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid: Pid = ctx.typed_arg(0);
        let pgid: Pid = ctx.typed_arg(1);
        // SAFETY: setpgid has no memory side effects; errors surface via errno.
        if let Err(errno) = (unsafe { libc::setpgid(pid.0, pgid.0) }).host_syscall_errno() {
            return Ok(errno.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn getpgid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as libc::pid_t;
        let r = match (unsafe { libc::getpgid(pid) }).host_syscall_errno() {
            Ok(value) => value,
            Err(errno) => return Ok(errno.into()),
        };
        Ok(DispatchOutcome::Returned {
            value: i64::from(r),
        })
    }

    pub(super) fn getsid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as libc::pid_t;
        let r = match (unsafe { libc::getsid(pid) }).host_syscall_errno() {
            Ok(value) => value,
            Err(errno) => return Ok(errno.into()),
        };
        Ok(DispatchOutcome::Returned {
            value: i64::from(r),
        })
    }

    pub(super) fn setsid<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = match (unsafe { libc::setsid() }).host_syscall_errno() {
            Ok(value) => value,
            Err(errno) => return Ok(errno.into()),
        };
        Ok(DispatchOutcome::Returned {
            value: i64::from(r),
        })
    }

    /// waitid(2): wait for a child's state change without (optionally) reaping
    /// it. Go's `os.Process.Wait` calls this (`P_PIDFD`/`P_PID` with
    /// `WEXITED|WNOWAIT`) to block until a child is waitable, then reaps via
    /// `wait4`; a stub `ECHILD` here breaks every `os/exec` round-trip. Backed
    /// by Darwin's own `waitid` (guest pids mirror host pids); `P_PIDFD`
    /// resolves through the pidfd's backing host pid.
    pub(super) fn waitid<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        use crate::linux_abi::{
            LINUX_WCONTINUED, LINUX_WEXITED, LINUX_WNOHANG, LINUX_WNOWAIT, LINUX_WSTOPPED,
        };
        let idtype = ctx.arg(0);
        let id = ctx.arg(1);
        let infop_addr = ctx.arg(2);
        let options = ctx.arg(3);
        if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if options & LINUX_WAITID_STATE_MASK == 0 {
            return Ok(LINUX_EINVAL.into());
        }
        // Map the Linux (idtype, id) to a macOS (idtype_t, id). P_PIDFD has no
        // host analogue, so resolve the pidfd to its backing host pid and wait
        // by P_PID.
        let (host_idtype, host_id): (libc::idtype_t, libc::id_t) = match idtype {
            LINUX_P_ALL => (libc::P_ALL, 0),
            LINUX_P_PID => (libc::P_PID, id as libc::id_t),
            LINUX_P_PGID => (libc::P_PGID, id as libc::id_t),
            LINUX_P_PIDFD => match self.pidfd_host_pid(id as i32) {
                Some(host_pid) => (libc::P_PID, host_pid as libc::id_t),
                None => return Ok(LINUX_EBADF.into()),
            },
            _ => return Ok(LINUX_EINVAL.into()),
        };
        // Linux and macOS agree on WNOHANG (1) but disagree on the state/wait
        // bits (WEXITED/WSTOPPED/WCONTINUED/WNOWAIT), so translate explicitly.
        let mut host_options: i32 = 0;
        if options & LINUX_WEXITED != 0 {
            host_options |= libc::WEXITED;
        }
        if options & LINUX_WSTOPPED != 0 {
            host_options |= libc::WSTOPPED;
        }
        if options & LINUX_WCONTINUED != 0 {
            host_options |= libc::WCONTINUED;
        }
        if options & LINUX_WNOHANG != 0 {
            host_options |= libc::WNOHANG;
        }
        if options & LINUX_WNOWAIT != 0 {
            host_options |= libc::WNOWAIT;
        }

        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // Retry across carrick-internal host-signal EINTR (the SIGURG vCPU
        // kick), surfacing EINTR to the guest only when it has a deliverable
        // signal pending — same discipline as wait4 above.
        let result = loop {
            let r = unsafe { libc::waitid(host_idtype, host_id, &mut info, host_options) };
            if r == 0 {
                break Ok(());
            }
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0);
            if errno == LINUX_EINTR && !crate::host_signal::has_process_pending() {
                continue;
            }
            break Err(errno);
        };
        if let Err(errno) = result {
            // macOS ECHILD/EINVAL share their numbers with Linux (10/22).
            return Ok(DispatchOutcome::errno(errno));
        }
        // Fill the guest siginfo_t (SIGCHLD layout). macOS, like Linux, leaves
        // si_pid == 0 with WNOHANG when no child is waitable — callers read that
        // as "nothing ready", so propagate it verbatim.
        if infop_addr != 0 {
            let bytes = if info.si_pid == 0 {
                [0u8; crate::linux_abi::LINUX_SIGINFO_SIZE]
            } else {
                build_sigchld_siginfo(info.si_pid, info.si_uid, info.si_code, info.si_status)
            };
            let memory = &mut *ctx.memory;
            if memory.write_bytes(infop_addr, &bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    pub(super) fn wait4<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let wstatus_addr = ctx.arg(1);
        let options = ctx.arg(2);
        let rusage_addr = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        // Translate Linux wait options to macOS: WNOHANG/WUNTRACED share bits
        // (1/2) but WCONTINUED is 8 on Linux vs 0x10 on macOS — passing the
        // Linux bit straight through makes macOS waitpid reject it with EINVAL
        // (breaking bash's WNOHANG|WUNTRACED|WCONTINUED job-control poll). The
        // Linux-only thread flags (WALL/WCLONE/WNOTHREAD) have no macOS analogue
        // and are dropped.
        let mut host_options: i32 = 0;
        if options & crate::linux_abi::LINUX_WNOHANG != 0 {
            host_options |= libc::WNOHANG;
        }
        if options & crate::linux_abi::LINUX_WUNTRACED != 0 {
            host_options |= libc::WUNTRACED;
        }
        if options & crate::linux_abi::LINUX_WCONTINUED != 0 {
            host_options |= libc::WCONTINUED;
        }
        let mut host_status: i32 = 0;
        // Collect the reaped child's resource usage from Darwin's own wait4
        // (the same mechanism Linux uses to fill RUSAGE_CHILDREN); we add the
        // child's *guest* CPU — which the host rusage can't see — separately.
        let mut host_rusage: libc::rusage = unsafe { std::mem::zeroed() };
        // Retry the blocking host wait4 across EINTR from carrick-internal
        // host signals (e.g. the SIGURG vCPU kick). Without this, a shell
        // blocked waiting on a foreground job spuriously returns from wait,
        // leaves the wait, and spins. Only surface EINTR to the guest when a
        // signal it can actually take is pending (so its handler runs / it
        // dies) — same discipline as host_sleep_interruptible and read_host_pipe.
        let result = loop {
            let r = unsafe { libc::wait4(pid, &mut host_status, host_options, &mut host_rusage) };
            match r.host_syscall_errno() {
                Ok(value) => break Ok(value),
                Err(errno) => {
                    if errno == LINUX_EINTR && !crate::host_signal::has_process_pending() {
                        continue;
                    }
                    break Err(errno);
                }
            }
        };
        let result = match result {
            Ok(value) => value,
            Err(errno) => {
                // ECHILD on macOS == ECHILD on Linux (10); EINTR surfaces only when
                // a guest-deliverable signal is pending (see the retry loop).
                return Ok(errno.into());
            }
        };
        if result == 0 {
            // WNOHANG and no child ready.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Roll the reaped child's CPU into this process's child-time totals
        // (getrusage RUSAGE_CHILDREN, times cutime/cstime). The host rusage
        // covers carrick's host-side work for the child; the child's guest
        // execution (invisible to the host rusage) is drained from the shared
        // table the child published on exit. user = guest compute + host user;
        // system = host system work.
        let tv_us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        let child_guest_us = crate::guest_cpu::reap_child_guest_ns(result as u32) / 1000;
        let child_user_us = child_guest_us + tv_us(host_rusage.ru_utime);
        let child_system_us = tv_us(host_rusage.ru_stime);
        crate::guest_cpu::add_reaped_child(child_user_us, child_system_us);
        // If the guest passed a rusage out-param, fill it with THIS child's
        // usage (not the cumulative total).
        if rusage_addr != 0 {
            let child_rusage = rusage_from_us(child_user_us, child_system_us);
            if memory
                .write_bytes(rusage_addr, child_rusage.abi_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
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
                return Ok(LINUX_EFAULT.into());
            }
        }
        Ok(DispatchOutcome::Returned {
            value: i64::from(result),
        })
    }

    /// Linux `execve(2)` (aarch64 syscall 221). Reads pathname, argv,
    /// and envp from guest memory, then surfaces `DispatchOutcome::Execve`
    /// so the runtime can tear down the guest address space and load
    /// the new image. Returns the usual errno on the failure paths
    /// (EFAULT on bad pointers, ENAMETOOLONG on oversized strings).
    pub(super) fn execve<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname_addr = ctx.arg(0);
        let argv_addr = ctx.arg(1);
        let envp_addr = ctx.arg(2);
        let memory = &*ctx.memory;

        let path = match read_guest_c_string(memory, pathname_addr) {
            Ok(p) => p,
            Err(errno) => return Ok(errno.into()),
        };
        let argv = match read_guest_string_array(memory, argv_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(errno.into()),
        };
        let env = match read_guest_string_array(memory, envp_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(errno.into()),
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
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(0);
        let thread_mask = LinuxCloneFlags::THREAD_MASK;
        if (flags & thread_mask) == thread_mask {
            // aarch64 ABI: clone(flags, stack, parent_tid, tls, child_tid)
            let stack = ctx.arg(1);
            let parent_tid_addr = if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
                ctx.arg(2)
            } else {
                0
            };
            let tls = if flags & LinuxCloneFlags::SETTLS.bits() != 0 {
                ctx.arg(3)
            } else {
                0
            };
            let child_tid_addr = if flags
                & (LinuxCloneFlags::CHILD_SETTID | LinuxCloneFlags::CHILD_CLEARTID).bits()
                != 0
            {
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
        // Legacy clone(2) returns the CLONE_PIDFD fd via the parent_tid pointer
        // (arg2); it's mutually exclusive with CLONE_PARENT_SETTID.
        let pidfd_out = if flags & LinuxCloneFlags::PIDFD.bits() != 0 {
            Some(ctx.arg(2))
        } else {
            None
        };
        Ok(DispatchOutcome::Fork { pidfd_out })
    }

    /// pidfd_open(2): return a file descriptor referring to process `pid`. The
    /// fd is backed by a host kqueue watching the real macOS process via
    /// `EVFILT_PROC`/`NOTE_EXIT` (guest pids mirror host pids), so the macOS
    /// kernel tracks the process lifecycle. Go 1.24's `os/exec` requires this
    /// to succeed before it will spawn (it probes pidfd support, then uses
    /// `CLONE_PIDFD`).
    pub(super) fn pidfd_open<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let flags = ctx.arg(1);
        // PIDFD_NONBLOCK == O_NONBLOCK (0o4000) on aarch64 Linux.
        const PIDFD_NONBLOCK: u64 = 0o4000;
        if pid <= 0 {
            return Ok(LINUX_EINVAL.into());
        }
        if flags & !PIDFD_NONBLOCK != 0 {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(self.open_pidfd(pid, flags))
    }

    /// Allocate a pidfd for `host_pid`. Shared by `pidfd_open` and the
    /// `CLONE_PIDFD` fork path. Registers `EVFILT_PROC`/`NOTE_EXIT` so the fd
    /// becomes readable when the process exits.
    pub(super) fn open_pidfd(&self, host_pid: i32, status_flags: u64) -> DispatchOutcome {
        let Some(kqueue) = crate::darwin_kqueue::Kqueue::new_internal() else {
            return crate::linux_abi::LINUX_EMFILE.into();
        };
        if kqueue
            .apply(&[crate::darwin_kqueue::Kevent::proc_exit(host_pid)])
            .is_err()
        {
            // No such process (already reaped, or never existed).
            return crate::linux_abi::LINUX_ESRCH.into();
        }
        let description = OpenDescription::Pidfd {
            host_pid,
            kqueue: std::sync::Arc::new(kqueue),
            status_flags,
        };
        self.install_fd(description, 0)
    }

    /// Allocate a pidfd referring to freshly-forked `child_pid` and return its
    /// guest fd, or `None` if installation failed. Called by the runtime's
    /// `CLONE_PIDFD` fork path (in the parent) to satisfy the clone pidfd-out
    /// pointer. Public because the runtime drives fork from outside `dispatch`.
    pub fn install_child_pidfd(&self, child_pid: i32) -> Option<i32> {
        match self.open_pidfd(child_pid, 0) {
            DispatchOutcome::Returned { value } => i32::try_from(value).ok(),
            _ => None,
        }
    }

    /// Resolve a pidfd to its backing host pid, or `None` if `fd` isn't a pidfd.
    pub(super) fn pidfd_host_pid(&self, fd: i32) -> Option<i32> {
        let open = self.open_file(fd)?;
        let desc = open.description.read();
        match &*desc {
            OpenDescription::Pidfd { host_pid, .. } => Some(*host_pid),
            _ => None,
        }
    }

    /// pidfd_send_signal(2): send `sig` to the process referred to by `pidfd`.
    /// Routed through the same cross-process delivery as `kill(2)` on the
    /// resolved host pid (guest pids mirror host pids).
    pub(super) fn pidfd_send_signal<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let signum = ctx.arg(1);
        let Some(host_pid) = self.pidfd_host_pid(fd) else {
            return Ok(LINUX_EBADF.into());
        };
        if signum == 0 {
            // Existence check.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if !crate::dispatch::signal::is_valid_signum(signum) {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(crate::dispatch::signal::bootstrap_signal_send(
            i64::from(host_pid),
            /*tid_required=*/ false,
            signum,
        ))
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
    fn clone3(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let args_ptr = request.arg(0);
        let args_size = request.arg(1);
        // clone_args is at least flags(8)+pidfd(8)+child_tid(8)+parent_tid(8)
        // +exit_signal(8) = 40 bytes; flags is the first field.
        if args_size < 8 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }

        // Read up to the full struct (64 bytes through tls@56). glibc always
        // passes the complete struct; if the caller passes a truncated struct
        // with thread flags set we fall back to ENOSYS with a note below.
        let read_len = args_size.min(<LinuxCloneArgs as KernelAbi>::ABI_SIZE as u64) as usize;
        let args = match read_kernel_prefix::<LinuxCloneArgs>(memory, args_ptr, read_len) {
            Ok(args) => args,
            Err(_) => {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        };

        let flags = args.flags;
        let thread_mask = LinuxCloneFlags::THREAD_MASK;
        if (flags & thread_mask) == thread_mask {
            // glibc always passes the full struct (64 bytes); if for some reason
            // the caller passes a short struct with thread flags, return ENOSYS
            // rather than misreading uninitialised fields.
            if args_size < 64 {
                return DispatchOutcome::errno(LINUX_ENOSYS);
            }

            let child_tid_ptr = args.child_tid;
            let parent_tid_ptr = args.parent_tid;
            let stack = args.stack;
            let stack_size = args.stack_size;
            let tls_val = args.tls;

            // child SP = stack base + stack_size (stack grows down on aarch64)
            let child_sp = stack + stack_size;
            let tls = if flags & LinuxCloneFlags::SETTLS.bits() != 0 {
                tls_val
            } else {
                0
            };
            let parent_tid_addr = if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
                parent_tid_ptr
            } else {
                0
            };
            let child_tid_addr = if flags
                & (LinuxCloneFlags::CHILD_SETTID | LinuxCloneFlags::CHILD_CLEARTID).bits()
                != 0
            {
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
        // clone3 returns the CLONE_PIDFD fd via the clone_args.pidfd field.
        let pidfd_out = if flags & LinuxCloneFlags::PIDFD.bits() != 0 {
            Some(args.pidfd)
        } else {
            None
        };
        DispatchOutcome::Fork { pidfd_out }
    }

    pub(super) fn getrandom<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length =
            usize::try_from(ctx.arg(1)).map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let memory = &mut *ctx.memory;
        let mut bytes = vec![0; length];
        if getrandom::fill(&mut bytes).is_err() {
            fill_deterministic_bootstrap_random(&mut bytes);
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_ENOSYS)
    }

    pub(super) fn sys_exit<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let code = ctx.request.arg(0) as i32;
        // exit_group(94) always tears down the whole process. exit(93) ends
        // just this thread IF siblings are still live; with only one live
        // thread (or no ThreadCtx) it's equivalent to whole-process exit.
        if ctx.request.number == 93
            && let Some(t) = ctx.thread
            && t.registry.live_count() > 1
        {
            return Ok(DispatchOutcome::ThreadExit { code });
        }
        Ok(DispatchOutcome::Exit { code })
    }

    pub(super) fn sys_clone3<M: GuestMemory>(
        &self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.clone3(ctx.request, &*ctx.memory))
    }

    pub(super) fn sys_rseq<M: GuestMemory>(
        &self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
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
    if low == 0x7f {
        // WIFSTOPPED (and macOS's WIFCONTINUED, which is a stopped status whose
        // stop signal is the sentinel 0x13). The stop signal lives in bits 8..15
        // and is in macOS numbering, so translate it host->Linux (e.g. SIGTSTP
        // is 18 on macOS, 20 on Linux) — without this, bash's WSTOPSIG check
        // after Ctrl-Z sees the wrong signal and job control misbehaves.
        let host_stopsig = (status >> 8) & 0xff;
        if host_stopsig == 0x13 {
            // macOS WIFCONTINUED → Linux WIFCONTINUED status (0xffff).
            return 0xffff;
        }
        let linux_stopsig = crate::host_signal::host_to_linux_signum(host_stopsig);
        (linux_stopsig << 8) | 0x7f
    } else if low != 0 {
        // Terminated by signal: translate the termination signal.
        let core = status & 0x80;
        let linux_sig = crate::host_signal::host_to_linux_signum(low);
        (linux_sig & 0x7f) | core
    } else {
        // Exited normally: high byte is the exit code, left untouched.
        status
    }
}

/// Build a Linux `siginfo_t` (SIGCHLD layout) for `waitid` from the fields
/// macOS's `waitid` filled. The Linux struct places si_pid@16, si_uid@20,
/// si_status@24 after the common si_signo/si_errno/si_code header. The CLD_*
/// codes match between the kernels; si_status is the raw exit code for
/// CLD_EXITED but a signal number otherwise, so translate that host->Linux.
fn build_sigchld_siginfo(
    si_pid: i32,
    si_uid: u32,
    si_code: i32,
    si_status: i32,
) -> [u8; crate::linux_abi::LINUX_SIGINFO_SIZE] {
    const LINUX_SIGCHLD: i32 = 17;
    const CLD_EXITED: i32 = 1;
    let linux_status = if si_code == CLD_EXITED {
        si_status
    } else {
        crate::host_signal::host_to_linux_signum(si_status)
    };
    let mut buf = [0u8; crate::linux_abi::LINUX_SIGINFO_SIZE];
    buf[0..4].copy_from_slice(&LINUX_SIGCHLD.to_ne_bytes());
    // si_errno [4..8] stays 0.
    buf[8..12].copy_from_slice(&si_code.to_ne_bytes());
    // _pad0 [12..16] stays 0 (union alignment on 64-bit).
    buf[16..20].copy_from_slice(&si_pid.to_ne_bytes());
    buf[20..24].copy_from_slice(&si_uid.to_ne_bytes());
    buf[24..28].copy_from_slice(&linux_status.to_ne_bytes());
    buf
}

#[cfg(test)]
mod affinity_tests {
    use super::{affinity_from_bytes, affinity_to_bytes, default_affinity, lowest_set_cpu};

    #[test]
    fn lowest_set_cpu_finds_first_bit() {
        assert_eq!(lowest_set_cpu(&[0x1]), Some(0));
        assert_eq!(lowest_set_cpu(&[0x3ff]), Some(0)); // full 10-CPU mask → CPU 0
        assert_eq!(lowest_set_cpu(&[1 << 9]), Some(9)); // pinned to CPU 9
        assert_eq!(lowest_set_cpu(&[0, 0x1]), Some(64)); // second word
        assert_eq!(lowest_set_cpu(&[0, 0]), None);
    }

    #[test]
    fn default_affinity_sets_low_ncpu_bits() {
        assert_eq!(default_affinity(1), vec![0x1]);
        assert_eq!(default_affinity(10), vec![0x3ff]);
        assert_eq!(default_affinity(64), vec![u64::MAX]);
        // 65 CPUs spill into a second word.
        assert_eq!(default_affinity(65), vec![u64::MAX, 0x1]);
    }

    #[test]
    fn affinity_bytes_round_trip() {
        let mask = default_affinity(10);
        let bytes = affinity_to_bytes(&mask, 8);
        assert_eq!(bytes, vec![0xff, 0x03, 0, 0, 0, 0, 0, 0]);
        assert_eq!(affinity_from_bytes(&bytes, 1), mask);
    }

    #[test]
    fn affinity_to_bytes_truncates_and_pads() {
        // Truncate a two-word mask to 8 bytes.
        let mask = vec![u64::MAX, 0x1];
        assert_eq!(affinity_to_bytes(&mask, 8), vec![0xff; 8]);
        // Pad a one-word mask out to 16 bytes.
        let padded = affinity_to_bytes(&[0x1], 16);
        assert_eq!(padded[0], 0x1);
        assert!(padded[1..].iter().all(|b| *b == 0));
    }
}
