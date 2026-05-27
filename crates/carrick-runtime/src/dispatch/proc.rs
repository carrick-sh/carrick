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
    /// Whether hardware x86_64 TSO memory ordering is active for this guest
    /// (`prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO)`, set by Rosetta). Tracked
    /// so `PR_GET_MEM_MODEL` reports the current model. The actual ACTLR_EL1
    /// toggle happens in the runtime loop (the dispatcher can't reach the vCPU).
    pub tso_enabled: bool,
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
            tso_enabled: false,
        }
    }
}

impl SyscallDispatcher {
    /// True once this dispatcher is running in a real host child created for a
    /// guest `fork`/fork-like `clone`. Such descendants inherited the original
    /// CLI process state and must use `_exit` on guest process exit instead of
    /// returning through normal Rust/Tokio cleanup.
    pub(crate) fn is_forked_guest_process(&self) -> bool {
        std::process::id() != self.proc.lock().bootstrap_host_pid
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
            base: OpenDescriptionBase::new(status_flags),
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
        &self,
        args_ptr: GuestPtr,
        args_size: u64,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let args_ptr = args_ptr.0;
        if args_size < 8 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }

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
            if args_size < 64 {
                return DispatchOutcome::errno(LINUX_ENOSYS);
            }

            let child_tid_ptr = args.child_tid;
            let parent_tid_ptr = args.parent_tid;
            let stack = args.stack;
            let stack_size = args.stack_size;
            let tls_val = args.tls;

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

        let pidfd_out = if flags & LinuxCloneFlags::PIDFD.bits() != 0 {
            Some(args.pidfd)
        } else {
            None
        };
        DispatchOutcome::Fork { pidfd_out }
    }

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_ENOSYS)
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn personality(this, cx, requested: u64) {
            let mut proc = this.proc.lock();
            let previous = proc.personality;
            if requested != LINUX_PERSONALITY_QUERY {
                proc.personality = requested;
            }
            Ok(DispatchOutcome::Returned {
                value: previous as i64,
            })
        }

        fn prctl(this, cx, option: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) {
            let memory = &mut *cx.memory;
            Ok(match option {
                LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                    value: this.proc.lock().dumpable,
                },
                LINUX_PR_SET_DUMPABLE => {
                    if arg2 > 1 {
                        return Ok(LINUX_EINVAL.into());
                    }
                    this.proc.lock().dumpable = arg2 as i64;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_SET_NAME => {
                    let Ok(bytes) = memory.read_bytes(arg2, LINUX_TASK_COMM_LEN) else {
                        return Ok(LINUX_EFAULT.into());
                    };
                    let task_name = linux_task_name_from_bytes(&bytes);
                    this.proc.lock().task_name = task_name;
                    set_host_process_name(&task_name);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_NAME => {
                    let task_name = this.proc.lock().task_name;
                    if memory.write_bytes(arg2, &task_name).is_err() {
                        return Ok(LINUX_EFAULT.into());
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_SET_PDEATHSIG => {
                    if arg2 > 64 {
                        return Ok(LINUX_EINVAL.into());
                    }
                    this.proc.lock().pdeathsig = arg2 as i64;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_PDEATHSIG => {
                    let pdeathsig = this.proc.lock().pdeathsig;
                    if memory
                        .write_bytes(arg2, &(pdeathsig as i32).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(LINUX_EFAULT.into());
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                // PR_GET_MEM_MODEL — query the active CPU memory-ordering model.
                // 0 = default (weakly-ordered AArch64), 1 = TSO (x86_64-compatible).
                LINUX_PR_GET_MEM_MODEL => DispatchOutcome::Returned {
                    value: i64::from(this.proc.lock().tso_enabled),
                },
                // PR_SET_MEM_MODEL — request a memory-ordering model. Rosetta
                // calls this with PR_SET_MEM_MODEL_TSO at startup. We record the
                // request and hand the runtime a SetMemoryModel outcome; the
                // runtime loop performs the ACTLR_EL1.EnTSO write on the active
                // vCPU thread (the dispatcher can't reach the vCPU) and completes
                // prctl with 0.
                LINUX_PR_SET_MEM_MODEL => match arg2 {
                    LINUX_PR_SET_MEM_MODEL_DEFAULT => {
                        this.proc.lock().tso_enabled = false;
                        DispatchOutcome::SetMemoryModel { tso: false }
                    }
                    LINUX_PR_SET_MEM_MODEL_TSO => {
                        this.proc.lock().tso_enabled = true;
                        DispatchOutcome::SetMemoryModel { tso: true }
                    }
                    _ => DispatchOutcome::errno(LINUX_EINVAL),
                },
                _ => DispatchOutcome::errno(LINUX_EINVAL),
            })
        }

        fn getcpu(this, cx, cpu_address: GuestPtr, node_address: GuestPtr) {
            let memory = &mut *cx.memory;
            let cpu = lowest_set_cpu(&this.proc.lock().affinity).unwrap_or(0);
            let cpu_value = cpu.to_ne_bytes();
            let node_value = 0u32.to_ne_bytes();

            if cpu_address.0 != 0 && memory.write_bytes(cpu_address.0, &cpu_value).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            if node_address.0 != 0 && memory.write_bytes(node_address.0, &node_value).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn gettid(this, cx) {
            if let Some(t) = cx.thread {
                if t.registry.live_count() > 1 {
                    return Ok(DispatchOutcome::Returned {
                        value: t.tid as i64,
                    });
                }
            }
            Ok(this.getpid())
        }

        fn set_tid_address(this, cx, addr: GuestPtr) {
            if let Some(t) = cx.thread {
                t.registry.set_clear_child_tid(t.tid, addr.0);
                return Ok(DispatchOutcome::Returned {
                    value: t.tid as i64,
                });
            }
            Ok(this.getpid())
        }

        fn set_robust_list(this, cx, head: GuestPtr, len: u64) {
            if len == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sched_yield(this, cx) {
            std::thread::yield_now();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sched_getaffinity(this, cx, pid: u64, size: u64, address: GuestPtr) {
            let size = size as usize;
            let memory = &mut *cx.memory;

            if matches!(this.resolve_affinity_target(pid), AffinityTarget::NotFound) {
                return Ok(LINUX_ESRCH.into());
            }
            let kernel_bytes = crate::host_facts::logical_cpu_count().div_ceil(64) * 8;
            if size < kernel_bytes {
                return Ok(LINUX_EINVAL.into());
            }
            let mask = this.proc.lock().affinity.clone();
            let buf = affinity_to_bytes(&mask, kernel_bytes);
            if memory.write_bytes(address.0, &buf).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned {
                value: kernel_bytes as i64,
            })
        }

        fn sched_setaffinity(this, cx, pid: u64, size: u64, address: GuestPtr) {
            let size = size as usize;
            let memory = &*cx.memory;

            let read_len = size.min(128);
            let bytes = match memory.read_bytes(address.0, read_len) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(LINUX_EFAULT.into()),
            };
            let target = this.resolve_affinity_target(pid);
            if matches!(target, AffinityTarget::NotFound) {
                return Ok(LINUX_ESRCH.into());
            }
            if matches!(target, AffinityTarget::OtherGuest) && this.creds.lock().euid != 0 {
                return Ok(LINUX_EPERM.into());
            }
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
            if matches!(target, AffinityTarget::SelfProc) {
                this.proc.lock().affinity = effective;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn futex(this, cx, address: GuestPtr, operation: u64, value: u64, timeout_address: GuestPtr) {
            let value = value as u32;
            let args = cx.raw_args();
            let thread = cx.thread;
            let memory = &*cx.memory;
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
            let word = match read_u32(memory, address.0) {
                Ok(word) => word,
                Err(errno) => return Ok(errno.into()),
            };

            let Some(thread) = thread else {
                return Ok(match command {
                    LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
                    LINUX_FUTEX_WAIT => {
                        if word != value || timeout_address.0 == 0 {
                            return Ok(LINUX_EAGAIN.into());
                        }
                        let timespec = match read_timespec(memory, timeout_address.0) {
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

            if !futex_flags.contains(LinuxFutexFlags::PRIVATE) {
                cx.reporter
                    .record(crate::compat::CompatEvent::partial_syscall(
                        98,
                        "futex",
                        args,
                        "non-private futex treated as private (shared address space)",
                    ));
            }

            Ok(match command {
                LINUX_FUTEX_WAKE => {
                    let n = thread.futex.wake(address.0, value);
                    DispatchOutcome::Returned {
                        value: i64::from(n),
                    }
                }
                LINUX_FUTEX_WAIT => {
                    if word != value {
                        return Ok(LINUX_EAGAIN.into());
                    }
                    let timeout = if timeout_address.0 == 0 {
                        None
                    } else {
                        let timespec = match read_timespec(memory, timeout_address.0) {
                            Ok(t) => t,
                            Err(errno) => return Ok(errno.into()),
                        };
                        match duration_from_linux_timespec(timespec) {
                            Ok(t) => t,
                            Err(errno) => return Ok(errno.into()),
                        }
                    };
                    DispatchOutcome::FutexWait {
                        wait: thread.futex.prepare_wait(address.0),
                        timeout,
                    }
                }
                _ => DispatchOutcome::errno(LINUX_ENOSYS),
            })
        }

        fn uname(this, cx, address: GuestPtr) {
            let memory = &mut *cx.memory;
            if memory
                .write_bytes(address.0, LinuxUtsname::carrick_aarch64().abi_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn ptrace(this, cx) {
            Ok(LINUX_ENOSYS.into())
        }

        fn reboot(this, cx) {
            Ok(LINUX_EPERM.into())
        }

        fn sethostname(this, cx) {
            Ok(LINUX_EPERM.into())
        }

        fn setdomainname(this, cx) {
            Ok(LINUX_EPERM.into())
        }

        fn setpgid(this, cx, pid: Pid, pgid: Pid) {
            if let Err(errno) = (unsafe { libc::setpgid(pid.0, pgid.0) }).host_syscall_errno() {
                return Ok(errno.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn getpgid(this, cx, pid: Pid) {
            let r = match (unsafe { libc::getpgid(pid.0) }).host_syscall_errno() {
                Ok(value) => value,
                Err(errno) => return Ok(errno.into()),
            };
            Ok(DispatchOutcome::Returned {
                value: i64::from(r),
            })
        }

        fn getsid(this, cx, pid: Pid) {
            let r = match (unsafe { libc::getsid(pid.0) }).host_syscall_errno() {
                Ok(value) => value,
                Err(errno) => return Ok(errno.into()),
            };
            Ok(DispatchOutcome::Returned {
                value: i64::from(r),
            })
        }

        fn setsid(this, cx) {
            let r = match (unsafe { libc::setsid() }).host_syscall_errno() {
                Ok(value) => value,
                Err(errno) => return Ok(errno.into()),
            };
            Ok(DispatchOutcome::Returned {
                value: i64::from(r),
            })
        }

        fn waitid(this, cx, idtype: u64, id: u64, infop_addr: GuestPtr, options: u64) {
            use crate::linux_abi::{
                LINUX_WCONTINUED, LINUX_WEXITED, LINUX_WNOHANG, LINUX_WNOWAIT, LINUX_WSTOPPED,
            };
            if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if options & LINUX_WAITID_STATE_MASK == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let (host_idtype, host_id): (libc::idtype_t, libc::id_t) = match idtype {
                LINUX_P_ALL => (libc::P_ALL, 0),
                LINUX_P_PID => (libc::P_PID, id as libc::id_t),
                LINUX_P_PGID => (libc::P_PGID, id as libc::id_t),
                LINUX_P_PIDFD => match this.pidfd_host_pid(id as i32) {
                    Some(host_pid) => (libc::P_PID, host_pid as libc::id_t),
                    None => return Ok(LINUX_EBADF.into()),
                },
                _ => return Ok(LINUX_EINVAL.into()),
            };
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
            if options & LINUX_WNOWAIT != 0 {
                host_options |= libc::WNOWAIT;
            }
            let guest_nohang = options & LINUX_WNOHANG != 0;

            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::waitid(
                    host_idtype,
                    host_id,
                    &mut info,
                    host_options | libc::WNOHANG,
                )
            };
            if r != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Ok(DispatchOutcome::errno(errno));
            }
            clear_unrequested_waitid_state(&mut info, options);
            let si_pid = info.si_pid;
            if si_pid == 0 && !guest_nohang {
                if idtype == LINUX_P_PIDFD {
                    if let Some(host_fd) = this.host_fd_for_poll(id as i32) {
                        return Ok(DispatchOutcome::WaitOnPollFds {
                            fds: vec![(host_fd, libc::POLLIN)],
                            timeout: None,
                            on_timeout: 0,
                            block_signals: 0,
                        });
                    }
                }
                if idtype == LINUX_P_PID {
                    return Ok(DispatchOutcome::WaitOnProcExit {
                        pid: id as i32,
                        block_signals: 0,
                    });
                }
                loop {
                    let r = unsafe { libc::waitid(host_idtype, host_id, &mut info, host_options) };
                    if r == 0 {
                        if !clear_unrequested_waitid_state(&mut info, options) {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        break;
                    }
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if errno == LINUX_EINTR
                        && !crate::host_signal::has_process_pending()
                        && !crate::fork_quiesce::is_quiescing()
                    {
                        continue;
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            if infop_addr.0 != 0 {
                let bytes = if info.si_pid == 0 {
                    [0u8; crate::linux_abi::LINUX_SIGINFO_SIZE]
                } else {
                    build_sigchld_siginfo(info.si_pid, info.si_uid, info.si_code, info.si_status)
                };
                let memory = &mut *cx.memory;
                if memory.write_bytes(infop_addr.0, &bytes).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn wait4(this, cx, pid: Pid, wstatus_addr: GuestPtr, options: u64, rusage_addr: GuestPtr) {
            let memory = &mut *cx.memory;
            if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
                return Ok(LINUX_EINVAL.into());
            }
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
            let mut host_rusage: libc::rusage = unsafe { std::mem::zeroed() };
            let can_park_on_proc_exit = pid.0 > 0
                && host_options & libc::WNOHANG == 0
                && options & (crate::linux_abi::LINUX_WUNTRACED | crate::linux_abi::LINUX_WCONTINUED)
                    == 0;
            let result = if can_park_on_proc_exit {
                let r = unsafe {
                    libc::wait4(
                        pid.0,
                        &mut host_status,
                        host_options | libc::WNOHANG,
                        &mut host_rusage,
                    )
                };
                match r.host_syscall_errno() {
                    Ok(0) => {
                        return Ok(DispatchOutcome::WaitOnProcExit {
                            pid: pid.0,
                            block_signals: 0,
                        });
                    }
                    Ok(value) => Ok(value),
                    Err(errno) => Err(errno),
                }
            } else {
                loop {
                    let r =
                        unsafe { libc::wait4(pid.0, &mut host_status, host_options, &mut host_rusage) };
                    match r.host_syscall_errno() {
                        Ok(value) => break Ok(value),
                        Err(errno) => {
                            if errno == LINUX_EINTR && !crate::host_signal::has_process_pending() {
                                continue;
                            }
                            break Err(errno);
                        }
                    }
                }
            };
            let result = match result {
                Ok(value) => value,
                Err(errno) => {
                    return Ok(errno.into());
                }
            };
            if result == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let tv_us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
            let child_guest_us = crate::guest_cpu::reap_child_guest_ns(result as u32) / 1000;
            let child_user_us = child_guest_us + tv_us(host_rusage.ru_utime);
            let child_system_us = tv_us(host_rusage.ru_stime);
            crate::guest_cpu::add_reaped_child(child_user_us, child_system_us);
            if rusage_addr.0 != 0 {
                let child_rusage = rusage_from_us(child_user_us, child_system_us);
                if memory
                    .write_bytes(rusage_addr.0, child_rusage.abi_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            let host_status = translate_wait_status(host_status);
            if wstatus_addr.0 != 0 {
                let bytes = host_status.to_ne_bytes();
                if memory.write_bytes(wstatus_addr.0, &bytes).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(result),
            })
        }

        fn execve(this, cx, pathname_addr: GuestPtr, argv_addr: GuestPtr, envp_addr: GuestPtr) {
            let memory = &*cx.memory;

            let path = match read_guest_c_string(memory, pathname_addr.0) {
                Ok(p) => p,
                Err(errno) => return Ok(errno.into()),
            };
            let argv = match read_guest_string_array(memory, argv_addr.0) {
                Ok(v) => v,
                Err(errno) => return Ok(errno.into()),
            };
            let env = match read_guest_string_array(memory, envp_addr.0) {
                Ok(v) => v,
                Err(errno) => return Ok(errno.into()),
            };

            Ok(DispatchOutcome::Execve { path, argv, env })
        }

        fn clone(this, cx, flags: u64, stack: u64, parent_tid: GuestPtr, tls: u64, child_tid: GuestPtr) {
            let thread_mask = LinuxCloneFlags::THREAD_MASK;
            if (flags & thread_mask) == thread_mask {
                let parent_tid_addr = if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
                    parent_tid.0
                } else {
                    0
                };
                let tls = if flags & LinuxCloneFlags::SETTLS.bits() != 0 {
                    tls
                } else {
                    0
                };
                let child_tid_addr = if flags
                    & (LinuxCloneFlags::CHILD_SETTID | LinuxCloneFlags::CHILD_CLEARTID).bits()
                    != 0
                {
                    child_tid.0
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

            let pidfd_out = if flags & LinuxCloneFlags::PIDFD.bits() != 0 {
                Some(parent_tid.0)
            } else {
                None
            };
            Ok(DispatchOutcome::Fork { pidfd_out })
        }

        fn pidfd_open(this, cx, pid: Pid, flags: u64) {
            const PIDFD_NONBLOCK: u64 = 0o4000;
            if pid.0 <= 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if flags & !PIDFD_NONBLOCK != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(this.open_pidfd(pid.0, flags))
        }

        fn pidfd_send_signal(this, cx, fd: Fd, signum: u64, _info: GuestPtr, _flags: u64) {
            let Some(host_pid) = this.pidfd_host_pid(fd.0) else {
                return Ok(LINUX_EBADF.into());
            };
            if signum == 0 {
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

        fn getrandom(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let length = usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;
            let memory = &mut *cx.memory;
            let mut bytes = vec![0; length];
            if getrandom::fill(&mut bytes).is_err() {
                fill_deterministic_bootstrap_random(&mut bytes);
            }
            if memory.write_bytes(address.0, &bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned {
                value: length as i64,
            })
        }

        fn sys_exit(this, cx, code: u64) {
            let code = code as i32;
            if cx.number() == 93
                && let Some(t) = cx.thread
                && t.registry.live_count() > 1
            {
                return Ok(DispatchOutcome::ThreadExit { code });
            }
            Ok(DispatchOutcome::Exit { code })
        }

        fn sys_clone3(this, cx, args_ptr: GuestPtr, size: u64) {
            Ok(this.clone3(args_ptr, size, &*cx.memory))
        }

        fn sys_rseq(this, cx) {
            Ok(this.rseq())
        }
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

/// Darwin can report a stopped child from `waitid(WEXITED|WNOWAIT)`. Linux only
/// reports SIGCHLD states selected by the caller's W* bits, so filter the host
/// siginfo before deciding whether a child is waitable.
fn clear_unrequested_waitid_state(info: &mut libc::siginfo_t, options: u64) -> bool {
    if info.si_pid == 0 || waitid_state_requested(info.si_code, options) {
        return true;
    }
    *info = unsafe { std::mem::zeroed() };
    false
}

fn waitid_state_requested(si_code: i32, options: u64) -> bool {
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_TRAPPED: i32 = 4;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;

    match si_code {
        CLD_EXITED | CLD_KILLED | CLD_DUMPED => options & crate::linux_abi::LINUX_WEXITED != 0,
        CLD_TRAPPED | CLD_STOPPED => options & crate::linux_abi::LINUX_WSTOPPED != 0,
        CLD_CONTINUED => options & crate::linux_abi::LINUX_WCONTINUED != 0,
        _ => true,
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
