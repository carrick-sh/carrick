//! proc syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;

/// Process I/O priority stored by `ioprio_set` and echoed by `ioprio_get`.
/// carrick has no real I/O scheduler; default is IOPRIO_CLASS_BE(2) level 4 =
/// (2<<13)|4, what the kernel reports for a process that never set one.
static IOPRIO_VALUE: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new((2 << 13) | 4);

/// `sizeof(struct robust_list_head)` on 64-bit Linux: three 8-byte fields
/// (list.next, futex_offset, list_op_pending). set_robust_list requires the
/// caller's `len` to equal this exactly; get_robust_list reports it.
const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Per-Linux-policy priority window for `sched_get_priority_{max,min}`. RT
/// policies expose MAX_USER_RT_PRIO-1 / 1; time-sharing policies expose 0/0;
/// unknown policy is EINVAL.
fn sched_priority_for(policy: i32, max: bool) -> DispatchOutcome {
    match policy {
        LINUX_SCHED_FIFO | LINUX_SCHED_RR => DispatchOutcome::Returned {
            value: if max { 99 } else { 1 },
        },
        LINUX_SCHED_OTHER | LINUX_SCHED_BATCH | LINUX_SCHED_IDLE | LINUX_SCHED_DEADLINE => {
            DispatchOutcome::Returned { value: 0 }
        }
        _ => LINUX_EINVAL.into(),
    }
}

/// True when `pid` names the calling task for the purposes of a sched_* query.
/// Linux accepts `0`, the process pid, and a thread's own tid. Carrick presents
/// the host pid as the guest process pid, plus `LINUX_BOOTSTRAP_PID` (the stable
/// guest-init alias used elsewhere); threaded dispatch also carries the current
/// guest tid.
fn sched_pid_is_self<M: GuestMemory>(cx: &SyscallCtx<'_, M>, pid: u64) -> bool {
    pid == 0
        || pid == std::process::id() as u64
        || pid == LINUX_BOOTSTRAP_PID as u64
        || cx.thread.is_some_and(|thread| pid == thread.tid as u64)
}

/// True when `pid` names a live sibling thread in this Carrick guest process.
fn sched_pid_is_live_guest_thread<M: GuestMemory>(cx: &SyscallCtx<'_, M>, pid: u64) -> bool {
    if pid == 0 || pid > i32::MAX as u64 {
        return false;
    }
    cx.thread
        .is_some_and(|thread| thread.registry.is_live(pid as crate::thread::ThreadId))
}

/// True when `pid` names a live process accessible to the guest: either
/// the calling process / its alias, a live Carrick guest thread tid, or a peer
/// host pid the kernel confirms via `kill(pid, 0)`. Used by sched_get* queries
/// so they can answer for any task in the system the way Linux does (with our
/// uniform SCHED_OTHER + prio 0 model, the actual answer is the same for every
/// valid pid; only the "does it exist?" check varies).
fn sched_pid_exists<M: GuestMemory>(cx: &SyscallCtx<'_, M>, pid: u64) -> bool {
    if sched_pid_is_self(cx, pid) || sched_pid_is_live_guest_thread(cx, pid) {
        return true;
    }
    if pid == 0 || pid > i32::MAX as u64 {
        return false;
    }
    unsafe {
        libc::kill(pid as i32, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// True when `policy` is one of the kernel's known scheduling policies.
fn sched_policy_is_known(policy: i32) -> bool {
    matches!(
        policy,
        LINUX_SCHED_OTHER
            | LINUX_SCHED_FIFO
            | LINUX_SCHED_RR
            | LINUX_SCHED_BATCH
            | LINUX_SCHED_IDLE
            | LINUX_SCHED_DEADLINE
    )
}

/// Read a `struct sched_param { int sched_priority; }` out of guest memory
/// at `address` (or EFAULT on a bad pointer). The struct's only field is the
/// priority on Linux (sched_setattr is a separate richer entry point).
fn sched_read_param_priority<M: GuestMemory>(
    cx: &mut SyscallCtx<M>,
    address: GuestPtr,
) -> Result<i32, i32> {
    if address.0 == 0 {
        // NULL param: kept as the legacy "-1" sentinel so the time-sharing
        // policies' prio!=0 check yields EINVAL (unchanged behavior).
        return Ok(-1);
    }
    let memory = &*cx.memory;
    match memory.read_bytes(address.0, 4) {
        Ok(b) => {
            let arr: [u8; 4] = b.as_slice().try_into().unwrap_or([0; 4]);
            Ok(i32::from_le_bytes(arr))
        }
        // A bad (non-NULL) param pointer is EFAULT — checked before the
        // priority-range validation (sched_setscheduler01 bad-ptr case).
        Err(_) => Err(LINUX_EFAULT),
    }
}

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

    /// Resolve an affinity pid argument. 0 or our own pid is `SelfProc`; a live
    /// sibling guest thread is also `SelfProc` (carrick keeps a single
    /// per-process affinity mask, so a sibling's affinity IS the process
    /// affinity — and `sched_getaffinity`/`setaffinity` accept a thread tid,
    /// like sched_getscheduler/getparam already do); any other thread/process
    /// in the guest tree is `OtherGuest`; anything else is `NotFound` (ESRCH).
    fn resolve_affinity_target<M: GuestMemory>(
        &self,
        cx: &SyscallCtx<M>,
        pid: u64,
    ) -> AffinityTarget {
        if pid == 0 || pid == std::process::id() as u64 {
            AffinityTarget::SelfProc
        } else if cx
            .thread
            .as_ref()
            .is_some_and(|t| t.registry.is_live(pid as crate::thread::ThreadId))
        {
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
        // Linux creates the pidfd with O_CLOEXEC unconditionally (the flags arg
        // only carries PIDFD_NONBLOCK), so the returned fd must have FD_CLOEXEC
        // set — pidfd_open01 asserts F_GETFD & FD_CLOEXEC.
        self.install_fd(description, LINUX_FD_CLOEXEC)
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
        // The Linux kernel only accepts size == one of the documented
        // CLONE_ARGS_SIZE_VERn — anything else is EINVAL (clone302 / glibc's
        // probe). Carrick had this as `< 8` which silently accepted a
        // truncated args buffer and then forked anyway, fork-bombing into
        // the rest of the probe.
        const CLONE_ARGS_SIZE_VER0: u64 = 64;
        const CLONE_ARGS_SIZE_VER1: u64 = 80;
        const CLONE_ARGS_SIZE_VER2: u64 = 88;
        if !matches!(
            args_size,
            CLONE_ARGS_SIZE_VER0 | CLONE_ARGS_SIZE_VER1 | CLONE_ARGS_SIZE_VER2
        ) {
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
        // Reject unknown flag bits (clone303 — kernel allows bits 8..34 only).
        // 0x7_FFFF_FF00 covers CLONE_VM (0x100) through CLONE_INTO_CGROUP
        // (0x4_0000_0000). Anything outside that range is reserved-zero.
        const CLONE3_VALID_FLAGS: u64 = 0x0000_0007_FFFF_FF00;
        if flags & !CLONE3_VALID_FLAGS != 0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        // Inconsistent stack/stack_size pair → EINVAL (clone05/08 shape). A
        // non-zero stack_size with a zero stack is gibberish; symmetric.
        if (args.stack == 0) != (args.stack_size == 0) {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
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
        // clone3 carries the exit signal in its own field; mask to the low
        // byte (signal domain) — faithful and bounded.
        let exit_signal = (args.exit_signal & 0xff) as u32;
        DispatchOutcome::Fork {
            pidfd_out,
            exit_signal,
        }
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

        fn sys_seccomp(this, cx, operation: u64, _flags: u64, args: GuestPtr) {
            // SECCOMP_SET_MODE_FILTER installs a cBPF filter from a sock_fprog;
            // the dispatcher checks it before every subsequent syscall (see
            // `seccomp_precheck`). STRICT mode and the filter flags (TSYNC/LOG/…)
            // are not differentiated in v1.
            match operation as u32 {
                crate::seccomp::SECCOMP_SET_MODE_FILTER => {
                    let memory = &*cx.memory;
                    // struct sock_fprog { unsigned short len; <pad>; sock_filter *filter; }
                    // — `filter` is 8-byte aligned, so it sits at offset 8.
                    let Ok(len_bytes) = memory.read_bytes(args.0, 2) else {
                        return Ok(LINUX_EFAULT.into());
                    };
                    let len = u16::from_ne_bytes([len_bytes[0], len_bytes[1]]) as usize;
                    if len == 0 || len > 4096 {
                        return Ok(LINUX_EINVAL.into());
                    }
                    let Ok(ptr_bytes) = memory.read_bytes(args.0 + 8, 8) else {
                        return Ok(LINUX_EFAULT.into());
                    };
                    let filter_ptr = u64::from_ne_bytes([
                        ptr_bytes[0], ptr_bytes[1], ptr_bytes[2], ptr_bytes[3],
                        ptr_bytes[4], ptr_bytes[5], ptr_bytes[6], ptr_bytes[7],
                    ]);
                    let Ok(prog_bytes) = memory.read_bytes(filter_ptr, len * 8) else {
                        return Ok(LINUX_EFAULT.into());
                    };
                    let Some(prog) = crate::seccomp::SockFilter::parse_program(&prog_bytes) else {
                        return Ok(LINUX_EINVAL.into());
                    };
                    this.seccomp.install(prog);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // STRICT mode (allow only read/write/exit/sigreturn) is not
                // emulated yet; unknown operations are EINVAL.
                crate::seccomp::SECCOMP_SET_MODE_STRICT => Ok(LINUX_ENOSYS.into()),
                _ => Ok(LINUX_EINVAL.into()),
            }
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
            // Linux rejects any len != sizeof(struct robust_list_head) with
            // EINVAL (LTP set_robust_list01 passes len = (size_t)-1). carrick
            // has no robust-futex death-cleanup, so the head pointer is accepted
            // but not retained — this is purely the ABI-conformant validation.
            if len != ROBUST_LIST_HEAD_SIZE {
                return Ok(LINUX_EINVAL.into());
            }
            let _ = head;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// get_robust_list(pid, head_ptr, len_ptr): report the robust-list head
        /// (Linux nr 100). pid 0 names the caller; a non-self pid that exists is
        /// another task we can't inspect without ptrace privilege (EPERM), and a
        /// pid that doesn't exist is ESRCH (LTP get_robust_list01: pid 1 → EPERM,
        /// an unused pid → ESRCH). For the caller, both output pointers must be
        /// writable (NULL → EFAULT). carrick keeps no robust-list head, so it
        /// reports an empty list with the ABI-fixed length; the test checks only
        /// the errno/return path, not the contents.
        fn get_robust_list(this, cx, pid: Pid, head_ptr: GuestPtr, len_ptr: GuestPtr) {
            let pid = i64::from(pid.0);
            let self_pid = std::process::id() as i64;
            if pid != 0 && pid != self_pid {
                // Does the task exist? kill(pid,0) probes it: rc==0 means it
                // exists and we may signal it; errno EPERM means it exists but
                // is owned by another user (e.g. pid 1 / launchd, which LTP
                // uses as its EPERM case); errno ESRCH means no such task. The
                // robust list of any task that ISN'T us is inaccessible without
                // ptrace privilege → EPERM; a nonexistent task → ESRCH.
                if pid > 0 && pid <= i32::MAX as i64 {
                    let rc = unsafe { libc::kill(pid as i32, 0) };
                    let exists = rc == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                    return Ok(if exists { LINUX_EPERM } else { LINUX_ESRCH }.into());
                }
                return Ok(LINUX_ESRCH.into());
            }
            if head_ptr.0 == 0 || len_ptr.0 == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            let memory = &mut *cx.memory;
            if memory.write_bytes(head_ptr.0, &0u64.to_le_bytes()).is_err()
                || memory
                    .write_bytes(len_ptr.0, &ROBUST_LIST_HEAD_SIZE.to_le_bytes())
                    .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// ioprio_set(which, who, ioprio): set the I/O scheduling priority.
        /// carrick has no real I/O scheduler, so this stores a per-process
        /// value that ioprio_get echoes back. Validates `which` ∈ {PROCESS,
        /// PGRP, USER} and the class/data per Linux (LTP ioprio_set02 checks
        /// the EINVAL edges). `who == 0` means the calling process.
        fn ioprio_set(this, cx, which: u64, _who: u64, ioprio: u64) {
            const PROCESS: u64 = 1;
            const PGRP: u64 = 2;
            const USER: u64 = 3;
            if !matches!(which, PROCESS | PGRP | USER) {
                return Ok(LINUX_EINVAL.into());
            }
            let v = ioprio as u32;
            let class = v >> 13;
            let data = v & 0x1fff;
            // Classes: 0=NONE 1=RT 2=BE 3=IDLE (kernel ioprio.c set_task_ioprio).
            // NONE is valid only with level 0 (resets to default), else EINVAL;
            // IDLE ignores the level; RT/BE carry a 0..7 level.
            match class {
                0 => {
                    if data != 0 {
                        return Ok(LINUX_EINVAL.into());
                    }
                }
                3 => {} // IDLE: data ignored
                1 | 2 => {
                    if data >= 8 {
                        return Ok(LINUX_EINVAL.into());
                    }
                }
                _ => return Ok(LINUX_EINVAL.into()),
            }
            IOPRIO_VALUE.store(v, std::sync::atomic::Ordering::SeqCst);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// ioprio_get(which, who): return the stored I/O priority. Default is
        /// IOPRIO_CLASS_BE (2) level 4 — what the kernel reports for a process
        /// that never set one (LTP ioprio_get01 only checks the class is in
        /// range).
        fn ioprio_get(this, cx, which: u64, _who: u64) {
            const PROCESS: u64 = 1;
            const PGRP: u64 = 2;
            const USER: u64 = 3;
            if !matches!(which, PROCESS | PGRP | USER) {
                return Ok(LINUX_EINVAL.into());
            }
            let v = IOPRIO_VALUE.load(std::sync::atomic::Ordering::SeqCst);
            Ok(DispatchOutcome::Returned { value: v as i64 })
        }

        /// vhangup(): "virtually hang up" the current tty. Requires
        /// CAP_SYS_TTY_CONFIG, which carrick models as euid==0 — so a non-root
        /// caller gets EPERM (LTP vhangup01) and root succeeds (vhangup02).
        /// carrick has no real controlling tty to revoke, so success is a
        /// no-op.
        fn vhangup(this, cx) {
            if this.creds.lock().euid != 0 {
                return Ok(LINUX_EPERM.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sched_yield(this, cx) {
            std::thread::yield_now();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn sched_getaffinity(this, cx, pid: u64, size: u64, address: GuestPtr) {
            let size = size as usize;

            // Resolve the target BEFORE borrowing cx.memory (resolve reads
            // cx.thread; the mutable memory borrow below would otherwise alias).
            if matches!(this.resolve_affinity_target(cx, pid), AffinityTarget::NotFound) {
                return Ok(LINUX_ESRCH.into());
            }
            let memory = &mut *cx.memory;
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
            let target = this.resolve_affinity_target(cx, pid);
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

        /// `sched_get_priority_max(policy)`: per Linux kernel/sched/core.c, the
        /// real-time policies (SCHED_FIFO, SCHED_RR) expose MAX_USER_RT_PRIO-1
        /// = 99; the time-sharing policies (NORMAL/OTHER, BATCH, IDLE) and
        /// SCHED_DEADLINE all return 0; any other policy value is EINVAL.
        fn sched_get_priority_max(this, cx, policy: u64) {
            Ok(sched_priority_for(policy as i32, /*max=*/ true))
        }

        /// `sched_get_priority_min(policy)`: the symmetric pair — RT policies
        /// return 1, time-sharing policies return 0, anything else EINVAL.
        fn sched_get_priority_min(this, cx, policy: u64) {
            Ok(sched_priority_for(policy as i32, /*max=*/ false))
        }

        /// `sched_getscheduler(pid)`: return the per-process policy. Carrick
        /// doesn't track guest-set policy yet, so a normal (unprivileged)
        /// process is SCHED_OTHER (0). pid=0 / self / guest thread tids / live
        /// host pids all resolve to a task; unknown pids are ESRCH.
        fn sched_getscheduler(this, cx, pid: u64) {
            // Linux rejects a negative pid with EINVAL before the ESRCH path.
            if (pid as i32) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            Ok(DispatchOutcome::Returned { value: LINUX_SCHED_OTHER as i64 })
        }

        /// `sched_getparam(pid, &sched_param)`: write the scheduling priority
        /// for `pid` into `*sched_param`. With a stubbed SCHED_OTHER, this is
        /// always `sched_priority = 0`.
        fn sched_getparam(this, cx, pid: u64, address: GuestPtr) {
            // Linux semantics: any process can query any other process's
            // sched params. With SCHED_OTHER+prio 0 across the board, the
            // value the guest reads back is the same regardless of which
            // valid pid it picks. A negative pid is EINVAL (before ESRCH).
            if (pid as i32) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            if address.0 == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let memory = &mut *cx.memory;
            let prio: i32 = 0;
            if memory.write_bytes(address.0, &prio.to_le_bytes()).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `sched_getattr(pid, attr, size, flags)`: read a task's scheduling
        /// attributes. carrick presents every task as SCHED_OTHER / nice 0 /
        /// prio 0, so the success path returns a zeroed sched_attr (with the
        /// size field set). Validation matches Linux (LTP sched_getattr02):
        /// flags must be 0, size >= SCHED_ATTR_SIZE_VER0, attr non-NULL (all
        /// EINVAL), and a non-existent pid → ESRCH. Was ENOSYS.
        fn sched_getattr(this, cx, pid: u64, attr: GuestPtr, size: u64, flags: u64) {
            const SCHED_ATTR_SIZE_VER0: u64 = 48;
            // No sched_getattr flags are defined → any flag is EINVAL.
            if flags != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            // The buffer must be at least the ver0 struct.
            if size < SCHED_ATTR_SIZE_VER0 {
                return Ok(LINUX_EINVAL.into());
            }
            // Linux returns EINVAL (not EFAULT) for a NULL attr pointer.
            if attr.0 == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if (pid as i32) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            // SCHED_OTHER, nice 0, priority 0 — a zeroed sched_attr with only
            // the leading `size` field populated (layout: size@0 u32,
            // sched_policy@4 u32, sched_flags@8 u64, sched_nice@16 s32,
            // sched_priority@20 u32, runtime/deadline/period@24/32/40 u64).
            let memory = &mut *cx.memory;
            let mut buf = [0u8; SCHED_ATTR_SIZE_VER0 as usize];
            buf[0..4].copy_from_slice(&(SCHED_ATTR_SIZE_VER0 as u32).to_le_bytes());
            if memory.write_bytes(attr.0, &buf).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `sched_setscheduler(pid, policy, &param)`: switch a process's
        /// policy. Without CAP_SYS_NICE (we are non-root in the guest), Linux
        /// refuses any RT policy with EPERM; SCHED_OTHER+priority=0 succeeds
        /// as a no-op. Unknown policies are EINVAL.
        fn sched_setscheduler(this, cx, pid: u64, policy: u64, address: GuestPtr) {
            if (pid as i32) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            let policy_i = policy as i32;
            if !sched_policy_is_known(policy_i) {
                return Ok(LINUX_EINVAL.into());
            }
            let prio = match sched_read_param_priority(cx, address) {
                Ok(prio) => prio,
                Err(errno) => return Ok(errno.into()),
            };
            if policy_i == LINUX_SCHED_FIFO || policy_i == LINUX_SCHED_RR {
                // No CAP_SYS_NICE in carrick guest → mirror Linux's EPERM.
                return Ok(LINUX_EPERM.into());
            }
            // Time-sharing policies require priority==0.
            if prio != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(DispatchOutcome::Returned { value: LINUX_SCHED_OTHER as i64 })
        }

        /// `sched_setparam(pid, &param)`: change just the priority. For our
        /// SCHED_OTHER-only model the only valid priority is 0; anything else
        /// is EINVAL (matches Linux for SCHED_NORMAL/OTHER/BATCH/IDLE).
        fn sched_setparam(this, cx, pid: u64, address: GuestPtr) {
            if (pid as i32) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            let prio = match sched_read_param_priority(cx, address) {
                Ok(prio) => prio,
                Err(errno) => return Ok(errno.into()),
            };
            if prio != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `sched_rr_get_interval(pid, &timespec)`: write the round-robin
        /// quantum into `*timespec`. SCHED_OTHER tasks aren't on a RR
        /// schedule; Linux returns {0, 0} (and 0). We mirror that.
        fn sched_rr_get_interval(this, cx, pid: u64, address: GuestPtr) {
            if !sched_pid_exists(cx, pid) {
                return Ok(LINUX_ESRCH.into());
            }
            if address.0 == 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let memory = &mut *cx.memory;
            // struct timespec on aarch64: i64 tv_sec, i64 tv_nsec.
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&0i64.to_le_bytes());
            buf[8..16].copy_from_slice(&0i64.to_le_bytes());
            if memory.write_bytes(address.0, &buf).is_err() {
                return Ok(LINUX_EFAULT.into());
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

            // A futex word that lives in a genuine MAP_SHARED file mapping is
            // a CROSS-PROCESS rendezvous (e.g. LTP `tst_checkpoint` between
            // a parent and a forked child sharing `/dev/shm/ltp_*`). The
            // single-threaded dispatcher used to short-circuit to the
            // per-process parking-lot table here, which made the parent's
            // WAIT and the child's WAKE land in DIFFERENT tables — so the
            // wake never reached the wait and LTP TBROKed on
            // `tst_checkpoint_wake … ETIMEDOUT`. Route shared addresses
            // through `__ulock` (the same path the multi-threaded
            // dispatcher uses) so the wakeup keys on the physical page.
            let shared_host_addr = memory.shared_futex_host_addr(address.0);
            crate::probes::futex_route(
                address.0,
                command as i32,
                if shared_host_addr.is_some() { 1 } else { 0 },
                shared_host_addr.map(|h| h as u64).unwrap_or(0),
            );

            Ok(match command {
                LINUX_FUTEX_WAKE => {
                    if let Some(host_addr) = shared_host_addr {
                        // See dispatch/mod.rs futex_threaded — sched_yield
                        // between iterations is the cure for macOS's
                        // wake_by_address_any reporting spurious successes
                        // when called back-to-back on a SHARED address.
                        let mut woke = 0i64;
                        for i in 0..value {
                            let rc = crate::ulock::wake(host_addr, false);
                            crate::probes::ulock_wake(host_addr as u64, i as i32, rc);
                            if rc < 0 {
                                break;
                            }
                            woke += 1;
                            unsafe { libc::sched_yield(); }
                        }
                        return Ok(DispatchOutcome::Returned { value: woke });
                    }
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
                    if let Some(host_addr) = shared_host_addr {
                        return Ok(DispatchOutcome::SharedFutexWait {
                            host_addr,
                            value,
                            timeout,
                        });
                    }
                    if !futex_flags.contains(LinuxFutexFlags::PRIVATE) {
                        cx.reporter
                            .record(crate::compat::CompatEvent::partial_syscall(
                                98,
                                "futex",
                                args,
                                "non-private futex treated as private (shared address space)",
                            ));
                    }
                    DispatchOutcome::FutexWait {
                        wait: thread.futex.prepare_wait(address.0),
                        timeout,
                    }
                }
                LINUX_FUTEX_REQUEUE | LINUX_FUTEX_CMP_REQUEUE => {
                    // Mirror the multi-threaded path (dispatch/mod.rs): arg3 is
                    // nr_requeue, arg4 uaddr2, arg5 val3. See that handler for
                    // the full rationale on how requeue composes with the
                    // parking-lot generation/token model.
                    let nr_wake = value;
                    if (args.0[2] as i32) < 0 || (args.0[3] as i32) < 0 {
                        return Ok(LINUX_EINVAL.into());
                    }
                    let nr_requeue = args.0[3] as u32;
                    let uaddr2 = args.0[4];
                    let val3 = args.0[5] as u32;
                    if raw_command == LINUX_FUTEX_CMP_REQUEUE && word != val3 {
                        return Ok(LINUX_EAGAIN.into());
                    }
                    if let Some(host_addr) = shared_host_addr {
                        // Shared path: no native requeue → wake nr_wake+nr_requeue
                        // (correct per the spurious-wake-tolerant futex contract).
                        let total = (nr_wake as u64).saturating_add(nr_requeue as u64);
                        let mut woke = 0i64;
                        let mut i = 0u64;
                        while i < total {
                            let rc = crate::ulock::wake(host_addr, false);
                            if rc < 0 {
                                break;
                            }
                            woke += 1;
                            unsafe { libc::sched_yield() };
                            i += 1;
                        }
                        return Ok(DispatchOutcome::Returned { value: woke });
                    }
                    let (woken, requeued) =
                        thread.futex.requeue(address.0, uaddr2, nr_wake, nr_requeue);
                    DispatchOutcome::Returned {
                        value: i64::from(woken + requeued),
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
                // Route the host errno through the central Darwin->Linux helper
                // (a raw Darwin errno >34 would otherwise leak to the guest).
                let errno = crate::dispatch::HostSyscallError::last().linux_errno();
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
                    // Same no-interrupt mask as wait4: a blocked or
                    // delivered-and-dropped signal must not EINTR the park.
                    let tid = Self::ctx_tid(cx);
                    let block_signals = this.non_interrupting_signal_mask(tid);
                    return Ok(DispatchOutcome::WaitOnProcExit {
                        pid: id as i32,
                        block_signals,
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
                    let errno = crate::dispatch::HostSyscallError::last().linux_errno();
                    if errno == LINUX_EINTR
                        && !crate::host_signal::has_process_pending()
                        && !crate::fork_quiesce::is_quiescing()
                    {
                        continue;
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            // Mirror wait4 (the child-CPU drain): roll a reaped child's guest CPU
            // into this process's child-time accumulators (RUSAGE_CHILDREN / times
            // cutime). Only on a TERMINAL reap that consumed the zombie: si_pid
            // set, not WNOWAIT (peek leaves the zombie for the real reap), and an
            // exit/kill code (not stop/continue). (audit M4; probe waitidcputime)
            {
                const CLD_EXITED: i32 = 1;
                const CLD_KILLED: i32 = 2;
                const CLD_DUMPED: i32 = 3;
                let terminal = matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED);
                if info.si_pid != 0 && options & LINUX_WNOWAIT == 0 && terminal {
                    let child_guest_us =
                        crate::guest_cpu::reap_child_guest_ns(info.si_pid as u32) / 1000;
                    crate::guest_cpu::add_reaped_child(child_guest_us, 0);
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
                        // Don't interrupt the park for a pending signal that is
                        // blocked OR will be delivered-and-dropped (SIG_IGN /
                        // default-ignore SIGCHLD/SIGURG/SIGWINCH). Otherwise a
                        // sibling child's default-ignored SIGCHLD spuriously
                        // EINTRs this wait — LTP futex_cmp_requeue01 / any
                        // multi-child reap. A real handler still interrupts
                        // (then SA_RESTART restarts wait4).
                        let tid = Self::ctx_tid(cx);
                        let block_signals = this.non_interrupting_signal_mask(tid);
                        return Ok(DispatchOutcome::WaitOnProcExit {
                            pid: pid.0,
                            block_signals,
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
                    // A process-group wait (pid < -1) for a group the kernel
                    // can't find is ESRCH on Linux; macOS surfaces EINVAL for
                    // the bad pgid (LTP waitpid04 INT_MIN case). Remap only that
                    // case — a valid pgid with no children stays ECHILD, and
                    // every other error passes through unchanged.
                    if (pid.0 as i32) < -1 && errno == LINUX_EINVAL {
                        return Ok(LINUX_ESRCH.into());
                    }
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
            // argv/env are opaque BYTE strings (Linux ABI), not UTF-8 — read
            // them byte-preserving so a non-UTF-8 arg/env (e.g. CPython
            // regrtest's PYTHONREGRTEST_UNICODE_GUARD) doesn't EINVAL the execve.
            let argv = match read_guest_string_array_bytes(memory, argv_addr.0) {
                Ok(v) => v,
                Err(errno) => return Ok(errno.into()),
            };
            let env = match read_guest_string_array_bytes(memory, envp_addr.0) {
                Ok(v) => v,
                Err(errno) => return Ok(errno.into()),
            };

            Ok(DispatchOutcome::Execve { path, argv, env })
        }

        fn clone(this, cx, flags: u64, stack: u64, parent_tid: GuestPtr, tls: u64, child_tid: GuestPtr) {
            // Kernel flag-consistency rules (linux/kernel/fork.c copy_process):
            // CLONE_THREAD requires CLONE_SIGHAND, and CLONE_SIGHAND requires
            // CLONE_VM. A guest that asks for a thread without sharing signal
            // handlers + the address space gets EINVAL on real Linux; carrick
            // must mirror that BEFORE the THREAD_MASK dispatch, or a malformed
            // clone would silently take the fork path (LTP clone08 negative
            // shape; the `clonebasic` probe's CLONE_THREAD-alone assertion).
            let vm = LinuxCloneFlags::VM.bits();
            let sighand = LinuxCloneFlags::SIGHAND.bits();
            let thread = LinuxCloneFlags::THREAD.bits();
            if (flags & thread != 0 && flags & sighand == 0)
                || (flags & sighand != 0 && flags & vm == 0)
            {
                return Ok(LINUX_EINVAL.into());
            }

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
            // Legacy clone encodes the exit signal in the low byte of `flags`
            // (CSIGNAL = 0xff). Thread it through so the parent receives the
            // requested signal on child exit instead of a hardcoded SIGCHLD.
            let exit_signal = (flags & 0xff) as u32;
            Ok(DispatchOutcome::Fork {
                pidfd_out,
                exit_signal,
            })
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
            // Only GRND_NONBLOCK(1) | GRND_RANDOM(2) | GRND_INSECURE(4) are
            // valid; any other bit → EINVAL (LTP getrandom05). carrick draws
            // from the host CSPRNG regardless of the source/blocking flags.
            const GRND_SUPPORTED: u64 = 0x0001 | 0x0002 | 0x0004;
            if flags & !GRND_SUPPORTED != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let length = usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;
            // Linux caps getrandom at 2^31-1 and returns a short count; clamp so a
            // huge length can't OOM-abort the runtime. Probe: bigread (read class).
            let length = length.min(crate::dispatch::MAX_RW_COUNT);
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
        let linux_sig = crate::host_signal::host_to_linux_signum(low);
        // macOS by default has RLIMIT_CORE=0 so the host wait status doesn't
        // set the core-dumped bit (0x80) — but the Linux contract is that
        // `WCOREDUMP(status)` is true whenever the process died by a
        // core-dumping signal (SIGABRT/SEGV/BUS/FPE/ILL/QUIT/SYS/TRAP/XCPU/
        // XFSZ). Apps that check `WCOREDUMP` care about "did this die in a
        // core-dumping way", not whether a core file was physically written.
        // Mirror Linux by OR-ing the bit on for those signals; preserve the
        // host's bit if it set it.
        let host_core = status & 0x80;
        // Linux core-dumping signals per signal(7): SIGQUIT(3), SIGILL(4),
        // SIGTRAP(5), SIGABRT(6), SIGBUS(7), SIGFPE(8), SIGSEGV(11),
        // SIGXCPU(24), SIGXFSZ(25), SIGSYS(31).
        let synthetic_core = if matches!(linux_sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
            0x80
        } else {
            0
        };
        (linux_sig & 0x7f) | host_core | synthetic_core
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
    use crate::linux_abi::LINUX_SIGCHLD;
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
