//! Process lifecycle, scheduling, identity, and `prctl` — the syscalls that
//! create, name, schedule, and reap tasks.
//!
//! # Theory of operation
//!
//! Guest processes are Carrick-kernel objects inside one carrier. Guest threads
//! use carrier threads and bounded vCPU leases, while process identity,
//! parentage, waits, signals, and address spaces remain in the kernel graph.
//! Guest identifiers never authorize host process creation or control.
//!
//! ## fork vs. clone(CLONE_THREAD)
//!
//! `clone` is the process/thread split: the kernel's flag-consistency rules are
//! enforced UP FRONT (CLONE_THREAD ⇒ CLONE_SIGHAND ⇒ CLONE_VM, else EINVAL)
//! before dispatch chooses a path, so a malformed thread-clone fails like Linux
//! instead of silently taking the fork path. When the full `THREAD_MASK` is set
//! the handler returns a `CloneThread` outcome (the runtime creates a new vCPU
//! thread sharing the address space); otherwise it is a logical process fork
//! with a distinct MM projection.
//! Thread creation is what apt/dpkg, Go, Node and CPython all actually depend
//! on; the per-thread-vCPU model lives in the runtime, not here.
//!
//! ## Kernel-owned identity ([`ProcState`])
//!
//! Identity queries resolve through kernel task keys and namespace mappings.
//! The carrier's host pid is lifecycle metadata, not a guest process identity
//! or a fallback target for guest-facing process syscalls.
//!
//! ## prctl: mostly a faithful register file
//!
//! Most `prctl` options have no host effect; carrick's job is to RECORD them so
//! the matching `PR_GET_*` reads back exactly what was set (task comm
//! name, pdeathsig, keepcaps, child-subreaper, no-new-privs, timerslack). These
//! round-trip even when the modulated behavior is a follow-up, because real
//! programs (init systems, libcap, seccomp installers) feature-check by setting
//! and reading back. The exceptions with teeth: `PR_SET_NAME` feeds
//! `/proc/self/comm`; `PR_SET_NO_NEW_PRIVS` is a one-way latch (the seccomp
//! precondition); `PR_SET_MEM_MODEL_TSO` flips a flag the runtime loop reads to
//! toggle ACTLR_EL1 x86-TSO ordering (Rosetta), since the dispatcher can't
//! reach the vCPU.
//!
//! ## scheduling, affinity, and the rest
//!
//! carrick has a uniform SCHED_OTHER / priority-0 model, so `sched_get*`
//! queries answer the same for any valid pid — the only thing that varies is
//! "does this task exist?" (resolved through the kernel graph). Affinity is
//! recorded as an observable mask inherited by logical child tasks without
//! physically pinning the host thread. `getrandom` and the interval timers
//! (`itimers`, whose expiry signal is delivered by an `EVFILT_TIMER` on the
//! signal pump's kqueue — see `crate::itimer`) round out the file.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table.
use super::*;
use crate::linux_abi::LinuxErrno;

syscall_table! {
    /// Per-module syscall routing for the `proc` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `proc` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_proc;
    30 => ioprio_set,
    31 => ioprio_get,
    58 => vhangup,
    92 => personality,
    95 => waitid,
    96 => set_tid_address,
    97 => unshare,
    98 => futex,
    99 => set_robust_list,
    100 => get_robust_list,
    117 => ptrace,
    118 => sched_setparam,
    119 => sched_setscheduler,
    120 => sched_getscheduler,
    121 => sched_getparam,
    122 => sched_setaffinity,
    123 => sched_getaffinity,
    124 => sched_yield,
    125 => sched_get_priority_max,
    126 => sched_get_priority_min,
    127 => sched_rr_get_interval,
    142 => reboot,
    154 => setpgid,
    155 => getpgid,
    156 => getsid,
    157 => setsid,
    160 => uname,
    161 => sethostname,
    162 => setdomainname,
    167 => prctl,
    168 => getcpu,
    220 => clone,
    221 => execve,
    449 => futex_waitv,
    281 => execveat,
    260 => wait4,
    270 => process_vm_readv,
    271 => process_vm_writev,
    277 => sys_seccomp,
    275 => sched_getattr,
    278 => getrandom,
    424 => pidfd_send_signal,
    434 => pidfd_open,
    438 => pidfd_getfd,
    93 | 94 => sys_exit,
    178 => gettid,
    435 => sys_clone3,
    293 => sys_rseq,
}
// ptrace(2) PEEK/POKE request numbers live in the shared ABI crate (the
// dispatch ABI-constant gate forbids module-level LINUX_* declarations here).
use crate::linux_abi::{
    LINUX_PTRACE_ATTACH, LINUX_PTRACE_PEEKDATA, LINUX_PTRACE_PEEKTEXT, LINUX_PTRACE_PEEKUSER,
    LINUX_PTRACE_POKEDATA, LINUX_PTRACE_POKETEXT, LINUX_PTRACE_POKEUSER,
};

/// `sizeof(struct robust_list_head)` on 64-bit Linux: three 8-byte fields
/// (list.next, futex_offset, list_op_pending). set_robust_list requires the
/// caller's `len` to equal this exactly; get_robust_list reports it.
const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Render the freshly-created session through the caller's PID namespace.
/// `setsid(2)` returns a session id that is also its leader's pid.
fn ns_visible_session(
    context: &crate::kernel::KernelContext,
    session: crate::kernel::SessionId,
) -> i32 {
    u32::try_from(session.raw())
        .ok()
        .and_then(|raw| crate::namespace::pid::kernel_to_ns_for(context, raw))
        .and_then(|visible| i32::try_from(visible).ok())
        .unwrap_or(0)
}

/// The Linux process a pid-taking identity syscall names: `0` is the caller,
/// anything positive is a guest pid, anything negative is ESRCH.
///
/// Resolution is entirely guest-domain. The pid arguments of `getpgid`/`getsid`
/// have never been host pids under HVPatch — a Linux process there is a thread
/// of one carrier — so translating them through the pid-namespace region and
/// handing the result to Darwin asked the host about a number that means
/// something else in its own namespace.
/// Resolve a pid the GUEST supplied into carrick's task id.
///
/// A guest names processes in its own pid namespace, and carrick's kernel graph
/// names them by task id -- two domains that share `i32` and are offset the
/// moment a container exists (task 5 is ns pid 4). Treating the guest's number
/// as a task id silently addresses a DIFFERENT process, or none: a guest asking
/// about ITSELF by `getpid()` did not match its own task, so
/// `process_vm_readv(getpid(), ...)` missed the self-transfer path entirely.
///
/// Untranslatable ids stay untranslated rather than becoming zero, so a guest
/// outside any namespace region is unaffected.
fn guest_pid_to_task_id(
    context: &crate::kernel::KernelContext,
    pid: Pid,
) -> Result<crate::kernel::TaskId, LinuxErrno> {
    let raw = u32::try_from(pid.0).map_err(|_| LINUX_ESRCH)?;
    let host = crate::namespace::pid::ns_to_kernel_for(context, raw).ok_or(LINUX_ESRCH)?;
    let host = i32::try_from(host).map_err(|_| LINUX_ESRCH)?;
    crate::kernel::TaskId::from_abi_positive(host).map_err(|_| LINUX_ESRCH)
}

fn identity_target_task(
    context: &crate::kernel::KernelContext,
    pid: Pid,
) -> Result<crate::kernel::TaskId, LinuxErrno> {
    if pid.0 == 0 {
        return Ok(context.task().key().id);
    }
    guest_pid_to_task_id(context, pid)
}

/// Per-Linux-policy priority window for `sched_get_priority_{max,min}`. RT
/// Build the [`DispatchOutcome::CloneThread`] for a thread-creating clone/clone3.
/// Applies the SETTLS / PARENT_SETTID / (CHILD_SETTID|CHILD_CLEARTID) gates to
/// the raw arg values (gated-off slots become 0). Params follow the `clone(2)`
/// ABI order — flags, child stack pointer, parent-tid ptr, tls, child-tid ptr —
/// so both callers pass them in the same memorable order (clone3 pre-adds
/// stack_size to get the child SP).
fn clone_thread_outcome(
    flags: u64,
    child_sp: u64,
    parent_tid_ptr: u64,
    tls_val: u64,
    child_tid_ptr: u64,
) -> DispatchOutcome {
    DispatchOutcome::CloneThread {
        stack: child_sp,
        tls: if flags & LinuxCloneFlags::SETTLS.bits() != 0 {
            Some(tls_val)
        } else {
            None
        },
        flags,
        parent_tid_addr: if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
            parent_tid_ptr
        } else {
            0
        },
        child_tid_addr: if flags & LinuxCloneFlags::CHILD_SETTID.bits() != 0 {
            child_tid_ptr
        } else {
            0
        },
        clear_child_tid_addr: if flags & LinuxCloneFlags::CHILD_CLEARTID.bits() != 0 {
            child_tid_ptr
        } else {
            0
        },
    }
}

fn is_thread_clone(flags: u64) -> bool {
    flags & LinuxCloneFlags::THREAD.bits() != 0
}

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
        _ => DispatchOutcome::errno(LINUX_EINVAL),
    }
}

/// True when `pid` names the calling task for the purposes of a sched_* query.
/// Linux accepts `0`, the process pid, and a thread's own tid. Carrick presents
/// the host pid as the guest process pid, plus `LINUX_BOOTSTRAP_PID` (the stable
/// guest-init alias used elsewhere); threaded dispatch also carries the current
/// guest tid.
pub(super) fn sched_pid_is_self<M: CurrentMmMemory>(cx: &SyscallCtx<'_, M>, pid: u64) -> bool {
    if pid == 0 || pid > i32::MAX as u64 {
        return pid == 0;
    }
    let requested = pid as u32;
    let own_pid = u32::try_from(cx.kernel.task().key().id.raw())
        .ok()
        .and_then(|id| crate::namespace::pid::kernel_to_ns_for(cx.kernel, id));
    let own_tid = u32::try_from(cx.kernel.thread().key().tid.raw())
        .ok()
        .and_then(|id| crate::namespace::pid::kernel_to_ns_for(cx.kernel, id));
    own_pid == Some(requested) || own_tid == Some(requested)
}

/// True when `pid` names a live sibling thread in this Carrick guest process.
pub(super) fn sched_pid_is_live_guest_thread<M: CurrentMmMemory>(
    cx: &SyscallCtx<'_, M>,
    pid: u64,
) -> bool {
    if pid == 0 || pid > i32::MAX as u64 {
        return false;
    }
    let Some(internal) = crate::namespace::pid::guest_tid_to_kernel_for(cx.kernel, pid as i32)
    else {
        return false;
    };
    cx.thread.is_some_and(|thread| {
        thread
            .registry
            .is_live(crate::thread::ThreadId::from_guest_supplied_tid(internal))
    })
}

/// Classification of a sched_*/priority `pid` argument relative to the caller,
/// resolved against carrick's guest process model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SchedTarget {
    /// 0, the caller's own pid/alias, or one of its live sibling thread tids —
    /// operate on the calling process.
    SelfProc,
    /// Another Linux process, carrying the effective uid it runs as (EPERM for
    /// an unprivileged, non-owning caller changing its scheduling attributes).
    OtherGuest { euid: carrick_abi::NsUid },
    /// No such guest task — ESRCH.
    NotFound,
}

/// Resolve a guest-supplied sched/affinity `pid` against carrick's guest process
/// model — the single resolver shared by every sched_* handler. Self (0, our own
/// pid/alias, our own thread, a live sibling thread) is `SelfProc`; any other
/// Linux process is `OtherGuest` carrying its own euid; anything else is
/// `NotFound` (ESRCH).
///
/// On the HVPatch lane the answer comes from carrick's kernel graph, because
/// there is nothing else to ask: every logical Linux process is a THREAD of one
/// VM carrier, so `host_proc::is_guest_process` — which walks the DARWIN ppid
/// chain via libproc — finds no host process for any live sibling and reported
/// ESRCH for every one of them (LTP sched_getparam01, sched_setparam05,
/// sched_setaffinity01, process_vm01). The target's euid comes from the same
/// graph, so it is read from the same authority as the caller's own
/// `cred_snapshot()`.
///
/// Off that lane a Linux process IS a host process: the guest names it by
/// ns-pid, so translate to the host pid and consult the guest process table
/// rather than `kill(pid, 0)`-ing an arbitrary host pid — a raw ns-pid probed
/// against the host would spuriously match an unrelated host process/kthread
/// sharing the numeric value (over-inclusive), and a valid sibling's ns-pid
/// would never be recognised as a peer guest (under-inclusive).
pub(super) fn resolve_sched_target<M: CurrentMmMemory>(
    this: &SyscallDispatcher,
    cx: &SyscallCtx<'_, M>,
    pid: u64,
) -> SchedTarget {
    if sched_pid_is_self(cx, pid) || sched_pid_is_live_guest_thread(cx, pid) {
        return SchedTarget::SelfProc;
    }
    if pid == 0 || pid > i32::MAX as u64 {
        return SchedTarget::NotFound;
    }
    if let Some(target) = this.guest_process_target(cx.kernel, pid as i32) {
        return match target.euid() {
            Some(euid) => SchedTarget::OtherGuest { euid },
            None => SchedTarget::NotFound,
        };
    }
    SchedTarget::NotFound
}

/// True when `pid` names a live process accessible to the guest (self or another
/// live carrick guest). Used by the sched_get*/policy queries, which answer the
/// same for every valid pid under our uniform SCHED_OTHER + prio 0 model; only
/// the "does it exist?" check varies. Backed by [`resolve_sched_target`].
fn sched_pid_exists<M: CurrentMmMemory>(
    this: &SyscallDispatcher,
    cx: &SyscallCtx<'_, M>,
    pid: u64,
) -> bool {
    resolve_sched_target(this, cx, pid) != SchedTarget::NotFound
}

/// `check_same_owner` for a cross-process `sched_setparam`/`sched_setaffinity`
/// (an already-resolved `SchedTarget::OtherGuest`). Root always may; a non-root
/// caller may change another process's scheduling attributes only when its euid
/// matches the target's — the same ownership rule carrick's `kill`/`setpriority`
/// use, NOT a root-only proxy (a SAME-OWNER non-root set must succeed: LTP
/// sched_setparam05 / sched_setaffinity01). Returns true when the set is
/// PERMITTED.
fn sched_cross_owner_ok(target_euid: carrick_abi::NsUid, caller_euid: carrick_abi::NsUid) -> bool {
    caller_euid.is_root() || caller_euid == target_euid
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

fn ptrace_text_data_addr_is_invalid(addr: GuestPtr) -> bool {
    let signed_addr = addr.0 as i64;
    signed_addr < 0 || addr.0 < 4096
}

fn ptrace_user_addr_is_invalid(addr: GuestPtr) -> bool {
    let signed_addr = addr.0 as i64;
    signed_addr < 0 || addr.0 > 4096
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtraceTransport {
    Host,
    VirtualNative,
    VirtualHvpatch,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostPgid(u32);

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtraceWaitTarget {
    Exact(HostPid),
    Any,
    ProcessGroup(HostPgid),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VirtualPtraceControlRequest {
    Continue,
    Kill,
    Detach,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtraceRequestRoute {
    Host,
    Shared,
    VirtualTraceme,
    VirtualControl(VirtualPtraceControlRequest),
}

fn select_ptrace_transport(
    page_geometry: crate::page_profile::PageGeometry,
    hvpatch_lane: bool,
) -> PtraceTransport {
    if hvpatch_lane {
        PtraceTransport::VirtualHvpatch
    } else if page_geometry.native_profile.is_some() {
        PtraceTransport::VirtualNative
    } else {
        PtraceTransport::Host
    }
}

#[cfg(test)]
fn should_drain_child_guest_cpu(transport: PtraceTransport, terminal_reap: bool) -> bool {
    transport == PtraceTransport::Host || terminal_reap
}

#[cfg(test)]
fn route_ptrace_request(
    transport: PtraceTransport,
    request: u64,
    data: u64,
) -> Result<PtraceRequestRoute, LinuxErrno> {
    if transport == PtraceTransport::Host {
        return Ok(PtraceRequestRoute::Host);
    }
    match request {
        0 => Ok(PtraceRequestRoute::VirtualTraceme),
        7 if data == 0 => Ok(PtraceRequestRoute::VirtualControl(
            VirtualPtraceControlRequest::Continue,
        )),
        8 => Ok(PtraceRequestRoute::VirtualControl(
            VirtualPtraceControlRequest::Kill,
        )),
        17 if data == 0 => Ok(PtraceRequestRoute::VirtualControl(
            VirtualPtraceControlRequest::Detach,
        )),
        7 | 17 => Err(LINUX_EINVAL),
        _ => Ok(PtraceRequestRoute::Shared),
    }
}

#[cfg(test)]
fn ptrace_wait_target_for_wait4(host_target: i32) -> PtraceWaitTarget {
    match host_target {
        target if target > 0 => PtraceWaitTarget::Exact(HostPid(target as u32)),
        -1 => PtraceWaitTarget::Any,
        0 => PtraceWaitTarget::ProcessGroup(HostPgid(unsafe { libc::getpgrp() } as u32)),
        target => PtraceWaitTarget::ProcessGroup(HostPgid(target.unsigned_abs())),
    }
}

// `libc::id_t` is u32 on Darwin and i64 on FreeBSD, so the fallible pid
// conversion below is load-bearing on some targets and an identity on others.
#[allow(clippy::useless_conversion)]
#[cfg(test)]
fn ptrace_wait_target_for_waitid(
    host_idtype: libc::idtype_t,
    host_id: libc::id_t,
) -> PtraceWaitTarget {
    // `host_id` re-enters the typed pid domain here. It was built from a host
    // pid/pgid that already fits u32 (`ns_to_host_or_self` /
    // `ns_to_host_pgid` / `pidfd_host_pid` all return u32 host ids; the
    // `getpgrp` sentinel resolution is a positive pid_t), so this conversion
    // is lossless by construction even where `libc::id_t` is a wider signed
    // type (FreeBSD's i64). A value outside u32 names no real host process;
    // degrade it to the conservative `Any` target (matches every lease)
    // rather than wrapping into an unrelated pid.
    let typed_host_id = u32::try_from(host_id).ok();
    if host_idtype == libc::P_PID {
        match typed_host_id {
            Some(pid) => PtraceWaitTarget::Exact(HostPid(pid)),
            None => PtraceWaitTarget::Any,
        }
    } else if host_idtype == libc::P_PGID {
        let pgid = if host_id == 0 {
            u32::try_from(unsafe { libc::getpgrp() }).ok()
        } else {
            typed_host_id
        };
        match pgid {
            Some(pgid) => PtraceWaitTarget::ProcessGroup(HostPgid(pgid)),
            None => PtraceWaitTarget::Any,
        }
    } else {
        PtraceWaitTarget::Any
    }
}

#[cfg(test)]
fn ptrace_wait_target_conflicts(leased_pid: u32, target: PtraceWaitTarget) -> bool {
    match target {
        PtraceWaitTarget::Exact(pid) => pid.0 == leased_pid,
        PtraceWaitTarget::Any => true,
        PtraceWaitTarget::ProcessGroup(pgid) => {
            let leased_pgid = unsafe { libc::getpgid(leased_pid as i32) };
            leased_pgid > 0 && leased_pgid as u32 == pgid.0
        }
    }
}

#[cfg(test)]
fn ptrace_wait_park_pid(target: PtraceWaitTarget) -> Option<i32> {
    match target {
        PtraceWaitTarget::Exact(pid) => i32::try_from(pid.0).ok(),
        PtraceWaitTarget::Any => crate::guest_cpu::wait_any_park_pid(std::process::id()),
        PtraceWaitTarget::ProcessGroup(pgid) => {
            let has_direct_member = crate::guest_cpu::direct_children_for_wait(std::process::id())
                .into_iter()
                .any(|pid| unsafe { libc::getpgid(pid as i32) } == pgid.0 as i32);
            if has_direct_member {
                return Some(-1);
            }
            i32::try_from(pgid.0)
                .ok()
                .and_then(i32::checked_neg)
                .and_then(|target| {
                    crate::guest_cpu::pending_adopted_child(std::process::id(), target)
                })
                .and_then(|pid| i32::try_from(pid).ok())
        }
    }
}

fn hvpatch_reported_tid(kernel_tid: i32) -> Option<u32> {
    u32::try_from(kernel_tid).ok()
}

#[cfg(test)]
fn virtual_ptrace_stop_status(linux_signum: i32) -> i32 {
    (linux_signum << 8) | 0x7f
}

#[cfg(test)]
fn child_is_terminally_waitable(pid: u32) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc != 0 || carrick_portable::si_pid(&info) != pid as i32 {
        return false;
    }
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED)
}

/// Read a `struct sched_param { int sched_priority; }` out of guest memory
/// at `address` (or EFAULT on a bad pointer). The struct's only field is the
/// priority on Linux (sched_setattr is a separate richer entry point).
/// First non-canonical x86_64 user virtual address: user space occupies the low
/// canonical half `[0, 0x0000_8000_0000_0000)`. A guest pointer at or above this
/// is non-canonical and can never be a valid mapping.
const NONCANONICAL_USER_VA: u64 = 0x0000_8000_0000_0000;

fn sched_read_param_priority<M: CurrentMmMemory>(
    cx: &mut SyscallCtx<M>,
    address: GuestPtr,
) -> Result<i32, LinuxErrno> {
    if address.0 == 0 {
        // NULL param: kept as the legacy "-1" sentinel so the time-sharing
        // policies' prio!=0 check yields EINVAL (unchanged behavior).
        return Ok(-1);
    }
    // A non-canonical user pointer (>= the x86_64 low-half canonical ceiling) can
    // never name a valid guest mapping — every guest VA lives in the low canonical
    // half (identity: guest VA == host VA, and host user maps sit far below this
    // ceiling). Reject it as EFAULT here: on the identity native lane a raw read of
    // such an address (e.g. `sched_setscheduler(0, 0, usize::MAX)`, schedprio's
    // bad-ptr case) would fault the HOST rather than return an error the handler
    // can turn into EFAULT. (LINUX_NONCANONICAL_USER_VA == 0x0000_8000_0000_0000.)
    if address.0 >= NONCANONICAL_USER_VA {
        return Err(LINUX_EFAULT);
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
#[derive(Clone)]
pub(super) struct ProcState {
    /// Path of the currently-running executable, surfaced via
    /// `/proc/self/exe`, `/proc/self/cmdline`, `/proc/self/comm`, etc.
    pub executable_path: String,
    /// Current guest argv, surfaced as NUL-separated bytes through
    /// `/proc/self/cmdline`.
    pub argv: Vec<String>,
    /// Set when this guest is a foreign-arch binary running through a
    /// `binfmt_misc` interpreter (Apple's Rosetta). The redirect keeps the
    /// program's own identity (`executable_path`/`argv` stay the target, as on
    /// real Linux), so arch-dependent syscalls that must reflect the *translated*
    /// program — `uname(2)` reporting `x86_64` — key off this flag instead of
    /// inspecting `executable_path`.
    pub binfmt_interpreted: bool,
    /// `true` when the guest's NATIVE ISA is x86_64 (the bhyve / KVM-x86
    /// backends), as opposed to a binfmt-translated x86_64 guest
    /// (`binfmt_interpreted`) or a native aarch64 guest. Set once at run-image
    /// setup from `E::Arch::elf_machine()`. `uname(2)` reports `x86_64` when
    /// EITHER this or `binfmt_interpreted` holds.
    pub native_x86_64: bool,
    /// Current guest environment (`KEY=VALUE` entries) as OPAQUE BYTES, surfaced
    /// as NUL-separated bytes through `/proc/self/environ`. Kept as raw bytes —
    /// env values are not required to be UTF-8, and a lossy String round-trip
    /// would corrupt them (a class of bug carrick has hit before). Captured at
    /// exec; empty until then.
    pub env: Vec<Vec<u8>>,
    /// `personality(2)` execution-domain flags, recorded and echoed back.
    pub personality: u64,
    /// `prctl(PR_SET_NAME)` task comm name (16 bytes, NUL-padded).
    pub task_name: [u8; LINUX_TASK_COMM_LEN],
    /// `prctl(PR_SET_PDEATHSIG)` parent-death signal (0 = none). Recorded and
    /// echoed back via PR_GET_PDEATHSIG; not yet delivered on parent exit.
    pub pdeathsig: i64,
    /// `prctl(PR_SET_KEEPCAPS)` flag (0/1, default 0). Recorded and echoed back
    /// via PR_GET_KEEPCAPS; the uid-transition cap-clear it modulates is a
    /// follow-up — the flag round-trips so libcap/init feature checks pass.
    pub keepcaps: i64,
    /// `prctl(PR_SET_CHILD_SUBREAPER)` flag (0 = not a subreaper, default).
    /// Recorded and echoed back via PR_GET_CHILD_SUBREAPER.
    pub child_subreaper: i64,
    /// Linux-visible pid that set `child_subreaper`. The bit is copied by host
    /// `fork`, but Linux does not inherit child-subreaper status; the owner
    /// separates "this process is a subreaper" from "this process has a
    /// subreaper ancestor". HVPatch uses its logical task id here because many
    /// Linux processes share one host pid.
    pub child_subreaper_owner: u32,
    /// Nearest subreaper ancestor inherited by fork descendants. This is not
    /// reported by PR_GET_CHILD_SUBREAPER; it is the target used if this
    /// process's direct parent exits.
    pub subreaper_ancestor: u32,
    /// Exact-generation form of `subreaper_ancestor` for HVPatch. A bare pid
    /// can be reused before a descendant exits; terminal reparenting must never
    /// adopt to a different task generation wearing the same number.
    pub hvpatch_subreaper_ancestor: Option<crate::kernel::TaskKey>,
    /// `prctl(PR_SET_NO_NEW_PRIVS)` bit. Once set it cannot be cleared (one-way
    /// latch). The precondition for an unprivileged seccomp filter install.
    pub no_new_privs: bool,
    /// `prctl(PR_SET_TIMERSLACK)` per-process timer slack in nanoseconds
    /// (default 50000). Recorded and echoed back; carrick does not coarsen waits.
    pub timerslack: u64,
    /// Default timer slack used by `PR_SET_TIMERSLACK(0)`. Linux gives a forked
    /// child a default equal to the parent's current slack at fork time.
    pub timerslack_default: u64,
    /// Per-resource `setrlimit`/`prlimit64` overrides, indexed by the Linux
    /// resource number (0..16). `None` uses the Carrick default from
    /// `rlimit_for_resource`. This process/thread-group authority is independent
    /// Host pid of the ROOT guest process, captured at construction — before
    /// any guest `fork(2)`. Carrick forks each guest process as a real host
    /// child, so the host process tree mirrors the guest tree. A forked child
    /// inherits this value through the copied address space and can tell it is
    /// NOT the root by comparing it to its own (now-different) pid. Used by
    /// `getppid`: the root reports the stable bootstrap parent (init), while a
    /// forked child reports its real host parent — which, because the trees
    /// mirror, IS its parent guest process. See `sys_getppid`.
    pub bootstrap_host_pid: u32,
    /// Hvpatch-only guest PID when multiple Linux processes share one host
    /// process. `None` preserves the host-pid identity model of every other
    /// backend.
    pub virtual_pid: Option<u32>,
    /// Namespace-local form of `virtual_pid`, captured while the exact task
    /// binding is live. A consuming wait legitimately removes live namespace
    /// membership before every runtime-owned suffix has released its
    /// dispatcher, so those suffixes must not re-query the liveness index.
    pub namespace_pid: Option<u32>,
    pub hvpatch_process: Option<crate::hvpatch::ProcessContext>,
    /// Interval-timer state for `[ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF]`,
    /// indexed by the `which` value. Anchored to the monotonic clock so
    /// setitimer/getitimer report the time remaining; `None` = disarmed.
    /// glibc's `alarm()` is `setitimer(ITIMER_REAL, …)` and returns the
    /// previous timer's remaining seconds. The matching expiry signal
    /// (SIGALRM/SIGVTALRM/SIGPROF) is delivered by an EVFILT_TIMER event on the
    /// signal pump's kqueue (see crate::itimer). VIRTUAL/PROF are keyed to
    /// guest CPU accounting and use wall-clock kqueue timers only as rechecks.
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
    /// free. See `host_facts`.
    pub affinity: Vec<u64>,
    /// Whether hardware x86_64 TSO memory ordering is active for this guest
    /// (`prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO)`, set by Rosetta). Tracked
    /// so `PR_GET_MEM_MODEL` reports the current model. The actual ACTLR_EL1
    /// toggle happens in the runtime loop (the dispatcher can't reach the vCPU).
    pub tso_enabled: bool,
    /// This process successfully called `ptrace(PTRACE_TRACEME)`. Linux reports
    /// self-delivered signals to the tracer before applying default/ignore
    /// dispositions; Carrick needs this bit so the signal path can avoid routing
    /// those through the ordinary pending-signal queue.
    pub ptrace_traceme: bool,
    /// Reported native virtual-ptrace stops keyed by host child PID. Presence is
    /// also the exclusive wait lease: no terminal wait/reap may consume this PID
    /// until control finishes its carrier delivery and removes the token.
    pub virtual_ptrace_stops: std::collections::HashMap<u32, crate::guest_cpu::VirtualPtraceStop>,
    /// `membarrier(2)` per-process registration state: a bitmask of the
    /// expedited command bits this process has registered for (via the
    /// matching `MEMBARRIER_CMD_REGISTER_*`). An expedited private barrier
    /// requires prior registration — an unregistered call is EPERM. Reset to 0
    /// in a forked child (the address-space copy carries the parent's value,
    /// but Linux does not inherit the membarrier registration across fork, so
    /// the fork path clears it). See `SyscallDispatcher::membarrier`.
    pub membarrier_ready: u64,
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

/// Build a `LinuxRusage` carrying just CPU time (user/system microseconds);
/// other fields stay zero. Used for the `wait4` rusage out-param.
#[cfg(test)]
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
            binfmt_interpreted: false,
            native_x86_64: false,
            env: Vec::new(),
            personality: 0,
            task_name: linux_task_name_from_bytes(b"exe"),
            pdeathsig: 0,
            keepcaps: 0,
            child_subreaper: 0,
            child_subreaper_owner: 0,
            subreaper_ancestor: 0,
            hvpatch_subreaper_ancestor: None,
            no_new_privs: false,
            timerslack: LINUX_DEFAULT_TIMERSLACK_NS,
            timerslack_default: LINUX_DEFAULT_TIMERSLACK_NS,
            bootstrap_host_pid: std::process::id(),
            virtual_pid: None,
            namespace_pid: None,
            hvpatch_process: None,
            itimers: [None, None, None],
            affinity: default_affinity(crate::host_facts::logical_cpu_count()),
            tso_enabled: false,
            ptrace_traceme: false,
            virtual_ptrace_stops: std::collections::HashMap::new(),
            membarrier_ready: 0,
        }
    }

    pub(super) fn bind_hvpatch_identity(&mut self, internal_pid: u32, namespace_pid: u32) {
        self.virtual_pid = Some(internal_pid);
        self.namespace_pid = Some(namespace_pid);
    }

    pub(super) fn fork_clone(&self, parent_guest_pid: u32, child_guest_pid: u32) -> Self {
        let mut child = self.clone();
        child.virtual_pid = Some(child_guest_pid);
        // The child's exact namespace identity becomes authoritative only at
        // kernel publication; `bind_hvpatch_process_exact` caches it before
        // the child can execute.
        child.namespace_pid = None;
        child.pdeathsig = 0;
        child.subreaper_ancestor = if self.child_subreaper != 0 {
            parent_guest_pid
        } else {
            self.subreaper_ancestor
        };
        child.hvpatch_subreaper_ancestor = if self.child_subreaper != 0 {
            self.hvpatch_process
                .as_ref()
                .map(crate::hvpatch::ProcessContext::task_key)
        } else {
            self.hvpatch_subreaper_ancestor
        };
        child.child_subreaper = 0;
        child.child_subreaper_owner = 0;
        child.timerslack_default = self.timerslack;
        child.itimers = [None, None, None];
        child.ptrace_traceme = false;
        child.virtual_ptrace_stops.clear();
        child.membarrier_ready = 0;
        child
    }

    fn logical_pid(&self) -> u32 {
        self.virtual_pid.unwrap_or_else(std::process::id)
    }

    /// The ISA this guest reports about *itself*. A native x86_64 guest
    /// (`native_x86_64`, the bhyve/KVM-x86/NVMM backends) and a binfmt-translated
    /// x86_64 guest (`binfmt_interpreted`, Apple Rosetta) both report x86_64;
    /// otherwise native aarch64. SINGLE source for every arch-dependent synthetic
    /// surface — `uname(2)`, `/proc/cpuinfo`, and future arch-keyed files — so
    /// they can never contradict each other.
    pub(super) fn reported_arch(&self) -> crate::vfs::GuestReportedArch {
        if self.binfmt_interpreted || self.native_x86_64 {
            crate::vfs::GuestReportedArch::X86_64
        } else {
            crate::vfs::GuestReportedArch::Aarch64
        }
    }

    #[cfg(test)]
    fn matching_virtual_ptrace_leases(
        &mut self,
        target: PtraceWaitTarget,
    ) -> Vec<(u32, crate::guest_cpu::VirtualPtraceStop)> {
        let stale: Vec<u32> = self
            .virtual_ptrace_stops
            .iter()
            .filter_map(|(pid, stop)| {
                (!crate::guest_cpu::virtual_ptrace_stop_is_reported(*stop)
                    || child_is_terminally_waitable(*pid))
                .then_some(*pid)
            })
            .collect();
        for pid in stale {
            self.virtual_ptrace_stops.remove(&pid);
        }
        self.virtual_ptrace_stops
            .iter()
            .filter(|(pid, _)| ptrace_wait_target_conflicts(**pid, target))
            .map(|(pid, stop)| (*pid, *stop))
            .collect()
    }

    #[cfg(test)]
    fn record_virtual_ptrace_stop(&mut self, pid: u32, stop: crate::guest_cpu::VirtualPtraceStop) {
        self.virtual_ptrace_stops.insert(pid, stop);
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

    /// Host pid of the top-level guest process.
    #[allow(dead_code)]
    pub(crate) fn bootstrap_host_pid(&self) -> u32 {
        self.proc.lock().bootstrap_host_pid
    }

    /// True after the process successfully called `ptrace(PTRACE_TRACEME)`.
    pub(crate) fn is_ptrace_traceme(&self) -> bool {
        self.proc.lock().ptrace_traceme
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn set_ptrace_traceme_for_test(&self) {
        self.proc.lock().ptrace_traceme = true;
    }

    #[cfg(all(test, target_os = "freebsd", target_arch = "x86_64"))]
    pub(crate) fn hold_proc_mutex_for_native_fork_test(
        &self,
        on_locked: impl FnOnce(),
        wait_for_release: impl FnOnce(),
    ) {
        let _proc = self.proc.lock();
        on_locked();
        wait_for_release();
    }

    /// Exact live HVPatch subreaper inherited by this process. Returning no
    /// adopter deliberately falls back to the kernel run root: a retired exact
    /// key must not be followed by numeric pid reuse.
    pub(crate) fn hvpatch_orphan_adopter(&self) -> Option<crate::kernel::TaskKey> {
        let proc = self.proc.lock();
        let process = proc.hvpatch_process.as_ref()?;
        proc.hvpatch_subreaper_ancestor
            .filter(|adopter| process.kernel_graph().task_key_is_live(*adopter))
    }

    #[cfg(test)]
    pub(crate) fn mark_child_subreaper_for_test(&self) {
        let mut proc = self.proc.lock();
        proc.child_subreaper = 1;
        proc.child_subreaper_owner = proc.logical_pid();
    }

    /// Parse a `struct sock_fprog *` at `fprog_ptr` and install its cBPF program
    /// as a seccomp filter. Shared by `seccomp(SECCOMP_SET_MODE_FILTER)` and the
    /// legacy `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` entry point.
    /// Returns 0 on success, EFAULT/EINVAL on a bad program.
    fn install_seccomp_filter<M: CurrentMmMemory>(
        &self,
        task: &crate::kernel::Task,
        memory: &mut M,
        fprog_ptr: u64,
    ) -> DispatchOutcome {
        // struct sock_fprog { unsigned short len; <pad>; sock_filter *filter; }
        // — `filter` is 8-byte aligned, so it sits at offset 8.
        let Ok(len_bytes) = memory.read_bytes(fprog_ptr, 2) else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        let len = u16::from_ne_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if len == 0 || len > 4096 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let Ok(ptr_bytes) = memory.read_bytes(fprog_ptr.wrapping_add(8), 8) else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        let filter_ptr = u64::from_ne_bytes([
            ptr_bytes[0],
            ptr_bytes[1],
            ptr_bytes[2],
            ptr_bytes[3],
            ptr_bytes[4],
            ptr_bytes[5],
            ptr_bytes[6],
            ptr_bytes[7],
        ]);
        let Ok(prog_bytes) = memory.read_bytes(filter_ptr, len * 8) else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        let Some(prog) = crate::seccomp::SockFilter::parse_program(&prog_bytes) else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        let no_new_privs = self.proc.lock().no_new_privs;
        if !no_new_privs
            && !task
                .caps()
                .has_effective(crate::namespace::process::CAP_SYS_ADMIN)
        {
            return DispatchOutcome::errno(LINUX_EACCES);
        }
        match self.seccomp.install(prog) {
            Ok(()) => {
                self.disable_identity_syscall_shim(memory);
                DispatchOutcome::Returned { value: 0 }
            }
            Err(crate::seccomp::SeccompInstallError::InvalidProgram) => {
                DispatchOutcome::errno(LINUX_EINVAL)
            }
            Err(crate::seccomp::SeccompInstallError::PathTooLong) => {
                DispatchOutcome::errno(LINUX_ENOMEM)
            }
        }
    }

    fn disable_identity_syscall_shim<M: CurrentMmMemory>(&self, memory: &mut M) {
        if crate::syscall_shim_enabled() {
            let _ = memory.write_bytes(
                crate::memory::LINUX_IDENTITY_PAGE_BASE + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
                &0u32.to_le_bytes(),
            );
        }
    }

    fn install_seccomp_strict<M: CurrentMmMemory>(&self, memory: &mut M) -> DispatchOutcome {
        self.seccomp.install_strict();
        self.disable_identity_syscall_shim(memory);
        DispatchOutcome::Returned { value: 0 }
    }

    /// Allocate a pidfd for `host_pid`. Shared by `pidfd_open` and the
    /// `CLONE_PIDFD` fork path. Registers `EVFILT_PROC`/`NOTE_EXIT` so the fd
    /// becomes readable when the process exits.
    pub(super) fn open_pidfd(&self, host_pid: i32, status_flags: u64) -> DispatchOutcome {
        // Watch the real host process for exit through the platform
        // `EventMultiplexer` (macOS: kqueue `NOTE_EXIT|NOTE_EXITSTATUS`; Linux:
        // a real `pidfd_open(2)` added to the epoll set). The exit-readiness fd
        // becomes pollable when the process exits, so the guest reads its exit
        // code. The token is the host pid (no consumer reads it back today, but
        // it keeps the registration self-describing).
        let kqueue = {
            let mut mux = match crate::event_mux::make_event_multiplexer() {
                Ok(m) => m,
                Err(_) => return DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE),
            };
            if mux.watch_process_exit(host_pid, host_pid as u64).is_err() {
                // No such process (already reaped, or never existed).
                return DispatchOutcome::errno(crate::linux_abi::LINUX_ESRCH);
            }
            std::sync::Arc::new(PidfdWatch::new(mux))
        };
        let description = OpenDescription::Pidfd {
            target: PidfdTarget::Host(host_pid),
            kqueue,
            base: OpenDescriptionBase::new(status_flags),
        };
        // Linux creates the pidfd with O_CLOEXEC unconditionally (the flags arg
        // only carries PIDFD_NONBLOCK), so the returned fd must have FD_CLOEXEC
        // set — pidfd_open01 asserts F_GETFD & FD_CLOEXEC.
        self.install_fd_with_status_flags(
            description,
            LINUX_O_RDWR | status_flags,
            LINUX_FD_CLOEXEC,
        )
    }

    /// Allocate a pidfd for one Linux process multiplexed inside the shared
    /// HvPatch VM. Its readiness is a user event published by the guest process
    /// table, never an `EVFILT_PROC` watch on the common Carrick host pid.
    pub(super) fn open_hvpatch_pidfd(
        &self,
        process: &crate::hvpatch::ProcessContext,
        guest_pid: i32,
        status_flags: u64,
    ) -> DispatchOutcome {
        let kqueue = {
            let mut mux = match crate::event_mux::make_event_multiplexer() {
                Ok(mux) => mux,
                Err(_) => return DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE),
            };
            if mux.register_user(0).is_err() {
                return DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE);
            }
            std::sync::Arc::new(PidfdWatch::new(mux))
        };
        let Some(target) = process.register_pidfd_watch(guest_pid, &kqueue) else {
            return DispatchOutcome::errno(crate::linux_abi::LINUX_ESRCH);
        };
        let description = OpenDescription::Pidfd {
            target: PidfdTarget::Hvpatch(target),
            kqueue,
            base: OpenDescriptionBase::new(status_flags),
        };
        self.install_fd_with_status_flags(
            description,
            LINUX_O_RDWR | status_flags,
            LINUX_FD_CLOEXEC,
        )
    }

    /// Allocate a pidfd referring to freshly-forked `child_pid`. Called by the
    /// runtime's `CLONE_PIDFD` parent setup before releasing the child. Preserve
    /// the allocation/watch errno so clone can fail atomically rather than
    /// returning a child with an invalid pidfd output.
    /// Install a CLONE_PIDFD descriptor for a freshly forked host child.
    ///
    /// The pidfd lands in the FORKING PARENT's table, so the caller passes the
    /// exact parent `KernelContext` it already captured and this establishes
    /// the resource scope. Several fork paths (the VMM quiesce path among
    /// them) run on the vCPU loop OUTSIDE any dispatch boundary, where the fd
    /// helpers' ambient `captured_file_table()` has nothing installed and
    /// aborts rather than guess a table. Re-establishing a scope that is
    /// already active is free — `with_captured_resources` short-circuits on
    /// pointer identity.
    pub fn install_child_pidfd(
        &self,
        context: &crate::kernel::KernelContext,
        child_pid: i32,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        match super::resources::with_captured_resources(context, || self.open_pidfd(child_pid, 0)) {
            DispatchOutcome::Returned { value } => {
                i32::try_from(value).map_err(|_| crate::linux_abi::LINUX_EMFILE)
            }
            DispatchOutcome::Errno { errno } => Err(errno),
            _ => Err(crate::linux_abi::LINUX_EMFILE),
        }
    }

    /// Reserve and install a pidfd while its HVPatch child is still
    /// undiscoverable. The watch is armed by `PreparedFork::commit` in the
    /// same registry transaction that publishes the child.
    ///
    /// The pidfd lands in the FORKING PARENT's table, so the caller passes the
    /// exact parent `KernelContext` it already captured and this establishes
    /// the resource scope for the install. The HVPatch fork path runs on the
    /// vCPU loop OUTSIDE any dispatch boundary, so the fd helpers' ambient
    /// `captured_file_table()` has nothing installed there — it aborted the
    /// process rather than guess a table. Threading the context is also what
    /// K1 requires: a lifecycle operation acts on the exact captured
    /// references, never on a recaptured or ambient binding.
    pub(crate) fn install_reserved_hvpatch_child_pidfd(
        &self,
        context: &crate::kernel::KernelContext,
        prepared: &mut crate::kernel::PreparedFork,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        let mut mux = crate::event_mux::make_event_multiplexer()
            .map_err(|_| crate::linux_abi::LINUX_EMFILE)?;
        mux.register_user(0)
            .map_err(|_| crate::linux_abi::LINUX_EMFILE)?;
        let watch = std::sync::Arc::new(PidfdWatch::new(mux));
        let target = prepared
            .reserve_pidfd_subscription(&watch)
            .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        let description = OpenDescription::Pidfd {
            target: PidfdTarget::Hvpatch(target.task()),
            kqueue: watch,
            base: OpenDescriptionBase::new(0),
        };
        match super::resources::with_captured_resources(context, || {
            self.install_fd_with_status_flags(description, LINUX_O_RDWR, LINUX_FD_CLOEXEC)
        }) {
            DispatchOutcome::Returned { value } => {
                i32::try_from(value).map_err(|_| crate::linux_abi::LINUX_EMFILE)
            }
            DispatchOutcome::Errno { errno } => Err(errno),
            _ => Err(crate::linux_abi::LINUX_EMFILE),
        }
    }

    /// Roll back one freshly installed CLONE_PIDFD descriptor before its gated
    /// child is released. The native fork path retains exact thread exclusion,
    /// so this fd cannot have been observed, closed, or reused by guest code.
    pub fn remove_installed_child_pidfd(&self, fd: i32, child_pid: i32) -> bool {
        if self.pidfd_target(None, fd) != Some(PidfdTarget::Host(child_pid)) {
            return false;
        }
        self.remove_pidfd(fd)
    }

    /// Roll back a pidfd installed before an HvPatch child was materialized.
    /// Roll back an installed child pidfd. Runs on the same out-of-dispatch
    /// fork path as the install, so it takes the same exact parent context.
    pub(crate) fn remove_installed_hvpatch_child_pidfd(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        child: crate::kernel::TaskKey,
    ) -> bool {
        super::resources::with_captured_resources(context, || {
            if self.pidfd_target(None, fd) != Some(PidfdTarget::Hvpatch(child)) {
                return false;
            }
            self.remove_pidfd(fd)
        })
    }

    fn remove_pidfd(&self, fd: i32) -> bool {
        self.detach_fd_from_epolls(fd);
        let removed = self.captured_file_table().write_open_files().remove(&fd);
        if let Some(open_file) = removed {
            self.close_open_file_and_free_pty(&open_file);
            self.note_fd_closed(fd);
            true
        } else {
            false
        }
    }

    /// Resolve a pidfd to its typed process target.
    fn proc_directory_pidfd_target(
        &self,
        context: Option<&crate::kernel::KernelContext>,
        path: &str,
    ) -> Option<PidfdTarget> {
        if let Some(process) = self.hvpatch_process() {
            let context = context?;
            let visible = crate::vfs::proc::proc_pid_dir_linux_pid(path)?;
            let internal = crate::namespace::pid::ns_to_kernel_for(context, visible)?;
            let internal = i32::try_from(internal).ok()?;
            return process.live_process_key(internal).map(PidfdTarget::Hvpatch);
        }
        crate::vfs::proc::proc_pid_dir_host_pid(path).map(|pid| PidfdTarget::Host(pid as i32))
    }

    fn pidfd_target(
        &self,
        context: Option<&crate::kernel::KernelContext>,
        fd: i32,
    ) -> Option<PidfdTarget> {
        let open = self.open_file(fd)?;
        let desc = open.description.read()?;
        match &*desc {
            OpenDescription::Pidfd { target, .. } => Some(*target),
            // A `/proc/<pid>` directory fd is a valid pidfd on Linux (e.g.
            // `pidfd_send_signal`/`waitid(P_PIDFD)` accept one). Resolve its
            // backing host pid; any other directory (or non-numeric /proc path)
            // yields None → EBADF. (CPython test_pidfd_send_signal.)
            OpenDescription::Directory { path, .. } => {
                self.proc_directory_pidfd_target(context, path)
            }
            _ => None,
        }
    }

    /// Resolve a pidfd to its backing host pid, or `None` for guest-virtual
    /// HvPatch pidfds and non-pidfd descriptors.
    #[cfg(test)]
    pub(super) fn pidfd_host_pid(&self, fd: i32) -> Option<i32> {
        match self.pidfd_target(None, fd)? {
            PidfdTarget::Host(pid) => Some(pid),
            PidfdTarget::Hvpatch(_) => None,
        }
    }

    fn pidfd_hvpatch_task(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
    ) -> Option<crate::kernel::TaskKey> {
        match self.pidfd_target(Some(context), fd)? {
            PidfdTarget::Hvpatch(task) => Some(task),
            PidfdTarget::Host(_) => None,
        }
    }

    #[inline]
    fn pidfd_is_nonblocking(&self, fd: i32) -> bool {
        let Some(open) = self.open_file(fd) else {
            return false;
        };
        let Some(desc) = open.description.read() else {
            return false;
        };
        match &*desc {
            OpenDescription::Pidfd { .. } => carrick_abi::LinuxOpenFlags::from_bits_truncate(
                open.description.common().status_flags(),
            )
            .contains(carrick_abi::LinuxOpenFlags::NONBLOCK),
            _ => false,
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
        memory: &impl CurrentMmMemory,
    ) -> DispatchOutcome {
        let args_ptr = args_ptr.0;
        const CLONE_ARGS_SIZE_VER0: u64 = 64;
        const CLONE_ARGS_SIZE_VER1: u64 = 80;
        const CLONE_ARGS_SIZE_VER2: u64 = 88;
        const CLONE_ARGS_SIZE_MAX: u64 = LINUX_PAGE_SIZE;
        let abi_size = <LinuxCloneArgs as KernelAbi>::ABI_SIZE as u64;
        if args_size < CLONE_ARGS_SIZE_VER0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        if args_size > CLONE_ARGS_SIZE_MAX {
            return DispatchOutcome::errno(LINUX_E2BIG);
        }

        let read_len = args_size.min(abi_size) as usize;
        let args = match read_kernel_prefix::<LinuxCloneArgs>(memory, args_ptr, read_len) {
            Ok(args) => args,
            Err(_) => {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        };
        if args_size > abi_size {
            let Some(extra_addr) = args_ptr.checked_add(abi_size) else {
                return DispatchOutcome::errno(LINUX_EFAULT);
            };
            let extra_len = (args_size - abi_size) as usize;
            let extra = match memory.read_bytes(extra_addr, extra_len) {
                Ok(extra) => extra,
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            };
            if extra.iter().any(|&byte| byte != 0) {
                return DispatchOutcome::errno(LINUX_E2BIG);
            }
        } else if !matches!(
            args_size,
            CLONE_ARGS_SIZE_VER0 | CLONE_ARGS_SIZE_VER1 | CLONE_ARGS_SIZE_VER2
        ) {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }

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
        let vm = LinuxCloneFlags::VM.bits();
        let sighand = LinuxCloneFlags::SIGHAND.bits();
        let thread = LinuxCloneFlags::THREAD.bits();
        if (flags & thread != 0 && flags & sighand == 0)
            || (flags & sighand != 0 && flags & vm == 0)
            || (flags & LinuxCloneFlags::FS.bits() != 0
                && flags & LinuxCloneFlags::NEWNS.bits() != 0)
        {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        if args.exit_signal != 0 && !crate::dispatch::signal::is_valid_signum(args.exit_signal) {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        if is_thread_clone(flags) {
            if args_size < 64 {
                return DispatchOutcome::errno(LINUX_ENOSYS);
            }

            let child_tid_ptr = args.child_tid;
            let parent_tid_ptr = args.parent_tid;
            let stack = args.stack;
            let stack_size = args.stack_size;
            let tls_val = args.tls;

            let child_sp = stack + stack_size;
            return clone_thread_outcome(flags, child_sp, parent_tid_ptr, tls_val, child_tid_ptr);
        }
        if flags & (LinuxCloneFlags::NEWUSER | LinuxCloneFlags::NEWPID).bits() != 0 {
            return DispatchOutcome::errno(LINUX_EPERM);
        }

        let pidfd_out = if flags & LinuxCloneFlags::PIDFD.bits() != 0 {
            if !memory.guest_range_is_writable(args.pidfd, core::mem::size_of::<i32>()) {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
            Some(args.pidfd)
        } else {
            None
        };
        // clone3 carries the exit signal in its own field, unlike legacy clone's
        // low-byte CSIGNAL encoding.
        let exit_signal = args.exit_signal as u32;
        // vfork-for-exec: same classification as legacy clone (see `clone`).
        // clone3's `stack` is the BASE and `stack_size` the length, so the stack
        // POINTER (SP, which grows down on aarch64) is base+size — mirror the
        // thread path's `stack + stack_size` (legacy clone instead passes the SP
        // directly). For Go's child_stack=NULL both are 0 → 0 (use parent SP).
        let vfork = (flags & LinuxCloneFlags::VFORK.bits() != 0
            && flags & LinuxCloneFlags::VM.bits() != 0)
            .then_some(args.stack.wrapping_add(args.stack_size));
        DispatchOutcome::Fork {
            flags,
            pidfd_out,
            clone_parent: flags & LinuxCloneFlags::PARENT.bits() != 0,
            parent_tid_addr: if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
                Some(args.parent_tid)
            } else {
                None
            },
            child_tid_addr: if flags & LinuxCloneFlags::CHILD_SETTID.bits() != 0 {
                Some(args.child_tid)
            } else {
                None
            },
            exit_signal,
            child_stack: args.stack.wrapping_add(args.stack_size),
            vfork,
        }
    }

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::errno(LINUX_ENOSYS)
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn personality(this, cx, requested: u64) {
            // PER_LINUX32 (0x8) and PER_LINUX32_3GB (0x20008) name a 32-bit
            // execution domain aarch64 has no support for, so the kernel
            // answers EINVAL — verified against the oracle BOTH confined and
            // unconfined, i.e. a kernel check rather than Docker's profile
            // (which whitelists those two values). carrick accepted every
            // persona and reported success.
            const PER_LINUX32: u64 = 0x0008;
            const PER_LINUX32_3GB: u64 = 0x2_0008;
            if matches!(requested, PER_LINUX32 | PER_LINUX32_3GB) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
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
                    Ok(this.install_seccomp_filter(cx.kernel.task(), &mut *cx.memory, args.0))
                }
                crate::seccomp::SECCOMP_SET_MODE_STRICT => {
                    Ok(this.install_seccomp_strict(&mut *cx.memory))
                }
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
        }

        fn prctl(this, cx, option: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) {
            let memory = &mut *cx.memory;
            Ok(match option {
                // Dumpable lives on the kernel `Task`, not in `ProcState`: a
                // ptrace attach reads the TARGET process's attribute.
                LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                    value: cx.kernel.task().dumpable().to_prctl(),
                },
                LINUX_PR_SET_DUMPABLE => {
                    let Some(mode) = crate::kernel::DumpableMode::from_prctl(arg2) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    cx.kernel.task().set_dumpable(mode);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_SET_NAME => {
                    let Ok(bytes) = memory.read_bytes(arg2, LINUX_TASK_COMM_LEN) else {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    };
                    let task_name = linux_task_name_from_bytes(&bytes);
                    // PR_SET_NAME names the CALLING thread (Linux): record it
                    // per-tid so /proc/<pid>/task/<tid>/comm reports it. Keep
                    // task_name as the process-wide fallback + host proctitle.
                    if let Some(t) = cx.thread.as_ref() {
                        t.registry.set_thread_name(t.tid, &bytes);
                    }
                    this.proc.lock().task_name = task_name;
                    set_host_process_name(&task_name);
                    let name_str = linux_task_name_to_string(&task_name);
                    cx.kernel.kernel().set_diagnostic_name(cx.kernel.task().key().id, name_str);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_NAME => {
                    // PR_GET_NAME reads the CALLING thread's name; fall back to
                    // the process name for a thread that never named itself.
                    let name = cx
                        .thread
                        .as_ref()
                        .and_then(|t| t.registry.thread_name(t.tid))
                        .unwrap_or_else(|| this.proc.lock().task_name);
                    memory.write_bytes(arg2, &name)?;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_SET_PDEATHSIG => {
                    if arg2 > 64 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
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
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
                // Capability bounding-set query/drop, modeled against the
                // per-process capability set (accept-and-record; §4.4). cap > 63
                // is EINVAL (the cap number must be a valid bit index).
                LINUX_PR_CAPBSET_READ => {
                    if arg2 > 63 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    DispatchOutcome::Returned {
                        value: i64::from(cx.kernel.task().caps().capbset_read(arg2 as u32)),
                    }
                }
                LINUX_PR_CAPBSET_DROP => {
                    if arg2 > 63 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    // Gate and drop under one lock: the drop is irreversible,
                    // so re-reading the set between the check and the mutation
                    // could act on a set a sibling thread has since changed.
                    let dropped = cx.kernel.task().with_caps(|caps| {
                        if !caps.has_effective(crate::namespace::process::CAP_SETPCAP) {
                            return false;
                        }
                        caps.capbset_drop(arg2 as u32);
                        true
                    });
                    if !dropped {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_SET_SECUREBITS => {
                    if !cx
                        .kernel
                        .task()
                        .caps()
                        .has_effective(crate::namespace::process::CAP_SETPCAP)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                // PR_SET_NO_NEW_PRIVS: arg2 must be 1, arg3..arg5 must be 0
                // (Linux). Once set the bit cannot be cleared (one-way latch).
                // Precondition for an unprivileged seccomp filter install.
                LINUX_PR_SET_NO_NEW_PRIVS => {
                    if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    this.proc.lock().no_new_privs = true;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_NO_NEW_PRIVS => {
                    if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    DispatchOutcome::Returned {
                        value: i64::from(this.proc.lock().no_new_privs),
                    }
                }
                // PR_SET_KEEPCAPS: arg2 ∈ {0,1}. Recorded; echoed by GET.
                LINUX_PR_SET_KEEPCAPS => {
                    if arg2 > 1 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    this.proc.lock().keepcaps = arg2 as i64;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_KEEPCAPS => DispatchOutcome::Returned {
                    value: this.proc.lock().keepcaps,
                },
                // PR_SET_CHILD_SUBREAPER: any nonzero arg2 marks this process a
                // subreaper. PR_GET_CHILD_SUBREAPER writes the value to *arg2.
                LINUX_PR_SET_CHILD_SUBREAPER => {
                    let mut proc = this.proc.lock();
                    if arg2 != 0 {
                        proc.child_subreaper = 1;
                        proc.child_subreaper_owner = proc.logical_pid();
                    } else {
                        proc.child_subreaper = 0;
                        proc.child_subreaper_owner = 0;
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_CHILD_SUBREAPER => {
                    let proc = this.proc.lock();
                    let value = i32::from(
                        proc.child_subreaper != 0
                            && proc.child_subreaper_owner == proc.logical_pid(),
                    );
                    memory.write_bytes(arg2, &value.to_ne_bytes())?;
                    DispatchOutcome::Returned { value: 0 }
                }
                // PR_SET_TIMERSLACK: arg2 = new slack in ns (0 → reset to the
                // default). PR_GET_TIMERSLACK returns the current slack.
                LINUX_PR_SET_TIMERSLACK => {
                    let default = this.proc.lock().timerslack_default;
                    let slack = if arg2 == 0 {
                        default
                    } else {
                        arg2
                    };
                    this.proc.lock().timerslack = slack;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_TIMERSLACK => DispatchOutcome::Returned {
                    value: this.proc.lock().timerslack as i64,
                },
                LINUX_PR_SET_THP_DISABLE => {
                    if arg2 > 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_GET_THP_DISABLE => {
                    if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_PR_CAP_AMBIENT => match arg2 {
                    LINUX_PR_CAP_AMBIENT_IS_SET => {
                        if arg3 > crate::namespace::process::CAP_LAST_CAP as u64
                            || arg4 != 0
                            || arg5 != 0
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        DispatchOutcome::Returned {
                            value: i64::from(cx.kernel.task().caps().ambient_is_set(arg3 as u32)),
                        }
                    }
                    LINUX_PR_CAP_AMBIENT_RAISE => {
                        if arg3 > crate::namespace::process::CAP_LAST_CAP as u64
                            || arg4 != 0
                            || arg5 != 0
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        if !cx
                            .kernel
                            .task()
                            .with_caps(|caps| caps.ambient_raise(arg3 as u32))
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        }
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_PR_CAP_AMBIENT_LOWER => {
                        if arg3 > crate::namespace::process::CAP_LAST_CAP as u64
                            || arg4 != 0
                            || arg5 != 0
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        cx.kernel
                            .task()
                            .with_caps(|caps| caps.ambient_lower(arg3 as u32));
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_PR_CAP_AMBIENT_CLEAR_ALL => {
                        if arg3 != 0 || arg4 != 0 || arg5 != 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        cx.kernel
                            .task()
                            .with_caps(crate::namespace::process::CapabilitySet::ambient_clear_all);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    _ => DispatchOutcome::errno(LINUX_EINVAL),
                },
                LINUX_PR_GET_SPECULATION_CTRL => {
                    if !matches!(
                        arg2,
                        LINUX_PR_SPEC_STORE_BYPASS
                            | LINUX_PR_SPEC_INDIRECT_BRANCH
                            | LINUX_PR_SPEC_L1D_FLUSH
                    ) || arg3 != 0
                        || arg4 != 0
                        || arg5 != 0
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                // PR_SET_SECCOMP(SECCOMP_MODE_FILTER, prog) is the legacy entry
                // point for the same cBPF install as seccomp(2). STRICT mode is
                // accepted as a no-op record (not differentiated). arg2 is the
                // mode; arg3 is the `struct sock_fprog *` for FILTER mode.
                LINUX_PR_SET_SECCOMP => match arg2 {
                    LINUX_SECCOMP_MODE_FILTER => {
                        this.install_seccomp_filter(cx.kernel.task(), memory, arg3)
                    }
                    LINUX_SECCOMP_MODE_STRICT => this.install_seccomp_strict(memory),
                    _ => DispatchOutcome::errno(LINUX_EINVAL),
                },
                // PR_GET_SECCOMP: 2 if a filter is installed, else 0 (Linux
                // reports the filter mode; strict mode would kill on this call).
                LINUX_PR_GET_SECCOMP => DispatchOutcome::Returned {
                    value: if this.seccomp.is_active() {
                        LINUX_SECCOMP_MODE_FILTER as i64
                    } else {
                        0
                    },
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
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if node_address.0 != 0 && memory.write_bytes(node_address.0, &node_value).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn gettid(this, cx) {
            // The kernel graph is THE tid authority — same reasoning as
            // `set_tid_address` below. The deleted arm returned the executor
            // REGISTRY ThreadId when the process was multithreaded: a
            // different numbering that only coincides with kernel ThreadKey
            // tids while the guest is the carrier's sole process. In a
            // container (sh init + probe) the two diverge, so a guest's
            // gettid() named a tid that tgkill/procfs resolve to a DIFFERENT
            // thread — sigsuspendxthread's tgkill(SIGUSR1) landed on main
            // instead of the suspended sibling (handler ran, wrong thread,
            // sibling parked forever).
            if let Some(tid) = hvpatch_reported_tid(cx.kernel.thread().key().tid.raw())
                .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(cx.kernel, tid))
            {
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(tid),
                });
            }
            Ok(DispatchOutcome::errno(LINUX_ESRCH))
        }

        fn set_tid_address(this, cx, addr: GuestPtr) {
            if let Some(t) = cx.thread {
                t.registry.set_clear_child_tid(t.tid, addr.0);
                // set_tid_address(2) returns the caller's TID, and the kernel
                // graph is where that lives — the same source the threaded
                // dispatch path already uses, and the same one two dozen lines
                // above. This used to recognise the thread-group leader by
                // `t.tid.raw() == std::process::id()`, i.e. "the main thread's
                // tid equals the process's host pid". That is the retired
                // one-Linux-process-per-host-process model: under HVPatch every
                // Linux process is a thread of ONE Darwin process, so the
                // comparison can match at most one logical thread in the whole
                // VM and every other process's leader fell through to a raw
                // host tid.
                //
                // LTP set_tid_address01 asserts the result == getpid(); that
                // holds by construction here, because both the leader and
                // secondary threads are translated through this task's exact
                // namespace region. A missing mapping must not fall back to a
                // carrier-global TID.
                let Some(tid) = u32::try_from(cx.kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(cx.kernel, tid))
                else {
                    return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                };
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(tid),
                });
            }
            Ok(this.getpid())
        }

        /// unshare(2) — disassociate parts of the caller's execution context.
        /// carrick honors CLONE_NEWUSER (move the caller into a fresh user
        /// namespace with full modeled caps + empty maps) and CLONE_NEWPID
        /// (arm "the next fork becomes the init of a new pid ns" — the caller
        /// itself does NOT move, per unshare(2)/§5.5). All other namespace
        /// flags are accept-and-ignore (the guest is treated as already in a
        /// private instance) rather than EINVAL, so container inits that pass
        /// CLONE_NEWNS/UTS/IPC/CGROUP/NET don't break (§1.1, §6).
        fn unshare(this, cx, flags: u64) {
            let _ = this;
            let parsed = LinuxCloneFlags::from_bits_truncate(flags);
            // Every namespace flag EXCEPT CLONE_NEWUSER requires
            // CAP_SYS_ADMIN (unshare(2)); CLONE_NEWUSER deliberately needs
            // none, which is how an unprivileged guest bootstraps a namespace
            // in which it holds a full set. Verified against the oracle with
            // the seccomp profile OFF and the default caps: unshare(NEWUTS)
            // is EPERM there while unshare(CLONE_FILES) succeeds, so this is
            // a kernel capability check, not Docker's launch policy (which
            // this handler must not model — see `container_policy`).
            let privileged_namespaces = parsed
                & (LinuxCloneFlags::NEWNS
                    | LinuxCloneFlags::NEWUTS
                    | LinuxCloneFlags::NEWIPC
                    | LinuxCloneFlags::NEWNET
                    | LinuxCloneFlags::NEWPID
                    | LinuxCloneFlags::NEWCGROUP);
            if !privileged_namespaces.is_empty()
                && !super::creds::has_effective_capability(
                    cx.kernel,
                    crate::namespace::process::CAP_SYS_ADMIN,
                )
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if parsed.contains(LinuxCloneFlags::NEWUSER) {
                // Allocate a fresh user ns for the CALLING TASK; grant it full
                // caps within that namespace. Only this process moves — a
                // sibling guest process keeps its own namespace and maps.
                let _id = cx.kernel.task().unshare_user_ns();
            }
            // A privileged caller asking for a namespace carrick does not
            // model gets the answer a kernel built without that namespace
            // option gives — EINVAL — rather than a silent success that
            // leaves the guest believing it was unshared (CPython's
            // test_unshare_setns treats EINVAL as "not configured" and skips;
            // the previous accept-and-ignore made it report
            // "os.unshare failed" instead). CLONE_NEWPID is included: per
            // unshare(2) it only affects the caller's future children, which
            // carrick does not model either.
            if !privileged_namespaces.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The non-namespace flags (CLONE_FILES / FS / SIGHAND / SYSVSEM)
            // need no capability and are accepted. Unknown bits are tolerated
            // (truncated above).
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn set_robust_list(this, cx, head: GuestPtr, len: u64) {
            // Linux rejects any len != sizeof(struct robust_list_head) with
            // EINVAL (LTP set_robust_list01 passes len = (size_t)-1). carrick
            // has no robust-futex death-cleanup, so the head pointer is accepted
            // but not retained — this is purely the ABI-conformant validation.
            if len != ROBUST_LIST_HEAD_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
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
            // "Is this me?" is a guest question. It used to compare against
            // `std::process::id()`, so guest process 3 asking for its OWN
            // robust list (`get_robust_list(getpid(), …)`, exactly what glibc's
            // and LTP's helpers do) failed the self test against the carrier's
            // five-digit pid, took the peer branch, and got EPERM for its own
            // list. Only the `pid == 0` spelling worked.
            let is_self = pid.0 == 0 || u32::try_from(pid.0).is_ok_and(|pid| pid == this.identity_pid());
            if !is_self {
                // Another task's robust list is inaccessible without ptrace
                // privilege → EPERM; a pid naming no process → ESRCH (LTP
                // get_robust_list01 uses pid 1 for the EPERM case and an unused
                // pid for ESRCH). Existence is zombie-inclusive because Linux
                // keeps an unreaped process addressable.
                let exists = guest_pid_to_task_id(cx.kernel, pid)
                    .is_ok_and(|task| cx.kernel.kernel().process_identity(task).is_some());
                return Ok(DispatchOutcome::errno(if exists { LINUX_EPERM } else { LINUX_ESRCH }));
            }
            if head_ptr.0 == 0 || len_ptr.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let memory = &mut *cx.memory;
            if memory.write_bytes(head_ptr.0, &0u64.to_le_bytes()).is_err()
                || memory
                    .write_bytes(len_ptr.0, &ROBUST_LIST_HEAD_SIZE.to_le_bytes())
                    .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
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
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                }
                3 => {} // IDLE: data ignored
                1 | 2 => {
                    if data >= 8 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                }
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }
            cx.kernel.task().set_ioprio(v);
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let v = cx.kernel.task().ioprio();
            Ok(DispatchOutcome::Returned { value: v as i64 })
        }

        /// vhangup(): "virtually hang up" the current tty. Requires
        /// CAP_SYS_TTY_CONFIG, which carrick models as euid==0 — so a non-root
        /// caller gets EPERM (LTP vhangup01) and root succeeds (vhangup02).
        /// carrick has no real controlling tty to revoke, so success is a
        /// no-op.
        fn vhangup(this, cx) {
            if !this.cred_snapshot().euid.is_root() {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
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
            if resolve_sched_target(this, cx, pid) == SchedTarget::NotFound {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let memory = &mut *cx.memory;
            let kernel_bytes = crate::host_facts::logical_cpu_count().div_ceil(64) * 8;
            if size < kernel_bytes {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mask = this.proc.lock().affinity.clone();
            let buf = affinity_to_bytes(&mask, kernel_bytes);
            memory.write_bytes(address.0, &buf)?;
            Ok(DispatchOutcome::Returned {
                value: kernel_bytes as i64,
            })
        }

        fn sched_setaffinity(this, cx, pid: u64, size: u64, address: GuestPtr) {
            let size = size as usize;
            let memory = &*cx.memory;

            let read_len = size.min(128);
            let bytes = memory.read_bytes(address.0, read_len)?;
            let target = resolve_sched_target(this, cx, pid);
            if target == SchedTarget::NotFound {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            if let SchedTarget::OtherGuest { euid } = target
                && !sched_cross_owner_ok(euid, this.cred_snapshot().euid)
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if target == SchedTarget::SelfProc {
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !sched_pid_exists(this, cx, pid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !sched_pid_exists(this, cx, pid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            if address.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let memory = &mut *cx.memory;
            let prio: i32 = 0;
            memory.write_bytes(address.0, &prio.to_le_bytes())?;
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The buffer must be at least the ver0 struct.
            if size < SCHED_ATTR_SIZE_VER0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Linux returns EINVAL (not EFAULT) for a NULL attr pointer.
            if attr.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if (pid as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !sched_pid_exists(this, cx, pid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            // SCHED_OTHER, nice 0, priority 0 — a zeroed sched_attr with only
            // the leading `size` field populated (layout: size@0 u32,
            // sched_policy@4 u32, sched_flags@8 u64, sched_nice@16 s32,
            // sched_priority@20 u32, runtime/deadline/period@24/32/40 u64).
            let memory = &mut *cx.memory;
            let mut buf = [0u8; SCHED_ATTR_SIZE_VER0 as usize];
            buf[0..4].copy_from_slice(&(SCHED_ATTR_SIZE_VER0 as u32).to_le_bytes());
            memory.write_bytes(attr.0, &buf)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `sched_setscheduler(pid, policy, &param)`: switch a process's
        /// policy. Without CAP_SYS_NICE (we are non-root in the guest), Linux
        /// refuses any RT policy with EPERM; SCHED_OTHER+priority=0 succeeds
        /// as a no-op. Unknown policies are EINVAL.
        fn sched_setscheduler(this, cx, pid: u64, policy: u64, address: GuestPtr) {
            if (pid as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !sched_pid_exists(this, cx, pid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let policy_i = policy as i32;
            if !sched_policy_is_known(policy_i) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let prio = sched_read_param_priority(cx, address)?;
            if policy_i == LINUX_SCHED_FIFO || policy_i == LINUX_SCHED_RR {
                // No CAP_SYS_NICE in carrick guest → mirror Linux's EPERM.
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // Time-sharing policies require priority==0.
            if prio != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::Returned { value: LINUX_SCHED_OTHER as i64 })
        }

        /// `sched_setparam(pid, &param)`: change just the priority. For our
        /// SCHED_OTHER-only model the only valid priority is 0; anything else
        /// is EINVAL (matches Linux for SCHED_NORMAL/OTHER/BATCH/IDLE). Changing
        /// ANOTHER process's params requires `check_same_owner` (or root): a
        /// DIFFERENT-owner non-root caller is refused with EPERM (LTP
        /// sched_setparam05: a `nobody` child calling `sched_setparam(getppid(),
        /// …)` on its root parent), but a SAME-owner non-root cross-process set
        /// succeeds — hence the ownership check, not a root-only proxy.
        fn sched_setparam(this, cx, pid: u64, address: GuestPtr) {
            if (pid as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let target = resolve_sched_target(this, cx, pid);
            if target == SchedTarget::NotFound {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let prio = sched_read_param_priority(cx, address)?;
            if prio != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let SchedTarget::OtherGuest { euid } = target
                && !sched_cross_owner_ok(euid, this.cred_snapshot().euid)
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `sched_rr_get_interval(pid, &timespec)`: write the scheduling quantum
        /// into `*timespec`.
        ///
        /// The old body returned `{0, 0}` under a comment claiming that is what
        /// Linux does for a SCHED_OTHER task. The Docker oracle disproves it:
        /// it reports `tv_nsec = 2000000` for exactly that case, and LTP scores
        /// a zero quantum as "Invalid time quantum 0s 0ns". See
        /// `LINUX_SCHED_OTHER_SLICE`.
        fn sched_rr_get_interval(this, cx, pid: u64, address: GuestPtr) {
            // A negative pid is EINVAL and outranks the existence probe, the
            // same ordering `sched_getscheduler` above already implements.
            if (pid as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !sched_pid_exists(this, cx, pid) {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let memory = &mut *cx.memory;
            // An unwritable destination — NULL included — faults, as the
            // oracle's `sched_rr_get_interval(0, <bad>) : EFAULT` row shows.
            if address.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            memory.write_bytes(
                address.0,
                zerocopy::IntoBytes::as_bytes(&carrick_abi::LINUX_SCHED_OTHER_SLICE),
            )?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn futex(this, cx, address: GuestPtr, operation: u64, value: u64, timeout_address: GuestPtr) {
            let value = value as u32;
            let args = cx.raw_args();
            let thread = cx.thread;
            let tid = cx.tid();
            let memory = &mut *cx.memory;
            let raw_command = operation & LINUX_FUTEX_CMD_MASK;
            let command = match raw_command {
                LINUX_FUTEX_WAIT_BITSET => LINUX_FUTEX_WAIT,
                LINUX_FUTEX_WAKE_BITSET => LINUX_FUTEX_WAKE,
                other => other,
            };
            let flags = operation & !LINUX_FUTEX_CMD_MASK;
            let futex_flags = LinuxFutexFlags::from_bits_retain(flags);
            // Unknown OPERATION outranks bad flags: Linux switches on the
            // command first and falls through to ENOSYS, so `op = 99999`
            // (command 31 plus unsupported flag bits) is ENOSYS, not the EINVAL
            // the flag mask below would give (`eventwaitmatrix`
            // `futex_invalid_op_enosys`).
            if !linux_futex_command_is_known(raw_command) {
                return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
            }
            if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Well-formedness, before the futex word is read or any wait is
            // set up. Oracle-derived (`eventwaitmatrix`); carrick accepted all
            // four and either waited or reported the wrong errno.
            //
            // A futex word is a naturally aligned 32-bit object, so a
            // misaligned `uaddr` is EINVAL rather than a wait on a torn word.
            if !address.0.is_multiple_of(4) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The BITSET forms take a mask in `val3`; an all-zero mask can
            // match nothing, and Linux rejects it instead of parking forever.
            if matches!(
                raw_command,
                LINUX_FUTEX_WAIT_BITSET | LINUX_FUTEX_WAKE_BITSET
            ) && args.0[5] as u32 == 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A timeout is validated before the wait, not folded into a
            // duration: a negative or >= 1s `tv_nsec` is EINVAL.
            if timeout_address.0 != 0
                && matches!(
                    raw_command,
                    LINUX_FUTEX_WAIT | LINUX_FUTEX_WAIT_BITSET
                )
                && let Ok(timespec) = read_timespec(memory, timeout_address.0)
                && !super::linux_timeout_timespec_is_valid(timespec)
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Only WAIT / CMP_REQUEUE / PI ops consult the futex VALUE; WAKE and
            // plain REQUEUE are address-keyed (Linux FUTEX_WAKE computes only the
            // hash key — it never reads the word). Surfacing the read's EFAULT for
            // a value-independent op spuriously fails a wake whenever the caller's
            // `GuestMemory` view can't translate the page (e.g. a cross-thread
            // waker over a per-sibling window snapshot), crashing guests like Go
            // whose `futexwakeup` treats EFAULT as fatal. Mirror
            // `dispatch_threaded_futex`: make the read non-fatal for WAKE/REQUEUE.
            let needs_word = matches!(
                command,
                LINUX_FUTEX_WAIT
                    | LINUX_FUTEX_LOCK_PI
                    | LINUX_FUTEX_TRYLOCK_PI
                    | LINUX_FUTEX_UNLOCK_PI
                    | LINUX_FUTEX_CMP_REQUEUE
            );
            let word = match read_futex_word(memory, address.0) {
                Ok(word) => word,
                Err(errno) if needs_word => return Ok(DispatchOutcome::Errno { errno }),
                Err(_) => 0,
            };

            if matches!(
                command,
                LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_TRYLOCK_PI | LINUX_FUTEX_UNLOCK_PI
            ) {
                let Some(guest_tid) = u32::try_from(cx.kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(cx.kernel, tid))
                else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                return Ok(dispatch_futex_pi(
                    memory,
                    address.0,
                    command,
                    word,
                    guest_tid,
                    thread.map(|t| t.futex),
                ));
            }

            let Some(thread) = thread else {
                return Ok(match command {
                    LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
                    LINUX_FUTEX_WAIT => {
                        if word != value || timeout_address.0 == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        let timespec = read_timespec(memory, timeout_address.0)?;
                        let timeout = duration_from_linux_timespec(timespec)?;
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
            // A non-PRIVATE futex on a live thread's CLONE_CHILD_CLEARTID address
            // (glibc's `pthread_join` waits on `pd->tid` non-PRIVATE) is woken by
            // carrick's IN-PROCESS `handle_thread_exit` (`futex.wake`), NOT a guest
            // `FUTEX_WAKE` — so it must use the in-process futex table, never a
            // cross-process mirror. On bhyve the mirror is a SEPARATE word and a
            // mirror `__ulock` WAIT would never be woken by the in-process exit-wake,
            // so the join HANGS (the immediate-`pthread_join` failure; KVM is immune —
            // its "mirror" IS the guest word). A no-op on HVF/KVM, where this private
            // descriptor word never resolved to a mirror anyway. This is the one
            // non-PRIVATE word whose waker is the host, not the guest.
            let shared_location = if futex_flags.contains(LinuxFutexFlags::PRIVATE)
                || thread.registry.is_clear_child_tid_addr(address.0)
            {
                None
            } else {
                memory.shared_futex_location(address.0)
            };
            crate::probes::futex_route(
                address.0,
                command as i32,
                if shared_location.is_some() { 1 } else { 0 },
                shared_location
                    .map(|location| location.wait_addr().raw() as u64)
                    .unwrap_or(0),
            );

            Ok(match command {
                LINUX_FUTEX_WAKE => {
                    if let Some(location) = shared_location {
                        // Publish the waker's current word value to the fork-coherent
                        // host word BEFORE waking, so a WAITer (possibly in another
                        // process) observes the change the waker just made to its own
                        // guest word. No-op on HVF/KVM (the wait address IS the guest word);
                        // load-bearing on bhyve, whose per-VM sysmem copy of the word
                        // is not shared across the fork — the umtx waits/wakes on this
                        // mirror, not on the divergent per-process copies.
                        if location.is_mirror() {
                            shared_futex_store(location, word);
                        }
                        // Cross-process (MAP_SHARED) wake: route through the
                        // `PlatformFutex::shared_wake` seam (the wake counterpart
                        // of `SharedFutexWait`) so HVF's __ulock (one-at-a-time +
                        // sched_yield) or KVM's host SYS_futex is reached
                        // uniformly. The loop completes with the count woken.
                        return Ok(DispatchOutcome::SharedFutexWake {
                            location,
                            waiter_key: location.waiter_key(),
                            count: value,
                        });
                    }
                    let n = thread.futex.wake(address.0, value);
                    crate::event_ring::rec_futex_wake(address.0, n);
                    DispatchOutcome::Returned {
                        value: i64::from(n),
                    }
                }
                LINUX_FUTEX_WAIT => {
                    // For a SHARED (cross-process) futex the authoritative current
                    // value lives at the fork-coherent host word (the mirror on bhyve;
                    // == the guest word on HVF/KVM). Compare THAT, not the possibly
                    // stale per-VM sysmem copy, and publish it back into the guest word
                    // so the caller's retry loop (tst_checkpoint_wait &c.) re-reads what
                    // another process wrote instead of spinning on the stale value.
                    let current = if let Some(location) = shared_location {
                        let mirror = shared_futex_load(location);
                        if mirror != word && location.is_mirror() {
                            let _ = memory.write_bytes(address.0, &mirror.to_ne_bytes());
                        }
                        mirror
                    } else {
                        word
                    };
                    if current != value {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    let timeout = if timeout_address.0 == 0 {
                        // NULL timespec ptr = no timeout (block indefinitely).
                        None
                    } else {
                        // A non-NULL timespec ALWAYS specifies a deadline — even
                        // {0,0}, which means "time out IMMEDIATELY" (ETIMEDOUT
                        // now), NOT "infinite". duration_from_linux_timespec maps
                        // {0,0} to None ("no duration"); collapsing that to the
                        // `timeout_address == 0` None made the threaded futex park
                        // (wait_prepared_for_thread) compute no deadline and spin
                        // forever on a zero-timeout WAIT that Linux returns
                        // ETIMEDOUT from at once (futex_wait03 old-kernel-spec hung
                        // 110s). Force the zero case to a ZERO duration so the park
                        // deadline is `now` and fires immediately.
                        let timespec = read_timespec(memory, timeout_address.0)?;
                        Some(
                            duration_from_linux_timespec(timespec)?
                                .unwrap_or(std::time::Duration::ZERO),
                        )
                    };
                    if let Some(location) = shared_location {
                        return Ok(DispatchOutcome::SharedFutexWait {
                            location,
                            waiter_key: location.waiter_key(),
                            generation:
                                carrick_thread::platform_futex::carrier_shared_futex_table()
                                    .prepare_wait(location.waiter_key() as u64),
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
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let nr_requeue = args.0[3] as u32;
                    let uaddr2 = args.0[4];
                    let val3 = args.0[5] as u32;
                    if raw_command == LINUX_FUTEX_CMP_REQUEUE && word != val3 {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    if let Some(location) = shared_location {
                        let Some(to_location) = memory.shared_futex_location(uaddr2) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        return Ok(DispatchOutcome::SharedFutexRequeue {
                            from: location,
                            from_key: location.waiter_key(),
                            to: to_location,
                            to_key: to_location.waiter_key(),
                            wake: nr_wake,
                            requeue: nr_requeue,
                        });
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

        fn futex_waitv(
            this,
            cx,
            waiters: GuestPtr,
            nr_futexes: u64,
            flags: u64,
            timeout: GuestPtr,
            clockid: u64,
        ) {
            let clock = Arc::clone(cx.kernel.task().container().clock());
            Ok(dispatch_futex_waitv_args(
                &clock,
                &mut *cx.memory,
                cx.thread.map(|t| t.futex),
                waiters.0,
                nr_futexes,
                flags,
                timeout.0,
                clockid,
            ))
        }

        fn uname(this, cx, address: GuestPtr) {
            let memory = &mut *cx.memory;
            // Nodename is the calling task's UTS namespace. Under HVPatch a
            // dispatcher is not an identity boundary: two container tasks can
            // share the carrier while answering this syscall differently.
            // A binfmt-interpreted guest (x86_64 under Rosetta) reports x86_64;
            // otherwise native aarch64. The flag — not executable_path — is the
            // signal, because a faithful binfmt redirect keeps the program's own
            // identity (executable_path stays the target, as on real Linux). Both
            // carry the resolved nodename.
            let nodename = cx.kernel.task().uts_ns().nodename();
            let arch = this.proc.lock().reported_arch();
            let uts = match arch {
                crate::vfs::GuestReportedArch::X86_64 => {
                    LinuxUtsname::carrick_x86_64_with_nodename(&nodename)
                }
                crate::vfs::GuestReportedArch::Aarch64 => {
                    LinuxUtsname::carrick_aarch64_with_nodename(&nodename)
                }
            };
            memory.write_bytes(address.0, uts.abi_bytes())?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn ptrace(this, cx, request: u64, pid: Pid, addr: GuestPtr, data: u64) {
            let transport =
                select_ptrace_transport(this.page_geometry(), this.hvpatch_process().is_some());
            if transport == PtraceTransport::VirtualHvpatch {
                let Some(process) = this.hvpatch_process() else {
                    return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                };
                let kernel = process.kernel_graph();
                let target = || {
                    guest_pid_to_task_id(cx.kernel, pid)
                        .ok()
                        .and_then(|target| kernel.live_task_key(target))
                };
                let outcome = match request {
                    0 => {
                        let mut proc = this.proc.lock();
                        if proc.ptrace_traceme || !kernel.claim_ptrace_traceme(cx.kernel) {
                            DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM)
                        } else {
                            proc.ptrace_traceme = true;
                            DispatchOutcome::Returned { value: 0 }
                        }
                    }
                    7 => {
                        let signal = if data == 0 {
                            None
                        } else {
                            match crate::kernel::LinuxSignal::for_signal_number(data as i32) {
                                Ok(signal) if data <= i32::MAX as u64 => Some(signal),
                                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                            }
                        };
                        let Some(target) = target() else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        if !kernel.resume_task_from_ptrace(
                            process.task_key(),
                            target.id,
                            signal,
                        ) {
                            DispatchOutcome::errno(LINUX_ESRCH)
                        } else {
                            DispatchOutcome::Returned { value: 0 }
                        }
                    }
                    8 => {
                        let Some(target) = target() else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        let Ok(sigkill) = crate::kernel::LinuxSignal::for_signal_number(
                            crate::linux_abi::LINUX_SIGKILL,
                        ) else {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        };
                        if !kernel.resume_task_from_ptrace(
                            process.task_key(),
                            target.id,
                            Some(sigkill),
                        ) {
                            DispatchOutcome::errno(LINUX_ESRCH)
                        } else {
                            DispatchOutcome::Returned { value: 0 }
                        }
                    }
                    17 if data == 0 => {
                        let Some(target) = target() else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        if kernel.detach_task_from_ptrace(process.task_key(), target.id) {
                            DispatchOutcome::Returned { value: 0 }
                        } else {
                            DispatchOutcome::errno(LINUX_ESRCH)
                        }
                    }
                    17 => DispatchOutcome::errno(LINUX_EINVAL),
                    LINUX_PTRACE_ATTACH => {
                        let Ok(target_task_id) = guest_pid_to_task_id(cx.kernel, pid) else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        match kernel.attach_task_for_ptrace(cx.kernel, target_task_id) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        }
                    }
                    LINUX_PTRACE_PEEKTEXT | LINUX_PTRACE_PEEKDATA => {
                        let Ok(target_task_id) = guest_pid_to_task_id(cx.kernel, pid) else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        let Some(target_task) = kernel.registry().task(target_task_id) else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        if !kernel.task_key_is_live(target_task.key()) {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        let target_key = target_task.key();
                        let ptrace_witness = match kernel
                            .begin_ptrace_memory_access(process.task_key(), target_key)
                        {
                            Ok(witness) => witness,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        let relation = cx.with_execution_lease(|lease| {
                            kernel.foreign_mm(cx.kernel, lease, target_key)
                        });
                        let relation = match relation {
                            Some(Ok(r)) => r,
                            Some(Err(error)) => {
                                return Ok(DispatchOutcome::errno(ptrace_foreign_mm_errno(&error)));
                            }
                            None => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                        };
                        let expected_mm_id = match &relation {
                            crate::kernel::MmRelation::Current(current) => current.mm_id(),
                            crate::kernel::MmRelation::Foreign(foreign) => foreign.mm_id(),
                        };
                        if expected_mm_id != ptrace_witness.mm_id() {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        match ptrace_witness.with_revalidated(
                            || -> Result<DispatchOutcome, LinuxErrno> {
                                if !addr.0.is_multiple_of(8)
                                    || ptrace_text_data_addr_is_invalid(addr)
                                {
                                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                                }
                                match relation {
                                    crate::kernel::MmRelation::Foreign(foreign) => {
                                        let Some(authority) = process.mm_access_authority() else {
                                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                                        };
                                        let remote_va = carrick_guest_mem::GuestVa(addr.0);
                                        let range = match foreign.read_range(remote_va, 8) {
                                            Ok(Some(r)) => r,
                                            _ => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                                        };
                                        let mut buf = [0u8; 8];
                                        match authority.read_foreign(&foreign, range, &mut buf) {
                                            Ok(receipt) if receipt.bytes_read() == 8 => {
                                                let word = u64::from_le_bytes(buf);
                                                Ok(DispatchOutcome::Returned {
                                                    value: word as i64,
                                                })
                                            }
                                            _ => Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                                        }
                                    }
                                    crate::kernel::MmRelation::Current(_) => {
                                        let mut buf = [0u8; 8];
                                        match cx.memory.read_into(addr.0, &mut buf) {
                                            Ok(()) => {
                                                let word = u64::from_le_bytes(buf);
                                                Ok(DispatchOutcome::Returned {
                                                    value: word as i64,
                                                })
                                            }
                                            Err(_) => Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                                        }
                                    }
                                }
                            },
                        ) {
                            Ok(Ok(outcome)) => outcome,
                            Ok(Err(errno)) | Err(errno) => DispatchOutcome::errno(errno),
                        }
                    }
                    LINUX_PTRACE_POKETEXT | LINUX_PTRACE_POKEDATA => {
                        let Ok(target_task_id) = guest_pid_to_task_id(cx.kernel, pid) else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        let Some(target_task) = kernel.registry().task(target_task_id) else {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        };
                        if !kernel.task_key_is_live(target_task.key()) {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        let target_key = target_task.key();
                        let ptrace_witness = match kernel
                            .begin_ptrace_memory_access(process.task_key(), target_key)
                        {
                            Ok(witness) => witness,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        let relation = cx.with_execution_lease(|lease| {
                            kernel.foreign_mm(cx.kernel, lease, target_key)
                        });
                        let relation = match relation {
                            Some(Ok(r)) => r,
                            Some(Err(error)) => {
                                return Ok(DispatchOutcome::errno(ptrace_foreign_mm_errno(&error)));
                            }
                            None => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                        };
                        let expected_mm_id = match &relation {
                            crate::kernel::MmRelation::Current(current) => current.mm_id(),
                            crate::kernel::MmRelation::Foreign(foreign) => foreign.mm_id(),
                        };
                        if expected_mm_id != ptrace_witness.mm_id() {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        if !addr.0.is_multiple_of(8) || ptrace_text_data_addr_is_invalid(addr) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                        }
                        let staged_data = data.to_le_bytes();
                        let remote_va = carrick_guest_mem::GuestVa(addr.0);
                        let mutation_tid = cx.tid();
                        macro_rules! commit_transport_poke {
                            ($mm:expr, $with_mutation:ident) => {{
                                let Some(authority) = process.mm_access_authority() else {
                                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                                };
                                let result = this.with_current_mm_executor_released(cx, || {
                                    let mutation = authority.$with_mutation(
                                        &$mm,
                                        mutation_tid,
                                        |mutation_guard| -> Result<_, crate::kernel::MmAccessError> {
                                            Ok(if request == LINUX_PTRACE_POKETEXT {
                                            ptrace_witness.with_revalidated_text(
                                                $mm.mm_id(),
                                                |text_access| -> Result<(), crate::kernel::MmAccessError> {
                                                    authority.write_ptrace_text_under_witness(
                                                        mutation_guard,
                                                        &$mm,
                                                        &text_access,
                                                        remote_va,
                                                        &staged_data,
                                                    )?;
                                                    Ok(())
                                                },
                                            )
                                        } else {
                                            ptrace_witness.with_revalidated(
                                                || -> Result<(), crate::kernel::MmAccessError> {
                                                    let write_range = $mm
                                                        .write_range(remote_va, 8)?
                                                        .ok_or(crate::kernel::MmAccessError::SourceLengthMismatch {
                                                            range: 0,
                                                            source_len: staged_data.len(),
                                                        })?;
                                                let mut cow = authority.break_foreign_cow(
                                                    mutation_guard,
                                                    &$mm,
                                                    write_range,
                                                )?;
                                                authority
                                                    .prepare_foreign_write_range(
                                                        &mut cow,
                                                        write_range,
                                                        &staged_data,
                                                    )?
                                                    .commit();
                                                Ok(())
                                                },
                                            )
                                        })
                                        },
                                    );
                                    match mutation {
                                        Err(error) => Err(PtracePokeFailure::Mutation(error)),
                                        Ok(Err(errno)) => Err(PtracePokeFailure::Witness(errno)),
                                        Ok(Ok(Err(error))) => Err(PtracePokeFailure::Write(error)),
                                        Ok(Ok(Ok(()))) => Ok(()),
                                    }
                                })?;
                                match result {
                                    Ok(()) => DispatchOutcome::Returned { value: 0 },
                                    Err(error) => DispatchOutcome::errno(ptrace_poke_failure_errno(&error)),
                                }
                            }};
                        }
                        match relation {
                            crate::kernel::MmRelation::Current(current) => {
                                if request != LINUX_PTRACE_POKETEXT {
                                    match ptrace_witness.with_revalidated(
                                        || -> Result<DispatchOutcome, LinuxErrno> {
                                            match cx.memory.write_bytes(addr.0, &staged_data) {
                                                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                                                Err(_) => Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)),
                                            }
                                        },
                                    ) {
                                        Ok(Ok(outcome)) => outcome,
                                        Ok(Err(errno)) | Err(errno) => DispatchOutcome::errno(errno),
                                    }
                                } else {
                                    commit_transport_poke!(current, with_current_mutation)
                                }
                            }
                            crate::kernel::MmRelation::Foreign(foreign) => {
                                commit_transport_poke!(foreign, with_foreign_mutation)
                            }
                        }
                    }
                    LINUX_PTRACE_PEEKUSER | LINUX_PTRACE_POKEUSER => {
                        if target().is_none() {
                            DispatchOutcome::errno(LINUX_ESRCH)
                        } else if ptrace_user_addr_is_invalid(addr) {
                            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO)
                        } else {
                            DispatchOutcome::errno(LINUX_ENOSYS)
                        }
                    }
                    _ => DispatchOutcome::errno(LINUX_ENOSYS),
                };
                return Ok(outcome);
            }
            #[cfg(not(test))]
            return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
            #[cfg(test)]
            {
            // The tracee in the HOST domain (bare i32, NOT re-wrapped in
            // NsPid: a host pid inside the ns-pid wrapper silently defeats
            // every downstream `.names_self()`/`.to_host()`).
            let host_pid = |pid: Pid| -> Option<i32> {
                if crate::namespace::pid::enabled() && pid.0 > 0 {
                    crate::namespace::pid::ns_to_host_or_self(pid.0 as u32).map(|host| host as i32)
                } else {
                    Some(pid.0)
                }
            };
            let host_signal_data = || -> i32 {
                let linux_signal = data as i32;
                if linux_signal == 0 {
                    0
                } else {
                    crate::host_signal::linux_to_host_signum(linux_signal)
                }
            };
            // Carrick's kernel graph is the only guest-process liveness
            // authority. A missing kernel binding is a retired one-task path,
            // never permission to probe an arbitrary host pid.
            let target_exists = |host: i32| -> bool {
                this.guest_pid_is_live(host).unwrap_or(false)
            };

            let route = match route_ptrace_request(transport, request, data) {
                Ok(route) => route,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            match route {
                PtraceRequestRoute::VirtualTraceme => {
                    let mut proc = this.proc.lock();
                    if proc.ptrace_traceme {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM));
                    }
                    let tracer_pid = u32::try_from(unsafe { libc::getppid() }).unwrap_or(0);
                    if !crate::guest_cpu::register_self_virtual_ptrace(tracer_pid) {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM));
                    }
                    proc.ptrace_traceme = true;
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                PtraceRequestRoute::VirtualControl(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
                }
                PtraceRequestRoute::Host | PtraceRequestRoute::Shared => {}
            }

            let result = match request {
                0 => {
                    if this.proc.lock().ptrace_traceme {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM));
                    }
                    unsafe { carrick_portable::ptrace(carrick_portable::PT_TRACE_ME, 0, 0, 0) }
                }
                7 => match host_pid(pid) {
                    Some(host) => unsafe {
                        carrick_portable::ptrace(
                            carrick_portable::PT_CONTINUE,
                            host,
                            1,
                            host_signal_data(),
                        )
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                8 => match host_pid(pid) {
                    Some(host) => unsafe {
                        carrick_portable::ptrace(carrick_portable::PT_KILL, host, 0, 0)
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                17 => match host_pid(pid) {
                    Some(host) => unsafe {
                        carrick_portable::ptrace(
                            carrick_portable::PT_DETACH,
                            host,
                            1,
                            host_signal_data(),
                        )
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                LINUX_PTRACE_ATTACH => match host_pid(pid) {
                    Some(host) if host > 0 && target_exists(host) => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM));
                    }
                    _ => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                LINUX_PTRACE_PEEKTEXT
                | LINUX_PTRACE_PEEKDATA
                | LINUX_PTRACE_POKETEXT
                | LINUX_PTRACE_POKEDATA => match host_pid(pid) {
                    Some(host) if host > 0 => {
                        let exists = target_exists(host);
                        if !exists {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        if ptrace_text_data_addr_is_invalid(addr) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                        }
                        return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
                    }
                    _ => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                LINUX_PTRACE_PEEKUSER | LINUX_PTRACE_POKEUSER => match host_pid(pid) {
                    Some(host) if host > 0 => {
                        let exists = target_exists(host);
                        if !exists {
                            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                        }
                        if ptrace_user_addr_is_invalid(addr) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EIO));
                        }
                        return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
                    }
                    _ => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                },
                _ => return Ok(DispatchOutcome::errno(LINUX_ENOSYS)),
            };
            result.host_syscall_errno()?;
            if request == 0 {
                this.proc.lock().ptrace_traceme = true;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
            }
        }

        fn reboot(this, cx) {
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }

        fn sethostname(this, cx) {
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }

        fn setdomainname(this, cx) {
            Ok(DispatchOutcome::errno(LINUX_EPERM))
        }

        /// setpgid(pid, pgid): move a process between groups, in the kernel
        /// graph and nowhere else.
        ///
        /// The host call this replaces moved the CARRIER's Darwin group. Every
        /// guest process is a thread of that one carrier, so one guest calling
        /// `setpgid` relocated all of them at once — and the pgid it was handed
        /// is a guest number that names an unrelated Darwin group, so the move
        /// went somewhere arbitrary. The graph also owns the session, leader
        /// and already-execed-child rules `libc::setpgid` could only enforce
        /// against host state that no guest process actually occupies.
        fn setpgid(this, cx, pid: Pid, pgid: Pid) {
            // `pgid == 0` means "use `pid` as the group id", and that
            // substitution happens BEFORE the range check -- so `setpgid(-1, 0)`
            // asks for group -1 and is EINVAL, not the ESRCH a negative pid
            // alone would give (`lifecycleflagmatrix`
            // `setpgid_neg_pid_einval`). Resolving in this order keeps LTP
            // setpgid02's ESRCH case, which passes a nonexistent POSITIVE pid.
            let effective_pgid = if pgid.0 == 0 { pid.0 } else { pgid.0 };
            if effective_pgid < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if pid.0 < 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            }
            let target = match (pid.0 != 0)
                .then(|| guest_pid_to_task_id(cx.kernel, pid))
                .transpose()
            {
                Ok(target) => target,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
            };
            // Existing groups resolve through their own lifetime authority;
            // the leader's PID entry may already have been consumed. The PID
            // fallback is solely for Linux's create-a-new-group case, where
            // pgid names the still-live target process itself.
            let group = match (pgid.0 != 0)
                .then(|| {
                    let namespace_id = u32::try_from(pgid.0).map_err(|_| ())?;
                    if let Some(group) =
                        crate::namespace::pid::ns_to_process_group_for(cx.kernel, namespace_id)
                    {
                        return Ok(group);
                    }
                    let internal = crate::namespace::pid::ns_to_kernel_for(
                        cx.kernel,
                        namespace_id,
                    )
                    .and_then(|internal| i32::try_from(internal).ok())
                    .ok_or(())?;
                    crate::kernel::ProcessGroupId::from_abi_positive(internal).map_err(|_| ())
                })
                .transpose()
            {
                Ok(group) => group,
                Err(()) => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM)),
            };
            match cx
                .kernel
                .kernel()
                .set_process_group(cx.kernel.task().key().id, target, group)
            {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(error) => Ok(DispatchOutcome::errno(
                    crate::hvpatch::identity_operation_errno(error),
                )),
            }
        }

        /// getpgid(pid): the process group of `pid`, or of the caller for pid 0.
        ///
        /// Answers from the kernel graph including the ZOMBIE table, because
        /// Linux keeps an exited-but-unreaped child addressable until `wait(2)`:
        /// a shell that reaps a job member and then asks for its group must get
        /// the group, not ESRCH.
        fn getpgid(this, cx, pid: Pid) {
            let target = match identity_target_task(cx.kernel, pid) {
                Ok(target) => target,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            match cx.kernel.kernel().process_identity(target) {
                Some(identity) => Ok(DispatchOutcome::Returned {
                    value: i64::from(identity.namespace_process_group),
                }),
                None => Ok(DispatchOutcome::errno(LINUX_ESRCH)),
            }
        }

        /// getsid(pid): the session of `pid`, or of the caller for pid 0. Same
        /// zombie-inclusive authority as `getpgid`.
        fn getsid(this, cx, pid: Pid) {
            let target = match identity_target_task(cx.kernel, pid) {
                Ok(target) => target,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            match cx.kernel.kernel().process_identity(target) {
                Some(identity) => Ok(DispatchOutcome::Returned {
                    value: i64::from(identity.namespace_session),
                }),
                None => Ok(DispatchOutcome::errno(LINUX_ESRCH)),
            }
        }

        /// setsid(): a new session led by the caller. Same authority and the
        /// same reason as `setpgid` — `libc::setsid()` would detach the CARRIER
        /// from its controlling terminal on one guest process's behalf, which
        /// every other guest process would then observe.
        fn setsid(this, cx) {
            match cx.kernel.kernel().create_session(cx.kernel.task().key().id, None) {
                // A session/group id IS a leader's pid, so it must be reported
                // in the caller's PID-namespace view exactly as `getpid` is.
                // These returned the raw `TaskId`, so a forked child saw
                // `setsid() != getpid()` and `getpgrp()`/`getsid()` disagreeing
                // with its own pid (`lifecycleflagmatrix`
                // `setsid_in_child_*`). The mismatch is invisible whenever the
                // two numbering domains happen to coincide, which is why the
                // single-process lane never caught it.
                Ok(sid) => Ok(DispatchOutcome::Returned {
                    value: i64::from(ns_visible_session(cx.kernel, sid)),
                }),
                Err(error) => Ok(DispatchOutcome::errno(
                    crate::hvpatch::identity_operation_errno(error),
                )),
            }
        }

        fn waitid(this, cx, idtype: u64, id: u64, infop_addr: GuestPtr, options: u64) {
            #[cfg(test)]
            let transport =
                select_ptrace_transport(this.page_geometry(), this.hvpatch_process().is_some());
            // Retain unknown bits so the supported-mask rejection below stays
            // bit-identical to the raw `options & !SUPPORTED != 0` test.
            let options = LinuxWaitOptions::from_bits_retain(options);
            if !LinuxWaitOptions::WAITID_SUPPORTED.contains(options) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !options.intersects(LinuxWaitOptions::WAITID_STATE_MASK) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some(process) = this.hvpatch_process() {
                // HvPatch children are Linux processes in the in-process table,
                // not Darwin children, so a host waitid would truthfully return
                // ECHILD. Route terminal child state through the same table as
                // wait4 and synthesize Linux's SIGCHLD siginfo layout.
                // waitid(2) reports three kinds of state change, selected by
                // WEXITED / WSTOPPED / WCONTINUED. carrick previously ECHILD'd
                // unless WEXITED was set and ECHILD'd P_PGID outright, so a
                // guest could never observe a stopped or continued child.
                // The kernel graph has recorded both events all along
                // (`pending_stop`/`pending_continue`, consumed by
                // `waitable_job_control_event`) and `wait4` already asks for
                // them — this routes `waitid` through the same helpers.
                let include_stopped = options.contains(LinuxWaitOptions::WSTOPPED);
                let include_continued = options.contains(LinuxWaitOptions::WCONTINUED);
                let nowait = options.contains(LinuxWaitOptions::WNOWAIT);
                let class = crate::kernel::WaitChildClass::from_wait_options(options);
                let mut pidfd_target = None;
                let mut group_target = None;
                let target = match idtype {
                    LINUX_P_ALL => None,
                    // The id is an ns-pid; the graph waits by task id. A
                    // number naming no member is ECHILD, same as the range
                    // check below.
                    LINUX_P_PID if id > 0 && id <= i32::MAX as u64 => {
                        match crate::namespace::pid::ns_to_kernel_for(cx.kernel, id as u32)
                            .and_then(|host| i32::try_from(host).ok())
                        {
                            Some(host) => Some(host),
                            None => {
                                return Ok(DispatchOutcome::errno(
                                    crate::linux_abi::LINUX_ECHILD,
                                ));
                            }
                        }
                    }
                    LINUX_P_PID => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                    }
                    // P_PGID waits on a process group; id 0 means the caller's
                    // own group. The kernel graph indexes process groups, so
                    // this resolves there and never consults Darwin.
                    LINUX_P_PGID if id <= i32::MAX as u64 => {
                        let group = if id == 0 {
                            match process.process_group() {
                                Ok(group) => group,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                        } else {
                            match crate::namespace::pid::ns_to_process_group_for(
                                cx.kernel,
                                id as u32,
                            ) {
                                Some(group) => group.raw(),
                                None => {
                                    return Ok(DispatchOutcome::errno(
                                        crate::linux_abi::LINUX_ECHILD,
                                    ));
                                }
                            }
                        };
                        group_target = Some(group);
                        None
                    }
                    LINUX_P_PGID => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                    }
                    LINUX_P_PIDFD => match this.pidfd_hvpatch_task(cx.kernel, id as i32) {
                        Some(task) => {
                            pidfd_target = Some(task);
                            None
                        }
                        None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    },
                    _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                };
                let guest_nohang = options.contains(LinuxWaitOptions::WNOHANG);
                let waited = match (pidfd_target, group_target) {
                    (Some(task), _) => process.wait_child_key(task, class, nowait),
                    (None, Some(group)) => process
                        .wait_child_in_process_group_with_job_control(
                            group,
                            class,
                            nowait,
                            include_stopped,
                            include_continued,
                        ),
                    (None, None) => process.wait_child_with_job_control(
                        target,
                        class,
                        nowait,
                        include_stopped,
                        include_continued,
                    ),
                };
                match waited {
                    // A stop or continue is a REPORTABLE event, not "nothing
                    // happened". Folding `StateChanged` into the park arm did
                    // not merely fail to report it — the kernel-graph event was
                    // consumed by the wait above and then thrown away, so a
                    // ptrace stop (which `waitable_job_control_event` surfaces
                    // regardless of WSTOPPED) could be silently swallowed by an
                    // ordinary waitid(WEXITED).
                    crate::hvpatch::WaitResult::Exited(exit)
                    | crate::hvpatch::WaitResult::StateChanged(exit) => {
                        if infop_addr.0 != 0 {
                            let bytes = build_hvpatch_waitid_siginfo(exit);
                            (*cx.memory).write_bytes(infop_addr.0, &bytes)?;
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::hvpatch::WaitResult::StillRunning => {
                        if guest_nohang {
                            if infop_addr.0 != 0 {
                                (*cx.memory).write_bytes(
                                    infop_addr.0,
                                    &[0u8; crate::linux_abi::LINUX_SIGINFO_SIZE],
                                )?;
                            }
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        if idtype == LINUX_P_PIDFD && this.pidfd_is_nonblocking(id as i32) {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        let tid = Self::ctx_tid(cx);
                        let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                        // A deliverable pending signal must interrupt the wait
                        // BEFORE parking (Linux EINTR; SA_RESTART restarts it
                        // after the handler). Without this check a signal that
                        // arrived through the kernel post (an HVPatch itimer
                        // SIGALRM above all) woke the parked continuation, the
                        // re-dispatch saw StillRunning, and the park re-formed
                        // with the signal still pending — forever (the
                        // waitrestart hang). Every other interruptible park
                        // (ppoll/net/sysv/mqueue) already runs this gate.
                        if this.has_deliverable_dispatch_pending_for_wait(
                            cx.kernel,
                            tid,
                            carrick_abi::WaitSigMask::Additive(non_interrupting),
                        ) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        return Ok(DispatchOutcome::WaitOnHvpatchChild {
                            target,
                            sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
                        });
                    }
                    crate::hvpatch::WaitResult::NoChild => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                    }
                }
            }
            #[cfg(not(test))]
            return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
            #[cfg(test)]
            {
            let (host_idtype, host_id): (libc::idtype_t, libc::id_t) = match idtype {
                LINUX_P_ALL => (libc::P_ALL, 0),
                LINUX_P_PID => {
                    // Translate the ns-pid arg to the host pid the kernel knows
                    // (§5.3); an ns-pid that names no member is ECHILD.
                    match crate::namespace::pid::ns_to_host_or_self(id as u32) {
                        Some(h) => (libc::P_PID, h as libc::id_t),
                        None => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD)),
                    }
                }
                // P_PGID names a process group (§6.6). Linux `id == 0` means
                // the caller's own group; Darwin requires the concrete pgid,
                // so resolve that sentinel before entering waitid. A non-zero
                // `id` is the guest's ns-pgid; translate it to the
                // host pgid via the same helper `setpgid`/`F_OWNER_PGRP`/
                // `TIOCSPGRP` use, so the host waitid matches the real host
                // group instead of ECHILD-ing on an untranslated ns value. An
                // ns-pgid that names no group is ECHILD (no such child).
                LINUX_P_PGID => {
                    if id == 0 {
                        (libc::P_PGID, unsafe { libc::getpgrp() } as libc::id_t)
                    } else {
                        match crate::namespace::pid::ns_to_host_pgid(id as u32) {
                            Some(h) => (libc::P_PGID, h as libc::id_t),
                            None => {
                                return Ok(DispatchOutcome::errno(
                                    crate::linux_abi::LINUX_ECHILD,
                                ));
                            }
                        }
                    }
                }
                LINUX_P_PIDFD => match this.pidfd_host_pid(id as i32) {
                    Some(host_pid) => (libc::P_PID, host_pid as libc::id_t),
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                },
                _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            };
            let mut host_options: i32 = 0;
            if options.contains(LinuxWaitOptions::WEXITED) {
                host_options |= libc::WEXITED;
            }
            if options.contains(LinuxWaitOptions::WSTOPPED) {
                host_options |= libc::WSTOPPED;
            }
            if options.contains(LinuxWaitOptions::WCONTINUED) {
                host_options |= libc::WCONTINUED;
            }
            if options.contains(LinuxWaitOptions::WNOWAIT) {
                host_options |= libc::WNOWAIT;
            }
            let guest_nohang = options.contains(LinuxWaitOptions::WNOHANG);

            let lease_target = ptrace_wait_target_for_waitid(host_idtype, host_id);
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let mut virtual_waitid_stop = None;
            let mut native_proc = (transport == PtraceTransport::VirtualNative)
                .then(|| this.proc.lock());
            if let Some(proc) = native_proc.as_mut() {
                let leases = proc.matching_virtual_ptrace_leases(lease_target);
                if options.contains(LinuxWaitOptions::WSTOPPED) {
                    for (leased_pid, stop) in &leases {
                        let mut leased_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                        let probe_options = libc::WSTOPPED
                            | libc::WNOHANG
                            | (host_options & libc::WNOWAIT);
                        let rc = unsafe {
                            libc::waitid(
                                libc::P_PID,
                                *leased_pid as libc::id_t,
                                &mut leased_info,
                                probe_options,
                            )
                        };
                        if rc == 0
                            && carrick_portable::si_pid(&leased_info) == *leased_pid as i32
                            && carrick_portable::si_status(&leased_info) == libc::SIGSTOP
                            && matches!(
                                leased_info.si_code,
                                libc::CLD_TRAPPED | libc::CLD_STOPPED
                            )
                        {
                            info = leased_info;
                            virtual_waitid_stop = Some(*stop);
                            break;
                        }
                    }
                }
                if virtual_waitid_stop.is_none()
                    && matches!(lease_target, PtraceWaitTarget::Exact(_))
                    && let Some((leased_pid, _)) = leases.first()
                {
                    let leased_pid = *leased_pid;
                    drop(native_proc);
                    if guest_nohang {
                        if infop_addr.0 != 0 {
                            let memory = &mut *cx.memory;
                            memory.write_bytes(
                                infop_addr.0,
                                &[0u8; crate::linux_abi::LINUX_SIGINFO_SIZE],
                            )?;
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    if idtype == LINUX_P_PIDFD && this.pidfd_is_nonblocking(id as i32) {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    let tid = Self::ctx_tid(cx);
                    let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                    let sig_mask = carrick_abi::WaitSigMask::Additive(non_interrupting);
                    return Ok(if options.intersects(
                        LinuxWaitOptions::WSTOPPED | LinuxWaitOptions::WCONTINUED,
                    ) {
                        DispatchOutcome::WaitOnProcState {
                            pid: leased_pid as i32,
                            sig_mask,
                        }
                    } else {
                        DispatchOutcome::WaitOnProcExit {
                            pid: leased_pid as i32,
                            sig_mask,
                        }
                    });
                }
            }
            let mut native_main_waitid_peek = false;
            if virtual_waitid_stop.is_none() {
                let internal_options = host_options
                    | libc::WNOHANG
                    | if transport == PtraceTransport::VirtualNative {
                        native_main_waitid_peek = true;
                        libc::WNOWAIT
                    } else {
                        0
                    };
                let r = unsafe {
                    libc::waitid(host_idtype, host_id, &mut info, internal_options)
                };
                if r != 0 {
                    // Route the host errno through the central Darwin->Linux helper
                    // (a raw Darwin errno >34 would otherwise leak to the guest).
                    let errno = crate::dispatch::HostSyscallError::last().linux_errno();
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            let selected_state = clear_unrequested_waitid_state(&mut info, options);
            if selected_state
                && virtual_waitid_stop.is_none()
                && transport == PtraceTransport::VirtualNative
                && carrick_portable::si_pid(&info) > 0
                && carrick_portable::si_status(&info) == libc::SIGSTOP
                && matches!(info.si_code, libc::CLD_TRAPPED | libc::CLD_STOPPED)
                && let Some(stop) = crate::guest_cpu::report_child_virtual_ptrace_stop(
                    carrick_portable::si_pid(&info) as u32,
                )
            {
                if let Some(proc) = native_proc.as_mut() {
                    proc.record_virtual_ptrace_stop(
                        carrick_portable::si_pid(&info) as u32,
                        stop,
                    );
                    virtual_waitid_stop = Some(stop);
                }
            }
            if native_main_waitid_peek
                && selected_state
                && carrick_portable::si_pid(&info) > 0
                && !options.contains(LinuxWaitOptions::WNOWAIT)
            {
                let selected_pid = carrick_portable::si_pid(&info);
                let Some(state_option) = waitid_host_state_option(info.si_code) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let mut consumed_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let r = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        selected_pid as libc::id_t,
                        &mut consumed_info,
                        state_option | libc::WNOHANG,
                    )
                };
                if r != 0 {
                    let errno = crate::dispatch::HostSyscallError::last().linux_errno();
                    return Ok(DispatchOutcome::errno(errno));
                }
                if carrick_portable::si_pid(&consumed_info) != selected_pid {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                }
                info = consumed_info;
            }
            drop(native_proc);
            let si_pid = carrick_portable::si_pid(&info);
            if si_pid == 0 && !guest_nohang {
                if idtype == LINUX_P_PIDFD
                    && let Some(host_fd) = this.host_fd_for_poll(id as i32) {
                        if this.pidfd_is_nonblocking(id as i32) {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        let files = this.captured_file_table();
                        let fds = match WaitFds::raw_one(host_fd.get(), libc::POLLIN)
                            .with_guest_slots(&files, [id as i32])
                        {
                            Ok(fds) => fds,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        return Ok(DispatchOutcome::WaitOnPollFds {
                            fds,
                            timeout: None,
                            on_timeout: 0,
                            sig_mask: carrick_abi::WaitSigMask::NONE,
                        });
                    }
                if transport == PtraceTransport::VirtualNative {
                    let Some(wait_pid) = ptrace_wait_park_pid(lease_target) else {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                    };
                    let tid = Self::ctx_tid(cx);
                    let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                    let sig_mask = carrick_abi::WaitSigMask::Additive(non_interrupting);
                    return Ok(if options.intersects(
                        LinuxWaitOptions::WSTOPPED | LinuxWaitOptions::WCONTINUED,
                    ) {
                        DispatchOutcome::WaitOnProcState {
                            pid: wait_pid,
                            sig_mask,
                        }
                    } else {
                        DispatchOutcome::WaitOnProcExit {
                            pid: wait_pid,
                            sig_mask,
                        }
                    });
                }
                if idtype == LINUX_P_PID {
                    // Same no-interrupt mask as wait4: a blocked or
                    // delivered-and-dropped signal must not EINTR the park.
                    // Park on the HOST pid (host_id), not the guest ns-pid —
                    // WaitOnProcExit watches the real host process (§5.3).
                    let tid = Self::ctx_tid(cx);
                    let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                    return Ok(DispatchOutcome::WaitOnProcExit {
                        pid: host_id as i32,
                        sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
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
            let terminal_reap = {
                const CLD_EXITED: i32 = 1;
                const CLD_KILLED: i32 = 2;
                const CLD_DUMPED: i32 = 3;
                let terminal = matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED);
                if carrick_portable::si_pid(&info) != 0
                    && !options.contains(LinuxWaitOptions::WNOWAIT)
                    && terminal
                {
                    // Host waitid returns no rusage; the published channel is
                    // the only source (under the native provider it carries the
                    // child's full Darwin CPU, published at exit).
                    let child_guest_ns =
                        crate::guest_cpu::reap_child_guest_ns(carrick_portable::si_pid(&info) as u32);
                    let (child_user_us, child_system_us) =
                        crate::guest_cpu::reaped_child_cpu_parts(child_guest_ns, None);
                    crate::guest_cpu::add_reaped_child(child_user_us, child_system_us);
                    // Tear down the now-dead child's leaked host VM node (bhyve);
                    // no-op on KVM/HVF. See the wait4 reap path.
                    carrick_hal::vm_backend::reap_child_vm(carrick_portable::si_pid(&info) as u32);
                    true
                } else {
                    false
                }
            };
            if infop_addr.0 != 0 {
                let bytes = if carrick_portable::si_pid(&info) == 0 {
                    [0u8; crate::linux_abi::LINUX_SIGINFO_SIZE]
                } else {
                    // The reaped child's si_pid is a host pid; the guest must see
                    // its ns-local pid (§5.3). Identity when namespaces are off.
                    let ns_si_pid =
                        crate::namespace::pid::host_to_ns_or_self(carrick_portable::si_pid(&info) as u32) as i32;
                    // macOS reports CLD_KILLED for a signal death (the host never
                    // dumps core); Linux reports CLD_DUMPED when the child died by
                    // a core-dumping signal with core dumps enabled. Synthesize it
                    // (mirrors the wait4 wstatus 0x80 bit) so waitid(WEXITED)
                    // matches — waitid10: a SIGFPE child → CLD_DUMPED.
                    let si_code = this.core_dumped_si_code(
                        info.si_code,
                        carrick_portable::si_status(&info),
                    );
                    if let Some(stop) = virtual_waitid_stop {
                        build_linux_sigchld_siginfo(
                            ns_si_pid,
                            carrick_portable::si_uid(&info),
                            libc::CLD_TRAPPED,
                            stop.linux_signum(),
                        )
                    } else {
                        build_sigchld_siginfo(
                            ns_si_pid,
                            carrick_portable::si_uid(&info),
                            si_code,
                            carrick_portable::si_status(&info),
                        )
                    }
                };
                let memory = &mut *cx.memory;
                memory.write_bytes(infop_addr.0, &bytes)?;
            }
            if terminal_reap {
                crate::namespace::pid::unregister_reaped(carrick_portable::si_pid(&info) as u32);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
            }
        }

        fn wait4(this, cx, pid: Pid, wstatus_addr: GuestPtr, options: u64, rusage_addr: GuestPtr) {
            let memory = &mut *cx.memory;
            #[cfg(test)]
            let transport =
                select_ptrace_transport(this.page_geometry(), this.hvpatch_process().is_some());
            // Retain unknown bits so the supported-mask rejection stays
            // bit-identical to the raw `options & !SUPPORTED != 0` test.
            let options = LinuxWaitOptions::from_bits_retain(options);
            if !LinuxWaitOptions::WAIT4_SUPPORTED.contains(options) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some(process) = this.hvpatch_process() {
                let include_stopped = options.contains(LinuxWaitOptions::WUNTRACED);
                let include_continued = options.contains(LinuxWaitOptions::WCONTINUED);
                // wait(2): a child whose exit signal is not SIGCHLD -- a
                // `clone(CLONE_VM|0)` helper, say -- is a "clone child" that a
                // plain wait ignores (ECHILD when only such children exist);
                // `__WCLONE` selects only those and `__WALL` every child.
                let class = crate::kernel::WaitChildClass::from_wait_options(options);
                // The guest names its child by the pid `fork` returned — an
                // ns-pid — while the kernel graph waits by task id. An ns-pid
                // that names no member is ECHILD (no such child), exactly as
                // an untranslated miss would report. The translated value is
                // also what a park republishes as its exact-child selector.
                let mut host_target = None;
                let waited = match pid.0 {
                    -1 => process.wait_child_with_job_control(
                        None,
                        class,
                        false,
                        include_stopped,
                        include_continued,
                    ),
                    value if value > 0 => {
                        match u32::try_from(value)
                            .ok()
                            .and_then(|value| crate::namespace::pid::ns_to_kernel_for(cx.kernel, value))
                            .and_then(|host| i32::try_from(host).ok())
                        {
                            Some(host) => {
                                host_target = Some(host);
                                process.wait_child_with_job_control(
                                    Some(host),
                                    class,
                                    false,
                                    include_stopped,
                                    include_continued,
                                )
                            }
                            None => crate::hvpatch::WaitResult::NoChild,
                        }
                    }
                    0 => match process.process_group() {
                        Ok(group) => process.wait_child_in_process_group_with_job_control(
                            group,
                            class,
                            false,
                            include_stopped,
                            include_continued,
                        ),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    value => match value.checked_abs().and_then(|value| {
                        u32::try_from(value)
                            .ok()
                            .and_then(|value| {
                                crate::namespace::pid::ns_to_process_group_for(cx.kernel, value)
                            })
                            .map(crate::kernel::ProcessGroupId::raw)
                    })
                    {
                        Some(group) => process.wait_child_in_process_group_with_job_control(
                            group,
                            class,
                            false,
                            include_stopped,
                            include_continued,
                        ),
                        None => {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ESRCH));
                        }
                    },
                };
                let guest_nohang = options.contains(LinuxWaitOptions::WNOHANG);
                match waited {
                    crate::hvpatch::WaitResult::Exited(exit)
                    | crate::hvpatch::WaitResult::StateChanged(exit) => {
                        if wstatus_addr.0 != 0 {
                            memory.write_bytes(wstatus_addr.0, &exit.status().to_ne_bytes())?;
                        }
                        if rusage_addr.0 != 0 {
                            let rusage = LinuxRusage::zeroed();
                            memory.write_bytes(rusage_addr.0, rusage.abi_bytes())?;
                        }
                        return Ok(DispatchOutcome::Returned {
                            // The wait receipt retains the namespace pid because
                            // consuming the zombie also releases its live map.
                            value: i64::from(exit.visible_pid()),
                        });
                    }
                    crate::hvpatch::WaitResult::StillRunning => {
                        if guest_nohang {
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        let tid = Self::ctx_tid(cx);
                        let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                        // See the waitid arm above: a deliverable pending
                        // signal interrupts the wait BEFORE parking, or the
                        // TaskWake redispatch re-parks over it forever.
                        if this.has_deliverable_dispatch_pending_for_wait(
                            cx.kernel,
                            tid,
                            carrick_abi::WaitSigMask::Additive(non_interrupting),
                        ) {
                            return Ok(DispatchOutcome::errno(LINUX_EINTR));
                        }
                        return Ok(DispatchOutcome::WaitOnHvpatchChild {
                            // Only a positive pid is an exact child selector.
                            // `0`, `-1`, and `-pgid` are group/broad Linux wait
                            // selectors; the continuation intentionally wakes
                            // broadly and this handler re-applies the exact
                            // group filter on redispatch. Publishing a
                            // nonpositive value as an exact task id makes the
                            // continuation reject it as `StaleChildSelector`.
                            // The selector is the TRANSLATED task id: the
                            // continuation resolves it in the kernel graph.
                            target: host_target,
                            sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
                        });
                    }
                    crate::hvpatch::WaitResult::NoChild => {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                    }
                }
            }
            #[cfg(not(test))]
            return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
            #[cfg(test)]
            {
            // PID namespace (§5.3): a positive `pid` arg names a child by its
            // ns-pid; translate it to the host pid the kernel knows. An ns-pid
            // that names no member is ESRCH. pid <= 0 (any-child / pgrp) stays
            // host-level; only the RESULT is translated back (below). Identity
            // when namespaces are off.
            // The wait target in the HOST domain: a positive ns-pid translates
            // to the host pid; `<= 0` sentinels (any-child / process-group)
            // pass through untranslated. A bare i32 (not HostPid) because the
            // sentinel values are part of the domain; NOT an NsPid — stuffing
            // the translated host pid back into NsPid defeated the wrapper's
            // whole purpose (a downstream `.names_self()`/`.to_host()` would
            // silently double-translate).
            let host_target: i32 = if crate::namespace::pid::enabled() && pid.0 > 0 {
                match crate::namespace::pid::ns_to_host_or_self(pid.0 as u32) {
                    Some(h) => h as i32,
                    None => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD)),
                }
            } else if crate::namespace::pid::enabled() && pid.0 < -1 && pid.0 != i32::MIN {
                // A process-group wait names ns-pgid `-pid`; translate it to
                // the host pgid via the same helper `setpgid`/`F_OWNER_PGRP`/
                // `TIOCSPGRP` use, so the host wait4 matches the real host
                // group instead of finding none and ECHILD-ing. An ns-pgid
                // that names no group is ECHILD (Linux: no such child,
                // matching the `pid > 0` non-member case above). `i32::MIN` is
                // excluded: its magnitude can never be a real ns-pgid (LTP
                // waitpid04's "invalid process group" case expects ESRCH, via
                // the untranslated host_target < -1 EINVAL remap below — not
                // this branch's ECHILD).
                match crate::namespace::pid::ns_to_host_pgid(pid.0.unsigned_abs()) {
                    Some(h) => -(h as i32),
                    None => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD)),
                }
            } else {
                pid.0
            };
            let wait_target = ptrace_wait_target_for_wait4(host_target);
            let mut host_options: i32 = 0;
            if options.contains(LinuxWaitOptions::WNOHANG) {
                host_options |= libc::WNOHANG;
            }
            if options.contains(LinuxWaitOptions::WUNTRACED) {
                host_options |= libc::WUNTRACED;
            }
            if options.contains(LinuxWaitOptions::WCONTINUED) {
                host_options |= libc::WCONTINUED;
            }
            let virtual_stop_requested = transport == PtraceTransport::VirtualNative
                && if host_target > 0 {
                    crate::guest_cpu::child_virtual_ptrace_stop_requested(host_target as u32)
                } else {
                    crate::guest_cpu::direct_child_ptrace_stop_pending(std::process::id())
                };
            if virtual_stop_requested {
                // Linux reports ptrace stops without requiring guest WUNTRACED;
                // Darwin needs it only to expose our invisible SIGSTOP carrier.
                host_options |= libc::WUNTRACED;
            }
            let mut host_status: i32 = 0;
            let mut host_rusage: libc::rusage = unsafe { std::mem::zeroed() };
            // A ptraced child can become waitable for a signal-delivery stop
            // even without WUNTRACED. EVFILT_PROC/NOTE_EXIT would sleep past
            // that stop, so let Darwin's wait4 observe a published pending stop.
            let has_pending_ptrace_stop = host_target > 0
                && crate::guest_cpu::child_has_ptrace_stop_pending(host_target as u32);
            let can_park_on_proc_exit = (host_target > 0 || host_target == -1)
                && host_options & libc::WNOHANG == 0
                && !options.intersects(LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED)
                && !has_pending_ptrace_stop;
            let wait_proc_exit_pid = || -> Option<i32> {
                if transport == PtraceTransport::VirtualNative {
                    return ptrace_wait_park_pid(wait_target);
                }
                if host_target > 0 {
                    return Some(host_target);
                }
                if host_target == -1 {
                    // -1 stays -1 while any direct child exists: the io_wait
                    // any-child kqueue path watches EVERY direct child, so a
                    // single-pid substitution would sleep through a sibling's
                    // exit. None (no children at all) becomes ECHILD below.
                    return crate::guest_cpu::wait_any_park_pid(std::process::id());
                }
                None
            };
            let mut host_status_is_guest_status = false;
            let result = if transport == PtraceTransport::VirtualNative {
                // The process-state lock is the native backend's exclusive wait
                // lease. Keep it across the nonblocking host poll and stop-token
                // publication so control cannot race an in-flight consuming wait.
                let mut proc = this.proc.lock();
                let leases = proc.matching_virtual_ptrace_leases(wait_target);
                let mut leased_result = None;
                for (leased_pid, stop) in &leases {
                    let result = unsafe {
                        libc::wait4(
                            *leased_pid as i32,
                            &mut host_status,
                            libc::WUNTRACED | libc::WNOHANG,
                            &mut host_rusage,
                        )
                    }
                    .host_syscall_errno();
                    match result {
                        Ok(value)
                            if value > 0
                                && libc::WIFSTOPPED(host_status)
                                && libc::WSTOPSIG(host_status) == libc::SIGSTOP =>
                        {
                            host_status = virtual_ptrace_stop_status(stop.linux_signum());
                            host_status_is_guest_status = true;
                            leased_result = Some(Ok(value));
                            break;
                        }
                        Ok(value)
                            if value > 0
                                && (libc::WIFEXITED(host_status)
                                    || libc::WIFSIGNALED(host_status)) =>
                        {
                            proc.virtual_ptrace_stops.remove(leased_pid);
                            leased_result = Some(Ok(value));
                            break;
                        }
                        Err(errno) if errno != crate::linux_abi::LINUX_ECHILD => {
                            leased_result = Some(Err(errno));
                            break;
                        }
                        Ok(_) | Err(_) => {}
                    }
                }
                if leased_result.is_none()
                    && matches!(wait_target, PtraceWaitTarget::Exact(_))
                    && let Some((leased_pid, _)) = leases.first()
                {
                    let leased_pid = *leased_pid;
                    drop(proc);
                    if options.contains(LinuxWaitOptions::WNOHANG) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let tid = Self::ctx_tid(cx);
                    let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                    let sig_mask = carrick_abi::WaitSigMask::Additive(non_interrupting);
                    return Ok(if options.intersects(
                        LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED,
                    ) {
                        DispatchOutcome::WaitOnProcState {
                            pid: leased_pid as i32,
                            sig_mask,
                        }
                    } else {
                        DispatchOutcome::WaitOnProcExit {
                            pid: leased_pid as i32,
                            sig_mask,
                        }
                    });
                }
                let result = match leased_result {
                    Some(result) => result,
                    None => unsafe {
                        libc::wait4(
                            host_target,
                            &mut host_status,
                            host_options | libc::WNOHANG,
                            &mut host_rusage,
                        )
                    }
                    .host_syscall_errno(),
                };
                if let Ok(value) = result
                    && value > 0
                    && libc::WIFSTOPPED(host_status)
                    && libc::WSTOPSIG(host_status) == libc::SIGSTOP
                    && let Some(stop) =
                        crate::guest_cpu::report_child_virtual_ptrace_stop(value as u32)
                {
                    host_status = virtual_ptrace_stop_status(stop.linux_signum());
                    proc.record_virtual_ptrace_stop(value as u32, stop);
                    host_status_is_guest_status = true;
                }
                drop(proc);
                result
            } else if can_park_on_proc_exit {
                let r = loop {
                    let r = unsafe {
                        libc::wait4(
                            host_target,
                            &mut host_status,
                            host_options | libc::WNOHANG,
                            &mut host_rusage,
                        )
                    };
                    // KVM lane: a tracee stop on a carrick-internal signal is
                    // absorbed (PTRACE_CONT re-inject) and the WNOHANG probe is
                    // re-issued — never surfaced to the guest.
                    if let Ok(value) = r.host_syscall_errno()
                        && value > 0
                        && absorb_internal_tracee_stop(value, host_status)
                    {
                        continue;
                    }
                    break r;
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
                        let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                        let Some(wait_pid) = wait_proc_exit_pid() else {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                        };
                        return Ok(DispatchOutcome::WaitOnProcExit {
                            pid: wait_pid,
                            sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
                        });
                    }
                    Ok(value) => Ok(value),
                    Err(errno) => Err(errno),
                }
            } else {
                loop {
                    let r =
                        unsafe { libc::wait4(host_target, &mut host_status, host_options, &mut host_rusage) };
                    match r.host_syscall_errno() {
                        Ok(value) => {
                            // KVM lane: absorb (PTRACE_CONT re-inject) a tracee
                            // stop on a carrick-internal signal and re-wait.
                            if value > 0 && absorb_internal_tracee_stop(value, host_status) {
                                continue;
                            }
                            break Ok(value);
                        }
                        Err(errno) => {
                            if errno == LINUX_EINTR && !crate::host_signal::has_process_pending() {
                                continue;
                            }
                            break Err(errno);
                        }
                    }
                }
            };
            // Adopted children (subreaper orphans): the host kernel answers
            // ECHILD because this process never was the host parent. Classify
            // ready-vs-pending in ONE table scan (`adopted_child_wait`): the
            // orphan's exit publication (`record_child_exit_status`) flips
            // `exit_ready` false→true concurrently with this wait, and two
            // separate scans (reap-ready first, then pending) let the flip land
            // BETWEEN them — both miss and a live adopted child was reported
            // ECHILD (childsubreaper `wait_reaped_orphan=false` under native).
            let adopted = match result {
                Err(errno) if errno == crate::linux_abi::LINUX_ECHILD => {
                    crate::guest_cpu::adopted_child_wait(std::process::id(), host_target)
                }
                _ => None,
            };
            let result = match result {
                Ok(value) => value,
                Err(errno) => {
                    if let Some(crate::guest_cpu::AdoptedChildWait::Reaped {
                        pid,
                        status,
                        guest_ns,
                    }) = adopted
                    {
                        // Linux makes the child-exit signal observable by the
                        // time waitpid returns. A DIRECT child's terminal reap
                        // publishes its watch entry synchronously below; an
                        // adopted child's SIGCHLD instead rides the xsig ring
                        // (enqueued by the orphan BEFORE it published this
                        // reapable record) — drain it now so the signal is
                        // pending before this wait4 completes, not whenever the
                        // async nudge lands.
                        this.drain_xsignals_process_directed(cx.kernel);
                        // Adopted reap: this process was never the host parent,
                        // so there is no host rusage — the published channel is
                        // the only source under every provider.
                        let (child_user_us, child_system_us) =
                            crate::guest_cpu::reaped_child_cpu_parts(guest_ns, None);
                        crate::guest_cpu::add_reaped_child(child_user_us, child_system_us);
                        if rusage_addr.0 != 0 {
                            let child_rusage = rusage_from_us(child_user_us, child_system_us);
                            if memory
                                .write_bytes(rusage_addr.0, child_rusage.abi_bytes())
                                .is_err()
                            {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        if wstatus_addr.0 != 0 {
                            memory.write_bytes(wstatus_addr.0, &status.to_ne_bytes())?;
                        }
                        let value = if crate::namespace::pid::enabled() {
                            crate::namespace::pid::host_to_ns_or_self(pid)
                        } else {
                            pid
                        };
                        if crate::namespace::pid::enabled() {
                            crate::namespace::pid::unregister_reaped(pid);
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: i64::from(value),
                        });
                    }
                    // Not-yet-exited adopted child: park on its exit. Uses the
                    // SAME single scan's answer — a fresh `pending_adopted_child`
                    // re-scan here would reopen the reap/pending window this
                    // classification just closed.
                    if host_options & libc::WNOHANG == 0
                        && !options
                            .intersects(LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED)
                        && let Some(crate::guest_cpu::AdoptedChildWait::Pending(pid)) = adopted
                    {
                        let tid = Self::ctx_tid(cx);
                        let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                        return Ok(DispatchOutcome::WaitOnProcExit {
                            pid: pid as i32,
                            sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
                        });
                    }
                    // A process-group wait (pid < -1) for a group the kernel
                    // can't find is ESRCH on Linux; macOS surfaces EINVAL for
                    // the bad pgid (LTP waitpid04 INT_MIN case). Remap only that
                    // case — a valid pgid with no children stays ECHILD, and
                    // every other error passes through unchanged.
                    if host_target < -1 && errno == LINUX_EINVAL {
                        return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
            };
            if result == 0 && host_options & libc::WNOHANG != 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if result == 0 {
                let tid = Self::ctx_tid(cx);
                let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                let Some(wait_pid) = wait_proc_exit_pid() else {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD));
                };
                let sig_mask = carrick_abi::WaitSigMask::Additive(non_interrupting);
                return Ok(if transport == PtraceTransport::VirtualNative
                    && (virtual_stop_requested
                        || options.intersects(
                            LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED,
                        ))
                {
                    DispatchOutcome::WaitOnProcState {
                        pid: wait_pid,
                        sig_mask,
                    }
                } else {
                    DispatchOutcome::WaitOnProcExit {
                        pid: wait_pid,
                        sig_mask,
                    }
                });
            }
            if !host_status_is_guest_status
                && host_wait_status_is_stopped_by(host_status, LINUX_SIGKILL)
            {
                crate::guest_cpu::clear_child_ptrace_stop_pending(result as u32);
                let host_sigkill = crate::host_signal::linux_to_host_signum(LINUX_SIGKILL);
                let cont = unsafe {
                    carrick_portable::ptrace(carrick_portable::PT_CONTINUE, result, 1, host_sigkill)
                };
                cont.host_syscall_errno()?;
                loop {
                    let r = unsafe {
                        libc::wait4(result, &mut host_status, host_options, &mut host_rusage)
                    };
                    match r.host_syscall_errno() {
                        Ok(value) => {
                            if value != 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        Err(errno) => {
                            if errno == LINUX_EINTR && !crate::host_signal::has_process_pending() {
                                continue;
                            }
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    }
                }
            }
            if !host_status_is_guest_status
                && libc::WIFSTOPPED(host_status)
                && let Some(linux_signum) =
                    crate::guest_cpu::take_child_ptrace_stop_signal(result as u32)
            {
                host_status = (linux_signum << 8) | 0x7f;
                host_status_is_guest_status = true;
            }
            let terminal_reap = libc::WIFEXITED(host_status) || libc::WIFSIGNALED(host_status);
            if terminal_reap {
                // Untraced lifecycle gauge (CARRICK_EXEC_STAMPS): closes the
                // child's `PreHostExit` window from the parent side.
                crate::exec_stamps::stamp_wait_reaped(
                    result as u32,
                    host_status,
                    &host_rusage,
                );
                // The child host process is now dead; tear down its leaked host VM
                // node (bhyve's named /dev/vmm/carrick-<pid>-* persists past the
                // child's _exit). Sole, non-hanging teardown — no live holder. No-op
                // on KVM/HVF. `result` is the reaped HOST pid.
                carrick_hal::vm_backend::reap_child_vm(result as u32);
            }
            let ns_result = crate::namespace::pid::host_to_ns(result as u32);
            if crate::namespace::pid::enabled() && host_target <= 0 && ns_result.is_none() {
                if terminal_reap {
                    crate::namespace::pid::unregister_reaped(result as u32);
                }
                if host_options & libc::WNOHANG != 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let tid = Self::ctx_tid(cx);
                let non_interrupting = this.non_interrupting_signal_mask(cx.kernel, tid);
                return Ok(DispatchOutcome::WaitOnProcExit {
                    pid: host_target,
                    sig_mask: carrick_abi::WaitSigMask::Additive(non_interrupting),
                });
            }
            let tv_us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
            let drain_child_guest_cpu = should_drain_child_guest_cpu(transport, terminal_reap);
            let child_guest_ns = if drain_child_guest_cpu {
                crate::guest_cpu::reap_child_guest_ns(result as u32)
            } else {
                0
            };
            // The published-guest-CPU channel and the host wait4 rusage combine
            // per-provider (additive under VMMs, host-authoritative under the
            // native backend) — single-sourced in `reaped_child_cpu_parts`.
            let (child_user_us, child_system_us) = crate::guest_cpu::reaped_child_cpu_parts(
                child_guest_ns,
                Some((tv_us(host_rusage.ru_utime), tv_us(host_rusage.ru_stime))),
            );
            if drain_child_guest_cpu {
                crate::guest_cpu::add_reaped_child(child_user_us, child_system_us);
            }
            if rusage_addr.0 != 0 {
                let child_rusage = rusage_from_us(child_user_us, child_system_us);
                if memory
                    .write_bytes(rusage_addr.0, child_rusage.abi_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            let host_status = if host_status_is_guest_status {
                host_status
            } else {
                translate_wait_status(host_status)
            };
            if wstatus_addr.0 != 0 {
                let bytes = host_status.to_ne_bytes();
                memory.write_bytes(wstatus_addr.0, &bytes)?;
            }
            // PID namespace (§5.3): the guest must see the reaped child's
            // ns-local pid, not its host pid — critical for `wait4(-1)` where
            // the arg was never translated. Identity when namespaces are off.
            let ns_result = ns_result.unwrap_or(result as u32);
            if terminal_reap {
                crate::namespace::pid::unregister_reaped(result as u32);
            }
            Ok(DispatchOutcome::Returned {
                value: i64::from(ns_result),
            })
            }
        }

        fn execve(this, cx, pathname_addr: GuestPtr, argv_addr: GuestPtr, envp_addr: GuestPtr) {
            let memory = &*cx.memory;

            let path = read_guest_c_string(memory, pathname_addr.0)?;
            // argv/env are opaque BYTE strings (Linux ABI), not UTF-8 — read
            // them byte-preserving so a non-UTF-8 arg/env (e.g. CPython
            // regrtest's PYTHONREGRTEST_UNICODE_GUARD) doesn't EINVAL the execve.
            let argv = read_guest_string_array_bytes(memory, argv_addr.0)?;
            let env = read_guest_string_array_bytes(memory, envp_addr.0)?;
            validate_exec_vector_size(&argv, &env)?;

            Ok(DispatchOutcome::Execve { path, argv, env })
        }

        /// execveat(dirfd, path, argv, envp, flags): execve relative to a dir fd,
        /// or — with AT_EMPTY_PATH and an empty path — execute the fd itself
        /// (this is how glibc/musl `fexecve` and CPython `os.execve(fd, …)` work;
        /// the guest issues execveat, not execve, so without this it was ENOSYS).
        fn execveat(this, cx, dirfd: u64, pathname_addr: GuestPtr, argv_addr: GuestPtr, envp_addr: GuestPtr, flags: u64) {
            let memory = &*cx.memory;
            // execveat(2) accepts only AT_EMPTY_PATH and AT_SYMLINK_NOFOLLOW; any
            // other flag bit is EINVAL — validated BEFORE touching the fd/path so a
            // malformed call never executes the target (execveat02 passes flags=-1).
            const EXECVEAT_VALID_FLAGS: u64 = LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW;
            if flags & !EXECVEAT_VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path_str = read_guest_c_string(memory, pathname_addr.0)?;
            let path = if flags & LINUX_AT_EMPTY_PATH != 0 && path_str.is_empty() {
                // fexecve: dirfd IS the executable's open fd. Recover the guest
                // path it was opened at (HostFile/File/etc.) and execve that.
                let fd = dirfd as i32;
                let p = this.open_file(fd).and_then(|f| {
                    let d = f.description.read()?;
                    d.open_path().map(|s| s.to_string())
                });
                match p {
                    Some(p) => p,
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            } else {
                let resolved = this.resolve_at_path(dirfd, &path_str)?;
                // AT_SYMLINK_NOFOLLOW: if the FINAL component is a symlink, the
                // kernel refuses to follow it and fails with ELOOP (execveat02).
                if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0
                    && this
                        .layered_lstat(&resolved)
                        .map(|m| m.kind == RootFsEntryKind::Symlink)
                        .unwrap_or(false)
                {
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP));
                }
                resolved
            };
            let argv = read_guest_string_array_bytes(memory, argv_addr.0)?;
            let env = read_guest_string_array_bytes(memory, envp_addr.0)?;
            validate_exec_vector_size(&argv, &env)?;
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
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            // Creating a child in a NEW namespace needs CAP_SYS_ADMIN for
            // every namespace type except CLONE_NEWUSER (clone(2),
            // capabilities(7)) — and carrick models neither the mount, ipc,
            // net, cgroup nor pid namespaces for a clone child, so an
            // unprivileged guest must get the same EPERM Linux gives rather
            // than a child silently sharing the caller's namespaces. LTP
            // clone11 pins this: "clone(CLONE_NEWIPC) should fail with EPERM".
            // CLONE_NEWUSER stays EPERM here for a different, pre-existing
            // reason (a clone-created user namespace is unmodelled), and
            // CLONE_NEWPID likewise.
            let ns_flags = LinuxCloneFlags::NEWUSER
                | LinuxCloneFlags::NEWPID
                | LinuxCloneFlags::NEWNS
                | LinuxCloneFlags::NEWUTS
                | LinuxCloneFlags::NEWIPC
                | LinuxCloneFlags::NEWNET
                | LinuxCloneFlags::NEWCGROUP;
            if flags & ns_flags.bits() != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if is_thread_clone(flags) {
                return Ok(clone_thread_outcome(flags, stack, parent_tid.0, tls, child_tid.0));
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
            // Legacy clone ACCEPTS an out-of-range CSIGNAL (oracle:
            // `clone(CLONE_VM|0xff)` succeeds on Linux; only clone3 EINVALs
            // its `exit_signal` field). No real signal bears that number, so
            // the parent simply gets no exit notification -- lower it to
            // "no exit signal" rather than letting an unrepresentable number
            // into the kernel: exit-signal 255 previously reached the fork
            // path, spawned a child that returned nonzero in BOTH processes,
            // and ended in a carrier abort (`lifecycleflagmatrix` 1.3, plus
            // every later line the runaway child chain corrupted).
            let exit_signal =
                if crate::dispatch::signal::is_valid_signum(u64::from(exit_signal)) {
                    exit_signal
                } else {
                    0
                };
            // vfork-for-exec (Go os/exec / glibc posix_spawn): CLONE_VM|CLONE_VFORK
            // without the full THREAD_MASK (excluded above). The child shares the
            // parent's address space and the parent is suspended until the child
            // execve/_exit — serviced by the runtime's vfork fork path. A plain
            // CLONE_VM without CLONE_VFORK stays an ordinary CoW fork (sharing RAM
            // without the suspend would race the parent).
            let vfork = (flags & LinuxCloneFlags::VFORK.bits() != 0
                && flags & LinuxCloneFlags::VM.bits() != 0)
                .then_some(stack);
            // Legacy clone's `stack` IS the child SP (clone3 passes base+len).
            Ok(DispatchOutcome::Fork {
                flags,
                child_stack: stack,
                pidfd_out,
                clone_parent: flags & LinuxCloneFlags::PARENT.bits() != 0,
                parent_tid_addr: if flags & LinuxCloneFlags::PARENT_SETTID.bits() != 0 {
                    Some(parent_tid.0)
                } else {
                    None
                },
                child_tid_addr: if flags & LinuxCloneFlags::CHILD_SETTID.bits() != 0 {
                    Some(child_tid.0)
                } else {
                    None
                },
                exit_signal,
                vfork,
            })
        }

        fn pidfd_open(this, cx, pid: Pid, flags: u64) {
            const PIDFD_NONBLOCK: u64 = 0o4000;
            if pid.0 <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & !PIDFD_NONBLOCK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let status_flags = if flags & PIDFD_NONBLOCK != 0 {
                LINUX_O_NONBLOCK
            } else {
                0
            };
            if let Some(process) = this.hvpatch_process() {
                // The guest names the target by ns-pid; the graph indexes by
                // task id. A non-member is ESRCH (`pidfd_open(getpid())`
                // failed exactly here once `getpid` reported ns pids).
                let Some(host) = u32::try_from(pid.0)
                    .ok()
                    .and_then(|pid| crate::namespace::pid::ns_to_kernel_for(cx.kernel, pid))
                    .and_then(|host| i32::try_from(host).ok())
                else {
                    return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                };
                return Ok(this.open_hvpatch_pidfd(&process, host, status_flags));
            }
            // PID namespace (§5.3): the guest names the target by its ns-pid;
            // the pidfd must watch the underlying host pid. A foreign ns-pid is
            // ESRCH. Identity when namespaces are off.
            let host_pid = if crate::namespace::pid::enabled() {
                match crate::namespace::pid::ns_to_host_or_self(pid.0 as u32) {
                    Some(h) => h as i32,
                    None => return Ok(DispatchOutcome::errno(LINUX_ESRCH)),
                }
            } else {
                pid.0
            };
            Ok(this.open_pidfd(host_pid, status_flags))
        }

        fn pidfd_getfd(this, cx, _pidfd: Fd, _targetfd: u64, _flags: u64) {
            // Carrick has no cross-process guest-fd duplication on macOS; a real
            // implementation needs a host helper to reach into another guest
            // process's fd table. Report the honest "unimplemented" (ENOSYS)
            // rather than a fabricated EPERM that would falsely claim the syscall
            // is implemented-but-denied. pidfd_open/pidfd_send_signal remain
            // genuinely implemented and are untouched.
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
        }

        fn pidfd_send_signal(this, cx, fd: Fd, signum: u64, info: GuestPtr, flags: u64) {
            let Some(target) = this.pidfd_target(Some(cx.kernel), fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            if flags != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let PidfdTarget::Hvpatch(guest_pid) = target {
                let Some(process) = this.hvpatch_process() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                if !process.process_is_live(guest_pid) {
                    return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                }
                if signum == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if !crate::dispatch::signal::is_valid_signum(signum) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let siginfo = if info.0 != 0 {
                    let bytes = match cx.memory.read_bytes(
                        info.0,
                        core::mem::size_of::<crate::linux_abi::LinuxSiginfo>(),
                    ) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    let user_info = match crate::linux_abi::LinuxSiginfo::read_from_bytes(&bytes) {
                        Ok(info) => info,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    if user_info.si_signo != signum as i32 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    Some(user_info)
                } else {
                    Some(crate::linux_abi::LinuxSiginfo::kill(
                        signum as i32,
                        crate::linux_abi::LINUX_SI_USER,
                        crate::dispatch::signal::ns_visible_sender_pid(cx.kernel),
                        this.cred_snapshot().ruid.raw(),
                    ))
                };
                return Ok(this.hvpatch_exact_process_signal(
                    cx.kernel,
                    guest_pid,
                    signum,
                    siginfo,
                ));
            }
            let PidfdTarget::Host(host_pid) = target else {
                unreachable!("HvPatch pidfd handled above")
            };
            #[cfg(not(test))]
            let _ = host_pid;
            #[cfg(not(test))]
            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
            #[cfg(test)]
            {
            if signum == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !crate::dispatch::signal::is_valid_signum(signum) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let caller_euid = this.cred_snapshot().euid;
            let target_euid = if host_pid as u32 == std::process::id() {
                caller_euid
            } else {
                crate::cred_ipc::read_target(host_pid).unwrap_or(carrick_abi::NsUid::ROOT)
            };
            if info.0 != 0 {
                let bytes = match cx
                    .memory
                    .read_bytes(
                        info.0,
                        core::mem::size_of::<crate::linux_abi::LinuxSiginfo>(),
                    )
                {
                    Ok(bytes) => bytes,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let mut user_info = match crate::linux_abi::LinuxSiginfo::read_from_bytes(&bytes) {
                    Ok(info) => info,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let signum_i32 = signum as i32;
                if user_info.si_signo != signum_i32 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if !caller_euid.is_root() && caller_euid != target_euid {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
                user_info.si_signo = signum_i32;
                let value = user_info
                    ._pad
                    .get(0..8)
                    .and_then(|b| b.try_into().ok())
                    .map(i64::from_le_bytes)
                    .unwrap_or(0);
                if crate::host_signal::xsig_enqueue(
                    host_pid,
                    signum_i32,
                    user_info.si_code,
                    this.identity_pid() as i32,
                    this.cred_snapshot().euid.raw(),
                    value,
                    // A pidfd names exactly one PROCESS (never a specific
                    // thread), so this send is always process-directed.
                    0,
                ) {
                    crate::host_signal::xsig_nudge(host_pid);
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            if !caller_euid.is_root() && caller_euid != target_euid {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // A pidfd names exactly one process by the HOST pid recorded at
            // creation (pidfd_open rejects pid <= 0; CLONE_PIDFD registers the
            // fork child's host pid) — never a group or tid.
            Ok(crate::dispatch::signal::bootstrap_signal_send_as(
                crate::dispatch::signal::SignalTarget::HostProcess(HostPid(host_pid as u32)),
                signum,
                Some(caller_euid),
            ))
            }
        }

        fn getrandom(this, cx, address: GuestPtr, length: u64, flags: u64) {
            // Only GRND_NONBLOCK(1) | GRND_RANDOM(2) | GRND_INSECURE(4) are
            // valid; any other bit → EINVAL (LTP getrandom05). carrick draws
            // from the host CSPRNG regardless of the source/blocking flags.
            const GRND_SUPPORTED: u64 = 0x0001 | 0x0002 | 0x0004;
            if flags & !GRND_SUPPORTED != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
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
            memory.write_bytes(address.0, &bytes)?;
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
            // Process exit: fold the EL1 shim's serviced-syscall counter into
            // the task's SYSTEM ledger so the zombie snapshot (and therefore
            // the reaper's RUSAGE_CHILDREN) carries the kernel time Linux
            // would have charged for those syscalls. Live getrusage/times
            // readers add the counter directly, so it is zeroed here to keep
            // the two accountings disjoint. A signal-killed process skips
            // this fold (its counter dies unread) — a bounded undercount.
            let counter_addr = crate::memory::LINUX_IDENTITY_PAGE_BASE
                + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS;
            if let Ok(bytes) = cx.memory.read_bytes(counter_addr, 8) {
                let count = u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]));
                if count != 0 {
                    let _ = cx.memory.write_bytes(counter_addr, &0_u64.to_le_bytes());
                    super::resources::with_active_context(|context| {
                        context.thread().charge_system_ns(
                            count
                                .saturating_mul(crate::memory::EL1_SHIM_SYSCALL_NOMINAL_NS),
                        );
                    });
                }
            }
            Ok(DispatchOutcome::Exit { code })
        }

        fn sys_clone3(this, cx, args_ptr: GuestPtr, size: u64) {
            Ok(this.clone3(args_ptr, size, &*cx.memory))
        }

        fn sys_rseq(this, cx) {
            Ok(this.rseq())
        }

        fn process_vm_readv(
            this, cx,
            pid: Pid,
            local_iov: GuestPtr, liovcnt: u64,
            remote_iov: GuestPtr, riovcnt: u64,
            flags: u64,
        ) {
            this.process_vm_rw(cx, pid, local_iov, liovcnt, remote_iov, riovcnt, flags, true)
        }

        fn process_vm_writev(
            this, cx,
            pid: Pid,
            local_iov: GuestPtr, liovcnt: u64,
            remote_iov: GuestPtr, riovcnt: u64,
            flags: u64,
        ) {
            this.process_vm_rw(cx, pid, local_iov, liovcnt, remote_iov, riovcnt, flags, false)
        }
    }
}

/// Copy the flattened byte stream from `src` iovecs into `dst` iovecs WITHIN a
/// single guest address space — the `process_vm_readv`/`process_vm_writev` case
/// where the caller IS the target (`pid == getpid()`). Walks both iovec lists
/// with independent cursors, transferring `min(remaining_src, remaining_dst)`
/// per step and stopping when either side is exhausted (Linux transfers the
/// shorter of the two flattened lengths). The gated `read_bytes`/`write_bytes`
/// enforce PROT_NONE / out-of-bounds, so a bad `iov_base` faults here. Returns
/// the byte count copied, or `EFAULT` when the FIRST access faults (once any
/// byte has moved Linux returns the partial count, not an error).
fn process_vm_copy_self<M: CurrentMmMemory>(
    memory: &mut M,
    src: &[LinuxIovec],
    dst: &[LinuxIovec],
) -> Result<i64, LinuxErrno> {
    // Bound a single read/write allocation; a large transfer streams in chunks.
    const CHUNK: u64 = 1 << 20;
    let mut copied: u64 = 0;
    let (mut si, mut so, mut di, mut dofs) = (0usize, 0u64, 0usize, 0u64);
    let fault = |copied: u64| -> Result<i64, LinuxErrno> {
        if copied == 0 {
            Err(LINUX_EFAULT)
        } else {
            Ok(copied as i64)
        }
    };
    loop {
        while si < src.len() && so >= src[si].iov_len {
            si += 1;
            so = 0;
        }
        while di < dst.len() && dofs >= dst[di].iov_len {
            di += 1;
            dofs = 0;
        }
        if si >= src.len() || di >= dst.len() {
            break;
        }
        let want = (src[si].iov_len - so)
            .min(dst[di].iov_len - dofs)
            .min(CHUNK);
        let want_usize = want as usize;
        if want_usize == 0 {
            break;
        }
        let src_addr = src[si].iov_base.wrapping_add(so);
        let dst_addr = dst[di].iov_base.wrapping_add(dofs);
        let bytes = match memory.read_bytes(src_addr, want_usize) {
            Ok(bytes) => bytes,
            Err(_) => return fault(copied),
        };
        if memory.write_bytes(dst_addr, &bytes).is_err() {
            return fault(copied);
        }
        copied += want;
        so += want;
        dofs += want;
    }
    Ok(copied as i64)
}

impl SyscallDispatcher {
    /// Shared body of `process_vm_readv` (270, `is_read=true`) and
    /// `process_vm_writev` (271, `is_read=false`): transfer between the caller's
    /// `local_iov` and the target process's `remote_iov`. readv copies
    /// remote→local, writev copies local→remote.
    ///
    /// Validation mirrors the kernel's `process_vm_rw`: `flags != 0` → EINVAL
    /// (only 0 is defined); the local array is imported first and an empty local
    /// transfer returns zero before the remote array or target is consulted, as
    /// measured by the clean-room oracle. Otherwise each imported array rejects
    /// `iov_len` overflow with EINVAL and a bad array pointer with EFAULT before
    /// any copy. The target `pid` is then resolved against carrick's guest
    /// process model (no such task → ESRCH); an unprivileged caller that does
    /// not own the target → EPERM (ptrace_may_access).
    ///
    /// Transfer memory between local and remote address spaces (`process_vm_readv` / `process_vm_writev`).
    ///
    /// When the target is the exact caller task (`target_task.key() == caller.key()`),
    /// the transfer runs directly within this guest's address space via `process_vm_copy_self`.
    ///
    /// Cross-process read transfers (`process_vm_readv`) route through Task 7 authority:
    /// the caller's live `ThreadExecutionLease` authenticates `Kernel::foreign_mm`,
    /// obtaining an immutable `ForeignMm` reference, which reads foreign memory through
    /// the carrier's `ForeignMmEndpoint` and `MmAccessAuthority` streaming with
    /// chunk bounds aligned to 4 KiB page boundaries in both remote and local spaces.
    ///
    /// Cross-process write transfers (`process_vm_writev`) acquire the target MM's real
    /// mutation authority via `MmAccessAuthority::with_foreign_mutation`, break foreign COW
    /// for each 16 KiB compound, prepare each subrange, and commit infallibly.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_vm_rw<M: CurrentMmMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        pid: Pid,
        local_iov: GuestPtr,
        liovcnt: u64,
        remote_iov: GuestPtr,
        riovcnt: u64,
        flags: u64,
        is_read: bool,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Only flags == 0 is defined; anything else is EINVAL (process_vm01
        // test_flags exercises -INT_MAX/-1/1/INT_MAX). Invalid nonzero flags
        // win over a zero-byte transfer.
        if flags != 0 {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        let liovcnt = usize::try_from(liovcnt).map_err(|_| LINUX_EINVAL)?;
        let local = read_iovecs(&*cx.memory, local_iov.0, liovcnt)?;
        let local_total: u64 = local.iter().map(|iov| iov.iov_len).sum();
        if local_total == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let riovcnt = usize::try_from(riovcnt).map_err(|_| LINUX_EINVAL)?;
        let remote = read_iovecs(&*cx.memory, remote_iov.0, riovcnt)?;
        let remote_total: u64 = remote.iter().map(|iov| iov.iov_len).sum();
        if remote_total == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        // process_vm_readv/writev do a plain task lookup: pid 0 names NO task
        // (unlike sched_*, where 0 means "the calling process"). Linux returns
        // ESRCH and transfers nothing.
        if pid.raw() == 0 {
            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
        }

        let Ok(target_task_id) = guest_pid_to_task_id(cx.kernel, pid) else {
            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
        };
        let Some(target_task) = cx.kernel.kernel().registry().task(target_task_id) else {
            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
        };
        if !cx.kernel.kernel().task_key_is_live(target_task.key()) {
            return Ok(DispatchOutcome::errno(LINUX_ESRCH));
        }

        // ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS): a non-root
        // caller that does not own the target is denied (process_vm01
        // test_invalid_perm drops to `nobody` then reads root's pid).
        // carrick models CAP_SYS_PTRACE as euid 0. The target's euid
        // comes from its own kernel-graph credentials, the same
        // authority `cred_snapshot()` answers the caller from.
        let caller_euid = self.cred_snapshot().euid;
        let target_euid = target_task.process_credentials().euid();
        if !caller_euid.is_root() && caller_euid != target_euid {
            return Ok(DispatchOutcome::errno(LINUX_EPERM));
        }

        if target_task.key() == cx.kernel.task().key() {
            let (src, dst) = if is_read {
                (&remote, &local)
            } else {
                (&local, &remote)
            };
            return match process_vm_copy_self(&mut *cx.memory, src, dst) {
                Ok(value) => Ok(DispatchOutcome::Returned { value }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }

        let relation = cx.with_execution_lease(|lease| {
            cx.kernel
                .kernel()
                .foreign_mm(cx.kernel, lease, target_task.key())
        });
        let relation = match relation {
            Some(Ok(r)) => r,
            Some(Err(error)) => {
                return Ok(DispatchOutcome::errno(process_vm_foreign_mm_errno(&error)));
            }
            None => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
        };

        match relation {
            crate::kernel::MmRelation::Current(_) => {
                let (src, dst) = if is_read {
                    (&remote, &local)
                } else {
                    (&local, &remote)
                };
                match process_vm_copy_self(&mut *cx.memory, src, dst) {
                    Ok(value) => Ok(DispatchOutcome::Returned { value }),
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                }
            }
            crate::kernel::MmRelation::Foreign(foreign) => {
                let Some(process) = self.hvpatch_process() else {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                };
                let Some(authority) = process.mm_access_authority() else {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                };

                const CHUNK_SIZE: usize = 64 * 1024;
                const PAGE_SIZE: u64 = 4096;
                let mut copied: u64 = 0;
                let mut ri = 0usize;
                let mut ro = 0u64;
                let mut li = 0usize;
                let mut lo = 0u64;

                if is_read {
                    let mut chunk_buf = vec![0u8; CHUNK_SIZE];

                    while ri < remote.len() && li < local.len() {
                        while ri < remote.len() && ro >= remote[ri].iov_len {
                            ri += 1;
                            ro = 0;
                        }
                        while li < local.len() && lo >= local[li].iov_len {
                            li += 1;
                            lo = 0;
                        }
                        if ri >= remote.len() || li >= local.len() {
                            break;
                        }
                        let rem_remote = remote[ri].iov_len - ro;
                        let rem_local = local[li].iov_len - lo;

                        let remote_va_raw = match remote[ri].iov_base.checked_add(ro) {
                            Some(va) => va,
                            None => break,
                        };
                        let local_va_raw = match local[li].iov_base.checked_add(lo) {
                            Some(va) => va,
                            None => break,
                        };

                        let page_rem_remote = PAGE_SIZE - (remote_va_raw % PAGE_SIZE);
                        let page_rem_local = PAGE_SIZE - (local_va_raw % PAGE_SIZE);

                        let want = rem_remote
                            .min(rem_local)
                            .min(page_rem_remote)
                            .min(page_rem_local)
                            .min(CHUNK_SIZE as u64);
                        let want_len = want as usize;
                        if want_len == 0 {
                            break;
                        }

                        let remote_va = carrick_guest_mem::GuestVa(remote_va_raw);
                        let local_va = local_va_raw;

                        let range = match foreign.read_range(remote_va, want_len) {
                            Ok(Some(r)) => r,
                            _ => break,
                        };

                        let read_buf = &mut chunk_buf[..want_len];
                        match authority.read_foreign(&foreign, range, read_buf) {
                            Ok(receipt) => {
                                if receipt.bytes_read() != want_len {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }

                        if cx.memory.write_bytes(local_va, read_buf).is_err() {
                            break;
                        }

                        copied += want;
                        ro += want;
                        lo += want;
                    }

                    if copied == 0 {
                        Ok(DispatchOutcome::errno(LINUX_EFAULT))
                    } else {
                        Ok(DispatchOutcome::Returned {
                            value: copied as i64,
                        })
                    }
                } else {
                    const COMPOUND_SIZE: u64 = 16 * 1024;
                    let mut stage_buf = Vec::with_capacity(COMPOUND_SIZE as usize);
                    let mut staged_chunks: Vec<StagedWriteChunk<'_>> = Vec::new();

                    while ri < remote.len() && li < local.len() {
                        while ri < remote.len() && ro >= remote[ri].iov_len {
                            ri += 1;
                            ro = 0;
                        }
                        while li < local.len() && lo >= local[li].iov_len {
                            li += 1;
                            lo = 0;
                        }
                        if ri >= remote.len() || li >= local.len() {
                            break;
                        }

                        let remote_va_raw = match remote[ri].iov_base.checked_add(ro) {
                            Some(va) => va,
                            None => break,
                        };
                        let compound_base = remote_va_raw & !(COMPOUND_SIZE - 1);
                        let compound_end = match compound_base.checked_add(COMPOUND_SIZE) {
                            Some(end) => end,
                            None => break,
                        };

                        // Stage consecutive chunks within this 16 KiB compound before acquiring target mutation authority.
                        stage_buf.clear();
                        staged_chunks.clear();

                        let mut stage_ri = ri;
                        let mut stage_ro = ro;
                        let mut stage_li = li;
                        let mut stage_lo = lo;

                        while stage_ri < remote.len() && stage_li < local.len() {
                            while stage_ri < remote.len() && stage_ro >= remote[stage_ri].iov_len {
                                stage_ri += 1;
                                stage_ro = 0;
                            }
                            while stage_li < local.len() && stage_lo >= local[stage_li].iov_len {
                                stage_li += 1;
                                stage_lo = 0;
                            }
                            if stage_ri >= remote.len() || stage_li >= local.len() {
                                break;
                            }

                            let cur_remote_va_raw =
                                match remote[stage_ri].iov_base.checked_add(stage_ro) {
                                    Some(va) => va,
                                    None => break,
                                };
                            if cur_remote_va_raw < compound_base
                                || cur_remote_va_raw >= compound_end
                            {
                                break;
                            }
                            let cur_local_va_raw =
                                match local[stage_li].iov_base.checked_add(stage_lo) {
                                    Some(va) => va,
                                    None => break,
                                };

                            let rem_remote = remote[stage_ri].iov_len - stage_ro;
                            let rem_local = local[stage_li].iov_len - stage_lo;
                            let page_rem_remote = PAGE_SIZE - (cur_remote_va_raw % PAGE_SIZE);
                            let page_rem_local = PAGE_SIZE - (cur_local_va_raw % PAGE_SIZE);
                            let compound_rem = compound_end - cur_remote_va_raw;

                            let want = rem_remote
                                .min(rem_local)
                                .min(page_rem_remote)
                                .min(page_rem_local)
                                .min(compound_rem)
                                .min(CHUNK_SIZE as u64);
                            let want_len = want as usize;
                            if want_len == 0 {
                                break;
                            }

                            let buf_offset = stage_buf.len();
                            stage_buf.resize(buf_offset + want_len, 0);
                            if cx
                                .memory
                                .read_into(
                                    cur_local_va_raw,
                                    &mut stage_buf[buf_offset..buf_offset + want_len],
                                )
                                .is_err()
                            {
                                stage_buf.truncate(buf_offset);
                                break;
                            }

                            let remote_va = carrick_guest_mem::GuestVa(cur_remote_va_raw);
                            let write_range = match foreign.write_range(remote_va, want_len) {
                                Ok(Some(r)) => r,
                                _ => {
                                    stage_buf.truncate(buf_offset);
                                    break;
                                }
                            };

                            stage_ro += want;
                            stage_lo += want;
                            while stage_ri < remote.len() && stage_ro >= remote[stage_ri].iov_len {
                                stage_ri += 1;
                                stage_ro = 0;
                            }
                            while stage_li < local.len() && stage_lo >= local[stage_li].iov_len {
                                stage_li += 1;
                                stage_lo = 0;
                            }
                            staged_chunks.push(StagedWriteChunk {
                                range: write_range,
                                buf_offset,
                                len: want_len,
                                want,
                                post_ri: stage_ri,
                                post_ro: stage_ro,
                                post_li: stage_li,
                                post_lo: stage_lo,
                            });
                        }

                        if staged_chunks.is_empty() {
                            break;
                        }

                        // Acquire target MM's real mutation authority for the staged compound.
                        // No cx.memory access or allocation occurs while mutation_guard is live.
                        let mutation_tid = cx.tid();
                        let commit_res = self.with_current_mm_executor_released(cx, || {
                            authority.with_foreign_mutation(&foreign, mutation_tid, |mutation_guard| {
                                let mut witness: Option<crate::kernel::CowBroken<'_, '_, '_>> = None;
                                let mut committed_chunks = 0usize;

                                for chunk in &staged_chunks {
                                    let src_chunk =
                                        &stage_buf[chunk.buf_offset..chunk.buf_offset + chunk.len];

                                    let (need_new_witness, prep_result) = match witness.as_mut() {
                                        Some(w) => match authority
                                            .prepare_foreign_write_range(w, chunk.range, src_chunk)
                                        {
                                            Ok(prep) => (false, Some(prep)),
                                            Err(
                                                crate::kernel::MmAccessError::ForeignRangeAuthorityMismatch,
                                            ) => (true, None),
                                            Err(_) => (false, None),
                                        },
                                        None => (true, None),
                                    };

                                    let prepared = if need_new_witness {
                                        drop(witness.take());
                                        let new_witness = match authority.break_foreign_cow(
                                            mutation_guard,
                                            &foreign,
                                            chunk.range,
                                        ) {
                                            Ok(w) => w,
                                            Err(_) => break,
                                        };
                                        witness = Some(new_witness);
                                        let Some(current_witness) = witness.as_mut() else {
                                            break;
                                        };
                                        match authority.prepare_foreign_write_range(
                                            current_witness,
                                            chunk.range,
                                            src_chunk,
                                        ) {
                                            Ok(prep) => prep,
                                            Err(_) => break,
                                        }
                                    } else {
                                        match prep_result {
                                            Some(prep) => prep,
                                            None => break,
                                        }
                                    };

                                    let _receipt = prepared.commit();
                                    committed_chunks += 1;
                                }

                                Ok(committed_chunks)
                            })
                        })?;

                        let committed_chunks = match commit_res {
                            Ok(count) => count,
                            Err(error) => {
                                if copied == 0 {
                                    return Ok(DispatchOutcome::errno(
                                        process_vm_foreign_mm_errno(&error),
                                    ));
                                }
                                break;
                            }
                        };

                        if committed_chunks > 0 {
                            for chunk in &staged_chunks[..committed_chunks] {
                                copied += chunk.want;
                            }
                            let last = &staged_chunks[committed_chunks - 1];
                            ri = last.post_ri;
                            ro = last.post_ro;
                            li = last.post_li;
                            lo = last.post_lo;
                        }

                        if committed_chunks < staged_chunks.len() {
                            break;
                        }
                    }

                    if copied == 0 {
                        Ok(DispatchOutcome::errno(LINUX_EFAULT))
                    } else {
                        Ok(DispatchOutcome::Returned {
                            value: copied as i64,
                        })
                    }
                }
            }
        }
    }
}

struct StagedWriteChunk<'mm> {
    range: crate::kernel::MmWriteRange<'mm>,
    buf_offset: usize,
    len: usize,
    want: u64,
    post_ri: usize,
    post_ro: u64,
    post_li: usize,
    post_lo: u64,
}

fn process_vm_foreign_mm_errno(error: &crate::kernel::MmAccessError) -> LinuxErrno {
    match error {
        crate::kernel::MmAccessError::UnknownTask(_) => LINUX_ESRCH,
        _ => LINUX_EFAULT,
    }
}

fn ptrace_foreign_mm_errno(error: &crate::kernel::MmAccessError) -> LinuxErrno {
    match error {
        crate::kernel::MmAccessError::UnknownTask(_) => LINUX_ESRCH,
        _ => crate::linux_abi::LINUX_EIO,
    }
}

#[derive(Debug)]
enum PtracePokeFailure {
    Mutation(crate::kernel::MmAccessError),
    Witness(LinuxErrno),
    Write(crate::kernel::MmAccessError),
}

fn ptrace_poke_failure_errno(error: &PtracePokeFailure) -> LinuxErrno {
    match error {
        PtracePokeFailure::Mutation(error) | PtracePokeFailure::Write(error) => {
            ptrace_foreign_mm_errno(error)
        }
        PtracePokeFailure::Witness(errno) => *errno,
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

/// Absorb a tracee stop on a carrick-internal host carrier signal. Such a stop
/// is an implementation artifact the guest knows nothing about: `PTRACE_CONT`
/// re-injects the carrier so its handler still runs in the tracee, and the
/// caller re-waits instead of surfacing a bogus `WIFSTOPPED` to the guest. The
/// parked `wait_proc_exit` path absorbs the same stops; this covers the blocking
/// host-wait4 observation points.
#[cfg(test)]
fn absorb_internal_tracee_stop(pid: i32, host_status: i32) -> bool {
    if pid <= 0 || !libc::WIFSTOPPED(host_status) {
        return false;
    }
    let sig = libc::WSTOPSIG(host_status);
    if !crate::io_wait::is_internal_kick_signal(sig) {
        return false;
    }
    // SAFETY: PT_CONTINUE with addr 1 ("resume where stopped"), re-injecting
    // `sig`; same shape as the dispatch ptrace(PTRACE_CONT). Failure (the
    // tracee died meanwhile) is benign — the caller's re-wait surfaces the
    // real state.
    unsafe {
        carrick_portable::ptrace(carrick_portable::PT_CONTINUE, pid, 1, sig);
    }
    true
}

/// Translate a host `waitpid` status so a signal-death's termsig uses Linux
/// numbering. The wstatus layout is shared (low 7 bits = signal, bit 7 = core
/// dump flag, bits 8..15 = exit code); only the signal NUMBER differs between
/// macOS and Linux. Exited children (low 7 bits == 0) and stopped children
/// (low byte == 0x7f) are returned unchanged.
#[cfg(test)]
fn translate_wait_status(status: i32) -> i32 {
    // The host IS Linux on the KVM lane: the wait status is already in the
    // guest ABI (same encoding, same signal numbers, and 0xffff really means
    // WIFCONTINUED). The Darwin remapping below must NOT run there — its
    // WIFCONTINUED sentinel (stop signal 0x13 == Darwin SIGCONT) collides with
    // a genuine Linux SIGSTOP(19) signal-delivery stop, so a ptraced child
    // stopped by SIGSTOP (raised directly, or as the shared kill path's
    // RT/SIGCONT carrier) was reported as WIFCONTINUED instead of WIFSTOPPED
    // (LTP ptrace05 signums 18/19/34..64).
    #[cfg(target_os = "linux")]
    {
        // The host IS Linux: signal numbers + the wstatus encoding already match
        // the guest ABI, so no remap. But the host runs with RLIMIT_CORE=0 (so it
        // never sets the 0x80 core-dumped bit), while carrick models the GUEST's
        // setrlimit/PR_SET_DUMPABLE — the Linux contract is that WCOREDUMP() is
        // true whenever the process died by a core-dumping signal. Synthesize the
        // bit for those signals (signal numbers are already Linux-native here).
        let low = status & 0x7f;
        if low != 0 && low != 0x7f {
            (status & !0x80) | core_dump_bit_for(low)
        } else {
            status
        }
    }
    #[cfg(not(target_os = "linux"))]
    translate_wait_status_darwin(status)
}

/// The wstatus core-dumped bit (0x80) iff `linux_sig` is a core-dumping signal
/// per signal(7): SIGQUIT(3), SIGILL(4), SIGTRAP(5), SIGABRT(6), SIGBUS(7),
/// SIGFPE(8), SIGSEGV(11), SIGXCPU(24), SIGXFSZ(25), SIGSYS(31).
#[cfg(test)]
fn core_dump_bit_for(linux_sig: i32) -> i32 {
    if matches!(linux_sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
        0x80
    } else {
        0
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(test)]
fn translate_wait_status_darwin(status: i32) -> i32 {
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
        (linux_sig & 0x7f) | host_core | core_dump_bit_for(linux_sig)
    } else {
        // Exited normally: high byte is the exit code, left untouched.
        status
    }
}

/// Atomically load a cross-process futex word from its fork-coherent host address
/// (the shared aperture on HVF/KVM, the bhyve futex mirror on bhyve). Atomic to
/// match the guest's own atomic access to the same word.
#[inline]
fn shared_futex_load(location: carrick_guest_mem::SharedFutexLocation) -> u32 {
    // SAFETY: the wait address is a live 4-byte-aligned host word from shared_futex_location.
    unsafe {
        (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Atomically publish a value to a cross-process futex word's fork-coherent host
/// address. On HVF/KVM the address IS the guest word's host memory, so this is a
/// self-store (harmless no-op); on bhyve it pushes the value into the shared mirror
/// the umtx waits/wakes on (the per-VM sysmem copy is NOT shared across the fork).
#[inline]
fn shared_futex_store(location: carrick_guest_mem::SharedFutexLocation, value: u32) {
    // SAFETY: as in shared_futex_load.
    unsafe {
        (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
            .store(value, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
fn host_wait_status_is_stopped_by(status: i32, linux_signum: i32) -> bool {
    let low = status & 0x7f;
    if low != 0x7f {
        return false;
    }
    let host_stopsig = (status >> 8) & 0xff;
    crate::host_signal::host_to_linux_signum(host_stopsig) == linux_signum
}

/// Darwin can report a stopped child from `waitid(WEXITED|WNOWAIT)`. Linux only
/// reports SIGCHLD states selected by the caller's W* bits, so filter the host
/// siginfo before deciding whether a child is waitable.
#[cfg(test)]
fn clear_unrequested_waitid_state(info: &mut libc::siginfo_t, options: LinuxWaitOptions) -> bool {
    if carrick_portable::si_pid(info) == 0 || waitid_state_requested(info.si_code, options) {
        return true;
    }
    *info = unsafe { std::mem::zeroed() };
    false
}

#[cfg(test)]
impl SyscallDispatcher {
    /// Promote a `waitid` `CLD_KILLED` to `CLD_DUMPED` when the child died by a
    /// core-dumping signal AND core dumps are enabled (RLIMIT_CORE soft > 0).
    /// macOS's `waitid` never sets CLD_DUMPED (the host doesn't dump core), but
    /// Linux does — the same "died in a core-dumping way" contract the wait4
    /// wstatus 0x80 bit encodes. `host_si_status` is the host signal number.
    fn core_dumped_si_code(&self, si_code: i32, host_si_status: i32) -> i32 {
        const CLD_KILLED: i32 = 2;
        const CLD_DUMPED: i32 = 3;
        if si_code != CLD_KILLED {
            return si_code;
        }
        let linux_sig = crate::host_signal::host_to_linux_signum(host_si_status);
        if core_dump_bit_for(linux_sig) != 0 && self.rlimit_core_enabled() {
            CLD_DUMPED
        } else {
            si_code
        }
    }

    /// True iff RLIMIT_CORE's soft limit is nonzero (core dumps are produced).
    /// The carrick default is RLIM_INFINITY; a `setrlimit(RLIMIT_CORE, 0)` in the
    /// override table disables it.
    fn rlimit_core_enabled(&self) -> bool {
        match Some(self.task_rlimits().get(carrick_abi::LinuxResource::Core)) {
            Some(limit) => limit.rlim_cur != 0,
            None => true,
        }
    }
}

#[cfg(test)]
fn waitid_state_requested(si_code: i32, options: LinuxWaitOptions) -> bool {
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_TRAPPED: i32 = 4;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;

    match si_code {
        CLD_EXITED | CLD_KILLED | CLD_DUMPED => options.contains(LinuxWaitOptions::WEXITED),
        CLD_TRAPPED | CLD_STOPPED => options.contains(LinuxWaitOptions::WSTOPPED),
        CLD_CONTINUED => options.contains(LinuxWaitOptions::WCONTINUED),
        _ => true,
    }
}

#[cfg(test)]
fn waitid_host_state_option(si_code: i32) -> Option<i32> {
    match si_code {
        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => Some(libc::WEXITED),
        libc::CLD_TRAPPED | libc::CLD_STOPPED => Some(libc::WSTOPPED),
        libc::CLD_CONTINUED => Some(libc::WCONTINUED),
        _ => None,
    }
}

/// Decode the Linux wait-status word stored by the in-process process table
/// into the `si_code`/`si_status` pair returned by `waitid(2)`.
fn hvpatch_waitid_exit_fields(wait_status: i32) -> (i32, i32) {
    // Job-control statuses are decoded FIRST: their encodings collide with the
    // exited/killed ones. A stop is `(signal << 8) | 0x7f` and a continue is
    // 0xffff (see `ProcessContext::wait_child_with_job_control`), so a stopped
    // child read through the terminal-status arms below would come back as
    // CLD_KILLED with si_status 0x7f.
    if wait_status == 0xffff {
        // LINUX_SIGCONT (18), never `libc::SIGCONT` — this value is written
        // into the GUEST's siginfo, and Darwin numbers SIGCONT 19. The stop arm
        // below needs no translation because its signal comes from the kernel
        // graph and is already a Linux signum.
        return (libc::CLD_CONTINUED, crate::linux_abi::LINUX_SIGCONT);
    }
    if wait_status & 0xff == 0x7f {
        return (libc::CLD_STOPPED, (wait_status >> 8) & 0xff);
    }
    let signal = wait_status & 0x7f;
    if signal == 0 {
        (libc::CLD_EXITED, (wait_status >> 8) & 0xff)
    } else if wait_status & 0x80 != 0 {
        (libc::CLD_DUMPED, signal)
    } else {
        (libc::CLD_KILLED, signal)
    }
}

/// Render one authoritative HVPatch child state change into Linux's SIGCHLD
/// `siginfo_t` layout. The child pid, real uid, and wait status all come
/// from the same Carrick-kernel wait result; host process credentials are not
/// meaningful for logical guest children sharing the VM carrier.
pub(crate) fn build_hvpatch_waitid_siginfo(
    exit: crate::hvpatch::ChildExit,
) -> [u8; crate::linux_abi::LINUX_SIGINFO_SIZE] {
    let (si_code, si_status) = hvpatch_waitid_exit_fields(exit.status());
    build_linux_sigchld_siginfo(exit.visible_pid(), exit.ruid().raw(), si_code, si_status)
}

/// Build a Linux `siginfo_t` (SIGCHLD layout) for `waitid` from the fields
/// macOS's `waitid` filled. The Linux struct places si_pid@16, si_uid@20,
/// si_status@24 after the common si_signo/si_errno/si_code header. The CLD_*
/// codes match between the kernels; si_status is the raw exit code for
/// CLD_EXITED but a signal number otherwise, so translate that host->Linux.
#[cfg(test)]
fn build_sigchld_siginfo(
    si_pid: i32,
    si_uid: u32,
    si_code: i32,
    si_status: i32,
) -> [u8; crate::linux_abi::LINUX_SIGINFO_SIZE] {
    const CLD_EXITED: i32 = 1;
    let linux_status = if si_code == CLD_EXITED {
        si_status
    } else {
        crate::host_signal::host_to_linux_signum(si_status)
    };
    build_linux_sigchld_siginfo(si_pid, si_uid, si_code, linux_status)
}

fn build_linux_sigchld_siginfo(
    si_pid: i32,
    si_uid: u32,
    si_code: i32,
    linux_status: i32,
) -> [u8; crate::linux_abi::LINUX_SIGINFO_SIZE] {
    use crate::linux_abi::LINUX_SIGCHLD;
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
mod hvpatch_identity_tests {
    use super::{ProcState, hvpatch_reported_tid};

    #[test]
    fn hvpatch_gettid_reports_the_kernel_thread_identity() {
        assert_eq!(hvpatch_reported_tid(7), Some(7));
        // A negative kernel tid is not a Linux tid and must not be reported.
        assert_eq!(hvpatch_reported_tid(-1), None);
    }

    #[test]
    fn hvpatch_subreaper_inheritance_uses_linux_visible_pid() {
        let mut parent = ProcState::new();
        parent.virtual_pid = Some(41);
        parent.child_subreaper = 1;
        parent.child_subreaper_owner = parent.logical_pid();

        let child = parent.fork_clone(41, 42);

        assert_eq!(parent.child_subreaper_owner, 41);
        assert_eq!(child.subreaper_ancestor, 41);
        assert_eq!(child.child_subreaper, 0);
        assert_eq!(child.child_subreaper_owner, 0);
    }
}

#[cfg(test)]
mod kernel_process_dispatch_tests {
    use super::*;
    use std::num::{NonZeroU16, NonZeroU64};
    use std::sync::Arc;
    use std::time::Instant;

    use crate::compat::CompatReporter;
    use crate::kernel::{
        Asid, ClonePlan, KernelContext, LinuxWaitStatus, MmBackend, MmBackendSnapshot, MmBinding,
        SnapshotError, Stage1Root, VmaAccess, VmaRevision, VmaSummary,
    };
    use crate::thread::ThreadId;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::{
        ForeignMmReadLease, ForeignMmReadReceipt, ForeignMmSnapshot, ForeignMmTransport,
        ForeignMmTransportError,
    };

    const INFO_ADDR: u64 = 0x4000;
    const SYS_WAITID: u64 = 95;
    const SYS_PTRACE: u64 = 117;
    const SYS_PROCESS_VM_READV: u64 = 270;
    const SYS_PROCESS_VM_WRITEV: u64 = 271;
    const SYS_WAIT4: u64 = 260;
    const LINUX_P_ALL: u64 = 0;
    const LINUX_P_PID: u64 = 1;
    const LINUX_P_PGID: u64 = 2;
    const LINUX_WNOHANG: u64 = 1;
    const LINUX_WSTOPPED: u64 = 2;
    const LINUX_WEXITED: u64 = 4;
    const LINUX_WNOWAIT: u64 = 0x0100_0000;
    const LOCAL_IOV: u64 = 0x1800;
    const REMOTE_IOV: u64 = 0x1810;
    const LOCAL_BUF: u64 = 0x2000;
    const TARGET_VA: u64 = 0x3000;

    #[derive(Debug)]
    struct ProcessVmBackend {
        binding: MmBinding,
        pages: u64,
    }

    impl ProcessVmBackend {
        fn with_pages(binding: MmBinding, pages: u64) -> Self {
            Self { binding, pages }
        }
    }

    impl MmBackend for ProcessVmBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            Ok(MmBackendSnapshot {
                revision: 17,
                binding: self.binding,
                vmas: vec![VmaSummary {
                    start: GuestVa(TARGET_VA),
                    end: GuestVa(TARGET_VA + self.pages * 0x1000),
                    access: VmaAccess {
                        readable: true,
                        writable: true,
                        executable: false,
                        kernel_visible: true,
                    },
                }],
                vma_revision: Some(VmaRevision::from_authority_raw(19)),
                mapping_ids: Vec::new(),
                frame_inventory_revision: Some(23),
            })
        }

        fn revision(&self) -> u64 {
            17
        }

        fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
            Ok(Some(VmaRevision::from_authority_raw(19)))
        }
    }

    #[derive(Debug)]
    struct ProcessVmReadTransport {
        payload: Vec<u8>,
    }

    #[derive(Debug)]
    struct ProcessVmReadLease {
        payload: Vec<u8>,
    }

    #[derive(Debug)]
    struct ProcessVmReadReceipt {
        bytes: usize,
        owners: [carrick_hal::ForeignOwnerGeneration; 1],
    }

    impl ForeignMmReadReceipt for ProcessVmReadReceipt {
        fn bytes_read(&self) -> usize {
            self.bytes
        }

        fn owner_generations(&self) -> &[carrick_hal::ForeignOwnerGeneration] {
            &self.owners
        }

        fn authenticates(&self, _snapshot: &dyn ForeignMmSnapshot) -> bool {
            true
        }
    }

    impl ForeignMmReadLease for ProcessVmReadLease {
        fn read(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
            _snapshot: &dyn ForeignMmSnapshot,
            va: GuestVa,
            dst: &mut [u8],
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
            if va.0 < TARGET_VA || self.payload.is_empty() {
                return Err(ForeignMmTransportError::Translation(va));
            }
            let offset = (va.0 - TARGET_VA) as usize;
            for (i, b) in dst.iter_mut().enumerate() {
                *b = self.payload[(offset + i) % self.payload.len()];
            }
            Ok(Box::new(ProcessVmReadReceipt {
                bytes: dst.len(),
                owners: [carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    NonZeroU64::MIN,
                )],
            }))
        }
    }

    impl ForeignMmTransport for ProcessVmReadTransport {
        fn retain(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _snapshot: &dyn ForeignMmSnapshot,
            _deadline: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            Ok(Arc::new(ProcessVmReadLease {
                payload: self.payload.clone(),
            }))
        }
    }

    fn bound_dispatcher(
        root_pid: i32,
    ) -> (
        HvpatchLaneScope,
        SyscallDispatcher,
        crate::hvpatch::ProcessContext,
        KernelContext,
        crate::kernel::objects::ThreadExecutionLease,
    ) {
        let lane = HvpatchLaneScope::force(false);
        let (mut process, root) = crate::hvpatch::process_context_for_tests(root_pid);
        let state = crate::kernel::objects::MigratableTaskState {
            cpu: carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                    gprs: [0; 31],
                    pc: 0,
                    pstate: 0,
                    trap_pc: 0,
                    trap_pstate: 0,
                    sp_el0: 0,
                    elr_el1: 0,
                    spsr_el1: 0,
                    ttbr0: 0,
                    ttbr1: 0,
                    tcr: 0,
                    sctlr_el1: 0,
                    mair_el1: 0,
                    vbar_el1: 0,
                    cpacr_el1: 0,
                    cntkctl_el1: 0,
                    tpidr_el1: 0,
                    actlr_el1: 0,
                    tpidr_el0: 0,
                    tpidrro_el0: 0,
                    contextidr_el1: 0,
                    vregs: [0; 32],
                    fpsr: 0,
                    fpcr: 0,
                    pending_resume_pc: None,
                    last_syscall_nr: None,
                    last_syscall_orig_x0: 0,
                    last_fault_esr: 0,
                    last_exit_class: 0,
                    is_forked_child: false,
                    syscall_continuation: None,
                    mm_generation: root.shared().mm().id().raw(),
                    asid_generation: root.shared().mm().id().raw(),
                },
            ),
            mm: root.shared().mm().id(),
            asid_generation: root.shared().mm().id().raw(),
        };
        root.thread()
            .publish_initial_task_state(state)
            .expect("publish test task state");
        let executor = crate::kernel::objects::ExecutorId::for_transitional_thread(
            crate::thread::ThreadId::synthetic_for_tests(root_pid),
        )
        .expect("test executor ID");
        let lease = root
            .thread()
            .claim_runnable(executor)
            .expect("claim test lease");
        process.enable_mm_access_for_tests();
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process.clone());
        let root = dispatcher
            .capture_one_task_context()
            .expect("bound HVPatch root context");
        (lane, dispatcher, process, root, lease)
    }

    fn refreshed(context: &KernelContext) -> KernelContext {
        context
            .kernel()
            .context(context.task().key().id, context.thread().key().tid)
            .expect("refresh kernel context")
    }

    fn fork_child(parent: &KernelContext, registry_id: i32) -> KernelContext {
        parent
            .kernel()
            .reserve_fork(
                parent,
                ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap(),
                format!("wait-child-{registry_id}"),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(registry_id))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0
    }

    fn clone_vm_child(parent: &KernelContext, registry_id: i32) -> KernelContext {
        parent
            .kernel()
            .reserve_fork(
                parent,
                ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::VM).unwrap(),
                format!("clone-vm-child-{registry_id}"),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(registry_id))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0
    }

    fn process_vm_target(parent: &KernelContext, registry_id: i32) -> KernelContext {
        process_vm_target_with_payload_and_pages(parent, registry_id, b"PEER", 1)
    }

    fn process_vm_target_with_payload(
        parent: &KernelContext,
        registry_id: i32,
        payload: &[u8],
    ) -> KernelContext {
        process_vm_target_with_payload_and_pages(parent, registry_id, payload, 1)
    }

    fn process_vm_target_with_pages(
        parent: &KernelContext,
        registry_id: i32,
        pages: u64,
    ) -> KernelContext {
        process_vm_target_with_payload_and_pages(parent, registry_id, b"PEER", pages)
    }

    fn process_vm_target_with_payload_and_pages(
        parent: &KernelContext,
        registry_id: i32,
        payload: &[u8],
        pages: u64,
    ) -> KernelContext {
        let asid = Asid::from_registry_allocation(
            NonZeroU16::new((registry_id as u16).max(1)).expect("nonzero ASID"),
        );
        let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned stage-1 root");
        let backend: Arc<dyn MmBackend> = Arc::new(ProcessVmBackend::with_pages(
            MmBinding::for_aarch64(asid, root),
            pages,
        ));
        let child = parent
            .kernel()
            .reserve_fork(
                parent,
                ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap(),
                format!("process-vm-child-{registry_id}"),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(backend, ThreadId::synthetic_for_tests(registry_id))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(ProcessVmReadTransport {
                payload: payload.to_vec(),
            })),
        );
        child
    }

    fn arm_ptrace_memory_access(tracer: &KernelContext, tracee: &KernelContext) {
        assert!(tracer.kernel().claim_ptrace_traceme(tracee));
        let stop = crate::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(
            tracer
                .kernel()
                .stop_task_for_ptrace(tracee.task().key().id, stop)
        );
        assert_eq!(
            tracer
                .kernel()
                .settle_task_ptrace_stop(tracee.task().key().id),
            crate::kernel::objects::PtraceStopSettlement::Stopped,
        );
    }

    fn write_iovec(memory: &mut LinearMemory, address: u64, base: u64, len: u64) {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&base.to_le_bytes());
        bytes[8..].copy_from_slice(&len.to_le_bytes());
        memory.write_bytes(address, &bytes).unwrap();
    }

    fn dispatch(
        dispatcher: &mut SyscallDispatcher,
        context: &KernelContext,
        memory: &mut LinearMemory,
        number: u64,
        args: [u64; 6],
    ) -> DispatchOutcome {
        dispatch_with_lease(dispatcher, context, memory, number, args, None)
    }

    fn dispatch_with_lease(
        dispatcher: &mut SyscallDispatcher,
        context: &KernelContext,
        memory: &mut LinearMemory,
        number: u64,
        args: [u64; 6],
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> DispatchOutcome {
        dispatcher
            .dispatch_with_lease(
                context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                memory,
                &CompatReporter::default(),
                lease,
            )
            .unwrap()
    }

    fn siginfo_i32(memory: &LinearMemory, offset: u64) -> i32 {
        i32::from_ne_bytes(
            memory
                .read_bytes(INFO_ADDR + offset, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn process_vm_readv_reads_the_exact_foreign_mm() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_090);
        let target = process_vm_target(&root, 61_091);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        memory.write_bytes(TARGET_VA, b"SELF").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"PEER");
    }

    #[test]
    fn process_vm_readv_routes_to_exact_distinct_target_payloads() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_070);
        let target_one = process_vm_target_with_payload(&root, 61_071, b"ONE1");
        let target_two = process_vm_target_with_payload(&root, 61_072, b"TWO2");
        let root = refreshed(&root);
        let pid_one = target_one.task().key().id.raw();
        let pid_two = target_two.task().key().id.raw();

        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [pid_one as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"ONE1");

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [pid_two as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"TWO2");
    }

    #[test]
    fn process_vm_zero_length_ordering_matches_clean_room_oracle() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_092);
        let missing_pid = 2_000_000_000u64;
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x3000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 0);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 0);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [missing_pid, LOCAL_IOV, 1, 1, 1, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
            "zero local total must not import the remote array or resolve pid",
        );
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [missing_pid, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
            "zero remote total must not resolve pid",
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [missing_pid, 1, 1, 0, 0, 0],
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
            "a nonempty invalid local vector faults before remote zero",
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [missing_pid, 0, 0, 0, 0, 1],
            ),
            DispatchOutcome::errno(LINUX_EINVAL),
            "invalid flags win over a zero-byte transfer",
        );
    }

    #[test]
    fn process_vm_readv_exact_current_routes_to_self_copy() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_093);
        let self_pid = root.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        memory.write_bytes(TARGET_VA, b"SELF").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [self_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"SELF");
    }

    #[test]
    fn process_vm_readv_exact_caller_without_lease_succeeds() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_076);
        let self_pid = root.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        memory.write_bytes(TARGET_VA, b"SELF").unwrap();

        // Dispatch via public dispatch (which passes no execution lease) for pid=self
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [self_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
            ),
            DispatchOutcome::Returned { value: 4 },
            "exact caller self-copy must succeed without an execution lease",
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"SELF");
    }

    #[test]
    fn process_vm_readv_foreign_first_fault_returns_efault() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_094);
        let target = process_vm_target(&root, 61_095);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, 0x9999_0000, 4);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
        );
    }

    #[test]
    fn process_vm_readv_later_foreign_fault_returns_completed_prefix() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_088);
        let target = process_vm_target(&root, 61_089);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 8);
        const REMOTE_IOV_SECOND: u64 = REMOTE_IOV + 16;
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        write_iovec(&mut memory, REMOTE_IOV_SECOND, 0x9999_0000, 4);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 2, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
            "later fault must return exact completed prefix",
        );
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"PEER");
    }

    #[test]
    fn process_vm_readv_remote_single_iovec_mid_fault_returns_completed_prefix() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_086);
        let target = process_vm_target(&root, 61_087);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x10000]);

        // Single remote iovec of 8192 bytes (first 4096 mapped at TARGET_VA, second 4096 unmapped)
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 8192);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 8192);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4096 },
            "single remote iovec mid-fault must return exact completed prefix",
        );
        let read_bytes = memory.read_bytes(LOCAL_BUF, 4096).unwrap();
        let expected = (0..4096).map(|i| b"PEER"[i % 4]).collect::<Vec<_>>();
        assert_eq!(read_bytes, expected);
        assert_eq!(
            memory.read_bytes(LOCAL_BUF + 4096, 4096).unwrap(),
            vec![0; 4096]
        );
    }

    #[test]
    fn process_vm_readv_local_single_iovec_mid_fault_returns_completed_prefix() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_084);
        let target = process_vm_target_with_pages(&root, 61_085, 2);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        // Memory has only 0x2000 total size starting at 0x1000, so LOCAL_BUF (0x2000) has capacity 0x1000 (4096 bytes).
        // Writing at LOCAL_BUF + 4096 (0x3000) faults.
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x2000]);

        // Single remote iovec of 8192 bytes, single local iovec of 8192 bytes
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 8192);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 8192);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4096 },
            "single local iovec mid-fault must return exact completed prefix",
        );
        let read_bytes = memory.read_bytes(LOCAL_BUF, 4096).unwrap();
        let expected = (0..4096).map(|i| b"PEER"[i % 4]).collect::<Vec<_>>();
        assert_eq!(read_bytes, expected);
    }

    #[test]
    fn process_vm_readv_stale_target_returns_esrch() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_082);
        let target = process_vm_target(&root, 61_083);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);

        target
            .kernel()
            .exit_task(
                target.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit test task");

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "stale target task must return ESRCH",
        );
    }

    #[test]
    fn process_vm_readv_wrong_or_stale_caller_lease_returns_efault() {
        let (_lane, mut dispatcher, _process, root, _root_lease) = bound_dispatcher(61_074);
        let (_other_lane, _other_dispatcher, _other_process, _other_root, wrong_lease) =
            bound_dispatcher(61_075);
        let target = process_vm_target(&root, 61_076);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);

        // Supplying a wrong/mismatched caller lease (from a different thread/task) must fail closed with EFAULT (not ESRCH)
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&wrong_lease),
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
            "wrong caller lease authority must fail closed with EFAULT",
        );
    }

    #[test]
    fn process_vm_foreign_mm_errno_distinguishes_target_from_caller_staleness() {
        let (_lane, _dispatcher, _process, root, _lease) = bound_dispatcher(61_077);
        let key = root.task().key();

        assert_eq!(
            process_vm_foreign_mm_errno(&crate::kernel::MmAccessError::UnknownTask(key)),
            LINUX_ESRCH,
            "only a missing target is ESRCH",
        );
        assert_eq!(
            process_vm_foreign_mm_errno(&crate::kernel::MmAccessError::StaleContext(key)),
            LINUX_EFAULT,
            "stale caller context is an authority failure, not a missing target",
        );
    }

    #[test]
    fn process_vm_writev_changes_only_the_exact_foreign_target() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_096);
        let mut initial = vec![b'_'; 0x4000];
        initial[..4].copy_from_slice(b"same");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_097, initial);
        target.observe_caller_executor_census(dispatcher.mm_executor_census());
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        memory.write_bytes(LOCAL_BUF, b"EDIT").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(target.child_bytes(0, 4), b"EDIT");
        assert_eq!(&target.peer_bytes()[..4], b"same");
        assert_eq!(memory.read_bytes(LOCAL_BUF, 4).unwrap(), b"EDIT");
        assert_eq!(memory.read_bytes(TARGET_VA, 4).unwrap(), b"\0\0\0\0");
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 1);
        assert_eq!(target.commit_calls(), 1);
        assert!(
            !target.break_observed_caller_executor(),
            "caller MM participation must be absent before target COW mutation begins",
        );
    }

    #[test]
    fn process_vm_writev_reuses_one_compound_for_two_remote_subranges() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_100);
        let mut initial = vec![b'_'; 0x4000];
        initial[..16].copy_from_slice(b"same_old_data___");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_101, initial);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x5000]);
        const LOCAL_IOVS: u64 = 0x1400;
        const REMOTE_IOVS: u64 = 0x1440;
        write_iovec(&mut memory, LOCAL_IOVS, LOCAL_BUF, 4);
        write_iovec(&mut memory, LOCAL_IOVS + 16, LOCAL_BUF + 4, 4);
        write_iovec(&mut memory, REMOTE_IOVS, TARGET_VA, 4);
        write_iovec(&mut memory, REMOTE_IOVS + 16, TARGET_VA + 8, 4);
        memory.write_bytes(LOCAL_BUF, b"ONE1TWO2").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOVS, 2, REMOTE_IOVS, 2, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 8 },
        );
        assert_eq!(target.child_bytes(0, 12), b"ONE1_oldTWO2");
        assert_eq!(&target.peer_bytes()[..16], b"same_old_data___");
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 2);
        assert_eq!(target.commit_calls(), 2);
    }

    #[test]
    fn process_vm_writev_later_foreign_fault_returns_completed_prefix() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_102);
        let mut initial = vec![b'_'; 0x4000];
        initial[..8].copy_from_slice(b"samepeer");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_103, initial);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        const REMOTE_IOV_SECOND: u64 = REMOTE_IOV + 16;
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 8);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);
        write_iovec(&mut memory, REMOTE_IOV_SECOND, 0x9999_0000, 4);
        memory.write_bytes(LOCAL_BUF, b"EDITTAIL").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 2, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
        );
        assert_eq!(target.child_bytes(0, 8), b"EDITpeer");
        assert_eq!(&target.peer_bytes()[..8], b"samepeer");
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 1);
        assert_eq!(target.commit_calls(), 1);
    }

    #[test]
    fn process_vm_writev_first_foreign_fault_is_efault_without_mutation() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_104);
        let mut initial = vec![b'_'; 0x4000];
        initial[..4].copy_from_slice(b"same");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_105, initial);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, 0x9999_0000, 4);
        memory.write_bytes(LOCAL_BUF, b"EDIT").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
        );
        assert_eq!(target.child_bytes(0, 4), b"same");
        assert_eq!(&target.peer_bytes()[..4], b"same");
        assert_eq!(target.break_calls(), 0);
        assert_eq!(target.prepare_calls(), 0);
        assert_eq!(target.commit_calls(), 0);
    }

    #[test]
    fn process_vm_writev_local_single_iovec_mid_fault_returns_completed_prefix() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_106);
        let mut initial = vec![b'_'; 0x4000];
        initial[..8].copy_from_slice(b"samepeer");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_107, initial);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        // Memory has only 0x2000 total size starting at 0x1000, so LOCAL_BUF (0x2000) has capacity 0x1000 (4096 bytes).
        // Reading at LOCAL_BUF + 4096 (0x3000) faults.
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let input_bytes = (0..4096).map(|i| b"EDIT"[i % 4]).collect::<Vec<_>>();
        memory.write_bytes(LOCAL_BUF, &input_bytes).unwrap();

        // Single remote iovec of 8192 bytes, single local iovec of 8192 bytes
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 8192);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 8192);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4096 },
            "single local iovec mid-fault must return exact completed prefix",
        );
        assert_eq!(target.child_bytes(0, 4096), input_bytes);
        assert_eq!(&target.peer_bytes()[..8], b"samepeer");
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 1);
        assert_eq!(target.commit_calls(), 1);
    }

    #[test]
    fn process_vm_writev_internal_zero_remote_iovec_preserves_exact_shorter_total() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_108);
        let target =
            crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_109, vec![b'_'; 0x4000]);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x5000]);
        const LOCAL_IOV_20: u64 = 0x1300;
        const REMOTE_IOVS_5: u64 = 0x1400;

        write_iovec(&mut memory, LOCAL_IOV_20, LOCAL_BUF, 20);
        memory
            .write_bytes(LOCAL_BUF, b"11112222333344445555")
            .unwrap();
        write_iovec(&mut memory, REMOTE_IOVS_5, TARGET_VA, 4);
        write_iovec(&mut memory, REMOTE_IOVS_5 + 16, TARGET_VA + 4, 0);
        write_iovec(&mut memory, REMOTE_IOVS_5 + 32, TARGET_VA + 4, 4);
        write_iovec(&mut memory, REMOTE_IOVS_5 + 48, TARGET_VA + 8, 4);
        write_iovec(&mut memory, REMOTE_IOVS_5 + 64, TARGET_VA + 12, 4);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV_20, 1, REMOTE_IOVS_5, 5, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 16 },
        );
        assert_eq!(target.child_bytes(0, 16), b"1111222233334444");
        assert_eq!(target.child_bytes(16, 4), b"____");
    }

    #[test]
    fn process_vm_writev_internal_zero_local_iovec_preserves_exact_shorter_total() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_110);
        let target =
            crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_111, vec![b'_'; 0x4000]);
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x5000]);
        const LOCAL_IOVS_5: u64 = 0x1300;
        const REMOTE_IOV_20: u64 = 0x1400;

        write_iovec(&mut memory, REMOTE_IOV_20, TARGET_VA, 20);
        write_iovec(&mut memory, LOCAL_IOVS_5, LOCAL_BUF, 4);
        write_iovec(&mut memory, LOCAL_IOVS_5 + 16, LOCAL_BUF + 4, 0);
        write_iovec(&mut memory, LOCAL_IOVS_5 + 32, LOCAL_BUF + 4, 4);
        write_iovec(&mut memory, LOCAL_IOVS_5 + 48, LOCAL_BUF + 8, 4);
        write_iovec(&mut memory, LOCAL_IOVS_5 + 64, LOCAL_BUF + 12, 4);
        memory.write_bytes(LOCAL_BUF, b"1111222233334444").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOVS_5, 5, REMOTE_IOV_20, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 16 },
        );
        assert_eq!(target.child_bytes(0, 16), b"1111222233334444");
        assert_eq!(target.child_bytes(16, 4), b"____");
    }

    #[test]
    fn process_vm_lease_consumer_limited_to_process_vm_syscalls() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_098);
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        // When dispatching without an active execution lease:
        // Ordinary syscalls (getpid, getppid, getuid, sched_yield) succeed normally
        // without attempting foreign MM access or failing due to missing lease authority.
        // This fixture is the container's kernel-graph root, so Linux exposes no
        // parent inside its PID namespace: getppid() is 0, not a synthetic pid 1.
        assert_eq!(
            dispatch(&mut dispatcher, &root, &mut memory, 172, [0, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 61_098 },
            "getpid must not require or consume execution lease authority",
        );
        assert_eq!(
            dispatch(&mut dispatcher, &root, &mut memory, 173, [0, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
            "getppid must not require or consume execution lease authority",
        );
        assert_eq!(
            dispatch(&mut dispatcher, &root, &mut memory, 174, [0, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
            "getuid must not require or consume execution lease authority",
        );
        assert_eq!(
            dispatch(&mut dispatcher, &root, &mut memory, 124, [0, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
            "sched_yield must not require or consume execution lease authority",
        );

        // For process_vm_readv / writev with a foreign target, missing execution lease fails closed with EFAULT.
        let target = process_vm_target(&root, 61_099);
        let target_pid = target.task().key().id.raw();
        write_iovec(&mut memory, LOCAL_IOV, LOCAL_BUF, 4);
        write_iovec(&mut memory, REMOTE_IOV, TARGET_VA, 4);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
            "foreign process_vm_readv without execution lease fails closed with EFAULT",
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_WRITEV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
            ),
            DispatchOutcome::errno(LINUX_EFAULT),
            "foreign process_vm_writev without execution lease fails closed with EFAULT",
        );

        // With the valid execution lease, process_vm_readv consumes the lease and succeeds.
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PROCESS_VM_READV,
                [target_pid as u64, LOCAL_IOV, 1, REMOTE_IOV, 1, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 4 },
            "foreign process_vm_readv with valid execution lease consumes lease and succeeds",
        );
    }

    #[test]
    fn syscall_requires_execution_lease_matches_exact_process_vm_numbers() {
        use crate::dispatch::syscall_requires_execution_lease;
        let empty_args = SyscallArgs::from([0; 6]);
        assert!(syscall_requires_execution_lease(270, empty_args));
        assert!(syscall_requires_execution_lease(271, empty_args));

        for ordinary in [
            0,   // read
            1,   // write
            95,  // waitid
            98,  // futex
            124, // sched_yield
            172, // getpid
            173, // getppid
            174, // getuid
            220, // clone
            222, // mmap
            260, // wait4
        ] {
            assert!(
                !syscall_requires_execution_lease(ordinary, empty_args),
                "syscall {ordinary} must not require execution lease"
            );
        }

        for req in [
            LINUX_PTRACE_PEEKTEXT,
            LINUX_PTRACE_PEEKDATA,
            LINUX_PTRACE_POKETEXT,
            LINUX_PTRACE_POKEDATA,
        ] {
            let args = SyscallArgs::from([req, 0, 0, 0, 0, 0]);
            assert!(
                syscall_requires_execution_lease(117, args),
                "ptrace request {req} must require execution lease"
            );
        }

        for req in [
            0,  // PTRACE_TRACEME
            3,  // PTRACE_PEEKUSER
            6,  // PTRACE_POKEUSER
            7,  // PTRACE_CONT
            8,  // PTRACE_KILL
            16, // PTRACE_ATTACH
            17, // PTRACE_DETACH
        ] {
            let args = SyscallArgs::from([req, 0, 0, 0, 0, 0]);
            assert!(
                !syscall_requires_execution_lease(117, args),
                "ptrace request {req} must not require execution lease"
            );
        }
    }

    #[test]
    fn process_vm_writev_resolves_ordinary_then_acquires_only_target_mm_mutation() {
        let args = SyscallArgs::from([0; 6]);
        assert!(crate::dispatch::resolve_handler::<LinearMemory>(271).is_some());
        assert!(
            crate::dispatch::resolve_mutation_handler::<LinearMemory>(271).is_none(),
            "process_vm_writev must not acquire caller/current-MM mutation authority",
        );
        assert!(!crate::dispatch::syscall_requires_mm_mutation(271, args));
        assert!(crate::dispatch::syscall_requires_execution_lease(271, args));
        assert_eq!(crate::dispatch::MM_MUTATION_SYSCALLS.len(), 17);
    }

    #[test]
    fn kernel_wait_dispatch_validates_and_reports_echild() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_001);
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [LINUX_P_ALL, 0, 0, LINUX_WEXITED, 0, 0],
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD),
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [99, 0, 0, LINUX_WEXITED, 0, 0],
            ),
            DispatchOutcome::errno(LINUX_EINVAL),
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [LINUX_P_ALL, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::errno(LINUX_EINVAL),
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAIT4,
                [u64::MAX, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_ECHILD),
        );
    }

    #[test]
    fn kernel_blocking_waits_park_on_logical_children() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_011);
        let child = fork_child(&root, 61_012);
        let root = refreshed(&root);
        let child_pid = child.task().key().id.raw();
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        assert!(matches!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAIT4,
                [child_pid as u64, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(target),
                ..
            } if target == child_pid
        ));
        assert!(matches!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [LINUX_P_PID, child_pid as u64, 0, LINUX_WEXITED, 0, 0],
            ),
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(target),
                ..
            } if target == child_pid
        ));
    }

    #[test]
    fn kernel_process_group_waits_use_a_broad_wake_selector() {
        let (_lane, mut dispatcher, process, root, _lease) = bound_dispatcher(61_021);
        let _child = fork_child(&root, 61_022);
        let root = refreshed(&root);
        let process_group = process.process_group().unwrap();
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        for pid in [0_i32, -process_group] {
            assert!(matches!(
                dispatch(
                    &mut dispatcher,
                    &root,
                    &mut memory,
                    SYS_WAIT4,
                    [pid as u64, 0, 0, 0, 0, 0],
                ),
                DispatchOutcome::WaitOnHvpatchChild { target: None, .. }
            ));
        }
        assert!(matches!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [LINUX_P_PGID, 0, 0, LINUX_WEXITED, 0, 0],
            ),
            DispatchOutcome::WaitOnHvpatchChild { target: None, .. }
        ));
    }

    #[test]
    fn kernel_waitid_filters_unrequested_stop_and_finds_exited_sibling() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_031);
        let stopped = fork_child(&root, 61_032);
        let root = refreshed(&root);
        let exited = fork_child(&root, 61_033);
        let root = refreshed(&root);
        let stopped_pid = stopped.task().key().id.raw();
        let exited_pid = exited.task().key().id.raw();
        let sigstop =
            crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGSTOP).unwrap();
        assert!(
            root.kernel()
                .stop_task_for_job_control(stopped.task().key().id, sigstop, None)
        );
        root.kernel()
            .prepare_task_exit(
                exited.task().key().id,
                LinuxWaitStatus::from_wait_encoding(23 << 8),
                None,
            )
            .unwrap()
            .commit()
            .unwrap();
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        for idtype in [LINUX_P_ALL, LINUX_P_PGID] {
            memory.write_bytes(INFO_ADDR, &[0; 28]).unwrap();
            assert_eq!(
                dispatch(
                    &mut dispatcher,
                    &root,
                    &mut memory,
                    SYS_WAITID,
                    [
                        idtype,
                        0,
                        INFO_ADDR,
                        LINUX_WEXITED | LINUX_WNOHANG | LINUX_WNOWAIT,
                        0,
                        0,
                    ],
                ),
                DispatchOutcome::Returned { value: 0 },
            );
            assert_eq!(siginfo_i32(&memory, 16), exited_pid);
            assert_eq!(siginfo_i32(&memory, 24), 23);
        }

        memory.write_bytes(INFO_ADDR, &[0xff; 28]).unwrap();
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAITID,
                [
                    LINUX_P_PID,
                    stopped_pid as u64,
                    INFO_ADDR,
                    LINUX_WEXITED | LINUX_WNOHANG,
                    0,
                    0,
                ],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(memory.read_bytes(INFO_ADDR, 28).unwrap(), vec![0; 28]);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAIT4,
                [
                    stopped_pid as u64,
                    INFO_ADDR + 0x40,
                    LINUX_WSTOPPED,
                    0,
                    0,
                    0
                ],
            ),
            DispatchOutcome::Returned {
                value: i64::from(stopped_pid),
            },
        );
        assert_eq!(
            i32::from_ne_bytes(
                memory
                    .read_bytes(INFO_ADDR + 0x40, 4)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            (crate::linux_abi::LINUX_SIGSTOP << 8) | 0x7f,
        );
    }

    #[test]
    fn kernel_ptrace_stop_wait_and_control_are_task_scoped() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_041);
        let child = fork_child(&root, 61_042);
        let root = refreshed(&root);
        let child_pid = child.task().key().id.raw();
        let signal = crate::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(root.kernel().claim_ptrace_traceme(&child));
        assert!(
            root.kernel()
                .stop_task_for_ptrace(child.task().key().id, signal)
        );
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_WAIT4,
                [child_pid as u64, INFO_ADDR + 0x40, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned {
                value: i64::from(child_pid),
            },
        );
        assert_eq!(
            i32::from_ne_bytes(
                memory
                    .read_bytes(INFO_ADDR + 0x40, 4)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            (12 << 8) | 0x7f,
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [7, child_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
    }

    #[test]
    fn hvpatch_ptrace_peekdata_reads_exact_foreign_word_for_exact_tracer() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_120);
        let target = process_vm_target_with_payload(&root, 61_121, b"PEEKWORD");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0,],
                Some(&lease),
            ),
            DispatchOutcome::Returned {
                value: u64::from_le_bytes(*b"PEEKWORD") as i64,
            },
        );
    }

    #[test]
    fn hvpatch_ptrace_pokedata_changes_only_exact_target_under_cow() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_122);
        let mut initial = vec![b'_'; 0x4000];
        initial[..8].copy_from_slice(b"sameword");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_123, initial);
        target.observe_caller_executor_census(dispatcher.mm_executor_census());
        arm_ptrace_memory_access(&root, target.target());
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        let replacement = u64::from_le_bytes(*b"EDITWORD");

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    replacement,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(target.child_bytes(0, 8), b"EDITWORD");
        assert_eq!(&target.peer_bytes()[..8], b"sameword");
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 1);
        assert_eq!(target.commit_calls(), 1);
        assert!(!target.break_observed_caller_executor());
    }

    #[test]
    fn hvpatch_ptrace_poketext_accepts_rx_mapping_and_preserves_cow_peer() {
        // mov w0, #42; ret  ->  mov w0, #43; ret
        let before = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        let after = [0x60, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_153);
        let mut initial = vec![0; 0x4000];
        initial[..8].copy_from_slice(&before);
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_154, initial);
        target.set_vma_access_for_test(VmaAccess {
            readable: true,
            writable: false,
            executable: true,
            kernel_visible: true,
        });
        target.observe_caller_executor_census(dispatcher.mm_executor_census());
        arm_ptrace_memory_access(&root, target.target());
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKETEXT,
                    target_pid as u64,
                    TARGET_VA,
                    u64::from_le_bytes(after),
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(target.child_bytes(0, 8), after);
        assert_eq!(&target.peer_bytes()[..8], before);
        assert_eq!(target.break_calls(), 1);
        assert_eq!(target.prepare_calls(), 1);
        assert_eq!(target.commit_calls(), 1);
    }

    #[test]
    fn hvpatch_ptrace_poke_preserves_mutation_witness_and_write_error_domains() {
        let source = include_str!("proc.rs");
        let poke = source
            .split_once("macro_rules! commit_transport_poke")
            .expect("ptrace poke transport macro")
            .1
            .split_once("LINUX_PTRACE_PEEKUSER")
            .expect("end of ptrace poke transport block")
            .0;

        assert!(
            !poke.contains(".map_err(|_| crate::kernel::MmAccessError::UnknownTask(target_key))?"),
            "ptrace witness revalidation errors must not be erased into an unrelated MM-access error",
        );
        assert!(
            poke.contains("PtracePokeFailure::Mutation")
                && poke.contains("PtracePokeFailure::Witness")
                && poke.contains("PtracePokeFailure::Write"),
            "the dispatcher must retain the failing authority layer through errno lowering",
        );
    }

    #[test]
    fn hvpatch_ptrace_poketext_rejects_prot_none_and_nonexecutable_ranges() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_155);
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);
        for (registry_id, access) in [
            (
                61_156,
                VmaAccess {
                    readable: false,
                    writable: false,
                    executable: false,
                    kernel_visible: true,
                },
            ),
            (
                61_157,
                VmaAccess {
                    readable: true,
                    writable: false,
                    executable: false,
                    kernel_visible: true,
                },
            ),
            (
                61_158,
                VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: false,
                },
            ),
        ] {
            let target = crate::kernel::consumer_cow_fixture(
                root.kernel(),
                &root,
                registry_id,
                vec![0; 0x4000],
            );
            target.set_vma_access_for_test(access);
            target.observe_caller_executor_census(dispatcher.mm_executor_census());
            arm_ptrace_memory_access(&root, target.target());
            let refreshed_root = refreshed(&root);
            assert_eq!(
                dispatch_with_lease(
                    &mut dispatcher,
                    &refreshed_root,
                    &mut memory,
                    SYS_PTRACE,
                    [
                        LINUX_PTRACE_POKETEXT,
                        target.target().task().key().id.raw() as u64,
                        TARGET_VA,
                        0,
                        0,
                        0,
                    ],
                    Some(&lease),
                ),
                DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            );
            assert_eq!(target.break_calls(), 0);
            assert_eq!(target.commit_calls(), 0);
        }
    }

    #[test]
    fn hvpatch_ptrace_memory_rejects_holes_stale_targets_and_non_tracers() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_124);
        let target = process_vm_target(&root, 61_125);
        let target_pid = target.task().key().id.raw();
        let root = refreshed(&root);
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "a live target without the exact tracer relation is not ptrace-accessible",
        );

        arm_ptrace_memory_access(&root, &target);
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_PEEKDATA,
                    target_pid as u64,
                    TARGET_VA + 0x1000,
                    0,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            "an unmapped foreign word lowers to EIO",
        );

        target
            .kernel()
            .exit_task(
                target.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit test task");
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
        );
    }

    #[test]
    fn hvpatch_ptrace_peektext_and_peekdata_are_equivalent() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_126);
        let target = process_vm_target_with_payload(&root, 61_127, b"WORDPAIR");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        let peektext = dispatch_with_lease(
            &mut dispatcher,
            &root,
            &mut memory,
            SYS_PTRACE,
            [LINUX_PTRACE_PEEKTEXT, target_pid as u64, TARGET_VA, 0, 0, 0],
            Some(&lease),
        );
        let peekdata = dispatch_with_lease(
            &mut dispatcher,
            &root,
            &mut memory,
            SYS_PTRACE,
            [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
            Some(&lease),
        );

        assert_eq!(
            peektext,
            DispatchOutcome::Returned {
                value: u64::from_le_bytes(*b"WORDPAIR") as i64,
            },
        );
        assert_eq!(peektext, peekdata);
    }

    #[test]
    fn hvpatch_ptrace_poketext_and_pokedata_are_equivalent_for_writable_mapping() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_128);
        let mut initial = vec![b'_'; 0x4000];
        initial[..8].copy_from_slice(b"initword");
        let target = crate::kernel::consumer_cow_fixture(root.kernel(), &root, 61_129, initial);
        target.observe_caller_executor_census(dispatcher.mm_executor_census());
        arm_ptrace_memory_access(&root, target.target());
        let root = refreshed(&root);
        let target_pid = target.target().task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        let poketext_val = u64::from_le_bytes(*b"POKETEXT");
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKETEXT,
                    target_pid as u64,
                    TARGET_VA,
                    poketext_val,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(target.child_bytes(0, 8), b"POKETEXT");

        let pokedata_val = u64::from_le_bytes(*b"POKEDATA");
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    pokedata_val,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(target.child_bytes(0, 8), b"POKEDATA");
    }

    #[test]
    fn hvpatch_ptrace_memory_rejects_missing_or_wrong_execution_lease() {
        let (_lane, mut dispatcher, _process, root, _root_lease) = bound_dispatcher(61_130);
        let (_other_lane, _other_dispatcher, _other_process, _other_root, wrong_lease) =
            bound_dispatcher(61_131);
        let target = process_vm_target_with_payload(&root, 61_132, b"LEASTEST");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                None,
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            "missing execution lease on ptrace memory read fails closed with EIO",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&wrong_lease),
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            "wrong execution lease on ptrace memory read fails closed with EIO",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234_5678,
                    0,
                    0,
                ],
                None,
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            "missing execution lease on ptrace memory write fails closed with EIO",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234_5678,
                    0,
                    0,
                ],
                Some(&wrong_lease),
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
            "wrong execution lease on ptrace memory write fails closed with EIO",
        );
    }

    #[test]
    fn hvpatch_ptrace_memory_rejects_traced_but_running_target() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_134);
        let target = process_vm_target_with_payload(&root, 61_135, b"RUNNING1");
        assert!(root.kernel().claim_ptrace_traceme(&target));
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "traced but running target must return ESRCH on peek",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "traced but running target must return ESRCH on poke",
        );
    }

    #[test]
    fn hvpatch_ptrace_memory_rejects_unaligned_word_address() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_136);
        let target = process_vm_target_with_payload(&root, 61_137, b"ALIGNWRD");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        for offset in 1..8 {
            assert_eq!(
                dispatch_with_lease(
                    &mut dispatcher,
                    &root,
                    &mut memory,
                    SYS_PTRACE,
                    [
                        LINUX_PTRACE_PEEKDATA,
                        target_pid as u64,
                        TARGET_VA + offset,
                        0,
                        0,
                        0,
                    ],
                    Some(&lease),
                ),
                DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
                "unaligned peek address must return EIO",
            );
            assert_eq!(
                dispatch_with_lease(
                    &mut dispatcher,
                    &root,
                    &mut memory,
                    SYS_PTRACE,
                    [
                        LINUX_PTRACE_POKEDATA,
                        target_pid as u64,
                        TARGET_VA + offset,
                        0x5678,
                        0,
                        0,
                    ],
                    Some(&lease),
                ),
                DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
                "unaligned poke address must return EIO",
            );
        }
    }

    #[test]
    fn hvpatch_ptrace_memory_enforces_target_authority_before_address_validation() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_138);
        let target = process_vm_target(&root, 61_139);
        let target_pid = target.task().key().id.raw();
        let root = refreshed(&root);
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                None,
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "untraced target must return ESRCH before execution-lease/MM acquisition",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234,
                    0,
                    0,
                ],
                None,
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "untraced POKE must return ESRCH before execution-lease/MM acquisition",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, 1, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "untraced target with unaligned address must return ESRCH before address validation",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, 99_999, 1, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "nonexistent target with unaligned address must return ESRCH",
        );
    }

    #[test]
    fn hvpatch_ptrace_memory_witness_rejects_resume_restop_aba() {
        let (_lane, _dispatcher, _process, root, _lease) = bound_dispatcher(61_151);
        let target = process_vm_target_with_payload(&root, 61_152, b"ABASTOP1");
        arm_ptrace_memory_access(&root, &target);
        let tracer_key = root.task().key();
        let target_key = target.task().key();

        let witness = root
            .kernel()
            .begin_ptrace_memory_access(tracer_key, target_key)
            .expect("settled stop must mint an exact access witness");

        assert!(
            root.kernel()
                .resume_task_from_ptrace(tracer_key, target_key.id, None)
        );
        let stop = crate::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(root.kernel().stop_task_for_ptrace(target_key.id, stop));
        assert_eq!(
            root.kernel().settle_task_ptrace_stop(target_key.id),
            crate::kernel::objects::PtraceStopSettlement::Stopped,
        );

        assert_eq!(
            witness.with_revalidated(|| ()),
            Err(LINUX_ESRCH),
            "a new settled stop must not revive an earlier memory-access capability",
        );
    }

    #[test]
    fn hvpatch_ptrace_cont_immediately_revokes_memory_access_before_settlement() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_140);
        let target = process_vm_target_with_payload(&root, 61_141, b"CONTTEST");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned {
                value: u64::from_le_bytes(*b"CONTTEST") as i64,
            },
        );

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [7, target_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "resumed tracee before settlement must reject peek with ESRCH",
        );
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "resumed tracee before settlement must reject poke with ESRCH",
        );
    }

    #[test]
    fn hvpatch_ptrace_peek_preserves_high_bit_and_all_ones_word() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_142);
        let target = process_vm_target_with_payload(&root, 61_143, &[0xff; 8]);
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: -1 },
            "all-ones word must return -1 as i64",
        );

        let high_bit_word: u64 = 0x8000_0000_0000_0000;
        let mut payload = [0u8; 8];
        payload.copy_from_slice(&high_bit_word.to_le_bytes());
        let target2 = process_vm_target_with_payload(&root, 61_144, &payload);
        arm_ptrace_memory_access(&root, &target2);
        let root = refreshed(&root);
        let target2_pid = target2.task().key().id.raw();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_PEEKDATA,
                    target2_pid as u64,
                    TARGET_VA,
                    0,
                    0,
                    0
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned {
                value: high_bit_word as i64,
            },
            "high-bit word must be preserved as i64",
        );
    }

    #[test]
    fn hvpatch_ptrace_memory_supports_clone_vm_distinct_task_same_mm() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_145);
        let child = clone_vm_child(&root, 61_146);
        arm_ptrace_memory_access(&root, &child);
        let root = refreshed(&root);
        let child_pid = child.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        memory.write_bytes(0x2000, b"CLONEVM1").unwrap();

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, child_pid as u64, 0x2000, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::Returned {
                value: u64::from_le_bytes(*b"CLONEVM1") as i64,
            },
            "peek on CLONE_VM shared memory child must read shared bytes",
        );

        let new_word = u64::from_le_bytes(*b"CLONEVM2");
        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    child_pid as u64,
                    0x2000,
                    new_word,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::Returned { value: 0 },
            "poke on CLONE_VM shared memory child must succeed",
        );

        assert_eq!(
            memory.read_bytes(0x2000, 8).unwrap(),
            b"CLONEVM2",
            "poked word must be visible in shared memory",
        );
    }

    #[test]
    fn hvpatch_ptrace_memory_rejects_unsettled_pending_stop_target() {
        let (_lane, mut dispatcher, _process, root, lease) = bound_dispatcher(61_149);
        let target = process_vm_target_with_payload(&root, 61_150, b"UNSETTLE");
        assert!(root.kernel().claim_ptrace_traceme(&target));
        let stop = crate::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(
            root.kernel()
                .stop_task_for_ptrace(target.task().key().id, stop)
        );
        // Note: settle_task_ptrace_stop is deliberately NOT called here!
        let root = refreshed(&root);
        let target_pid = target.task().key().id.raw();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x4000]);

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_PEEKDATA, target_pid as u64, TARGET_VA, 0, 0, 0],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "unsettled pending-stop target must return ESRCH on peek",
        );

        assert_eq!(
            dispatch_with_lease(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [
                    LINUX_PTRACE_POKEDATA,
                    target_pid as u64,
                    TARGET_VA,
                    0x1234,
                    0,
                    0,
                ],
                Some(&lease),
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
            "unsettled pending-stop target must return ESRCH on poke",
        );
    }

    #[test]
    fn hvpatch_ptrace_scoped_guard_blocks_concurrent_cont_and_detach() {
        let (_lane, _dispatcher, _process, root, _lease) = bound_dispatcher(61_147);
        let target = process_vm_target_with_payload(&root, 61_148, b"BLOCKING");
        arm_ptrace_memory_access(&root, &target);
        let root = refreshed(&root);
        let target_key = target.task().key();
        let tracer_key = root.task().key();
        let witness = root
            .kernel()
            .begin_ptrace_memory_access(tracer_key, target_key)
            .unwrap();

        // 1. Verify CONT is blocked while scoped guard is live
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            witness
                .with_revalidated(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });

        entered_rx.recv().unwrap();

        let (resumed_tx, resumed_rx) = std::sync::mpsc::channel();
        let kernel_clone2 = Arc::clone(root.kernel());
        let resume_thread = std::thread::spawn(move || {
            let res = kernel_clone2.resume_task_from_ptrace(tracer_key, target_key.id, None);
            resumed_tx.send(res).unwrap();
        });

        assert_eq!(
            resumed_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "resume must be blocked while scoped memory guard is live",
        );

        release_tx.send(()).unwrap();
        handle.join().unwrap();

        assert!(resume_thread.join().is_ok());
        assert!(resumed_rx.recv().unwrap());

        // 2. Re-arm and settle stop, then verify DETACH is blocked while scoped guard is live
        let stop = crate::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(root.kernel().stop_task_for_ptrace(target_key.id, stop));
        assert_eq!(
            root.kernel().settle_task_ptrace_stop(target_key.id),
            crate::kernel::objects::PtraceStopSettlement::Stopped,
        );
        let witness2 = root
            .kernel()
            .begin_ptrace_memory_access(tracer_key, target_key)
            .unwrap();

        let (entered_tx2, entered_rx2) = std::sync::mpsc::channel();
        let (release_tx2, release_rx2) = std::sync::mpsc::channel();

        let handle2 = std::thread::spawn(move || {
            witness2
                .with_revalidated(|| {
                    entered_tx2.send(()).unwrap();
                    release_rx2.recv().unwrap();
                })
                .unwrap();
        });

        entered_rx2.recv().unwrap();

        let (detached_tx, detached_rx) = std::sync::mpsc::channel();
        let kernel_clone4 = Arc::clone(root.kernel());
        let detach_thread = std::thread::spawn(move || {
            let res = kernel_clone4.detach_task_from_ptrace(tracer_key, target_key.id);
            detached_tx.send(res).unwrap();
        });

        assert_eq!(
            detached_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "detach must be blocked while scoped memory guard is live",
        );

        release_tx2.send(()).unwrap();
        handle2.join().unwrap();

        assert!(detach_thread.join().is_ok());
        assert!(detached_rx.recv().unwrap());
    }

    #[test]
    fn kernel_ptrace_attach_reports_guest_target_semantics() {
        let (_lane, mut dispatcher, _process, root, _lease) = bound_dispatcher(61_051);
        let child = fork_child(&root, 61_052);
        let root = refreshed(&root);
        let child_pid = child.task().key().id.raw();
        let root_pid = root.task().key().id.raw();
        let mut memory = LinearMemory::new(INFO_ADDR, vec![0; 0x100]);

        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_ATTACH, root_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM),
            "a task cannot attach to itself",
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_ATTACH, 99_999, 0, 0, 0, 0],
            ),
            DispatchOutcome::errno(LINUX_ESRCH),
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_ATTACH, child_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &root,
                &mut memory,
                SYS_PTRACE,
                [LINUX_PTRACE_ATTACH, child_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EPERM),
            "an already-traced task rejects a second attach",
        );
    }
}

#[cfg(test)]
mod native_virtual_ptrace_tests {
    use super::*;

    fn geometry(
        native_profile: Option<carrick_spec::NativePageProfile>,
    ) -> crate::page_profile::PageGeometry {
        crate::page_profile::PageGeometry {
            host_page_size: 16 * 1024,
            linux_page_size: native_profile.map_or(4096, |profile| match profile {
                carrick_spec::NativePageProfile::Native16k => 16 * 1024,
                carrick_spec::NativePageProfile::Linux4kOn16k => 4096,
            }),
            native_profile,
        }
    }

    #[test]
    fn native_profiles_select_virtual_ptrace_transport() {
        assert_eq!(
            select_ptrace_transport(
                geometry(Some(carrick_spec::NativePageProfile::Native16k)),
                false,
            ),
            PtraceTransport::VirtualNative
        );
        assert_eq!(
            select_ptrace_transport(
                geometry(Some(carrick_spec::NativePageProfile::Linux4kOn16k)),
                false,
            ),
            PtraceTransport::VirtualNative
        );
        assert_eq!(
            select_ptrace_transport(geometry(None), false),
            PtraceTransport::Host
        );
        assert_eq!(
            select_ptrace_transport(geometry(None), true),
            PtraceTransport::VirtualHvpatch
        );
    }

    #[test]
    fn outstanding_stop_lease_only_blocks_matching_wait_targets() {
        let pid = std::process::id();
        let pgid = unsafe { libc::getpgrp() };
        assert!(pgid > 0);

        assert!(ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(pid as i32),
        ));
        assert!(!ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(pid as i32 + 1),
        ));
        assert!(ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(-1),
        ));
        assert!(ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(0),
        ));
        assert!(ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(-pgid),
        ));
        assert!(!ptrace_wait_target_conflicts(
            pid,
            ptrace_wait_target_for_wait4(-(pgid + 1)),
        ));
    }

    #[test]
    fn virtual_stop_status_uses_linux_wait_encoding() {
        assert_eq!(virtual_ptrace_stop_status(19), 0x137f);
        assert_eq!(virtual_ptrace_stop_status(5), 0x057f);
    }

    #[test]
    fn hvpatch_waitid_decodes_linux_terminal_wait_status() {
        assert_eq!(hvpatch_waitid_exit_fields(7 << 8), (libc::CLD_EXITED, 7));
        assert_eq!(hvpatch_waitid_exit_fields(9), (libc::CLD_KILLED, 9));
        assert_eq!(
            hvpatch_waitid_exit_fields(11 | 0x80),
            (libc::CLD_DUMPED, 11)
        );
    }

    #[test]
    fn request_routing_keeps_host_traceme_and_virtualizes_native_control() {
        assert_eq!(
            route_ptrace_request(PtraceTransport::Host, 0, 0),
            Ok(PtraceRequestRoute::Host)
        );
        assert_eq!(
            route_ptrace_request(PtraceTransport::VirtualNative, 0, 0),
            Ok(PtraceRequestRoute::VirtualTraceme)
        );
        assert_eq!(
            route_ptrace_request(PtraceTransport::VirtualNative, 7, 0),
            Ok(PtraceRequestRoute::VirtualControl(
                VirtualPtraceControlRequest::Continue,
            ))
        );
        assert_eq!(
            route_ptrace_request(PtraceTransport::VirtualNative, 7, 9),
            Err(LINUX_EINVAL)
        );
    }

    #[test]
    fn only_native_nonterminal_wait_reports_defer_guest_cpu_drain() {
        assert!(should_drain_child_guest_cpu(PtraceTransport::Host, false));
        assert!(should_drain_child_guest_cpu(PtraceTransport::Host, true));
        assert!(!should_drain_child_guest_cpu(
            PtraceTransport::VirtualNative,
            false
        ));
        assert!(should_drain_child_guest_cpu(
            PtraceTransport::VirtualNative,
            true
        ));
    }
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

#[cfg(test)]
mod futex_timeout_tests {
    use super::*;
    use crate::thread::{FutexTable, ThreadRegistry};
    use std::time::Duration;

    /// A present (non-NULL) `{tv_sec:0, tv_nsec:0}` `FUTEX_WAIT` timeout means
    /// "expire NOW" (ETIMEDOUT immediately), NOT "block forever" (the NULL-timeout
    /// case). Collapsing `{0,0}` to "no deadline" made the threaded futex park
    /// compute no deadline and spin forever (futex_wait03 hung ~110s). Guard the
    /// fix at the handler: the parked `FutexWait` must carry `Some(Duration::ZERO)`
    /// (a deadline of `now`), never `None`.
    #[test]
    fn futex_wait_zero_but_present_timeout_parks_with_zero_deadline() {
        use crate::linux_abi::LINUX_FUTEX_PRIVATE_FLAG;

        let dispatcher = SyscallDispatcher::new();
        let reporter = CompatReporter::default();
        let registry = ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(10));
        let futex = FutexTable::new();
        // A live sibling so the process is genuinely multi-threaded.
        registry.register_child(0);

        let word_addr = 0x10800u64;
        let timeout_addr = 0x10810u64;
        let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
        // Futex word == the expected value, so WAIT does not short-circuit to
        // EAGAIN and must consult the timeout.
        memory.write_bytes(word_addr, &7u32.to_le_bytes()).unwrap();
        // A present (non-NULL) timespec of {0, 0}.
        memory.write_bytes(timeout_addr, &[0u8; 16]).unwrap();

        let thread = ThreadCtx {
            tid: crate::thread::ThreadId::synthetic_for_tests(10),
            registry: &registry,
            futex: &futex,
        };
        let out = dispatcher
            .dispatch_normalized(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        word_addr,
                        LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG,
                        7,
                        timeout_addr,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
                Some(thread),
            )
            .expect("the futex handler claims syscall 98")
            .expect("futex dispatch must not be a fatal DispatchError");

        match out {
            DispatchOutcome::FutexWait { timeout, .. } => assert_eq!(
                timeout,
                Some(Duration::ZERO),
                "a present {{0,0}} timeout must park with a zero deadline (expire now), \
                 not None (block forever)"
            ),
            other => panic!("expected a FutexWait park outcome, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod process_vm_copy_tests {
    use super::*;

    const BASE: u64 = 0x10000;
    const SRC: u64 = 0x10000;
    const DST: u64 = 0x10800;

    /// A LinearMemory seeded so `[SRC, SRC+256)` holds the ramp `i % 256` and the
    /// destination window is zero.
    fn seeded_memory() -> LinearMemory {
        let mut memory = LinearMemory::new(BASE, vec![0u8; 0x1000]);
        let ramp: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        memory.write_bytes(SRC, &ramp).unwrap();
        memory
    }

    /// Scatter: one 100-byte source spread across three uneven destination
    /// iovecs. Every byte lands contiguously and the count is the transferred
    /// total (readv02/03 use exactly this many-to-few / few-to-many shape).
    #[test]
    fn scatter_one_source_into_three_dests() {
        let mut memory = seeded_memory();
        let src = [LinuxIovec::new(SRC, 100)];
        let dst = [
            LinuxIovec::new(DST, 30),
            LinuxIovec::new(DST + 0x40, 30),
            LinuxIovec::new(DST + 0x80, 40),
        ];
        let n = process_vm_copy_self(&mut memory, &src, &dst).unwrap();
        assert_eq!(n, 100);
        assert_eq!(
            memory.read_bytes(DST, 30).unwrap(),
            (0..30u8).collect::<Vec<_>>()
        );
        assert_eq!(
            memory.read_bytes(DST + 0x40, 30).unwrap(),
            (30..60u8).collect::<Vec<_>>()
        );
        assert_eq!(
            memory.read_bytes(DST + 0x80, 40).unwrap(),
            (60..100u8).collect::<Vec<_>>()
        );
    }

    /// The transfer stops at the shorter flattened length: 100 source bytes into
    /// a 50-byte destination copies 50 (Linux `min(local, remote)`).
    #[test]
    fn copies_only_the_shorter_length() {
        let mut memory = seeded_memory();
        let src = [LinuxIovec::new(SRC, 100)];
        let dst = [LinuxIovec::new(DST, 50)];
        let n = process_vm_copy_self(&mut memory, &src, &dst).unwrap();
        assert_eq!(n, 50);
        assert_eq!(
            memory.read_bytes(DST, 50).unwrap(),
            (0..50u8).collect::<Vec<_>>()
        );
    }

    /// A source address outside the backing faults before any byte moves — the
    /// process_vm01 `iov_base = -1` / PROT_NONE cases must be EFAULT, not a
    /// zero-length success.
    #[test]
    fn first_access_fault_is_efault() {
        let mut memory = seeded_memory();
        let src = [LinuxIovec::new(0x9_0000, 10)];
        let dst = [LinuxIovec::new(DST, 10)];
        assert_eq!(
            process_vm_copy_self(&mut memory, &src, &dst),
            Err(LINUX_EFAULT)
        );
    }

    /// Zero total on either side is a valid 0-byte transfer (the setup sanity
    /// probe `process_vm_readv(getpid(), NULL, 0, NULL, 0, 0)`), never EFAULT.
    #[test]
    fn empty_vectors_transfer_zero_bytes() {
        let mut memory = seeded_memory();
        assert_eq!(process_vm_copy_self(&mut memory, &[], &[]).unwrap(), 0);
        let src = [LinuxIovec::new(SRC, 100)];
        assert_eq!(process_vm_copy_self(&mut memory, &src, &[]).unwrap(), 0);
    }
}

#[cfg(test)]
mod process_identity_dispatch_tests {
    use super::*;
    use crate::compat::CompatReporter;
    use crate::kernel::{ClonePlan, KernelContext, LinuxWaitStatus, WaitMode};
    use crate::thread::ThreadId;

    const SYS_SETPGID: u64 = 154;
    const SYS_GETPGID: u64 = 155;
    const SYS_GETSID: u64 = 156;
    const SYS_SETSID: u64 = 157;

    fn fork_child(parent: &KernelContext, registry_id: i32) -> KernelContext {
        parent
            .kernel()
            .reserve_fork(
                parent,
                ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap(),
                format!("identity-child-{registry_id}"),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(registry_id))
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0
    }

    /// Re-read a caller's own context after the graph has moved underneath it,
    /// the way the trap loop captures a fresh one per syscall.
    fn refreshed(context: &KernelContext) -> KernelContext {
        context
            .kernel()
            .context(context.task().key().id, context.thread().key().tid)
            .unwrap()
    }

    fn call(
        dispatcher: &mut SyscallDispatcher,
        caller: &KernelContext,
        number: u64,
        arg: i64,
    ) -> DispatchOutcome {
        call_args(dispatcher, caller, number, [arg as u64, 0, 0, 0, 0, 0])
    }

    fn call_args(
        dispatcher: &mut SyscallDispatcher,
        caller: &KernelContext,
        number: u64,
        args: [u64; 6],
    ) -> DispatchOutcome {
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
        dispatcher
            .dispatch(
                caller,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                &mut memory,
                &CompatReporter::default(),
            )
            .unwrap()
    }

    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("expected a value, got {other:?}"),
        }
    }

    #[test]
    fn container_pid_identity_isolated() {
        use std::sync::Arc;

        use carrick_kernel::arena::KernelArena;

        use crate::kernel::{Container, Kernel, LaunchContext, RootBootstrap, RunId};
        use crate::namespace::pid::NsSharedRegion;

        let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
        let alpha_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "identity-alpha",
        ))));
        alpha_container
            .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid region"))
            .expect("install alpha pid region");
        let alpha_bootstrap = RootBootstrap::for_reference_model(
            8_700,
            ThreadId::synthetic_for_tests(8_700),
            "identity-alpha-init".to_owned(),
        )
        .expect("alpha bootstrap")
        .with_container(Arc::clone(&alpha_container));
        let (kernel, alpha) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");

        let beta_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "identity-beta",
        ))));
        beta_container
            .install_pid_ns(NsSharedRegion::allocate(arena).expect("beta pid region"))
            .expect("install beta pid region");
        let beta = kernel
            .prepare_container_root(
                ThreadId::synthetic_for_tests(8_701),
                None,
                "identity-beta-init".to_owned(),
                beta_container,
                None,
            )
            .expect("prepare beta")
            .commit()
            .expect("commit beta");
        let mut dispatcher = SyscallDispatcher::new();

        for context in [&alpha, &beta] {
            assert_eq!(returned(call(&mut dispatcher, context, 172, 0)), 1);
            assert_eq!(returned(call(&mut dispatcher, context, 178, 0)), 1);
            assert_eq!(returned(call(&mut dispatcher, context, SYS_GETPGID, 0)), 1);
            assert_eq!(returned(call(&mut dispatcher, context, SYS_GETSID, 0)), 1);
            let core = dispatcher
                .core_process_snapshot(context)
                .expect("namespace-visible core identity");
            assert_eq!(core.identity.pid, 1);
            assert_eq!(core.identity.ppid, 0);
            assert_eq!(core.identity.pgrp, 1);
            assert_eq!(core.identity.session, 1);
        }
        assert_eq!(
            crate::namespace::pid::ns_to_process_group_for(&alpha, 1),
            Some(alpha.task().process_group())
        );
        assert_eq!(
            crate::namespace::pid::ns_to_process_group_for(&beta, 1),
            Some(beta.task().process_group())
        );
        assert_eq!(
            crate::namespace::pid::process_group_to_ns_for(&alpha, beta.task().process_group()),
            None,
            "another container's internal group key is invisible",
        );
        assert_eq!(
            crate::namespace::pid::ns_to_session_for(&alpha, 1),
            Some(alpha.task().session())
        );
        assert_eq!(
            crate::namespace::pid::session_to_ns_for(&alpha, beta.task().session()),
            None,
            "another container's internal session key is invisible",
        );

        let beta_internal = i64::from(beta.task().key().id.raw());
        assert!(matches!(
            call(&mut dispatcher, &alpha, SYS_GETPGID, beta_internal),
            DispatchOutcome::Errno { errno } if errno == LINUX_ESRCH
        ));
        assert!(matches!(
            call(&mut dispatcher, &alpha, SYS_GETSID, beta_internal),
            DispatchOutcome::Errno { errno } if errno == LINUX_ESRCH
        ));
    }

    /// `getpgid`/`getsid`/`setpgid`/`setsid` must describe the process that
    /// CALLED them, and must keep describing an exited child until it is reaped.
    ///
    /// This needs three live processes to say anything. Every one of these
    /// syscalls used to be answered by Darwin — `libc::getpgid(0)` and friends
    /// on the calling HOST process. Under HVPatch that is the VM carrier, one
    /// process shared by every logical guest process, so all three callers here
    /// received the same number and a `setpgid` from one would have moved all of
    /// them at once. With a single task the two readings are indistinguishable:
    /// the caller is the only process, so "the carrier's group" and "my group"
    /// are the same answer, which is why the existing single-process job-control
    /// assertions passed with the bug in place.
    #[test]
    fn identity_syscalls_answer_the_calling_process_and_outlive_its_exit() {
        let mut dispatcher = SyscallDispatcher::new();
        let root = dispatcher.capture_one_task_context().unwrap();
        let first = fork_child(&root, 8801);
        let root = refreshed(&root);
        let second = fork_child(&root, 8802);
        let root = refreshed(&root);
        let (first_pid, second_pid) = (
            i64::from(first.task().key().id.raw()),
            i64::from(second.task().key().id.raw()),
        );
        assert_ne!(first_pid, second_pid);

        // Both children inherit the forking process's group and session.
        let root_group = returned(call(&mut dispatcher, &root, SYS_GETPGID, 0));
        assert_eq!(
            returned(call(&mut dispatcher, &first, SYS_GETPGID, 0)),
            root_group
        );
        assert_eq!(
            returned(call(&mut dispatcher, &second, SYS_GETPGID, 0)),
            root_group
        );

        // One child leaves for a group of its own. Only that child moves.
        assert_eq!(returned(call(&mut dispatcher, &first, SYS_SETPGID, 0)), 0);
        let first = refreshed(&first);
        let first_group = returned(call(&mut dispatcher, &first, SYS_GETPGID, 0));
        assert_eq!(first_group, first_pid, "a new group is led by its creator");
        assert_eq!(
            returned(call(&mut dispatcher, &second, SYS_GETPGID, 0)),
            root_group
        );
        assert_ne!(first_group, root_group);

        // A peer asking about that child gets the child's group, not its own.
        assert_eq!(
            returned(call(&mut dispatcher, &second, SYS_GETPGID, first_pid)),
            first_group
        );

        // A new session detaches only its creator, and a peer observes it.
        let root_session = returned(call(&mut dispatcher, &root, SYS_GETSID, 0));
        assert_eq!(
            returned(call(&mut dispatcher, &first, SYS_GETSID, 0)),
            root_session,
            "changing groups does not change sessions",
        );
        assert_eq!(
            returned(call(&mut dispatcher, &second, SYS_SETSID, 0)),
            second_pid
        );
        let second = refreshed(&second);
        assert_eq!(
            returned(call(&mut dispatcher, &second, SYS_GETSID, 0)),
            second_pid
        );
        assert_eq!(
            returned(call(&mut dispatcher, &root, SYS_GETSID, second_pid)),
            second_pid
        );
        assert_ne!(root_session, second_pid);

        // An exited child stays addressable until its parent reaps it: `wait(2)`
        // removes a process from the table, `_exit(2)` does not.
        root.kernel()
            .prepare_task_exit(
                first.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            returned(call(&mut dispatcher, &root, SYS_GETPGID, first_pid)),
            first_group,
            "an unreaped child still reports the group it exited in",
        );
        root.kernel()
            .wait_child(
                root.task().key().id,
                Some(first.task().key().id),
                WaitMode::Consume,
            )
            .unwrap();
        assert_eq!(
            call(&mut dispatcher, &root, SYS_GETPGID, first_pid),
            DispatchOutcome::errno(LINUX_ESRCH),
            "a reaped child is gone from the process table",
        );
    }

    #[test]
    fn live_groups_and_session_keep_their_namespace_ids_after_leader_reap() {
        use std::sync::Arc;

        use carrick_kernel::arena::KernelArena;

        use crate::kernel::{Container, Kernel, LaunchContext, RootBootstrap, RunId};
        use crate::namespace::pid::NsSharedRegion;

        let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
        let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "job-identity-lifetime",
        ))));
        let region = NsSharedRegion::allocate(arena).expect("pid region");
        container
            .install_pid_ns(Arc::clone(&region))
            .expect("install pid region");
        let bootstrap = RootBootstrap::for_reference_model(
            8_800,
            ThreadId::synthetic_for_tests(8_800),
            "job-identity-init".to_owned(),
        )
        .expect("root bootstrap")
        .with_container(container);
        let (kernel, root) = Kernel::bootstrap_root(bootstrap).expect("root");
        let mut dispatcher = SyscallDispatcher::new();

        let leader = fork_child(&root, 8_801);
        let leader_pid = returned(call(&mut dispatcher, &leader, 172, 0));
        assert_eq!(leader_pid, 2);
        assert_eq!(returned(call(&mut dispatcher, &leader, SYS_SETSID, 0)), 2);
        let leader = refreshed(&leader);

        let first_group_member = fork_child(&leader, 8_802);
        let leader = refreshed(&leader);
        let second_group_member = fork_child(&leader, 8_803);
        assert_eq!(
            returned(call(&mut dispatcher, &second_group_member, SYS_SETPGID, 0)),
            0
        );
        let second_group_member = refreshed(&second_group_member);
        assert_eq!(
            returned(call(&mut dispatcher, &second_group_member, SYS_GETPGID, 0)),
            4
        );

        kernel
            .prepare_task_exit(
                leader.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare leader exit")
            .commit()
            .expect("publish leader exit");
        kernel
            .wait_child(
                root.task().key().id,
                Some(leader.task().key().id),
                WaitMode::Consume,
            )
            .expect("consume leader exit");
        assert_eq!(region.ns_to_host(leader_pid as u32), None);

        assert_eq!(
            returned(call(&mut dispatcher, &first_group_member, SYS_GETPGID, 0)),
            leader_pid,
            "the surviving leader group keeps its namespace-visible pgid",
        );
        assert_eq!(
            returned(call(&mut dispatcher, &second_group_member, SYS_GETSID, 0)),
            leader_pid,
            "a second live group keeps the reaped leader's session id",
        );
        assert_eq!(
            call_args(
                &mut dispatcher,
                &second_group_member,
                SYS_SETPGID,
                [0, leader_pid as u64, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
            "setpgid can still name the existing leader group",
        );
        let second_group_member = refreshed(&second_group_member);
        assert_eq!(
            returned(call(&mut dispatcher, &second_group_member, SYS_GETPGID, 0)),
            leader_pid,
        );

        kernel
            .prepare_task_exit(
                first_group_member.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare first member exit")
            .commit()
            .expect("publish first member exit");
        kernel
            .wait_child(
                root.task().key().id,
                Some(first_group_member.task().key().id),
                WaitMode::Consume,
            )
            .expect("consume first member exit");

        let second_pid = returned(call(&mut dispatcher, &second_group_member, 172, 0));
        kernel
            .prepare_task_exit(
                second_group_member.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare last member exit")
            .commit()
            .expect("publish last member exit");

        let root = refreshed(&root);
        assert_eq!(
            returned(call(&mut dispatcher, &root, SYS_GETPGID, second_pid)),
            leader_pid,
            "a zombie keeps the retired process group's namespace identity",
        );
        assert_eq!(
            returned(call(&mut dispatcher, &root, SYS_GETSID, second_pid)),
            leader_pid,
            "a zombie keeps the retired session's namespace identity",
        );
    }

    #[test]
    fn pidfd_open_status_flags_and_nonblock_wait() {
        let dispatcher = SyscallDispatcher::new();
        let my_pid = unsafe { libc::getpid() };
        const PIDFD_NONBLOCK: u64 = 0o4000;

        // 1. open_pidfd with 0 -> default is LINUX_O_RDWR, no O_NONBLOCK
        let outcome_def = dispatcher.open_pidfd(my_pid, 0);
        let fd_def = match outcome_def {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("expected fd, got {other:?}"),
        };
        assert!(fd_def >= 0);
        let open_def = dispatcher.open_file(fd_def).expect("open file");
        let fl = open_def.description.common().status_flags();
        assert_eq!(fl & LINUX_O_NONBLOCK, 0, "default pidfd has no O_NONBLOCK");
        assert_eq!(fl & LINUX_O_ACCMODE, LINUX_O_RDWR, "pidfd has O_RDWR");
        assert!(!dispatcher.pidfd_is_nonblocking(fd_def));

        // 2. open_pidfd with PIDFD_NONBLOCK -> has O_NONBLOCK
        let outcome_nb = dispatcher.open_pidfd(my_pid, PIDFD_NONBLOCK);
        let fd_nb = match outcome_nb {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("expected fd, got {other:?}"),
        };
        assert!(fd_nb >= 0);
        let open_nb = dispatcher.open_file(fd_nb).expect("open file");
        let fl_nb = open_nb.description.common().status_flags();
        assert_ne!(
            fl_nb & LINUX_O_NONBLOCK,
            0,
            "nonblocking pidfd has O_NONBLOCK"
        );
        assert_eq!(fl_nb & LINUX_O_ACCMODE, LINUX_O_RDWR, "pidfd has O_RDWR");
        assert!(dispatcher.pidfd_is_nonblocking(fd_nb));

        // 3. F_SETFL logic can toggle O_NONBLOCK on the pidfd description
        let mutable_flags = LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_ASYNC;
        let next_flags = (fl & LINUX_O_ACCMODE) | ((fl | LINUX_O_NONBLOCK) & mutable_flags);
        open_def.description.common().set_status_flags(next_flags);
        assert!(dispatcher.pidfd_is_nonblocking(fd_def));
        let next_flags_clear = (fl & LINUX_O_ACCMODE) | (fl & mutable_flags);
        open_def
            .description
            .common()
            .set_status_flags(next_flags_clear);
        assert!(!dispatcher.pidfd_is_nonblocking(fd_def));
    }
}
