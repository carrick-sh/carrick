//! USDT probe definitions and safe wrapper functions for Carrick runtime
//! observability.

use crate::compat::{CompatEvent, SyscallArgs};

/// USDT probes for the carrick provider. The `usdt` crate's hard cap is
/// 6 args per probe, so syscall args ride as a `&SyscallArgs` reference
/// — usdt JSON-encodes it through serde and passes the resulting
/// C-string pointer to DTrace. Consumers use `copyinstr(argN)` to read
/// the JSON (looks like `[v0,v1,v2,v3,v4,v5]`).
#[usdt::provider(provider = "carrick")]
mod carrick_usdt {
    use crate::compat::SyscallArgs;

    // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6], contiguous); DTrace
    // does `copyin(arg2, 48)` and reads the six args by offset. This probe
    // fires on EVERY guest syscall, so we must NOT JSON-encode here — that
    // string-builds on every fire even for a script that only wants one
    // syscall, which is what made `carrick trace` slow (DTrace itself is
    // production-safe; the cost was ours). Same raw-pointer trick as
    // `vcpu__trap`.
    fn syscall__entry(_: u64, _: &str, _: u64) {}
    fn syscall__return(_: u64, _: &str, _: i64, _: i32) {}
    // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6]); DTrace copyin's 48
    // bytes — same raw-pointer convention as `syscall__entry`, no JSON.
    fn unhandled__syscall(_: u64, _: &str, _: u64) {}
    fn partial__syscall(_: u64, _: &str, _: u64, _: &str) {}
    fn unhandled__ioctl(_: i32, _: u64, _: u64) {}
    fn proc__read__unimplemented(_: &str) {}
    fn sys__read__unimplemented(_: &str) {}
    fn signal__unsupported(_: i32, _: &str) {}
    // pid, signum, generation — fires when an interval-timer thread publishes.
    fn itimer__fire(_: u32, _: i32, _: u64) {}
    /// Fires on every guest syscall that passes flag bits we don't
    /// recognise. Catches Linux ABI drift loudly instead of letting
    /// the dispatcher silently drop behaviour the guest expected.
    fn unknown__syscall__flags(_: u64, _: &str, _: u32, _: u64) {}
    /// Fires before `libc::fork` from the trap engine's clone path.
    /// Args are the captured pre-fork vCPU PC, ELR_EL1, and CPSR.
    fn fork__pre(_: u64, _: u64, _: u64) {}
    /// Fires after the parent/child have rebuilt their HVF context and
    /// restored the snapshot. `pid` is the libc::fork return value
    /// (0 in the child, child pid in the parent).
    fn fork__post(_: i32, _: u64, _: u64) {}
    /// Fork stop-the-world quiesce trace. `phase`: 0=begin (a=others to wait
    /// for, b=kicker live count), 1=quiesce TIMEOUT (a=others, b=paused),
    /// 2=hv_vm_destroy result (a=rc — NONZERO means a vCPU was still live, the
    /// HV_BUSY root cause), 3=vcpu_create result in a sibling rebuild / spawn
    /// (a=rc, b=site: 0=rebuild 1=spawn). `tid` is the acting thread.
    fn fork__quiesce(_: i32, _: i64, _: i64, _: i32) {}
    /// Fires every syscall trap. `arg0` is the ADDRESS of a
    /// `compat::GuestRegs` (`#[repr(C)]`); DTrace does
    /// `copyin(arg0, sizeof(gregs_t))` and reads fields by offset. A
    /// raw pointer (not JSON) keeps this hot probe cheap and lets D
    /// read full u64 register values exactly.
    fn vcpu__trap(_: u64) {}
    /// Fires when a guest EL0 sync exception other than `svc #0` reaches the
    /// trap loop (the fatal `EL0Fault` path) — an instruction/data abort or
    /// undefined instruction that crashes the guest. Args: `esr`, `elr`, `far`,
    /// `x30`(LR), `sp`(SP_EL0), `tid`. Fires only on the fault, so a
    /// `carrick trace` script can `--stack`-walk the faulting guest thread with
    /// near-zero hot-path overhead (it never fires on the happy path). The key
    /// diagnostic for the c>=20 sibling-vCPU corruption faults.
    fn vcpu__fault(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
    /// Companion to `vcpu__fault` carrying the decoded fault diagnostics as
    /// SCALARS (captured at probe-fire time — robust even when the fault kills
    /// the process immediately, unlike a copyin-a-pointer probe whose action
    /// runs too late). `insn` is the faulting instruction word (read host-side
    /// at `elr` — DTrace can't copyin a guest VA); `rn` is the base register a
    /// load/store dereferenced (`(insn>>5)&0x1f`); `xrn` is that register's
    /// value, BEST-EFFORT (read after the EL1 trap trampoline, which may have
    /// clobbered it). The AUTHORITATIVE faulting pointer is `far` (HW-latched):
    /// for a data abort `far == base + imm`, so a `ldr xN,[xN,#8]` with far=0x19
    /// means the base held 0x11=17. Lets a trace see the faulting access
    /// WITHOUT an eprintln rebuild. Fires only at the fault.
    fn vcpu__fault__regs(_: u64, _: u64, _: u64, _: u64, _: u32, _: u64) {}
    /// Fires from `map_host_alias` (the post-boot high-VA hv_vm_map path) with
    /// the MANAGER's L0..L3 stage-1 descriptors for the alias VA + whether this
    /// is a forked child and whether the page-table build succeeded (rc: 0 ok,
    /// else nonzero). Diagnoses why a forked child's alias mapping diverges from
    /// the parent's. Fires only on this path (no hot-path cost).
    fn pt__alias__walk(_: u64, _: u64, _: u64, _: u64, _: u64, _: i32) {}
    /// Fires when a signal is published for later delivery. `target_tid` is the
    /// guest tid for a thread-directed signal (tkill/tgkill route) or 0 for a
    /// process-directed one; `signum` the Linux signum; `kind` 1=thread-directed
    /// 0=process-directed. Lets `carrick trace` see WHERE a signal was routed
    /// (vs which tid actually drains it via `signal-deliver`) — the missing
    /// visibility for the cross-thread / blocked-thread delivery bugs.
    fn signal__publish(_: i32, _: i32, _: i32) {}
    /// Fires at each `deliver_pending_signal` cycle. `tid` is the delivering
    /// thread; `pending` the signum it drained (0 = nothing deliverable to it).
    /// Pair with `signal-publish` to see a signal published for tid X but never
    /// drained by X (the routing/tid-mismatch and blocked-thread cases).
    fn signal__deliver(_: i32, _: i32) {}
    /// Fires when `execve_into` has finished swapping the engine to
    /// the new image. `path`, `entry`, `initial_sp`, `mapping_count`
    /// let dtrace operators verify the new process layout.
    fn execve__loaded(_: &str, _: u64, _: u64, _: u64) {}
    /// Fires at the tail of `execve_into` with the actual SCTLR/TTBR0/
    /// MAIR values read back from HVF. Use this to verify the new
    /// process's stage-1 MMU state matches what the fresh-from-cli
    /// case sets up.
    fn execve__sysregs(_: u64, _: u64, _: u64) {}
    /// Fires every time the dispatcher's `open_at_path` resolves a
    /// guest path. `pid` is the carrick-host pid (so the parent vs
    /// forked-children streams are demultiplexable). `result_size`
    /// is the bytes returned (for File) or `0` (for Directory /
    /// errno). `errno` is `0` on success.
    fn path__open(_: u32, _: &str, _: u64, _: i32) {}
    /// Fires when a guest process exits via exit_group. `pid` is the
    /// carrick-host pid; correlate with `execve__loaded` (same pid) to
    /// see which binary exited with which code.
    fn guest__exit(_: u32, _: i32) {}
    /// Fires on execve with the joined argv (space-separated), so
    /// dtrace operators can see exactly how the guest invokes a
    /// child (e.g. apt's sqv method calling /usr/bin/sqv).
    fn execve__argv(_: u32, _: &str, _: &str) {}
    /// Host-pipe I/O: `dir` is 0 for read, 1 for write; `n` is the
    /// byte count (negative on error). Used to trace whether a forked
    /// child's stdout actually reaches the parent's pipe read.
    fn host__pipe__io(_: u32, _: i32, _: i32, _: i64) {}
    /// epoll_ctl decision: decoded guest event values without forcing DTrace
    /// scripts to copyin guest memory. `errno` is zero on success.
    fn epoll__ctl(_: i32, _: u64, _: i32, _: u32, _: u64, _: i32) {}
    /// Per-interest epoll_pwait readiness decision. `requested`, `raw_ready`,
    /// `last_ready`, and `ready` are Linux epoll event bitmasks.
    fn epoll__interest(_: i32, _: i32, _: u32, _: u32, _: u32, _: u32) {}
    /// Host-backed fd that epoll_pwait hands to the runtime's kqueue waiter.
    /// `poll_events` is the libc POLL* mask used to build EVFILT registrations.
    fn epoll__wait__fd(_: i32, _: i32, _: i32, _: i32, _: i32) {}
    /// epoll_pwait result decision. `kind` is 0 for immediate guest return and
    /// 1 for WaitOnFds handoff.
    fn epoll__result(_: i32, _: i32, _: i32, _: i32, _: i32) {}
    /// Runtime blocking-I/O wait begin. `tid` is the guest thread id,
    /// `timeout_ms` is -1 for infinite, and fd0/events0 + fd1/events1 are the
    /// first two host fd wait targets.
    fn io__wait__begin(_: i32, _: i32, _: i64, _: i32, _: i32, _: i32) {}
    /// Runtime blocking-I/O wait end. `result` is 0=Ready, 1=TimedOut,
    /// 2=Interrupted; fd0/fd1/fd2 are the first host fds from the wait set.
    fn io__wait__end(_: i32, _: i32, _: i32, _: i32, _: i32, _: i32) {}
    /// Fires on a filesystem-backend decision/outcome. `op` names the
    /// operation + result (e.g. "set_times:ok", "set_times:open_none",
    /// "set_times:futimens_err", "unlink", "rename"), `path` is the
    /// resolved guest path, `errno` is the Linux errno carrick returns
    /// (0 on success). Lets `carrick trace` see WHY a host-backed fs
    /// syscall returned an errno — the internal reason invisible to the guest.
    fn fs__op(_: u32, _: &str, _: &str, _: i32) {}
    /// Fires when a guest signal handler frame is injected. `signum` is the
    /// Linux signal, `saved_pc` the pre-signal PC stored in the sigframe (the
    /// PC the eventual rt_sigreturn must restore), `new_sp` the SP_EL0 the
    /// frame was written at, `handler` the guest handler entry. Lets a trace
    /// see exactly what state is captured for later restore.
    fn signal__inject(_: i32, _: u64, _: u64, _: u64) {}
    /// Fires inside rt_sigreturn/restore. `saved_pc` is the PC about to be
    /// restored into ELR_EL1, `sp` the SP_EL0 the frame was read from,
    /// `magic` the frame magic read back. A corrupted `saved_pc` or `magic`
    /// here pinpoints sigframe corruption (the "PROT_REA" wild-PC crash).
    fn signal__restore(_: u64, _: u64, _: u64) {}
    /// Fires when a cross-thread kick (`hv_vcpus_exit`) lands while the vCPU is
    /// still executing carrick's EL1 trap trampoline (not at guest EL0). `pc` is
    /// the EL1 PC, `el` the current exception level (1+). carrick resumes
    /// instead of injecting a signal at this non-guest PC; a nonzero rate here
    /// is the signal-vs-trampoline race being correctly absorbed.
    fn kick__in_kernel(_: u64, _: u32) {}
    /// Cumulative kick/inject counters fired once at process exit (cheap, one
    /// fire per process) so a trace can read the totals without paying the
    /// per-event `kick-in-kernel` cost: `el1_resumed` (kicks absorbed in the
    /// EL1 trampoline), `kick_inject` (EL0 kick-path signal injections),
    /// `inject_at_el1` (carrick-vs-guest invariant violations — must be 0).
    fn kick__stats(_: u64, _: u64, _: u64) {}
    /// Reusable guest-memory watchpoint. When `CARRICK_WATCH_ADDR=<hex>` is
    /// set, fires before EVERY syscall with (`syscall_nr`, `addr`, the current
    /// little-endian u64 at `addr`). Lets a trace bracket exactly which
    /// syscall a guest address changes across — e.g. which operation corrupts
    /// a GOT slot. Zero-cost (and not even read) when the env var is unset.
    fn mem__watch(_: u64, _: u64, _: u64) {}
    /// Fires in rt_sigaction with the first four u64 words the guest passed in
    /// its `struct sigaction` (offsets 0/8/16/24). Lets a trace see the exact
    /// on-the-wire layout — sa_handler, sa_flags, and whether offset 16 is
    /// sa_restorer (glibc-style) or sa_mask (aarch64 kernel ABI, no restorer).
    fn sigaction__read(_: i32, _: u64, _: u64, _: u64, _: u64) {}
    /// Fires when the interactive session supervisor forks the Carrick runtime
    /// child. Distinct from guest fork-post; this is the host-side `run -t`
    /// process boundary.
    fn supervisor__fork(_: i32) {}
    /// Fires when the runtime child has moved into its own process group and
    /// is waiting for the supervisor to make that pgrp foreground.
    fn supervisor__child__ready(_: i32) {}
    /// Fires after the supervisor attempts to make the runtime child pgrp the
    /// pty foreground group. `errno` is 0 on success.
    fn supervisor__foreground__pgrp(_: i32, _: i32) {}
    /// Fires when the supervisor reaps the runtime child.
    fn supervisor__child__exit(_: i32, _: i32) {}
    /// Page-table-edit Pause-Modify-Resume tracing. carrick (the VMM) edits the
    /// guest's shared stage-1 descriptors from the host while sibling vCPUs run;
    /// these probes let a `carrick trace` PROVE the stop-the-world engages and
    /// converges (rather than guessing).
    ///  * `pt__pause__begin`: an editing vCPU became the sole coordinator.
    ///    `tid` editor, `others_in_guest` siblings still walking tables at entry,
    ///    `count` live vCPUs.
    ///  * `pt__pause__ready`: all siblings left guest; the edit may proceed.
    ///    `spins` wait iterations, `wait_us` microseconds waited.
    ///  * `pt__pause__timeout`: the convergence deadline was hit. MUST never
    ///    fire — a nonzero rate means a sibling stayed in guest (exactly the
    ///    corruption PMR prevents). `wait_us` is the deadline budget.
    ///  * `pt__pause__end`: the pause was released and siblings resumed. `tid`.
    fn pt__pause__begin(_: i32, _: i32, _: i32) {}
    fn pt__pause__ready(_: i32, _: i32, _: i64) {}
    fn pt__pause__timeout(_: i32, _: i64) {}
    fn pt__pause__end(_: i32) {}
    /// Stage-1 spare sub-table pool occupancy, fired after each table edit.
    /// `in_use` live split tables, `free_list` reclaimable pages, `capacity`
    /// total spare pages. A rising `in_use` toward `capacity` is the
    /// coalesce-disabled pool leak; flat `in_use` proves coalescing keeps it
    /// bounded. `changed` is 1 if this edit mutated descriptors (0 = no-op skip).
    fn pt__pool(_: u32, _: u32, _: u32, _: i32) {}
    /// Fault-site host page-table walk. On a guest EL0 translation/permission
    /// fault, the live stage-1 descriptors read from the host backing at the
    /// faulting VA: `far` and `l0`/`l1`/`l2`/`l3`. An invalid (`& 1 == 0`) leaf
    /// proves the PTE is wrong IN MEMORY (logic bug); a valid RW leaf proves the
    /// memory is fine and the faulting vCPU's TLB was stale (coherence bug).
    fn pt__fault__walk(_: u64, _: u64, _: u64, _: u64, _: u64) {}
}

pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
    carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
}

// For these helpers the PID read happens INSIDE the closure. usdt's
// `probe!` macro only invokes the closure when the probe is enabled
// (it gates on `is_enabled()` in asm before calling), so `getpid()`
// is genuinely zero-cost when no DTrace consumer is attached.
pub fn path_open(path: &str, result_size: u64, errno: i32) {
    carrick_usdt::path__open!(|| (libc::getpid() as u32, path, result_size, errno));
}

pub fn itimer_fire(signum: i32, generation: u64) {
    carrick_usdt::itimer__fire!(|| (libc::getpid() as u32, signum, generation));
}

pub fn guest_exit(code: i32) {
    carrick_usdt::guest__exit!(|| (libc::getpid() as u32, code));
}

pub fn execve_argv(path: &str, argv: &[String]) {
    // `argv.join` allocates, so it can't move inside the closure (the
    // returned `&str` would dangle once the closure's local String
    // drops, before usdt serialises it). execve is rare, so the
    // unconditional join is acceptable; the hot paths above are the
    // ones that matter for zero-cost-when-disabled.
    let joined = argv.join(" ");
    carrick_usdt::execve__argv!(|| (libc::getpid() as u32, path, joined.as_str()));
}

pub fn fs_op(op: &str, path: &str, errno: i32) {
    carrick_usdt::fs__op!(|| (libc::getpid() as u32, op, path, errno));
}

pub fn host_pipe_io(host_fd: i32, dir: i32, n: i64) {
    carrick_usdt::host__pipe__io!(|| (libc::getpid() as u32, host_fd, dir, n));
}

pub fn epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32) {
    carrick_usdt::epoll__ctl!(|| (epfd, op, fd, events, data, errno));
}

pub fn epoll_interest(
    epfd: i32,
    fd: i32,
    requested: u32,
    raw_ready: u32,
    last_ready: u32,
    ready: u32,
) {
    carrick_usdt::epoll__interest!(|| (epfd, fd, requested, raw_ready, last_ready, ready));
}

pub fn epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32) {
    carrick_usdt::epoll__wait__fd!(|| (epfd, fd, host_fd, poll_events, timeout_ms));
}

pub fn epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32) {
    carrick_usdt::epoll__result!(|| (epfd, ready_count, wait_count, timeout_ms, kind));
}

pub fn io_wait_begin(tid: i32, fd_count: i32, timeout_ms: i64, fd0: i32, events0: i32, fd1: i32) {
    carrick_usdt::io__wait__begin!(|| (tid, fd_count, timeout_ms, fd0, events0, fd1));
}

pub fn io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32) {
    carrick_usdt::io__wait__end!(|| (tid, result, fd_count, fd0, fd1, fd2));
}

pub fn fork_quiesce(phase: i32, a: i64, b: i64, tid: i32) {
    carrick_usdt::fork__quiesce!(|| (phase, a, b, tid));
}

pub fn fork_post(pid: i32, pc: u64, elr: u64) {
    carrick_usdt::fork__post!(|| (pid, pc, elr));
}

pub fn signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64) {
    carrick_usdt::signal__inject!(|| (signum, saved_pc, new_sp, handler));
}

pub fn signal_restore(saved_pc: u64, sp: u64, magic: u64) {
    carrick_usdt::signal__restore!(|| (saved_pc, sp, magic));
}

pub fn kick_in_kernel(pc: u64, el: u32) {
    carrick_usdt::kick__in_kernel!(|| (pc, el));
}

pub fn kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64) {
    carrick_usdt::kick__stats!(|| (el1_resumed, kick_inject, inject_at_el1));
}

pub fn mem_watch(syscall_nr: u64, addr: u64, value: u64) {
    carrick_usdt::mem__watch!(|| (syscall_nr, addr, value));
}

pub fn sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64) {
    carrick_usdt::sigaction__read!(|| (signum, w0, w1, w2, w3));
}

pub fn supervisor_fork(child_pid: i32) {
    carrick_usdt::supervisor__fork!(|| child_pid);
}

pub fn supervisor_child_ready(runtime_pid: i32) {
    carrick_usdt::supervisor__child__ready!(|| runtime_pid);
}

pub fn supervisor_foreground_pgrp(pgid: i32, errno: i32) {
    carrick_usdt::supervisor__foreground__pgrp!(|| (pgid, errno));
}

pub fn supervisor_child_exit(pid: i32, status: i32) {
    carrick_usdt::supervisor__child__exit!(|| (pid, status));
}

pub fn pt_pause_begin(tid: i32, others_in_guest: i32, count: i32) {
    carrick_usdt::pt__pause__begin!(|| (tid, others_in_guest, count));
}

pub fn pt_pause_ready(tid: i32, spins: i32, wait_us: i64) {
    carrick_usdt::pt__pause__ready!(|| (tid, spins, wait_us));
}

pub fn pt_pause_timeout(tid: i32, wait_us: i64) {
    carrick_usdt::pt__pause__timeout!(|| (tid, wait_us));
}

pub fn pt_pause_end(tid: i32) {
    carrick_usdt::pt__pause__end!(|| tid);
}

pub fn pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32) {
    carrick_usdt::pt__pool!(|| (in_use, free_list, capacity, changed));
}

pub fn pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64) {
    carrick_usdt::pt__fault__walk!(|| (far, l0, l1, l2, l3));
}

// `#[inline(never)]`: usdt embeds the probe site (an asm! anchor) in
// the function body. If this gets inlined into multiple callers, each
// copy becomes a SEPARATE DTrace probe site that fires independently
// — so a single logical trap would fire `vcpu-trap` twice. Pinning the
// function to one body keeps it a single, stable probe site.
#[inline(never)]
pub fn vcpu_trap(regs: &crate::compat::GuestRegs) {
    // Pass the struct's address; DTrace copyin's it. The reference is
    // live for the duration of this (inline(never)) function, which is
    // where usdt's synchronous probe fire happens, so the pointer is
    // valid when DTrace reads it.
    let ptr = regs as *const crate::compat::GuestRegs as u64;
    carrick_usdt::vcpu__trap!(|| ptr);
}

pub fn execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64) {
    carrick_usdt::execve__loaded!(|| (path, entry, initial_sp, mapping_count));
}

pub fn execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64) {
    carrick_usdt::execve__sysregs!(|| (sctlr, ttbr0, mair));
}

/// Fires on a fatal guest EL0 fault (instruction/data abort, undef). See the
/// `vcpu__fault` provider doc. Cheap: only fires at the fault.
pub fn vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32) {
    carrick_usdt::vcpu__fault!(|| (esr, elr, far, x30, sp, tid));
}

/// Emit the decoded fault diagnostics as scalars. See the `vcpu__fault__regs`
/// provider doc. Scalars are captured at fire time, so this survives a fault
/// that kills the process before DTrace's action runs. Fires only at the fault.
pub fn vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64) {
    carrick_usdt::vcpu__fault__regs!(|| (esr, elr, far, insn, rn, xrn));
}

/// Emit a high-VA alias page-table walk. See `pt__alias__walk`. `flag` bit0 =
/// forked child, bit1 = the page-table build failed.
pub fn pt_alias_walk(va: u64, descs: [u64; 4], flag: i32) {
    carrick_usdt::pt__alias__walk!(|| (va, descs[0], descs[1], descs[2], descs[3], flag));
}

/// A signal was published for delivery. See `signal__publish`.
pub fn signal_publish(target_tid: i32, signum: i32, kind: i32) {
    carrick_usdt::signal__publish!(|| (target_tid, signum, kind));
}

/// A `deliver_pending_signal` cycle ran. See `signal__deliver`.
pub fn signal_deliver(tid: i32, pending: i32) {
    carrick_usdt::signal__deliver!(|| (tid, pending));
}

pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
    usdt::register_probes()
}

pub fn fire(event: &CompatEvent) {
    fire_usdt(event);
}

fn fire_usdt(event: &CompatEvent) {
    match event {
        CompatEvent::SyscallEntry { number, name, args } => {
            // `args` lives in `event` for the duration of this synchronous
            // probe fire, so its address is valid when DTrace copyin's it.
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::syscall__entry!(|| (*number, name.as_ref(), args_ptr));
        }
        CompatEvent::SyscallReturn {
            number,
            name,
            retval,
            errno,
        } => {
            carrick_usdt::syscall__return!(|| {
                (*number, name.as_ref(), *retval, errno.unwrap_or(0))
            });
        }
        CompatEvent::UnhandledSyscall { number, name, args } => {
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::unhandled__syscall!(|| (*number, name.as_str(), args_ptr));
        }
        CompatEvent::PartialSyscall {
            number,
            name,
            args,
            reason,
        } => {
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::partial__syscall!(|| (*number, name.as_str(), args_ptr, reason.as_str()));
        }
        CompatEvent::UnhandledIoctl { fd, request, arg } => {
            carrick_usdt::unhandled__ioctl!(|| (*fd, *request, *arg));
        }
        CompatEvent::ProcReadUnimplemented { path } => {
            carrick_usdt::proc__read__unimplemented!(|| path.as_str());
        }
        CompatEvent::SysReadUnimplemented { path } => {
            carrick_usdt::sys__read__unimplemented!(|| path.as_str());
        }
        CompatEvent::SignalUnsupported { signum, reason } => {
            carrick_usdt::signal__unsupported!(|| (*signum, reason.as_str()));
        }
        CompatEvent::UnknownSyscallFlags {
            number,
            name,
            argument,
            unknown_bits,
        } => {
            carrick_usdt::unknown__syscall__flags!(|| (
                *number,
                name.as_str(),
                *argument,
                *unknown_bits
            ));
        }
    }
}

#[allow(dead_code)]
fn _assert_args_are_serializable(args: &SyscallArgs) -> &SyscallArgs {
    args
}
