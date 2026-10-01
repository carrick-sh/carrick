#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-executor-sched-events.d — how many scheduling events does a real
 * HVPatch workload drive through the executor pool, and how many host
 * syscalls does each kind of event cost? Companion to the sampled
 * `hvpatch-carrier-cpu-attribution` profile: that profile says how much
 * carrier CPU lands under the executor loop; this script supplies the
 * per-event denominators (settlements by kind, task switches, threads,
 * forwarded syscalls, guest exits) so a sampled bucket can be expressed as
 * cost per event and checked for per-exit vs per-thread scaling.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * For one traced `carrick run` (CLI + carrier descendants):
 *   - `hvpatch-lease-settle` by settlement kind (0 Runnable, 1 Blocked,
 *     2 BlockedContinuation, 3 Exited, 4 ExecInvalidated) and by flag word;
 *     distinct `thread_serial`s seen settling (= guest threads that ran);
 *   - `hvpatch-executor-claim` count and `hvpatch-executor-lifecycle` by
 *     phase (0 Create, 1 Load, 2 Save, 3 Switch, 4 Destroy, 5 InvalidateAsid);
 *   - `vcpu-run-exit` by `HostExitClass` ordinal (0 canceled, 1 idle, 2 kick,
 *     3 syscall, 4 metadata, 5 maintenance, 6 fault, 7 other);
 *   - `hvpatch-syscall-service-begin` (host-forwarded syscalls);
 *   - `hvpatch-reactor-cycle` (wait-service reactor wakeups) and
 *     `hvpatch-fork-quiesce`;
 *   - host `write`/`poll`/`close`/`psynch_cv*` syscalls issued by carrier
 *     threads, keyed by a 3-frame user stack so the offline reader can split
 *     the wait-service reactor nudge (`CarrierWaitServiceInner::nudge_reactor`
 *     is an inlined `libc::write` to the reactor control pipe; with
 *     frame pointers the leaf `write` stub has no frame, so frame 2 is the
 *     return address in the caller of the inlining function, e.g.
 *     `run_executor_loop+<off>` after the `prepare_registration` or
 *     `enroll` call) from guest-requested host writes.
 *   - WAKE-TO-RUN LATENCY of every blocked continuation, as log-linear
 *     histograms in microseconds, split by the blocked syscall
 *     (`epoll_pwait` = aarch64 nr 22, else `other`) and by stage:
 *       ready-to-wake   reactor `poll` returned -> scheduler wake of the
 *                       thread, on the reactor thread (reactor-sourced
 *                       wakes only);
 *       wake-to-claim   scheduler wake -> an executor claims the thread
 *                       (run-queue placement + idle executor wake-up);
 *       claim-to-run    claim -> the next `hv_vcpu_run` on that executor
 *                       (task load, continuation resume, syscall
 *                       completion);
 *       wake-to-run     the sum of the last two;
 *       ready-to-run    the whole reactor-sourced path.
 *     Blocked = the thread's last settlement was kind 2
 *     (BlockedContinuation); its syscall is the last
 *     `hvpatch-syscall-service-begin` on the settling executor thread.
 *
 * (b) PROVIDER ABI (carrick USDT, crates/carrick-observability/src/probes.rs,
 *     qualified live on macOS 27.2 / M4, 2026-10-01, binary c2c6b14f)
 *   hvpatch-lease-settle (u64 thread_serial, u32 kind, u32 flags,
 *                         u64 lease_gen, u64 successor_gen)
 *   hvpatch-executor-claim (u64 task, u64 thread, u32 executor, u64 gen, u64 asid)
 *   hvpatch-executor-lifecycle (u32 executor, u32 phase, u64 thread, u64, u64)
 *   vcpu-run-exit (u64 vcpu, u32 class, u64 esr)
 *   hvpatch-syscall-service-begin (i32 pid, i32 tid, u32 asid, u64 nr)
 *   hvpatch-reactor-cycle (u32 regs, u32 visited, u32 pollfds, i32 timeout_ms)
 *   hvpatch-fork-quiesce (i32 ppid, i32 tid, u32 siblings, u64 polls, u64 ns)
 *   host-image-base (i32 host_pid, u64 text_base, u64 slide)
 *   hvpatch-scheduler-wake (u64 thread_serial, u32 kind, u32 found_state,
 *                           u64 found_gen, u64 queued_gen)
 *   vcpu-run-enter (u64 vcpu), fired on the executor's own host thread
 *   syscall::poll:entry arg2 = timeout; the reactor's poll is the only
 *   carrier poll with a nonzero timeout (readiness samples use 0).
 *   syscall::{write,poll,close,psynch_cvwait,psynch_cvbroad,psynch_cvsignal}:entry
 *   `ustack(3)` is trustworthy only because `.cargo/config.toml` forces frame
 *   pointers; addresses print raw and are symbolized offline against the
 *   exact binary (text base from the `image` line; the leaf syscall stub's
 *   caller frame is skipped, see (a)).
 *
 * TARGETING: `pid == $target || progenyof($target)` under `dtrace -Z`; the
 * carrier is a child of the traced CLI.
 *
 * BOUND: ends on the target CLI's exit; a 300 s tick bound is a safety net
 * and reports `bounded=1`, which a reader must refuse.
 *
 * (c) PERTURBATION
 * --------------------
 * HIGH on exit-dense workloads (one aggregation update per guest exit, per
 * settlement and per carrier write/poll/psynch syscall). Counts and ratios of
 * counts are citable; wall and CPU time under this script are not.
 */
#pragma D option quiet
#pragma D option zdefs
#pragma D option bufsize=16m
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m

self uint64_t last_load;
self uint64_t exit_ts;
self uint64_t exit_class;
self uint64_t cvret;


dtrace:::BEGIN
{
    secs = 0;
    carrier_pid = 0;
    bounded = 0;
    printf("HVPSCHEDEV|header|schema=carrick.hvpatch-executor-sched-events.v1\n");
}

/* Exact carrier identity so `ustack` addresses symbolize offline. */
carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
    carrier_pid = (int)arg0;
    printf("HVPSCHEDEV|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
        (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

carrick*:::hvpatch-lease-settle
/pid == $target || progenyof($target)/
{
    @settle[arg1] = count();
    @settle_flags[arg1, arg2] = count();
    @threads[arg0] = count();
}

carrick*:::hvpatch-executor-claim
/pid == $target || progenyof($target)/
{
    @claims = count();
}

/* ---- wake-to-run latency of blocked continuations ---- */

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->last_nr = arg3;
}

carrick*:::hvpatch-lease-settle
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    blocked_class[arg0] = self->last_nr == 22 ? 1 : 2;
    wake_ts[arg0] = 0;
    ready_ts[arg0] = 0;
}

syscall::poll:entry
/carrier_pid != 0 && pid == carrier_pid && (int)arg2 != 0/
{
    self->reactor_poll = 1;
}

syscall::poll:return
/self->reactor_poll/
{
    self->reactor_poll = 0;
    self->ready = timestamp;
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && blocked_class[arg0] != 0/
{
    @wake_state[arg1, arg2, arg4 != 0 ? "queued" : "no-action"] = count();
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && blocked_class[arg0] != 0 && wake_ts[arg0] == 0 && arg4 != 0/
{
    wake_ts[arg0] = timestamp;
    ready_ts[arg0] = self->ready;
    @wake_src[blocked_class[arg0] == 1 ? "epoll_pwait" : "other",
        self->ready != 0 ? "reactor" : "producer"] = count();
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && blocked_class[arg0] != 0 && ready_ts[arg0] != 0 && wake_ts[arg0] == timestamp/
{
    @lat["ready-to-wake", blocked_class[arg0] == 1 ? "epoll_pwait" : "other"] =
        llquantize((timestamp - ready_ts[arg0]) / 1000, 10, 0, 5, 20);
}

syscall::psynch_cvwait:return
/carrier_pid != 0 && pid == carrier_pid/
{
    self->cvret = timestamp;
}

/*
 * How the claiming executor came to claim: the latest of a condvar park
 * return (`psynch_cvwait`) and a guest exit (an executor idling in the
 * guest zone leaves `hv_vcpu_run` on a kick or its idle timer) after the
 * wake, or neither (it was already running host-side and found the thread).
 */
carrick*:::hvpatch-executor-claim
/(pid == $target || progenyof($target)) && blocked_class[arg1] != 0 && wake_ts[arg1] != 0/
{
    this->cls = blocked_class[arg1] == 1 ? "epoll_pwait" : "other";
    this->w = wake_ts[arg1];
    this->ev = self->cvret > self->exit_ts ? self->cvret : self->exit_ts;
    this->how = this->ev <= this->w ? "host-running"
        : self->cvret > self->exit_ts ? "condvar-unpark"
        : self->exit_class == 2 ? "guest-exit-kick"
        : self->exit_class == 1 ? "guest-exit-idle"
        : self->exit_class == 3 ? "guest-exit-syscall"
        : "guest-exit-other";
    @claim_by[this->cls, this->how] = count();
    @lat[strjoin("wake-to-event:", this->how), this->cls] =
        llquantize(this->ev > this->w ? (this->ev - this->w) / 1000 : 0, 10, 0, 5, 20);
    @lat[strjoin("event-to-claim:", this->how), this->cls] =
        llquantize(this->ev > this->w ? (timestamp - this->ev) / 1000 : (timestamp - this->w) / 1000,
        10, 0, 5, 20);
}

carrick*:::hvpatch-executor-claim
/(pid == $target || progenyof($target)) && blocked_class[arg1] != 0 && wake_ts[arg1] != 0/
{
    this->cls = blocked_class[arg1] == 1 ? "epoll_pwait" : "other";
    @lat["wake-to-claim", this->cls] =
        llquantize((timestamp - wake_ts[arg1]) / 1000, 10, 0, 5, 20);
    self->run_cls = blocked_class[arg1];
    self->run_wake = wake_ts[arg1];
    self->run_ready = ready_ts[arg1];
    self->run_claim = timestamp;
    blocked_class[arg1] = 0;
    wake_ts[arg1] = 0;
    ready_ts[arg1] = 0;
}

carrick*:::vcpu-run-enter
/self->run_claim/
{
    this->cls = self->run_cls == 1 ? "epoll_pwait" : "other";
    @lat["claim-to-run", this->cls] =
        llquantize((timestamp - self->run_claim) / 1000, 10, 0, 5, 20);
    @lat["wake-to-run", this->cls] =
        llquantize((timestamp - self->run_wake) / 1000, 10, 0, 5, 20);
    @lat_n["wake-to-run", this->cls] = count();
    @lat_sum["wake-to-run", this->cls] = sum(timestamp - self->run_wake);
    @lat_sum["claim-to-run", this->cls] = sum(timestamp - self->run_claim);
    @lat_sum["wake-to-claim", this->cls] = sum(self->run_claim - self->run_wake);
}

carrick*:::vcpu-run-enter
/self->run_claim && self->run_ready/
{
    @lat["ready-to-run", self->run_cls == 1 ? "epoll_pwait" : "other"] =
        llquantize((timestamp - self->run_ready) / 1000, 10, 0, 5, 20);
    @lat_sum["ready-to-wake", self->run_cls == 1 ? "epoll_pwait" : "other"] =
        sum(self->run_wake - self->run_ready);
}

carrick*:::vcpu-run-enter
/self->run_claim/
{
    self->run_claim = 0;
    self->run_wake = 0;
    self->run_ready = 0;
    self->run_cls = 0;
}

carrick*:::hvpatch-executor-lifecycle
/pid == $target || progenyof($target)/
{
    @lifecycle[arg1] = count();
}

/*
 * Load (phase 1) of the same thread the executor last loaded: the task never
 * left this vCPU, so the flush/snapshot + restore pair of a task switch had
 * nothing to switch. Thread-local (`self->`): every load of one executor
 * runs on that executor's own host worker thread.
 */
carrick*:::hvpatch-executor-lifecycle
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    @load_same[self->last_load == (uint64_t)arg2 ? "same-thread" : "other-thread"] = count();
    self->last_load = (uint64_t)arg2;
}

carrick*:::vcpu-run-exit
/pid == $target || progenyof($target)/
{
    @exits[arg1] = count();
    self->exit_ts = timestamp;
    self->exit_class = arg1;
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    @forwarded = count();
}

carrick*:::hvpatch-reactor-cycle
/pid == $target || progenyof($target)/
{
    @reactor = count();
}

carrick*:::hvpatch-fork-quiesce
/pid == $target || progenyof($target)/
{
    @quiesce = count();
}

syscall::write:entry,
syscall::poll:entry,
syscall::close:entry,
syscall::psynch_cvwait:entry,
syscall::psynch_cvbroad:entry,
syscall::psynch_cvsignal:entry
/carrier_pid != 0 && pid == carrier_pid/
{
    @hostsys[probefunc, ustack(3)] = count();
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 300/
{
    bounded = 1;
    exit(0);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printf("HVPSCHEDEV|summary|bounded=%d|secs=%d\n", bounded, secs);
    printa("HVPSCHEDEV|settle|kind=%d|count=%@d\n", @settle);
    printa("HVPSCHEDEV|settle-flags|kind=%d|flags=%d|count=%@d\n", @settle_flags);
    printa("HVPSCHEDEV|lifecycle|phase=%d|count=%@d\n", @lifecycle);
    printa("HVPSCHEDEV|load-continuity|kind=%s|count=%@d\n", @load_same);
    printa("HVPSCHEDEV|exit|class=%d|count=%@d\n", @exits);
    printa("HVPSCHEDEV|claims|count=%@d\n", @claims);
    printa("HVPSCHEDEV|forwarded|count=%@d\n", @forwarded);
    printa("HVPSCHEDEV|reactor-cycles|count=%@d\n", @reactor);
    printa("HVPSCHEDEV|fork-quiesce|count=%@d\n", @quiesce);
    printa("HVPSCHEDEV|thread|serial=%d|settlements=%@d\n", @threads);
    printa("HVPSCHEDEV|wake-source|class=%s|source=%s|count=%@d\n", @wake_src);
    printa("HVPSCHEDEV|wake-state|kind=%d|found=%d|action=%s|count=%@d\n", @wake_state);
    printa("HVPSCHEDEV|claim-by|class=%s|executor=%s|count=%@d\n", @claim_by);
    printa("HVPSCHEDEV|latency-count|stage=%s|class=%s|count=%@d\n", @lat_n);
    printa("HVPSCHEDEV|latency-sum-ns|stage=%s|class=%s|sum=%@d\n", @lat_sum);
    printf("HVPSCHEDEV|section=latency-us\n");
    printa("HVPSCHEDEV|latency|stage=%s|class=%s%@d\n", @lat);
    printf("HVPSCHEDEV|section=host-syscalls\n");
    printa("%s%k%@d\n", @hostsys);
}
