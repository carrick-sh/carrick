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
    printf("HVPSCHEDEV|section=host-syscalls\n");
    printa("%s%k%@d\n", @hostsys);
}
