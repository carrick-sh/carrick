/*
 * hvpatch-guest-syscall-flow.d — which Linux task is parked in which syscall?
 *
 * WHAT: an ordered, per-LINUX-task syscall stream for one HVPatch run. Every
 * guest task lives inside the single VM carrier, so the default tracer's
 * host-pid keyed stream collapses a hundred forked children into one column
 * and cannot say who is stuck. This script keys each line on the Linux
 * pid/tid the service-begin probe carries, prints the first four guest args
 * at entry and the signed retval/errno at return, and records lifecycle
 * transitions (fork/exec/thread-start/exit), so a hang reads as "task N last
 * entered wait4(-1) and never returned" rather than as a host-pid blob.
 *
 * ABI (qualified live on macOS/arm64, 2026-09-02, from
 * carrick-observability/probes.rs and hvpatch-sigchld-delivery.d):
 * - hvpatch-syscall-service-begin: arg0 i32 Linux pid, arg1 i32 Linux tid,
 *   arg2 u32 ASID, arg3 u64 syscall number.
 * - hvpatch-syscall-args: arg0 u64 syscall number, arg1..arg4 guest args
 *   0..3; fires right after service-begin on the same host thread.
 * - syscall-return: arg0 u64 number, arg1 name, arg2 signed retval,
 *   arg3 errno. Same host thread as the matching service-begin (HVPatch runs
 *   one host pthread per logical guest thread), so `self->` pairing is sound.
 * - hvpatch-guest-lifecycle: arg0 phase (0 root, 1 fork, 2 exec, 3
 *   thread-start, 4 thread-exit, 5 process-exit, 6 exec-begin), arg1 Linux
 *   pid, arg2 Linux ppid, arg3 Linux tid, arg4 ASID.
 *
 * PERTURBATION: HIGH on syscall-dense workloads — one printf per syscall
 * entry and return. Diagnostic only; nothing timed under this script is
 * citable. Bounded: exits after BOUND_SECONDS (45, edit the inline to
 * change — `carrick trace` passes no macro args) so a hung guest cannot
 * stream forever. Zero syscall returns is a failed capture, not an
 * idle guest.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/hvpatch-guest-syscall-flow.d \
 *     --trace-out <out> -- run --fs host <image> /bin/sh -c <cmd>
 *   Then: grep 'GSF1|ret' <out> | awk -F'|' '{print $4}' | sort | uniq -c
 *   and, per task, `grep 'lpid=<N>|' <out> | tail`.
 */
#pragma D option quiet
#pragma D option strsize=128
#pragma D option bufsize=32m
#pragma D option switchrate=10hz

inline int BOUND_SECONDS = 45;

dtrace:::BEGIN
{
    printf("GSF1|header|version=1|bound_s=%d\n", BOUND_SECONDS);
    secs = 0;
    returns = 0;
    errors = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    self->lpid = (int32_t)arg0;
    self->ltid = (int32_t)arg1;
    self->nr = (uint64_t)arg3;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == self->nr/
{
    printf("GSF1|entry|ts=%llu|lpid=%d|ltid=%d|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, self->lpid, self->ltid, self->nr,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target))/
{
    returns++;
    printf("GSF1|ret|ts=%llu|lpid=%d|ltid=%d|nr=%llu|name=%s|ret=%lld|errno=%d\n",
        timestamp, self->lpid, self->ltid, (uint64_t)arg0, copyinstr(arg1),
        (int64_t)arg2, (int32_t)arg3);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target))/
{
    printf("GSF1|life|ts=%llu|phase=%d|lpid=%d|lppid=%d|ltid=%d|asid=%u\n",
        timestamp, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (int32_t)arg3, (uint32_t)arg4);
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1s
{
    secs++;
}

profile:::tick-1s
/secs >= BOUND_SECONDS/
{
    printf("GSF1|end|reason=bound|returns=%d|errors=%d\n", returns, errors);
    exit(returns == 0 ? 2 : 0);
}

dtrace:::END
{
    printf("GSF1|end|reason=end|returns=%d|errors=%d\n", returns, errors);
}
