/*
 * Epoll descriptor pollability: control wakes versus deliverable guest events.
 * Run the permanent epollcluster reducer through carrick trace, retaining its
 * stdout separately. This is correctness instrumentation and can perturb races;
 * do not cite traced durations as performance measurements.
 *
 * ABI is source-qualified against carrick-observability/probes.rs on the
 * canonical macOS arm64 lane. Live-qualified 2026-09-09 on source3595bf7c4,
 * CLI SHA256 f62af2c6b384b62f87e688d3cb4e6966ee0b60da6fa3b34253eebf0a8f332c4b:
 * 16 lookups,8 controls,15 interests,16 results,8 poll returns,0 errors.
 * Receipt: target/conformance/fix-forward-20260909/node-review/
 * epoll-descriptor-trace.json and .raw/.out. Both permanent readiness/lost-wake
 * failures reproduced. Cross-CPU output order is not a causal timestamp;
 * do not infer event ordering merely from line order in the raw capture.
 * service-begin/clear: Linux pid,tid,ASID,syscall-number.
 * epoll-lookup: table-id,epfd,slot-generation,description-id,lookup-kind.
 * epoll-ctl: epfd,op,fd,events,data,errno.
 * epoll-interest: epfd,fd,requested,raw,last,deliverable.
 * epoll-result: epfd,ready-count,wait-count,timeout-ms,result-kind.
 * syscall-return: number,name,return-value,errno.
 * No copyin or host kernel-provider ABI is assumed.
 *
 * The 20-second terminal check fails closed on missing event families or
 * DTrace errors. Use --require-script-exit and scoped CARRICK_RUN_ID cleanup.
 */
#pragma D option quiet
#pragma D option bufsize=4m
#pragma D option strsize=128

dtrace:::BEGIN
{
    printf("EPD1|begin|wall=%Y\n", walltimestamp);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (arg3 == 19 || arg3 == 20 || arg3 == 21 || arg3 == 22 || arg3 == 73 || arg3 == 63 || arg3 == 64)/
{
    self->service_started = timestamp;
    printf("EPD1|begin-service|hostpid=%d|hosttid=%d|pid=%d|tid=%d|asid=%d|nr=%d\n",
        pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2, arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && self->service_started/
{
    printf("EPD1|clear-service|hostpid=%d|hosttid=%d|pid=%d|tid=%d|asid=%d|nr=%d|ns=%d\n",
        pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2, arg3, timestamp-self->service_started);
    self->service_started = 0;
}

carrick*:::epoll-lookup
/pid == $target || progenyof($target)/
{
    lookups++;
    printf("EPD1|lookup|hostpid=%d|hosttid=%d|table=%d|epfd=%d|slot=%d|description=%d|kind=%d\n",
        pid, tid, arg0, (int)arg1, arg2, arg3, (uint32_t)arg4);
}

carrick*:::epoll-ctl
/pid == $target || progenyof($target)/
{
    controls++;
    printf("EPD1|ctl|hostpid=%d|hosttid=%d|epfd=%d|op=%d|fd=%d|events=%x|data=%d|errno=%d\n",
        pid, tid, (int)arg0, arg1, (int)arg2, (uint32_t)arg3, arg4, (int)arg5);
}

carrick*:::epoll-interest
/pid == $target || progenyof($target)/
{
    interests++;
    printf("EPD1|interest|hostpid=%d|hosttid=%d|epfd=%d|fd=%d|requested=%x|raw=%x|last=%x|deliverable=%x\n",
        pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg4, (uint32_t)arg5);
}

carrick*:::epoll-result
/pid == $target || progenyof($target)/
{
    results++;
    printf("EPD1|result|hostpid=%d|hosttid=%d|epfd=%d|ready=%d|wait=%d|timeout=%d|kind=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 73 || arg0 == 22 || arg0 == 63 || arg0 == 64)/
{
    if (arg0 == 73) { poll_returns++; }
    printf("EPD1|return|hostpid=%d|hosttid=%d|nr=%d|value=%d|errno=%d\n",
        pid, tid, arg0, (int64_t)arg2, (int)arg3);
}

dtrace:::ERROR
{
    errors++;
    printf("EPD1|error|epid=%d|action=%d|offset=%d|fault=%d\n", arg1, arg2, arg3, arg4);
}

tick-20s
{
    if (lookups == 0 || controls == 0 || interests == 0 || results == 0 || poll_returns == 0 || errors != 0) {
        printf("EPD1|fail|lookups=%d|controls=%d|interests=%d|results=%d|poll_returns=%d|errors=%d\n",
            lookups, controls, interests, results, poll_returns, errors);
        exit(1);
    }
    printf("EPD1|pass|lookups=%d|controls=%d|interests=%d|results=%d|poll_returns=%d|errors=%d\n",
        lookups, controls, interests, results, poll_returns, errors);
    exit(0);
}
