/*
 * hvpatch-forkexecstorm-lifecycle.d — does each vfork+exec child publish exit?
 *
 * WHAT: follow one signed forkexecstorm test launcher and record exact guest
 * fork, exec, process-exit and first wait4 target. The first wait target for
 * each (pid, tid, child) is enough to join a timed-out waiter to its child's
 * lifecycle without printing every WNOHANG poll. The 60 s bound terminates
 * a wedged test; no observed lifecycle event is a failed capture.
 *
 * ABI (qualified live on cloudmac macOS/arm64, 2026-10-04: signed
 * carrick-conformance-next external witness, FES1 trace `fes-trace3-2`;
 * source: carrick-observability/src/probes.rs and the live-qualified
 * scripts/dtrace/hvpatch-guest-syscall-flow.d):
 * - hvpatch-syscall-service-begin arg0=i32 Linux pid, arg1=i32 Linux tid,
 *   arg2=u32 ASID, arg3=u64 Linux syscall number; 220 clone, 221 execve, 260 wait4,
 *   93 exit, 94 exit_group on aarch64.
 * - hvpatch-syscall-args arg0=syscall number, arg1=guest arg0. It follows
 *   service-begin in the same service slice; no return-side host-thread
 *   identity is inferred from this pairing.
 * - hvpatch-guest-lifecycle arg0=phase (1 fork, 2 exec, 5 process-exit),
 *   arg1=Linux pid, arg2=Linux ppid, arg3=Linux tid, arg4=ASID.
 * - `$target` is the tracer's child launcher; USDT processes forked by the
 *   external signed test are included with progenyof($target).
 *
 * PERTURBATION: one printf per clone/exec/exit lifecycle edge and first
 * wait4 per child. One traced prefix passed at 374/427 ms for musl/GNU;
 * an uninstrumented prefix failed at 40 s. These runs have different
 * schedules, so use the trace for identity/ordering, never timing.
 * `proc:::exit` closes a completing traced launcher when that probe fires;
 * the external test path reached the `tick-1s` 60 s receipt after its test
 * had already exited. A bound receipt is a capture limit, not a test pass.
 *
 * Usage: carrick trace --require-script-exit --script <this-file> \
 *   --trace-out <output> -- --external <signed-test> \
 *   --exact generic_probe_shard_2 --nocapture
 */
#pragma D option quiet
#pragma D option strsize=128
#pragma D option bufsize=16m
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
    secs = 0;
    events = 0;
    first_wait[0, 0, 0, 0] = 0;
    printf("FES1|header|bound_s=60\n");
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
    ((uint64_t)arg3 == 220 || (uint64_t)arg3 == 221 ||
     (uint64_t)arg3 == 260 || (uint64_t)arg3 == 93 ||
     (uint64_t)arg3 == 94)/
{
    self->lpid = (int32_t)arg0;
    self->ltid = (int32_t)arg1;
    self->asid = (uint32_t)arg2;
    self->nr = (uint64_t)arg3;
    events++;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
    ((uint64_t)arg3 == 220 || (uint64_t)arg3 == 221 ||
     (uint64_t)arg3 == 93 || (uint64_t)arg3 == 94)/
{
    printf("FES1|entry|ts=%llu|lpid=%d|ltid=%d|asid=%u|nr=%llu\n",
        timestamp, self->lpid, self->ltid, self->asid, self->nr);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
    self->nr == 260 && (uint64_t)arg0 == 260/
{
    this->child = (int32_t)arg1;
    if (first_wait[self->asid, self->lpid, self->ltid, this->child] == 0) {
        printf("FES1|wait-target|ts=%llu|lpid=%d|ltid=%d|asid=%u|child=%d\n",
            timestamp, self->lpid, self->ltid, self->asid, this->child);
    }
    first_wait[self->asid, self->lpid, self->ltid, this->child]++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) &&
    ((int32_t)arg0 == 1 || (int32_t)arg0 == 2 || (int32_t)arg0 == 5)/
{
    events++;
    printf("FES1|life|ts=%llu|phase=%d|lpid=%d|lppid=%d|ltid=%d|asid=%u\n",
        timestamp, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (int32_t)arg3, (uint32_t)arg4);
}

proc:::exit
/pid == $target/
{
    printf("FES1|end|reason=launcher-exit|events=%d\n", events);
    exit(events == 0 ? 2 : 0);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 60/
{
    printf("FES1|end|reason=bound|events=%d\n", events);
    exit(events == 0 ? 2 : 0);
}
