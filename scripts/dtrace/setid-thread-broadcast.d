/*
 * Does an NPTL credential broadcast deliver once to each sibling and return
 * the same set*id result? Use carrick trace with the CLI running the GNU
 * setidthreadchurn executable through probeinit in ubuntu:24.04.
 *
 * ABI: hvpatch-syscall-service-begin carries Linux pid/tid and nr;
 * hvpatch-syscall-args carries nr and scalar arguments (no guest copyin).
 * syscall-return arg2/arg3 are result/errno. signal-deliver arg0/arg1 are
 * kernel tid/signum; signal-inject carries signum/guest PC/SP/handler.
 * Live-qualified on b5f739d5d: setresgid entry (21,0,201) returned -11/11
 * in one sibling, while others returned 0; tgkill SIGABRT followed. The
 * signed embed shard installs signal hooks but no compat syscall-return
 * hook, so tracing that executable alone cannot qualify this question.
 * A live stream must contain entries, returns and signal deliveries.
 *
 * Perturbation: per-event USDT tracing changes scheduling; this is diagnostic
 * evidence, never an uninstrumented reproduction-rate or timing measurement.
 * The 45-second bound ends the tracer; the caller owns run-ID cleanup.
 */
#pragma D option quiet
#pragma D option strsize=128
#pragma D option switchrate=10ms

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->lpid = (int)arg0;
    self->ltid = (int)arg1;
    self->nr = arg3;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 (arg0 == 131 || arg0 == 134 || arg0 == 139 ||
  (arg0 >= 143 && arg0 <= 151) || arg0 == 220 || arg0 == 94)/
{
    printf("%lld pid=%d host_tid=%d entry lpid=%d ltid=%d nr=%d args=%#x,%#x,%#x\n",
        (long long)timestamp, pid, tid, self->lpid, self->ltid,
        (int)arg0, arg1, arg2, arg3);
    entries++;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 131 || arg0 == 134 || arg0 == 139 ||
  (arg0 >= 143 && arg0 <= 151) || arg0 == 220 || arg0 == 94)/
{
    printf("%lld pid=%d host_tid=%d return %s ret=%lld errno=%d\n",
        (long long)timestamp, pid, tid, copyinstr(arg1), (long long)arg2, (int)arg3);
    returns++;
}

carrick*:::signal-deliver
/pid == $target || progenyof($target)/
{
    printf("%lld pid=%d host_tid=%d deliver guest_tid=%d sig=%d\n",
        (long long)timestamp, pid, tid, (int)arg0, (int)arg1);
    deliveries++;
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
    printf("%lld pid=%d host_tid=%d inject sig=%d pc=%#x sp=%#x handler=%#x\n",
        (long long)timestamp, pid, tid, (int)arg0, arg1, arg2, arg3);
}

tick-1s { seconds++; }
tick-1s /seconds >= 45/ { exit(entries == 0 || returns == 0 || deliveries == 0 ? 2 : 0); }

proc:::exit
/pid == $target/
{ exit(entries == 0 || returns == 0 || deliveries == 0 ? 2 : 0); }

dtrace:::ERROR
{ printf("setid trace error: %d\n", (int)arg4); exit(2); }

dtrace:::END
{
    printf("setid trace events: entries=%d returns=%d deliveries=%d\n",
        entries, returns, deliveries);
}
