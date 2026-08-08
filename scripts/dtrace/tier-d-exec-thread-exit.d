#pragma D option quiet
#pragma D option strsize=256

/*
 * tier-d-exec-thread-exit.d -- bind exec-replaced thread-group retirement.
 *
 * WHAT IT MEASURES
 * ----------------
 * The guest clone/exec/sleep/exit syscalls and Carrick wait transitions for
 * one launch-owned Tier-D process tree.  The exact question is whether the
 * exec-replaced Python main issues exit(93) or exit_group(94), and whether a
 * sleeping sibling observes the runner's terminal wake promptly.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. carrick syscall-entry exposes
 * (arg0=canonical Linux nr, arg1=host pointer to syscall name, arg2=host
 * pointer to six u64 args). io-wait-{begin,end} arg0 is guest tid; END result
 * ordinals are Ready=0, TimedOut=1, Interrupted=2, Errno=3. proc:::create
 * exposes the child pid as args[0]->pr_pid.
 *
 * PERTURBATION
 * ------------
 * MODERATE but sparse: only clone/exec/sleep/exit entries and wait lifecycle
 * probes print. This is mechanism attribution, never elapsed-time evidence.
 * A valid capture ends naturally with zero probe errors and live=0.
 */

dtrace:::BEGIN
{
    live = 1;
    complete = 0;
    errors = 0;
    tracked[$target] = 1;
}

dtrace:::ERROR
{
    errors++;
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    live++;
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
}

proc:::exit
/complete == 0 && live == 0/
{
    complete = 1;
    exit(0);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 93 || arg0 == 94 || arg0 == 101 || arg0 == 220 || arg0 == 221)/
{
    printf("TIERDEXIT1|syscall-entry|pid=%d|tid=%d|nr=%d|name=%s\n",
        pid, tid, arg0, copyinstr(arg1));
}

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{
    printf("TIERDEXIT1|wait-begin|pid=%d|host-tid=%d|guest-tid=%d|fds=%d|timeout-ms=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{
    printf("TIERDEXIT1|wait-end|pid=%d|host-tid=%d|guest-tid=%d|result=%d|fds=%d\n",
        pid, tid, (int)arg0, (int)arg1, (int)arg2);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 20/
{
    exit(0);
}

dtrace:::END
{
    printf("TIERDEXIT1|complete|natural=%d|errors=%d|live=%d\n",
        complete, errors, live);
}
