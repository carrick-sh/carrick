#!/usr/sbin/dtrace -qs
/*
 * Count COW transactions during repeated exec, including a valid zero result.
 * ABI qualified on macOS arm64, 2026-09-09: guest-lifecycle arg0 6=exec
 * begin, 2=exec success; frame-cow-identity arg4 0=stage2, 1=stage1,
 * 2=commit. syscall::exit:entry arg0 is the target process exit status.
 * All guest counts follow pid == target || progenyof(target).
 *
 * Require multiple balanced execs, live vcpu-fault events, balanced COW
 * phases, natural successful target exit, no DTrace errors or drops. Zero
 * COW is meaningful only paired with a positive-control artifact using the
 * same instrument and qualified provider ABI. No sampled COW is required:
 * eliminating these transactions is precisely the optimization under test.
 *
 * Perturbation: per-fault and COW lifecycle USDT probes; use event counts
 * only, never traced wall time as a performance gate. Bounded at 45 seconds.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    started = timestamp;
    begins = 0; ends = 0; faults = 0;
    stage2 = 0; stage1 = 0; commits = 0;
    errors = 0; bounded = 0;
    target_exit_seen = 0; target_exit_code = -1; target_exited = 0;
}

carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{ faults++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 6/
{ begins++; }

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{ ends++; }

carrick*:::hvpatch-frame-cow-identity
/pid == $target || progenyof($target)/
{
    stage2 += arg4 == 0;
    stage1 += arg4 == 1;
    commits += arg4 == 2;
}

syscall::exit:entry
/pid == $target/
{ target_exit_seen = 1; target_exit_code = (int)arg0; }

dtrace:::ERROR
{ errors++; exit(3); }

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(begins > 1 && begins == ends && faults > 0 && stage2 == stage1 && stage1 == commits && errors == 0 && target_exit_seen && target_exit_code == 0 ? 0 : 2);
}

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{
    printf("EXECCOW1|begins=%d|ends=%d|faults=%d|stage2=%d|stage1=%d|commits=%d|errors=%d|bounded=%d|target_exited=%d|target_exit_seen=%d|target_exit_code=%d\n",
        begins, ends, faults, stage2, stage1, commits, errors, bounded,
        target_exited, target_exit_seen, target_exit_code);
}
