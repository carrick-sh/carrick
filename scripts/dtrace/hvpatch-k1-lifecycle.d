#!/usr/sbin/dtrace -qs
/*
 * Validate the HVPatch K1 one-VM guest-process lifecycle fixture.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-guest-lifecycle carries
 * (uint32_t phase, int32_t pid, int32_t ppid, int32_t tid, uint32_t asid),
 * where phase 0=root, 1=fork, 2=exec, and 5=process-exit. The companion
 * hvpatch-guest-exit carries (pid, tid, asid, status). carrick*:::vm-lifecycle
 * carries (operation, admission), where operations 0/1/2/3 are create-attempt,
 * create-success, destroy-attempt, and destroy-success.
 *
 * This is a bounded, complete-workload profile: its strict Rust reader joins
 * every birth, exec, and terminal identity and rejects count drift, a live
 * residue, a timeout, DTrace errors, consumer drops, or interruption.
 *
 * Perturbation: low-frequency Carrick VM and guest lifecycle USDT probes only;
 * no syscall, fault, or instruction hot path is instrumented.
 */

#pragma D option quiet

/* HVPATCHK1 protocol version 1. Append fields only by defining version 2. */
dtrace:::BEGIN
{
    started = timestamp;
    roots = 0;
    forks = 0;
    execs = 0;
    exits = 0;
    births = 0;
    live = 0;
    bounded = 0;
    errors = 0;
    target_exit_reason = 0;
    printf("HVPATCHK1|header|version=1\n");
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    roots++;
    births++;
    live++;
    @birth[0, (int)arg1, (int)arg2, (int)arg3, (uint32_t)arg4] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 1/
{
    forks++;
    births++;
    live++;
    @birth[1, (int)arg1, (int)arg2, (int)arg3, (uint32_t)arg4] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{
    execs++;
    @exec[(int)arg1, (int)arg3, (uint32_t)arg4] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5/
{
    exits++;
    live--;
}

carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{
    @terminal[(int)arg0, (int)arg1, (uint32_t)arg2, (int64_t)arg3] = count();
}

carrick*:::vm-lifecycle
/pid == $target || progenyof($target)/
{
    @vm[(uint32_t)arg0, (int32_t)arg1] = count();
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    target_exit_reason = arg0;
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 180 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printa("HVPATCHK1|birth|kind=%d|pid=%d|ppid=%d|tid=%d|asid=%u|count=%@d\n", @birth);
    printa("HVPATCHK1|exec|pid=%d|tid=%d|asid=%u|count=%@d\n", @exec);
    printa("HVPATCHK1|terminal|pid=%d|tid=%d|asid=%u|status=%d|count=%@d\n", @terminal);
    printa("HVPATCHK1|vm|operation=%u|admission=%d|count=%@d\n", @vm);
    printf("HVPATCHK1|end|version=1|roots=%d|forks=%d|execs=%d|exits=%d|births=%d|live=%d|bounded=%d|errors=%d|target_exit_reason=%d\n",
        roots, forks, execs, exits, births, live, bounded, errors,
        target_exit_reason);
}
