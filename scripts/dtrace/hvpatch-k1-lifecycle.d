#!/usr/sbin/dtrace -qs
/*
 * Validate the HVPatch K1 one-VM guest-process lifecycle fixture.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-guest-lifecycle carries
 * (uint32_t phase, int32_t pid, int32_t ppid, int32_t tid, uint32_t asid),
 * where phase 0=root, 1=fork, 2=exec, and 5=process-exit.
 *
 * carrick*:::hvpatch-guest-lifecycle-identity carries
 * (int32_t pid, uint64_t task_serial, uint64_t parent_serial, uint64_t mm) and
 * fires IMMEDIATELY BEFORE its lifecycle record on the same thread. It exists
 * because a Linux TGID and an ASID are both recycled within a run, so
 * (pid, asid) cannot distinguish two task generations that share a number;
 * TaskSerial is never reused by one Kernel. The pair is split across two
 * probes because the lifecycle probe is already at macOS's five-reliable-
 * argument limit. This script stashes the identity in thread-locals and joins
 * it into the birth and exec aggregations, so a consumer never has to guess
 * which generation a pid referred to.
 *
 * The companion hvpatch-guest-exit carries (pid, tid, asid, status).
 * carrick*:::vm-lifecycle
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

/* HVPATCHK1 protocol version 2: birth/exec rows carry task/parent
 * serials and the mm id. Append fields only by defining version 3. */
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
    target_exit_seen = 0;
    target_exit_code = -1;
    target_exit_reason = 0;
    printf("HVPATCHK1|header|version=2\n");
}

carrick*:::hvpatch-guest-lifecycle-identity
/pid == $target || progenyof($target)/
{
    self->task_serial = (uint64_t)arg1;
    self->parent_serial = (uint64_t)arg2;
    self->mm = (uint64_t)arg3;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    roots++;
    births++;
    live++;
    @birth[0, (int)arg1, (int)arg2, (int)arg3, (uint32_t)arg4,
        self->task_serial, self->parent_serial, self->mm] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 1/
{
    forks++;
    births++;
    live++;
    @birth[1, (int)arg1, (int)arg2, (int)arg3, (uint32_t)arg4,
        self->task_serial, self->parent_serial, self->mm] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{
    execs++;
    @exec[(int)arg1, (int)arg3, (uint32_t)arg4, self->task_serial, self->mm] = count();
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

/*
 * proc:::exit arg0 is CLD_* reason, not the exit status. Qualify the exact
 * traced Carrick CLI status at the host syscall boundary so CLD_EXITED cannot
 * false-green a nonzero return.
 */
syscall::exit:entry
/pid == $target/
{
    target_exit_seen = 1;
    target_exit_code = (int)arg0;
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
    printa("HVPATCHK1|birth|kind=%d|pid=%d|ppid=%d|tid=%d|asid=%u|task_serial=%u|parent_serial=%u|mm=%u|count=%@d\n", @birth);
    printa("HVPATCHK1|exec|pid=%d|tid=%d|asid=%u|task_serial=%u|mm=%u|count=%@d\n", @exec);
    printa("HVPATCHK1|terminal|pid=%d|tid=%d|asid=%u|status=%d|count=%@d\n", @terminal);
    printa("HVPATCHK1|vm|operation=%u|admission=%d|count=%@d\n", @vm);
    printf("HVPATCHK1|end|version=2|roots=%d|forks=%d|execs=%d|exits=%d|births=%d|live=%d|bounded=%d|errors=%d|target_exit_seen=%d|target_exit_code=%d|target_exit_reason=%d\n",
        roots, forks, execs, exits, births, live, bounded, errors,
        target_exit_seen, target_exit_code, target_exit_reason);
}
