#!/usr/sbin/dtrace -qs
/*
 * Diagnose HVPatch guest job-control ordering without ever tracing host signal
 * delivery as a substitute for guest state. Emits every observed guest
 * kill/tgkill selector/signum and fails closed when no guest event fires, DTrace
 * reports an error/drop, or the 20-second diagnostic bound expires.
 *
 * Provider ABI qualified from carrick-observability on Darwin/arm64:
 * carrick*:::syscall-entry carries (uint64_t canonical_nr, char *name,
 * uint64_t *args), with arg2 pointing at six contiguous u64 arguments.
 * Canonical AArch64 Linux syscall numbers are kill=129 and tgkill=131.
 *
 * Per-vCPU DTrace buffers can flush records out of counter order, so the event
 * field proves population/identity but is not a cross-vCPU total-order clock.
 * Perturbation: one printf per guest kill/tgkill. This diagnostic is for
 * signal population and liveness only; it is not timing evidence.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    errors = 0;
    drops = 0;
    bounded = 0;
    target_exited = 0;
    printf("HVPATCHJOBFLOW1|header|version=1\n");
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 129 || arg0 == 131)/
{
    this->args = (uint64_t *)copyin(arg2, 48);
    events++;
    printf("HVPATCHJOBFLOW1|signal|event=%d|syscall=%d|selector=%d|thread=%d|signal=%d\n",
        events, (int)arg0, (int64_t)this->args[0],
        arg0 == 131 ? (int64_t)this->args[1] : 0,
        arg0 == 131 ? (int64_t)this->args[2] : (int64_t)this->args[1]);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::DROP
{
    drops++;
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 20 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCHJOBFLOW1|summary|status=%s|events=%d|errors=%d|drops=%d|bounded=%d|target_exited=%d\n",
        events > 0 && errors == 0 && drops == 0 && bounded == 0 && target_exited == 1
            ? "ok" : "error",
        events, errors, drops, bounded, target_exited);
}
