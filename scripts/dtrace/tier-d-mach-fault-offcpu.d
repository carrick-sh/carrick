/*
 * tier-d-mach-fault-offcpu.d — capture the kernel blocking site when Node's
 * Tier-D V8 worker stops at its repeatable raw write PC before Carrick's Mach
 * exception catch routine records an entry.
 *
 * Provider ABI qualified live on this host (2026-08-08): `sched:::off-cpu`
 * exposes the next LWP and process as `(lwpsinfo_t *, psinfo_t *)`; the probe
 * fires in the current thread's switch path, so `pid`, `tid`, `uregs[R_PC]`,
 * `stack()`, and `ustack()` describe the thread being descheduled.
 * `sched:::on-cpu` has no typed arguments. The Node v24 app-smoke worker PC
 * `0x6001d9b0be0` was identical in three untraced live hangs and one saved
 * core; this script intentionally answers only that qualified workload.
 *
 * Scheduler probes fire system-wide before the predicate. This capture is
 * attribution evidence, never performance evidence. It does not arm USDT or
 * pid-provider probes, so it avoids fasttrap detach risk.
 *
 * Usage:
 *   sudo dtrace -q -s scripts/dtrace/tier-d-mach-fault-offcpu.d \
 *     > /tmp/tier-d-mach-fault-offcpu.out
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option stackframes=48
#pragma D option ustackframes=24

dtrace:::BEGIN
{
    printf("TDMACHO1|event=begin|time=%Y\n", walltimestamp);
}

sched:::off-cpu
/execname == "carrick" && uregs[R_PC] == 0x6001d9b0be0/
{
    printf("TDMACHO1|event=off-cpu|ts=%d|pid=%d|tid=%d|pc=%#x\n",
        timestamp, pid, tid, uregs[R_PC]);
    stack();
    ustack();
}

sched:::on-cpu
/execname == "carrick" && uregs[R_PC] == 0x6001d9b0be0/
{
    printf("TDMACHO1|event=on-cpu|ts=%d|pid=%d|tid=%d|pc=%#x\n",
        timestamp, pid, tid, uregs[R_PC]);
}

tick-90s
{
    printf("TDMACHO1|event=bound|seconds=90\n");
    exit(0);
}

dtrace:::END
{
    printf("TDMACHO1|event=end|time=%Y\n", walltimestamp);
}
