/*
 * tier-d-mach-invalid-stop.d — freeze the exact Tier-D process whose Mach
 * exception receive returned MACH_RCV_INVALID_DATA, while preserving every
 * host munmap after its exception server was installed.
 *
 * WHAT IT MEASURES
 * ----------------
 * Phase 1 of native-tierd-exception marks the first installed thread
 * exception port in a process. From then on, every host munmap is recorded.
 * Phase 14 is the immediate return from mach_msg_server; status 0x10004008 is
 * MACH_RCV_INVALID_DATA. The script SIGSTOPs that process before Carrick can
 * retry, leaving the server thread and its stale libsystem stack available to
 * LLDB. Kill the scoped CARRICK_RUN_ID after capture; proc:::exit then ends the
 * tracer naturally.
 *
 * This answers two mutually exclusive questions:
 *   1. Did an observed munmap cover the just-freed Mach receive buffer?
 *   2. If not, was the generated exception message larger than the receive
 *      limit or did another VM protection transition invalidate the buffer?
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. Carrick
 * native-tierd-exception(phase, host_pid, a, b, c, d) uses phase 1 for install
 * and phase 14 for mach_msg_server return; phase-14 `a` is the return status.
 * syscall::munmap:entry exposes address and length as arg0/arg1. proc:::exit
 * fires in the exiting process. `stop()` is a DTrace destructive action, so
 * launch with `-w`.
 *
 * PERTURBATION
 * ------------
 * LOW until failure: one install probe per guest thread and one kernel
 * munmap event per tracked process. At the named failure it deliberately
 * SIGSTOPs the process for debugger capture. This is mechanism attribution,
 * never timing evidence. Let the DTrace consumer end after scoped process
 * cleanup; do not abort it while the tracee continues.
 *
 * Usage:
 *   sudo dtrace -wZq -s scripts/dtrace/tier-d-mach-invalid-stop.d \
 *     > target/conformance/logs/.../trace.out
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TDMACHSTOP1|event=begin|time=%Y\n", walltimestamp);
}

carrick*:::native-tierd-exception
/arg0 == 1 && tracked[pid] == 0/
{
    tracked[pid] = 1;
    printf("TDMACHSTOP1|event=server-installed|ts=%d|pid=%d|tid=%d|wire-pid=%d|slots=%#x|registration=%#x|exception-port=%#x|port-set=%#x\n",
        timestamp, pid, tid, (int)arg1, arg2, arg3, arg4, arg5);
}

syscall::munmap:entry
/tracked[pid]/
{
    unmaps[pid]++;
    printf("TDMACHSTOP1|event=munmap|ts=%d|pid=%d|tid=%d|address=%#x|length=%#x\n",
        timestamp, pid, tid, arg0, arg1);
}

carrick*:::native-tierd-exception
/arg0 == 14/
{
    failed[pid] = 1;
    failures++;
    printf("TDMACHSTOP1|event=INVALID-DATA|ts=%d|pid=%d|tid=%d|wire-pid=%d|status=%#x|prior-restarts=%d|port-set=%#x|retry=%d|munmaps=%d\n",
        timestamp, pid, tid, (int)arg1, arg2, arg3, arg4, arg5,
        unmaps[pid]);
    stop();
}

proc:::exit
/failed[pid]/
{
    printf("TDMACHSTOP1|event=failed-process-exit|pid=%d|tid=%d\n", pid,
        tid);
    exit(0);
}

tick-180s
{
    printf("TDMACHSTOP1|event=bound|seconds=180|failures=%d\n", failures);
    exit(0);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("TDMACHSTOP1|event=end|failures=%d|errors=%d|time=%Y\n",
        failures, errors, walltimestamp);
}
