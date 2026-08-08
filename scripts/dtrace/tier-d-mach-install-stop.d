/*
 * tier-d-mach-install-stop.d — freeze each newly initialized Tier-D Mach
 * exception process before its guest can retire startup mappings.
 *
 * WHAT IT MEASURES
 * ----------------
 * The first native-tierd-exception phase-1 event in a process is emitted just
 * after the current guest thread's exception port is installed. The shared
 * mach_msg_server thread has been created immediately before this event. This
 * script stops the process once at that boundary so LLDB can read the server
 * thread's live request/reply buffers; after debugger detach/continue, it logs
 * every host munmap below 8 GiB. All Mach message buffers observed during this
 * campaign have been in that low Darwin allocation region; filtering the much
 * higher JIT-cache churn keeps the overlap evidence readable. Correlating the
 * two proves whether a startup unmap invalidates Carrick's host-private Mach
 * receive storage.
 *
 * PROVIDER ABI QUALIFICATION
 * --------------------------
 * Qualified on Darwin/arm64 on 2026-08-08. Carrick
 * native-tierd-exception(phase, host_pid, a, b, c, d) uses phase 1 for a
 * completed per-thread install and phase 14 for mach_msg_server return.
 * syscall::munmap:entry exposes address and length as arg0/arg1. `stop()` is a
 * DTrace destructive action, so launch with `-w`.
 *
 * PERTURBATION
 * ------------
 * DELIBERATE stop-the-world debugger boundary at the first install in every
 * process, then low-region kernel munmap tracing. Attribution only; never
 * timing evidence. Resume each stopped process explicitly and let the tracer
 * reach its bound naturally after scoped cleanup.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TDMACHINSTALL1|event=begin|time=%Y\n", walltimestamp);
}

carrick*:::native-tierd-exception
/arg0 == 1 && seen[pid] == 0/
{
    seen[pid] = 1;
    printf("TDMACHINSTALL1|event=STOP|ts=%d|pid=%d|tid=%d|wire-pid=%d|slots=%#x|registration=%#x|exception-port=%#x|port-set=%#x\n",
        timestamp, pid, tid, (int)arg1, arg2, arg3, arg4, arg5);
    stop();
}

syscall::munmap:entry
/seen[pid] && arg0 < 0x200000000/
{
    printf("TDMACHINSTALL1|event=munmap|ts=%d|pid=%d|tid=%d|address=%#x|length=%#x\n",
        timestamp, pid, tid, arg0, arg1);
}

carrick*:::native-tierd-exception
/arg0 == 14/
{
    printf("TDMACHINSTALL1|event=server-return|ts=%d|pid=%d|tid=%d|status=%#x|prior-restarts=%d|port-set=%#x|retry=%d\n",
        timestamp, pid, tid, arg2, arg3, arg4, arg5);
}

tick-300s
{
    printf("TDMACHINSTALL1|event=bound|seconds=300\n");
    exit(0);
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("TDMACHINSTALL1|event=end|errors=%d|time=%Y\n", errors,
        walltimestamp);
}
