/*
 * Ordered HVPatch futex route identity for a bounded correctness reducer.
 *
 * Measures the authoritative Linux pid/tid/ASID at futex syscall entry and the
 * dispatcher route selected for each futex address. This distinguishes a true
 * MAP_SHARED host word (`shared=1`, stable host address across fork) from an
 * accidental process-private parking-lot route (`shared=0`).
 *
 * Provider ABI qualified on macOS 15.6.1 / arm64 on 2026-08-14:
 * - carrick*:::hvpatch-syscall-service-begin is four scalar CTF values:
 *   int32 linux_pid, int32 linux_tid, uint32 ASID, uint64 syscall number.
 * - carrick*:::hvpatch-syscall-service-clear repeats those four scalars.
 * - carrick*:::futex-route is five scalar CTF values: uint32 host pid,
 *   uint64 guest address, int32 command, int32 shared, uint64 host address.
 * - carrick*:::mn-admit is three scalar CTF values: int32 Linux tid,
 *   uint32 slot, uint32 budget; mn-reclaim is int32 Linux tid, uint32 old
 *   slot, uint32 new slot, int32 kind.
 *
 * PERTURBATION: HIGH for futex-heavy workloads because this prints every futex
 * route. Use only with a small reducer; conclusions are identity/ordering only,
 * never timing evidence. A capture with no futex route is an error.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("HVPATCHFUTEX1|phase=begin\n");
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && arg3 == 98/
{
    syscall_active[pid, tid] = 1;
    linux_pid[pid, tid] = (int)arg0;
    linux_tid[pid, tid] = (int)arg1;
    asid[pid, tid] = (uint32_t)arg2;
}

carrick*:::futex-route
/(pid == $target || progenyof($target))/
{
    routes++;
    printf("HVPATCHFUTEX1|phase=route|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|guest_addr=%#x|op=%d|shared=%d|host_addr=%#x\n",
        pid, tid, linux_pid[pid, tid], linux_tid[pid, tid], asid[pid, tid],
        arg1, (int)arg2, (int)arg3, arg4);
}

carrick*:::mn-admit
/(pid == $target || progenyof($target))/
{
    admits++;
    printf("HVPATCHFUTEX1|phase=mn-admit|host_pid=%d|host_tid=%d|linux_tid=%d|slot=%u|budget=%u\n",
        pid, tid, (int)arg0, (uint32_t)arg1, (uint32_t)arg2);
}

carrick*:::mn-reclaim
/(pid == $target || progenyof($target))/
{
    reclaims++;
    printf("HVPATCHFUTEX1|phase=mn-reclaim|host_pid=%d|host_tid=%d|linux_tid=%d|old_slot=%u|new_slot=%u|kind=%d\n",
        pid, tid, (int)arg0, (uint32_t)arg1, (uint32_t)arg2, (int)arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && arg3 == 98/
{
    syscall_active[pid, tid] = 0;
    linux_pid[pid, tid] = 0;
    linux_tid[pid, tid] = 0;
    asid[pid, tid] = 0;
}

tick-1s { seconds++; }
tick-1s /seconds >= 60/ { timed_out = 1; exit(0); }
proc:::exit /pid == $target/ { exit(0); }

END
{
    printf("HVPATCHFUTEX1|phase=end|routes=%d|admits=%d|reclaims=%d|timed_out=%d\n",
        routes, admits, reclaims, timed_out);
    exit(routes == 0 ? 1 : 0);
}
