#!/usr/sbin/dtrace -qs
/*
 * Order bounded HVPatch vCPU admission/reclaim against the guest syscalls that
 * create, block, and retire threads. This distinguishes a hard admission cap
 * from a guest thread that was admitted but resumed late (or returned early)
 * around a timed wait.
 *
 * Provider ABI qualified on macOS 15.6.1 / arm64 on 2026-08-15:
 * - carrick*:::hvpatch-syscall-service-begin and -clear carry int32 Linux pid,
 *   int32 Linux tid, uint32 ASID, uint64 syscall number.
 * - carrick*:::mn-admit carries int32 Linux tid, uint32 slot, uint32 budget.
 * - carrick*:::mn-reclaim carries int32 Linux tid, uint32 old slot,
 *   uint32 new slot, int32 kind (0 kept, 1 own slot, 2 different slot).
 *
 * The syscall stream is restricted to futex(98), clone(220), exit(93),
 * exit_group(94), nanosleep(101), and clock_nanosleep(115). `timestamp` is
 * monotonic host ns; compare ordering and deltas only. PERTURBATION: MEDIUM for
 * thread churn due to one scalar print per selected syscall edge and scheduler
 * event. Timing magnitudes are diagnostic, not performance evidence. Zero
 * admit or reclaim events, DTrace errors, or bounded termination make the
 * capture fail closed.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    admits = 0;
    reclaims = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 93 || arg3 == 94 || arg3 == 98 || arg3 == 101 || arg3 == 115 ||
  arg3 == 220)/
{
    events++;
    printf("HVPATCHMN1|syscall-begin|timestamp=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu\n",
        timestamp, pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2,
        (uint64_t)arg3);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 (arg3 == 93 || arg3 == 94 || arg3 == 98 || arg3 == 101 || arg3 == 115 ||
  arg3 == 220)/
{
    events++;
    printf("HVPATCHMN1|syscall-clear|timestamp=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu\n",
        timestamp, pid, tid, (int)arg0, (int)arg1, (uint32_t)arg2,
        (uint64_t)arg3);
}

carrick*:::mn-admit
/(pid == $target || progenyof($target))/
{
    events++;
    admits++;
    printf("HVPATCHMN1|admit|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|slot=%u|budget=%u\n",
        timestamp, pid, tid, (int)arg0, (uint32_t)arg1, (uint32_t)arg2);
}

carrick*:::mn-reclaim
/(pid == $target || progenyof($target))/
{
    events++;
    reclaims++;
    printf("HVPATCHMN1|reclaim|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|old_slot=%u|new_slot=%u|kind=%d\n",
        timestamp, pid, tid, (int)arg0, (uint32_t)arg1, (uint32_t)arg2,
        (int)arg3);
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCHMN1|summary|events=%d|admits=%d|reclaims=%d|bounded=%d|errors=%d\n",
        events, admits, reclaims, bounded, errors);
    exit(admits == 0 || reclaims == 0 || bounded != 0 || errors != 0 ? 1 : 0);
}
