/*
 * WHAT: identify which rt_sigprocmask user copy was lowered to EFAULT.
 * ABI: carrick-observability's rt-sigprocmask-copy-refusal carries
 * arg0 u32 which (0=new_set read, 1=old_set write), arg1 u64 guest VA,
 * arg2 u32 variant: 1 OwnerRetired, 2 ReadSuspended, 3 Physical,
 * 4 OwnerWait, 5 Supply, 6 OutOfBounds, 7 Unsupported, 8 HostMap,
 * 9 MetadataAllocation, 10 terminal copyout EFAULT. Guest VA is not
 * a host pointer. Source-qualified; live macOS qualification is pending.
 * PERTURBATION: one printf per refusal; diagnostic only, no timing claims.
 * Bounded to 45 seconds. Zero events means the probe did not fire;
 * it cannot prove that a memory dependency did not occur.
 * Usage: carrick trace -s scripts/dtrace/rt-sigprocmask-copy-refusal.d \
 *   -o <capture> -- run ubuntu:24.04 /bin/sh -c '<probe>'
 */
#pragma D option quiet

carrick*:::rt-sigprocmask-copy-refusal
/pid == $target || progenyof($target)/
{
    events++;
    printf("SIGMASK1|pid=%d|tid=%d|which=%u|va=0x%llx|variant=%u\n",
        pid, tid, (uint32_t)arg0, (uint64_t)arg1, (uint32_t)arg2);
}

tick-1s { secs++; }
tick-1s /secs >= 45/ { exit(0); }
dtrace:::END
{
    printf("SIGMASK1|events=%llu\n", events);
}

dtrace:::END
/events == 0/
{
    printf("SIGMASK1|ERROR|probe did not fire; capture is inconclusive\n");
    exit(1);
}
