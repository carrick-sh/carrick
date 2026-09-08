#!/usr/sbin/dtrace -qs
/*
 * hvpatch-alias-publication-order.d — in what order do concurrent guest mmap
 * alias installs STAGE (under the topology lock) versus PUBLISH (return to
 * the guest)?
 *
 * WHAT: for every guest mmap (AArch64 nr 222) one line per lifecycle point,
 * keyed on the Linux pid/tid the service-begin probe carries, with a
 * monotonic timestamp: syscall entry, AliasMap topology-lock acquired and
 * released (backend staging: reservation armed, hv_vm_map, alias commit
 * retrieved — a shared-file frame becomes visible to REUSERS in the backend
 * registry inside this window), the hv_vm_map itself, and the syscall
 * return (the kernel frame-inventory publication has completed by then).
 * Two installs of the same shared file where task C released the lock
 * BEFORE task B acquired it, yet B returned to the guest BEFORE C, is the
 * publication-order inversion behind the 2026-09-08 silent alias-install
 * abort (`UnreservedFrame`): B's batch names C's still-unpublished frame.
 * Post-process with a script that pairs release/acquire against returns;
 * the raw stream is deliberately kept so any ordering question can be re-asked.
 *
 * ABI (qualified live on macOS 26 arm64, 2026-09-08, from
 * carrick-observability/probes.rs and hvpatch-guest-syscall-flow.d):
 * - hvpatch-syscall-service-begin: arg0 i32 Linux pid, arg1 i32 Linux tid,
 *   arg2 u32 ASID, arg3 u64 syscall number; same host thread as the
 *   matching syscall-return (one host pthread per logical guest thread), so
 *   `self->` pairing is sound.
 * - hvpatch-topology-lock: arg0 u32 operation (8 = alias map, 10 = alias
 *   unmap), arg1 u32 phase (0 requested, 1 acquired, 2 released, 3 try
 *   miss), arg2 i32 guest pid, arg3 i32 guest tid, arg4 u64 elapsed ns.
 * - hv-vm-map-alias: arg0 u64 va, arg1 u64 ipa, arg2 u64 size, arg3 i32 rc,
 *   arg4 i32 forked.
 * - syscall-return: arg0 u64 number, arg2 signed retval, arg3 errno.
 * Host `pid` is the ONE carrier for every Linux process; only the Linux
 * identity in the probe arguments distinguishes guest tasks.
 *
 * PERTURBATION: moderate — a printf per mmap/munmap lifecycle point and
 * per topology-lock transition; nothing on the fault or instruction path.
 * It can shift lock scheduling, so only same-instrument orderings are
 * citable. Bounded: exits after BOUND_SECONDS. Zero mmap entries is a
 * failed capture, never evidence that the guest did not mmap.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-alias-publication-order.d \
 *     -o <out> -- run --fs host <image> <cmd>
 */
#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option switchrate=10hz
inline int BOUND_SECONDS = 45;

dtrace:::BEGIN
{
    printf("APO1|header|version=1|bound_s=%d\n", BOUND_SECONDS);
    secs = 0;
    entries = 0;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (arg3 == 222 || arg3 == 215)/
{
    self->lpid = (int)arg0;
    self->ltid = (int)arg1;
    self->nr = (int)arg3;
    entries++;
    printf("APO1|enter|ns=%llu|lpid=%d|ltid=%d|nr=%d\n",
        timestamp, self->lpid, self->ltid, self->nr);
}

carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && (arg0 == 8 || arg0 == 10) && (arg1 == 1 || arg1 == 2)/
{
    printf("APO1|lock|ns=%llu|lpid=%d|ltid=%d|op=%d|phase=%s|elapsed_ns=%llu\n",
        timestamp, (int)arg2, (int)arg3, (int)arg0,
        arg1 == 1 ? "acquired" : "released", (uint64_t)arg4);
}

carrick*:::hv-vm-map-alias
/(pid == $target || progenyof($target)) && self->nr == 222/
{
    printf("APO1|map|ns=%llu|lpid=%d|ltid=%d|va=0x%llx|ipa=0x%llx|size=0x%llx|rc=%d\n",
        timestamp, self->lpid, self->ltid, arg0, arg1, arg2, (int)arg3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 222 || arg0 == 215) && self->nr != 0/
{
    printf("APO1|return|ns=%llu|lpid=%d|ltid=%d|nr=%d|ret=%lld|errno=%d\n",
        timestamp, self->lpid, self->ltid, (int)arg0, (int64_t)arg2, (int)arg3);
    self->nr = 0;
}

profile:::tick-1sec
{
    secs++;
}

profile:::tick-1sec
/secs >= BOUND_SECONDS/
{
    printf("APO1|bound|secs=%d|entries=%d\n", secs, entries);
    exit(0);
}

dtrace:::END
/entries == 0/
{
    printf("APO1|error|zero mmap entries: the probes did not fire; this is not an idle guest\n");
}

dtrace:::END
/entries > 0/
{
    printf("APO1|end|entries=%d\n", entries);
}
