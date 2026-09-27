#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-el1-first-touch-grant-census.d — classify the stage-2 work behind
 * the signed EL1 anonymous first-touch slope.
 *
 * WHAT IT MEASURES
 *   The capture begins accounting when the first mmap-arena EL0 translation
 *   fault fires. It then counts every mmap translation/permission fault,
 *   successful global-frame stage-2 map by physical length, alias replay by
 *   size/result, frame-COW trigger, and delivered first-touch fault until the
 *   traced Carrick process exits. This distinguishes a bulk frame grant from
 *   page-granular backing, COW, or alias replay without adding product logging.
 *
 * PROVIDER ABI
 *   Qualified from carrick-observability and the shipped durable scripts on
 *   macOS/arm64:
 *     carrick*:::vcpu-fault(arg0=ESR, arg2=FAR)
 *     carrick*:::hvpatch-global-frame-stage2(arg0=phase, arg1=IPA,
 *       arg2=len, arg3=host, arg4=perms), phase 0 map / 1 unmap
 *     carrick*:::hv-vm-map-alias(arg0=VA, arg1=IPA, arg2=size, arg3=rc)
 *     carrick*:::hvpatch-frame-cow-trigger
 *     carrick*:::hvpatch-first-touch-deliver
 *   carrick trace binds $target at launch. carrick* plus progenyof follows
 *   every carrier child; execname is deliberately unused.
 *
 * PERTURBATION
 *   One probe action and aggregation update per relevant exit or stage-2
 *   transition. Counts are correctness evidence; timing under this script is
 *   not comparable with an untraced run.
 *
 * ACCEPTANCE
 *   Zero mmap translation faults or zero stage-2 maps after accounting starts
 *   is a failed capture. DTrace errors and drops fail it. The 30 s in-script
 *   bound prevents a wedged guest from leaving the consumer alive.
 */

#pragma D option dynvarsize=64m
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    live = 1;
    seconds = 0;
    complete = 0;
    active = 0;
    mmap_xlate = 0;
    stage2_maps = 0;
    stage2_unmaps = 0;
    alias_replays = 0;
    cow_triggers = 0;
    delivered = 0;
    drops = 0;
    errors = 0;
    printf("EL1GRANT1|start|ns=%d|target=%d\n", timestamp, $target);
}

carrick*:::vcpu-fault
/(pid == $target || progenyof($target)) &&
 arg2 >= 0x6000000000 && arg2 < 0x6800000000 &&
 (arg0 >> 26) == 0x24 && ((arg0 & 0x3f) & 0x3c) == 0x04/
{
    active = 1;
    mmap_xlate++;
    this->rw = (arg0 & 0x40) != 0 ? "write" : "read";
    @mmap_xlate_by_access[this->rw] = count();
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target)) && active && arg0 == 0/
{
    stage2_maps++;
    @stage2_map_len[arg2] = count();
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target)) && active && arg0 == 1/
{
    stage2_unmaps++;
    @stage2_unmap_len[arg2] = count();
}

carrick*:::hv-vm-map-alias
/(pid == $target || progenyof($target)) && active/
{
    alias_replays++;
    @alias_size_rc[arg2, arg3] = count();
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target)) && active/
{
    cow_triggers++;
}

carrick*:::hvpatch-first-touch-deliver
/(pid == $target || progenyof($target)) && active/
{
    delivered++;
    @delivered_reason[arg1] = count();
}

proc:::exit
/pid == $target/
{
    live = 0;
}

tick-100ms
/live == 0 && !complete/
{
    complete = 1;
    errors += mmap_xlate == 0 || stage2_maps == 0 || drops != 0;
    exit(errors == 0 ? 0 : 5);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 30 && !complete/
{
    complete = 1;
    printf("EL1GRANT1|TRUNCATED|seconds=%d\n", seconds);
    exit(4);
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("EL1GRANT1|summary|mmap_xlate=%d|stage2_maps=%d|stage2_unmaps=%d|alias_replays=%d|cow_triggers=%d|delivered=%d|drops=%d|errors=%d\n",
        mmap_xlate, stage2_maps, stage2_unmaps, alias_replays, cow_triggers,
        delivered, drops, errors);
    printa("EL1GRANT1|fault_access|%s|%@d\n", @mmap_xlate_by_access);
    printa("EL1GRANT1|stage2_map_len|0x%x|%@d\n", @stage2_map_len);
    printa("EL1GRANT1|stage2_unmap_len|0x%x|%@d\n", @stage2_unmap_len);
    printa("EL1GRANT1|alias|size=0x%x|rc=0x%x|%@d\n", @alias_size_rc);
    printa("EL1GRANT1|delivered_reason|%d|%@d\n", @delivered_reason);
}
