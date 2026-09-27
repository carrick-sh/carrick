#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-el1-retirement-grants.d — record the exact physical stage-2 lease
 * sequence behind repeated EL1 anonymous mapping retirement and reuse.
 *
 * WHAT IT MEASURES
 *   After the first mmap-arena translation fault, prints every such fault and
 *   every successful global-frame stage-2 map/unmap until the traced process
 *   exits. The event rows preserve timestamp, process, fault address, physical
 *   IPA, physical length, host address and permissions. They answer whether a
 *   later semantic grant overlaps a still-live physical lease or whether the
 *   wrong bytes arise after stage-2 allocation.
 *
 * PROVIDER ABI
 *   Qualified from carrick-observability and the shipped durable scripts on
 *   macOS/arm64:
 *     carrick*:::vcpu-fault(arg0=ESR, arg2=FAR)
 *     carrick*:::hvpatch-el1-frame-grant-plan(arg0=fault VA,
 *       arg1=semantic base, arg2=semantic length, arg3=permissions,
 *       arg4=request generation)
 *     carrick*:::pt-fault-walk(arg0=VA, arg1..arg4=L0..L3 descriptors)
 *     carrick*:::pt-fault-ttbr(arg0=VA, arg1=TTBR0_EL1)
 *     carrick*:::pt-fault-next-walk(arg0=adjacent VA,
 *       arg1..arg4=L0..L3 descriptors)
 *     carrick*:::hvpatch-sparse-boundary-walk(arg0=first VA beyond a host
 *       sparse publication, arg1..arg4=post-sync L0..L3 descriptors)
 *     carrick*:::hvpatch-global-frame-stage2(arg0=phase, arg1=IPA,
 *       arg2=len, arg3=host, arg4=perms), phase 0 map / 1 unmap
 *   The consumer must launch the exact signed Carrick artifact with `-c`, so
 *   `$target` is the CLI process and `progenyof($target)` includes its
 *   carrier-bearing child. Preserve that predicate across launch-shape changes.
 *
 * PERTURBATION
 *   Prints one row per relevant fault and stage-2 transition. This is ordering
 *   and address evidence only; no timing from this capture is citable.
 *
 * ACCEPTANCE
 *   A complete capture sees at least one anonymous-arena translation fault,
 *   one stage-2 map, target exit, zero DTrace errors, and zero drops. The 60 s
 *   bound makes a wedged target fail closed.
 */

#pragma D option bufsize=32m
#pragma D option dynvarsize=32m

dtrace:::BEGIN
{
    seconds = 0;
    active = 0;
    faults = 0;
    plans = 0;
    maps = 0;
    unmaps = 0;
    target_exited = 0;
    errors = 0;
    drops = 0;
    printf("EL1RETIREGRANT1|start|ns=%d|target=%d\n", timestamp, $target);
}

carrick*:::hvpatch-el1-frame-grant-plan
/(pid == $target || progenyof($target))/
{
    active = 1;
    plans++;
    printf("EL1RETIREGRANT1|plan|ns=%d|pid=%d|fault=0x%x|base=0x%x|len=0x%x|perms=0x%x|generation=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::vcpu-fault
/(pid == $target || progenyof($target)) &&
 arg2 >= 0x6000000000 && arg2 < 0x6800000000 &&
 (arg0 >> 26) == 0x24 && ((arg0 & 0x3f) & 0x3c) == 0x04/
{
    active = 1;
    faults++;
    printf("EL1RETIREGRANT1|fault|ns=%d|pid=%d|far=0x%x|esr=0x%x\n",
        timestamp, pid, arg2, arg0);
}

carrick*:::pt-fault-walk
/(pid == $target || progenyof($target)) &&
 arg0 >= 0x6000000000 && arg0 < 0x6800000000/
{
    printf("EL1RETIREGRANT1|walk|ns=%d|pid=%d|va=0x%x|l0=0x%x|l1=0x%x|l2=0x%x|l3=0x%x\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::pt-fault-ttbr
/(pid == $target || progenyof($target)) &&
 arg0 >= 0x6000000000 && arg0 < 0x6800000000/
{
    printf("EL1RETIREGRANT1|ttbr|ns=%d|pid=%d|va=0x%x|ttbr0=0x%x\n",
        timestamp, pid, arg0, arg1);
}

carrick*:::pt-fault-next-walk
/(pid == $target || progenyof($target)) &&
 arg0 >= 0x6000000000 && arg0 < 0x6800000000/
{
    printf("EL1RETIREGRANT1|next_walk|ns=%d|pid=%d|va=0x%x|l0=0x%x|l1=0x%x|l2=0x%x|l3=0x%x\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-sparse-boundary-walk
/(pid == $target || progenyof($target)) &&
 arg0 >= 0x6000000000 && arg0 < 0x6800000000/
{
    printf("EL1RETIREGRANT1|boundary_walk|ns=%d|pid=%d|va=0x%x|l0=0x%x|l1=0x%x|l2=0x%x|l3=0x%x\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target)) && active/
{
    maps += arg0 == 0;
    unmaps += arg0 == 1;
    printf("EL1RETIREGRANT1|stage2|ns=%d|pid=%d|phase=%d|ipa=0x%x|len=0x%x|host=0x%x|perms=0x%x\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

proc:::exit
/pid == $target/
{
    target_exited = 1;
}

tick-100ms
/target_exited && faults > 0 && plans > 0 && maps > 0 && drops == 0 && errors == 0/
{
    exit(0);
}

tick-100ms
/target_exited && (faults == 0 || plans == 0 || maps == 0 || drops != 0 || errors != 0)/
{
    printf("EL1RETIREGRANT1|INVALID|faults=%d|plans=%d|maps=%d|drops=%d|errors=%d\n",
        faults, plans, maps, drops, errors);
    exit(5);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 60 && !target_exited/
{
    printf("EL1RETIREGRANT1|TRUNCATED|seconds=%d\n", seconds);
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
    printf("EL1RETIREGRANT1|summary|faults=%d|plans=%d|maps=%d|unmaps=%d|target_exited=%d|errors=%d|drops=%d\n",
        faults, plans, maps, unmaps, target_exited, errors, drops);
}
