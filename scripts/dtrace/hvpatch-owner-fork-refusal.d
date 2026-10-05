#!/usr/sbin/dtrace -qs
/*
 * WHICH OWNER FORK SERVICE STAGE REFUSED THE CLOSED CHILD?
 *
 * (a) Count closed child publications and print each owner Fork refusal's
 *     raw Linux errno, service stage and exact parent/child MM identity.
 *     A closed publication with no refusal is not proof of a successful
 *     fork; compare the guest exit and the host fork runtime stages too.
 *
 * (b) Provider ABI declared by carrick-observability for Darwin/arm64:
 *     hvpatch-owner-fork-refusal(u32 errno, u64 stage, u64 parent_mm,
 *     u64 child_mm, u64 parent_generation). Stages: 0 slot, 1 operation,
 *     2 parent space, 3 table pool/live words, 4 census, 5 prepare,
 *     6 physical custody, 7 owner publication, 8 detached receipt.
 *     hvpatch-el1-root-prepublish(u64 mm, u32 phase) phase 9 records the
 *     closed child publication before this service starts. Live provider
 *     qualification on a signed artifact is pending; zero refusal events
 *     cannot be interpreted as a successful owner Fork.
 *
 * (c) Perturbation: one failure-only scalar probe per refused owner Fork,
 *     plus one low-frequency publication probe per child. No syscall or
 *     descriptor hot-path probe is enabled. The 45 s bound prevents a
 *     wedged guest from leaving this capture running indefinitely.
 *
 * Usage: target/release/carrick trace --script scripts/dtrace/hvpatch-owner-fork-refusal.d -- run ...
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    refusals = 0;
    children = 0;
    errors = 0;
    drops = 0;
    bounded = 0;
}

carrick*:::hvpatch-el1-root-prepublish
/(pid == $target || progenyof($target)) && arg1 == 9/
{
    children++;
    printf("OWNERFORKREFUSAL1|closed-child|mm=%llu|pid=%d\n",
        (uint64_t)arg0, pid);
}

carrick*:::hvpatch-owner-fork-refusal
/pid == $target || progenyof($target)/
{
    refusals++;
    printf("OWNERFORKREFUSAL1|refused|errno=%u|stage=%llu|parent_mm=%llu|child_mm=%llu|generation=%llu|pid=%d\n",
        (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4, pid);
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(children == 0 || errors != 0 || drops != 0 ? 3 : 0);
}

profile:::tick-1sec
/timestamp - started > 45 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("OWNERFORKREFUSAL1|summary|closed_children=%d|refusals=%d|errors=%d|drops=%d|bounded=%d\n",
        children, refusals, errors, drops, bounded);
}
