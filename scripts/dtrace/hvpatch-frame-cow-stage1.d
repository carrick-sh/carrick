#!/usr/sbin/dtrace -qs
/*
 * Attribute an HVPatch frame-COW rollback inside stage-1 publication.
 *
 * Provider ABI qualified on Darwin/arm64 from the current signed Carrick
 * binary: the pid provider exposes the non-external Rust symbols for
 * PageTableManager::repoint_preserving_attributes and
 * PageTableManager::set_writable_preserving_attributes. On a pid-provider
 * return probe, arg0 is the return-site offset and arg1 is the AArch64 integer
 * return register. The accompanying carrick USDT events use the durable
 * hvpatch-frame-cow profile ABI: trigger precedes mutation and phase 0 is the
 * successful stage-2 map boundary.
 *
 * Perturbation: two pid return probes on page-table COW publication plus the
 * existing COW USDT events. This is correctness attribution, never timing
 * evidence. This script is diagnostic and non-gating: its exit status only
 * reports DTrace execution errors. Consumers must reject a capture when the
 * return count required for the exercised path is zero. In particular,
 * repoints must be nonzero for repointing paths and writable must be nonzero
 * for in-place write-enable paths; trigger/stage2 counts are meaningful only
 * when the selected workload reaches frame COW.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    repoints = 0;
    writable = 0;
    triggers = 0;
    stage2 = 0;
    printf("HVPATCHCOWSTAGE1|header|version=1\n");
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    triggers++;
    printf("HVPATCHCOWSTAGE1|trigger|ts=%d|pid=%d|va=%x\n",
        timestamp, pid, arg0);
}

carrick*:::hvpatch-frame-cow-identity
/(pid == $target || progenyof($target))/
{
    self->cow_phase = arg4;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target)) && self->cow_phase == 0/
{
    stage2++;
    printf("HVPATCHCOWSTAGE1|stage2|ts=%d|pid=%d|va=%x|old_ipa=%x|new_ipa=%x\n",
        timestamp, pid, arg0, arg3, arg4);
}

pid$target::*repoint_preserving_attributes*:return
{
    repoints++;
    printf("HVPATCHCOWSTAGE1|repoint_return|ts=%d|pid=%d|offset=%x|x0=%x\n",
        timestamp, pid, arg0, arg1);
}

pid$target::*set_writable_preserving_attributes*:return
{
    writable++;
    printf("HVPATCHCOWSTAGE1|writable_return|ts=%d|pid=%d|offset=%x|x0=%x\n",
        timestamp, pid, arg0, arg1);
}

proc:::exit
/pid == $target/
{
    printf("HVPATCHCOWSTAGE1|summary|repoints=%d|writable=%d|triggers=%d|stage2=%d|gating=0\n",
        repoints, writable, triggers, stage2);
    exit(0);
}

dtrace:::ERROR
{
    printf("HVPATCHCOWSTAGE1|error|epid=%d\n", arg1);
    exit(2);
}
