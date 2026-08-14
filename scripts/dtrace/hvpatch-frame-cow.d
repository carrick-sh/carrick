#!/usr/sbin/dtrace -qs
/*
 * Prove HVPatch frame-COW ordering and identity on the signed fork fixture.
 *
 * Provider ABI qualified from carrick-observability on Darwin/arm64:
 * carrick*:::hvpatch-frame-cow-trigger-identity/data carries the exact trigger
 * class plus Linux pid/tid/mm/ASID and, for a stage-1 permission fault,
 * ESR/FAR/TTBR0. carrick*:::hvpatch-frame-cow-intent carries write authority
 * (0 guest-visible, 1 backing maintenance, 2 privileged internal), then
 * carrick*:::hvpatch-frame-cow-identity carries Linux pid, Linux tid, mm id,
 * ASID, and phase.  The immediately following
 * carrick*:::hvpatch-frame-cow carries semantic VA, old/new FrameId, and
 * old/new 16 KiB global-frame IPA.  Both probes fire on the same host thread.
 * hvpatch-fork-frame-identity plus hvpatch-fork-frame carry the child mm/ASID,
 * parent and child MappingId, shared FrameId, stable global IPA, and physical
 * extent. pt-alias-receipt is deliberately five arguments (the sixth argument
 * of pt-alias-walk is not reliable on this macOS build) and carries the live
 * leaf, independently expected IPA/AP, and phase (0 parent armed, 1 child
 * inherited, 2 writer COW published, 3 COW preserved denied protection,
 * 4/5/6 later writable/read-only/inaccessible publication).
 * hvpatch-global-frame-stage2 carries every successful map/unmap of an HVPatch
 * physical extent, including host backing/perms on map.  Boot frames retain
 * stable identity-numbered global IPAs while replacement/COW frames live in
 * the reusable global-frame arena; both populations must have observable
 * stage-2 lifetimes.  This makes overlap, duplicate installation, and
 * reuse-before-retirement directly rejectable instead of inferred from
 * allocation code.
 * pt-fault-walk and pt-fault-ttbr carry the fault VA's live descriptors and
 * TTBR0 (including ASID), including Carrick-current-EL COW faults.
 *
 * Perturbation: USDT firings at each structural transition.  This is
 * correctness evidence, never timing evidence.  The final consumer must reject
 * zero/missing/duplicate/out-of-order phases, identity drift, unchanged frame
 * or IPA, drops, provider errors, timeout, interruption, and nonzero target
 * exit.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    events = 0;
    identities = 0;
    intents = 0;
    errors = 0;
    drops = 0;
    bounded = 0;
    target_exited = 0;
    ptes = 0;
    copies = 0;
    fork_identities = 0;
    fork_frames = 0;
    stage2_maps = 0;
    stage2_unmaps = 0;
    vm_events = 0;
    vm_generation[0] = 0;
    cow_phase0 = 0;
    cow_phase1 = 0;
    cow_phase2 = 0;
    pte_phase0 = 0;
    pte_phase1 = 0;
    pte_phase2 = 0;
    fault_ptes = 0;
    fault_ttbrs = 0;
    faults = 0;
    triggers = 0;
    trigger_identities = 0;
    permission_triggers = 0;
    printf("HVPATCHFRAMECOW4|header|version=4\n");
}

carrick*:::vcpu-fault-regs
/(pid == $target || progenyof($target))/
{
    faults++;
    printf("HVPATCHFRAMECOW4|fault|ts=%d|host_pid=%d|host_tid=%d|esr=%x|elr=%x|far=%x|insn=%x|rn=%d|xrn=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, (uint32_t)arg4, arg5);
}

carrick*:::pt-fault-walk
/(pid == $target || progenyof($target))/
{
    fault_ptes++;
    printf("HVPATCHFRAMECOW4|fault_pte|ts=%d|host_pid=%d|host_tid=%d|va=%x|l0=%x|l1=%x|l2=%x|l3=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::pt-fault-ttbr
/(pid == $target || progenyof($target))/
{
    fault_ttbrs++;
    printf("HVPATCHFRAMECOW4|fault_ttbr|ts=%d|host_pid=%d|host_tid=%d|va=%x|ttbr0=%x\n",
        timestamp, pid, tid, arg0, arg1);
}

carrick*:::pt-alias-receipt
/(pid == $target || progenyof($target))/
{
    ptes++;
    pte_phase0 += arg4 == 0;
    pte_phase1 += arg4 == 1;
    pte_phase2 += arg4 == 2;
    errors += ((arg1 & 0x0000fffffffff000) != (arg2 & 0x0000fffffffff000));
    errors += ((arg1 & 0xc0) != arg3);
    errors += (arg1 & 0x800) == 0;
    printf("HVPATCHFRAMECOW4|pte|ts=%d|host_pid=%d|va=%x|leaf=%x|expected_ipa=%x|expected_ap=%x|phase=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3, (uint32_t)arg4);
}

carrick*:::hvpatch-fork-frame-identity
/(pid == $target || progenyof($target))/
{
    self->fork_pid = arg0;
    self->fork_tid = arg1;
    self->fork_mm = arg2;
    self->fork_asid = arg3;
    self->fork_kind = arg4;
    self->have_fork_identity = 1;
    fork_identities++;
}

carrick*:::hvpatch-fork-frame
/(pid == $target || progenyof($target))/
{
    fork_frames++;
    errors += self->have_fork_identity != 1;
    printf("HVPATCHFRAMECOW4|fork_frame|ts=%d|host_pid=%d|linux_pid=%d|linux_tid=%d|mm=%d|asid=%d|kind=%d|parent_mapping=%d|child_mapping=%d|frame=%d|ipa=%x|length=%x|identity=%d\n",
        timestamp, pid, self->fork_pid, self->fork_tid, self->fork_mm, self->fork_asid,
        self->fork_kind, arg0, arg1, arg2, arg3, arg4,
        self->have_fork_identity);
    self->have_fork_identity = 0;
}

carrick*:::vm-lifecycle
/(pid == $target || progenyof($target))/
{
    vm_generation[pid] += arg0 == 1;
    vm_events++;
    printf("HVPATCHFRAMECOW4|vm|ts=%d|host_pid=%d|operation=%d|admission=%d|generation=%d\n",
        timestamp, pid, (uint32_t)arg0, (int32_t)arg1, vm_generation[pid]);
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target))/
{
    stage2_maps += arg0 == 0;
    stage2_unmaps += arg0 == 1;
    errors += arg0 > 1;
    errors += arg1 == 0 || arg2 == 0;
    errors += arg0 == 0 && arg3 == 0;
    errors += arg0 == 1 && (arg3 != 0 || arg4 != 0);
    errors += vm_generation[pid] == 0;
    printf("HVPATCHFRAMECOW4|stage2|ts=%d|host_pid=%d|vm=%d|phase=%d|ipa=%x|length=%x|host=%x|perms=%x\n",
        timestamp, pid, vm_generation[pid], (uint32_t)arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-frame-cow-trigger-identity
/(pid == $target || progenyof($target))/
{
    self->trigger_pid = arg0;
    self->trigger_tid = arg1;
    self->trigger_mm = arg2;
    self->trigger_asid = arg3;
    self->trigger_class = arg4;
    self->have_trigger_identity = 1;
    trigger_identities++;
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    triggers++;
    permission_triggers += self->trigger_class == 0;
    errors += self->have_trigger_identity != 1;
    errors += self->trigger_class > 3;
    errors += self->trigger_class == 0 && (arg1 == 0 || arg2 == 0 || arg3 == 0);
    printf("HVPATCHFRAMECOW4|trigger|ts=%d|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|mm=%d|asid=%d|class=%d|va=%x|syndrome=%x|far=%x|ttbr0=%x|identity=%d\n",
        timestamp, pid, tid, self->trigger_pid, self->trigger_tid,
        self->trigger_mm, self->trigger_asid, self->trigger_class,
        arg0, arg1, arg2, arg3, self->have_trigger_identity);
    self->have_trigger_identity = 0;
}

carrick*:::hvpatch-frame-cow-intent
/(pid == $target || progenyof($target))/
{
    self->intent = arg0;
    self->have_intent = 1;
    intents++;
}

carrick*:::hvpatch-frame-cow-identity
/(pid == $target || progenyof($target))/
{
    self->linux_pid = arg0;
    self->linux_tid = arg1;
    self->mm = arg2;
    self->asid = arg3;
    self->phase = arg4;
    self->have_identity = 1;
    identities++;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target))/
{
    events++;
    cow_phase0 += self->phase == 0;
    cow_phase1 += self->phase == 1;
    cow_phase2 += self->phase == 2;
    errors += self->have_identity != 1;
    errors += self->have_intent != 1;
    errors += self->intent > 2;
    errors += arg1 == arg2;
    errors += arg3 == arg4;
    printf("HVPATCHFRAMECOW4|event|ts=%d|host_pid=%d|linux_pid=%d|linux_tid=%d|mm=%d|asid=%d|intent=%d|phase=%d|va=%x|old_frame=%d|new_frame=%d|old_ipa=%x|new_ipa=%x|identity=%d\n",
        timestamp, pid, self->linux_pid, self->linux_tid, self->mm, self->asid,
        self->intent, self->phase, arg0, arg1, arg2, arg3, arg4, self->have_identity);
    self->have_identity = 0;
    self->have_intent = 0;
}

carrick*:::hvpatch-frame-cow-copy
/(pid == $target || progenyof($target))/
{
    copies++;
    errors += arg2 != arg3;
    errors += arg4 != 16384;
    printf("HVPATCHFRAMECOW4|copy|ts=%d|host_pid=%d|old_frame=%d|old_ipa=%x|source_hash=%x|dest_hash=%x|length=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
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
    target_exited = 1;
    errors += events == 0 || fork_frames == 0 || ptes == 0 || stage2_maps == 0 || vm_events == 0;
    errors += identities != events || intents != events || fork_identities != fork_frames;
    errors += trigger_identities != triggers || triggers * 3 != events;
    errors += permission_triggers == 0;
    errors += cow_phase0 == 0 || cow_phase0 != cow_phase1 || cow_phase1 != cow_phase2;
    errors += pte_phase0 == 0 || pte_phase1 == 0 || pte_phase2 == 0;
    exit(errors == 0 ? 0 : 5);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCHFRAMECOW4|summary|events=%d|identities=%d|intents=%d|triggers=%d|trigger_identities=%d|permission_triggers=%d|fork_identities=%d|fork_frames=%d|stage2_maps=%d|stage2_unmaps=%d|vm_events=%d|ptes=%d|copies=%d|faults=%d|fault_ptes=%d|fault_ttbrs=%d|errors=%d|drops=%d|bounded=%d|target_exited=%d\n",
        events, identities, intents, triggers, trigger_identities, permission_triggers, fork_identities, fork_frames, stage2_maps,
        stage2_unmaps, vm_events, ptes, copies, faults, fault_ptes, fault_ttbrs, errors,
        drops, bounded, target_exited);
}
