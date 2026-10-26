#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-root-slot-retirement.d — follow a pooled stage-1 root from
 * publication through whole-MM retirement and pool return.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * Entries, raw arguments and eight host frames for stage-2 record admission,
 * pooled-root allocation/publication/release, neutral record retirement, and
 * the enclosing whole-MM/table-capacity retirement. `RETIRE` reads the first
 * u64 of `CarrierStage2Record`, whose first snapshot field is `record_id`.
 * The 60-second DTrace tick is an independent bound.
 *
 * (b) PROVIDER ABI
 * ----------------
 * The pid provider on `$target`; for carrick-embed `$target` must be the test
 * executable itself, because that process is the carrier. Do not put `env` or
 * another wrapper in dtrace's `-c` command: the pid provider is removed at
 * exec. Rust symbols are matched with mangled-name wildcards and were live-
 * qualified against `el1_sched-775614d8f5f84d25` from 6a20be84e. macOS SIP
 * requires the carrier to be diagnostic-signed with `get-task-allow` as well
 * as the hypervisor entitlement.
 *
 * The record-registration arguments use Rust's implementation ABI and are
 * deliberately labelled raw/ambiguous. Only `allocate_slot_at` arg1 (the IPA)
 * and `CarrierStage2Record`'s first u64 (`record_id`) are decoded. Ustacks are
 * the authority for every other ownership attribution.
 *
 * (c) PERTURBATION
 * ----------------
 * Moderate: one fasttrap plus `ustack(8)` for every matching lifecycle entry,
 * including every initial stage-2 record registration. Use for attribution,
 * never timing. A zero-event capture is invalid; the `PREFLIGHT` sentinels
 * prove attachment in the signed `el1_sched` witness.
 */
#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TRACE begin target=%d\n", $target);
}

pid$target::*request_record_retirement*:entry,
pid$target::*prepare_record_retirement*:entry,
pid$target::*terminalize_record*:entry
{
    this->record = (uint64_t *)copyin(arg0, 8);
    printf("RETIRE ts=%lld pid=%d tid=%d fn=%s record_id=%llu a0=%p a1=%p a2=%p a3=%p\n",
        walltimestamp, pid, tid, probefunc, this->record[0], arg0, arg1, arg2, arg3);
    ustack(8);
}

pid$target::*terminalize_carrier_stage2_retirement*:entry
{
    printf("RETIRE-CARRIER ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3);
    ustack(8);
}

pid$target::*register_stage2_record_locked*:entry
{
    printf("REGISTER ts=%lld pid=%d tid=%d fn=%s state=%p vm_or_spec=%p ipa_or_spec=%p len_or_spec=%p a4=%p a5=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3, arg4, arg5);
    ustack(8);
}

pid$target::*register_stage2_record_locked*:return
{
    printf("REGISTER-RETURN ts=%lld pid=%d tid=%d fn=%s offset=%p result=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1);
}

pid$target::*publish_pooled_exec_root_owner_in*:entry,
pid$target::*publish_exec_region_host_owner_in*:entry
{
    printf("PUBLISH ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p a4=%p a5=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3, arg4, arg5);
    ustack(8);
}

pid$target::*allocate_slot_at*:entry,
pid$target::*PooledRootSlotHandle*release_slot*:entry,
pid$target::*release_pooled_root_slot*:entry,
pid$target::*PooledRootSlotHandle*drop*:entry
{
    printf("ROOTSLOT ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3);
    ustack(8);
}

pid$target::*retire_table_capacity*:entry,
pid$target::*retire_table_capacity*closure*:entry,
pid$target::*retire_mm_root_stage2*:entry,
pid$target::*retire_task_state_process_mappings*:entry,
pid$target::*retire_detached_address_space*:entry
{
    printf("TABLE ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3);
    ustack(8);
}

pid$target::*carrier_or_fail*:entry,
pid$target::*run_fixture_in_image*:entry
{
    printf("PREFLIGHT ts=%lld pid=%d tid=%d fn=%s\n",
        walltimestamp, pid, tid, probefunc);
    ustack(8);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 60/
{
    printf("TRACE bound reached seconds=%d\n", secs);
    exit(0);
}

dtrace:::END
{
    printf("TRACE end seconds=%d\n", secs);
}
