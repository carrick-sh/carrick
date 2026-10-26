#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-host-read-stage2-invariant.d — identify the stage-2 mutation that
 * makes a current EL1 host-read selection lose physical authority.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * The failure-only host-read retention reason and exact carrier record
 * snapshot, plus stage-2 record registration/rebind/retirement and stage-1
 * Editor release entries with `ustack(8)`. The test's event-ring post-mortem
 * supplies the paired selected/current Editor revisions and held bit.
 *
 * `RETENTION-DETAIL` state bits are: mapped 0, backend mapping 1, retirement
 * requested 2, terminalized 3, superseded 4, release in flight 5, release
 * retry 6, sampled publication authority 7, and pin count in bits 63:16.
 *
 * (b) PROVIDER ABI
 * ----------------
 * `hvpatch-el1-host-read-retention-detail(ipa, reason, record_id,
 * vm_generation, owner_generation, state)` is a failure-only USDT probe.
 * The pid-provider arguments are Rust implementation ABI and deliberately
 * undecoded; stacks and the USDT record identity provide attribution. For an
 * embedded signed test `$target` is the carrier itself. A valid capture must
 * contain at least one `PREFLIGHT` and one USDT event; zero events means a
 * probe did not fire.
 *
 * (c) PERTURBATION
 * ----------------
 * Low until a refusal, then moderate: one USDT record per physical retention
 * refusal and one eight-frame stack per matching lifecycle mutation. This is
 * ordering evidence only, never timing evidence. The tick bound terminates
 * tracing after 60 seconds.
 */
#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TRACE begin target=%d\n", $target);
}

carrick*:::hvpatch-el1-host-read-retention
/pid == $target || progenyof($target)/
{
    printf("RETENTION ts=%lld pid=%d tid=%d ipa=0x%llx reason=%u\n",
        walltimestamp, pid, tid, arg0, arg1);
}

carrick*:::hvpatch-el1-host-read-retention-detail
/pid == $target || progenyof($target)/
{
    printf("RETENTION-DETAIL ts=%lld pid=%d tid=%d ipa=0x%llx reason=%u record=%llu vm_generation=%llu owner_generation=%llu state=0x%llx mapped=%u backend=%u retirement_requested=%u terminal=%u superseded=%u release_in_flight=%u release_retry=%u publication_authority=%u pins=%llu\n",
        walltimestamp, pid, tid, arg0, arg1, arg2, arg3, arg4, arg5,
        arg5 & 1, (arg5 >> 1) & 1, (arg5 >> 2) & 1,
        (arg5 >> 3) & 1, (arg5 >> 4) & 1, (arg5 >> 5) & 1,
        (arg5 >> 6) & 1, (arg5 >> 7) & 1, arg5 >> 16);
    ustack(8);
}

pid$target::*register_stage2_record_locked*:entry,
pid$target::*rebind_stage2_record*:entry,
pid$target::*request_record_retirement*:entry,
pid$target::*prepare_record_retirement*:entry,
pid$target::*terminalize_record*:entry,
pid$target::*remove_record*:entry,
pid$target::*remove_terminal_stage2_record*:entry
{
    printf("STAGE2-LIFECYCLE ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p a4=%p a5=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3, arg4, arg5);
    ustack(8);
}

pid$target::*edit_unpublishing*:entry,
pid$target::*finish_release*:entry,
pid$target::*close_and_wait_for_editor*:entry
{
    printf("EDITOR-LIFECYCLE ts=%lld pid=%d tid=%d fn=%s a0=%p a1=%p a2=%p a3=%p\n",
        walltimestamp, pid, tid, probefunc, arg0, arg1, arg2, arg3);
    ustack(8);
}

pid$target::*run_fixture_in_image*:entry,
pid$target::*poll_with_engine*:entry
{
    printf("PREFLIGHT ts=%lld pid=%d tid=%d fn=%s\n",
        walltimestamp, pid, tid, probefunc);
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
