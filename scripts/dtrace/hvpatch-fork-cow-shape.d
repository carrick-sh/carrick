#!/usr/sbin/dtrace -qs
/*
 * Aggregate the frame-COW shape of a repeated HVPatch fork workload.
 *
 * WHAT IT MEASURES
 * ----------------
 * Counts COW triggers and committed frame splits by semantic VA, authenticated
 * in-place last-owner promotions, plus forked frame kinds. This identifies
 * pages that every short-lived child writes and therefore selects whether fork
 * preparation, lazy COW, or child teardown is the next architectural target.
 *
 * LIVE ABI
 * --------
 * Qualified from carrick-observability on Darwin/arm64, 2026-09-18:
 * hvpatch-frame-cow-trigger-identity arg4 is trigger class; the immediately
 * following hvpatch-frame-cow-trigger arg0 is semantic VA.
 * hvpatch-frame-cow-identity arg4 is phase (0 mapped, 1 stage-1 published,
 * 2 committed); the immediately following hvpatch-frame-cow arg0 is semantic
 * VA. hvpatch-fork-frame-identity arg4 is fork-frame kind; its paired data
 * event closes that identity. pt-alias-receipt phase 7 is an authenticated
 * in-place write grant after VM-wide last-owner proof.
 *
 * PERTURBATION
 * ------------
 * Three USDT streams and in-kernel aggregations only. There is no per-event
 * output or copy hashing. Counts are diagnostic; elapsed time is not evidence.
 */

#pragma D option quiet
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    started = timestamp;
    triggers = 0;
    cow_commits = 0;
    fork_frames = 0;
    errors = 0;
    drops = 0;
    bounded = 0;
    target_exited = 0;
    exclusive_promotions = 0;
    printf("HVPATCHFORKCOWSHAPE2|header|version=2\n");
}

carrick*:::hvpatch-frame-cow-trigger-identity
/(pid == $target || progenyof($target))/
{
    self->trigger_class = (uint32_t)arg4;
    self->have_trigger_identity = 1;
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    errors += self->have_trigger_identity != 1;
    triggers++;
    @trigger_va_class[(uint64_t)arg0, self->trigger_class] = count();
    self->have_trigger_identity = 0;
}

carrick*:::hvpatch-frame-cow-identity
/(pid == $target || progenyof($target))/
{
    self->cow_phase = (uint32_t)arg4;
    self->have_cow_identity = 1;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target))/
{
    errors += self->have_cow_identity != 1;
    cow_commits += self->cow_phase == 2;
    @committed_cow_va[(uint64_t)arg0] = sum(self->cow_phase == 2);
    self->have_cow_identity = 0;
}

carrick*:::pt-alias-receipt
/(pid == $target || progenyof($target)) && arg4 == 7/
{
    exclusive_promotions++;
    @exclusive_va[(uint64_t)arg0] = count();
}

carrick*:::hvpatch-fork-frame-identity
/(pid == $target || progenyof($target))/
{
    self->fork_kind = (uint32_t)arg4;
    self->have_fork_identity = 1;
}

carrick*:::hvpatch-fork-frame
/(pid == $target || progenyof($target))/
{
    errors += self->have_fork_identity != 1;
    fork_frames++;
    @fork_kind[self->fork_kind] = count();
    self->have_fork_identity = 0;
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
    exit(triggers > 0 && cow_commits > 0 && fork_frames > 0 && errors == 0 && drops == 0 ? 0 : 2);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPATCHFORKCOWSHAPE2|summary|status=%s|triggers=%d|cow_commits=%d|exclusive_promotions=%d|fork_frames=%d|errors=%d|drops=%d|bounded=%d|target_exited=%d\n",
        target_exited && triggers > 0 && cow_commits > 0 && fork_frames > 0 &&
        errors == 0 && drops == 0 && !bounded ? "ok" : "error",
        triggers, cow_commits, exclusive_promotions, fork_frames, errors, drops, bounded, target_exited);
    printa("HVPATCHFORKCOWSHAPE2|trigger|va=%x|class=%d|count=%@d\n", @trigger_va_class);
    printa("HVPATCHFORKCOWSHAPE2|commit|va=%x|count=%@d\n", @committed_cow_va);
    printa("HVPATCHFORKCOWSHAPE2|exclusive|va=%x|count=%@d\n", @exclusive_va);
    printa("HVPATCHFORKCOWSHAPE2|fork_kind|kind=%d|count=%@d\n", @fork_kind);
}
