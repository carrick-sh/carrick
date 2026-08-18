#!/usr/sbin/dtrace -qs
/*
 * Which lifecycle phase does an HVPatch M:N clone child actually reach?
 *
 * `sibling materialization start gate timed out` says only that the PARENT
 * gave up after 10 s; it does not say whether the child never started, never
 * got a scheduler slot, or got one and then failed to materialize. This
 * counts every phase transition per tid so the stall can be attributed to an
 * exact step instead of inferred from a backtrace.
 *
 * Provider ABI qualified on macOS 15.6.1 / arm64 on 2026-08-18:
 * - carrick*:::mn-clone-outcome carries int32 Linux tid, uint32 phase,
 *   int32 errno. Phase ordinals come from
 *   `carrick_observability::probes::HvpatchCloneThreadPhase`:
 *   0 AdmissionClosed, 1 AdmissionCancelled, 2 Reserved, 3 HostThreadStarted,
 *   4 ChildCancelledBeforeSlot, 5 Admitted, 6 ChildCancelledBeforeMaterialize,
 *   7 Materialized, 8 ChildCancelledAfterMaterialize, 9 MaterializationFailed,
 *   10 HostThreadSpawnFailed, 11 StartCancelled, 12 ChildPublished,
 *   13 Started, 14 Completed.
 * - carrick*:::mn-admit carries int32 tid, uint32 slot, uint32 budget.
 *
 * Read it as a funnel: tids that reach 3 but never 5 are starving on a
 * scheduler slot; 5 but never 7 are failing inside materialization; 7 but
 * never 13 are stuck on the start handshake.
 *
 * PERTURBATION: LOW -- one aggregation update per clone lifecycle edge, which
 * is a few hundred events per run, not a per-syscall path.
 */

#pragma D option quiet
#pragma D option aggsortkey

dtrace:::BEGIN { events = 0; }

carrick*:::mn-clone-outcome
{
    events++;
    @phase[(int)arg1] = count();
    @last[(int)arg0] = max((int)arg1);
}

carrick*:::mn-admit
{
    @budget[(int)arg2] = count();
}

dtrace:::END
{
    printf("CLONEPHASE1|events=%d\n", events);
    printf("\n-- transitions by phase ordinal --\n");
    printa("phase %-3d %@d\n", @phase);
    printf("\n-- furthest phase reached, per linux tid --\n");
    printa("tid %-5d furthest=%@d\n", @last);
    printf("\n-- admits by budget --\n");
    printa("budget %-4d admits=%@d\n", @budget);
}
