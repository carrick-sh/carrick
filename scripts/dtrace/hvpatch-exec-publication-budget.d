#pragma D option quiet

/*
 * HOW MUCH INSTRUCTION-CACHE MAINTENANCE DO EXECUTABLE PUBLICATIONS COST?
 *
 * (a) What it measures: every EL0-executable publication that reaches the
 *     carrier's instruction-cache authority (`hvpatch-exec-publication`),
 *     counted with the bytes announced and the invalidations issued, so a
 *     workload's budget reads directly: data-only pages must cost nothing,
 *     and an executable page one invalidation per frame incarnation (or
 *     host write). Written for work/icache-clean (2026-10-01), the
 *     Linux-parity fix for stale instructions on recycled frames.
 *
 * (b) Provider ABI facts: `carrick*:::hvpatch-exec-publication` arg0 =
 *     guest-physical output, arg1 = bytes, arg2 = invalidations issued
 *     (0 = every page already clean). USDT probes follow forked children
 *     under the progeny predicate.
 *
 * (c) Perturbation: one aggregation per executable publication; none on
 *     data pages.
 *
 * Usage:
 *   target/release/carrick trace --script scripts/dtrace/hvpatch-exec-publication-budget.d \
 *     -- run ... <workload>
 */

carrick*:::hvpatch-exec-publication
/pid == $target || progenyof($target)/
{
    @announced = count();
    @bytes = sum(arg1);
    @invalidations = sum(arg2);
    @clean = sum(arg2 == 0 ? 1 : 0);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

END
{
    printa("announced %@d\n", @announced);
    printa("bytes %@d\n", @bytes);
    printa("invalidations %@d\n", @invalidations);
    printa("already_clean %@d\n", @clean);
}
