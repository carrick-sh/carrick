#!/usr/sbin/dtrace -qs
/*
 * Per-operation lookup work of HVPatch memory maintenance: the scrub a brk
 * shrink, an mremap onto reused arena VA, or an MREMAP_DONTUNMAP source runs
 * (`HvfVmState::ensure_frame_cow_write` with backing-maintenance intent,
 * then `HvfVmState::zero_guest_backing`), and how many bytes it zeroed.
 *
 * What it measures: for every census-armed operation, the Linux pages it
 * covered, the rows its lookups VISITED in the alias registry, the task
 * mapping index and the mm's frame-inventory extent ledger, next to the
 * populations those structures held. A visited count that tracks a
 * population names a full-table walk; one that tracks pages x population is
 * a per-page full-table walk (the 2026-09-24 cpython profile's shape); one
 * that tracks pages alone is the intended indexed lookup. It also sums the
 * `hvpatch-backing-scrub` bytes (explicitly zeroed vs. remapped to fresh
 * kernel zero pages) so a byte-level redundancy claim has its denominator.
 *
 * Provider ABI (carrick-observability `probes.rs`, provider `carrick`),
 * qualified live on macOS 26 arm64 on 2026-09-24:
 *   hvpatch-mm-maintenance-begin (uint32_t site, uint64_t requested_bytes)
 *       -- the census ARM. The producer reads its visit counters and the
 *          populations only while this probe is enabled, so this script MUST
 *          name it; a script naming only -work/-population arms nothing and
 *          prints an empty table (see hvpatch-mapping-index-census.d).
 *   hvpatch-mm-maintenance-work (uint32_t site, uint64_t pages,
 *       uint64_t alias_rows_visited, uint64_t task_rows_visited,
 *       uint64_t extents_visited)
 *   hvpatch-mm-maintenance-population (uint32_t site, uint64_t alias_rows,
 *       uint64_t task_rows, uint64_t extents)
 *       -- fired immediately after -work on the same host thread.
 *   hvpatch-backing-scrub (uint64_t total, uint64_t zeroed,
 *       uint64_t remapped, uint32_t eligible) -- one per flushed scrub run.
 * site 1 = backing-maintenance COW routing, 2 = scrub target resolution.
 * Visit counts are DIFFERENCES of per-thread counters across the operation,
 * so they are exactly that operation's walk length.
 *
 * Perturbation: bounded and one-sided. The visit counters are always on; the
 * two counter reads, one alias-registry lock (for the population), one
 * frame-inventory lock and the probe fires happen only while armed. Row and
 * byte columns are exact; this script reports no time.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-mm-maintenance-census.d -- run ...
 */

dtrace:::BEGIN
{
    begins = 0;
    works = 0;
    seconds = 0;
}

carrick*:::hvpatch-mm-maintenance-begin
/pid == $target || progenyof($target)/
{
    begins++;
}

carrick*:::hvpatch-mm-maintenance-work
/pid == $target || progenyof($target)/
{
    works++;
    self->site = arg0;
    self->pages = arg1;
    self->alias = arg2;
    self->task = arg3;
    self->ext = arg4;
    @ops[arg0] = count();
    @pages[arg0] = sum(arg1);
    @alias_visits[arg0] = sum(arg2);
    @task_visits[arg0] = sum(arg3);
    @extent_visits[arg0] = sum(arg4);
    @alias_max[arg0] = max(arg2);
    @task_max[arg0] = max(arg3);
    @extent_max[arg0] = max(arg4);
    @alias_per_page[arg0] = quantize(arg1 > 0 ? arg2 / arg1 : arg2);
    @extent_per_page[arg0] = quantize(arg1 > 0 ? arg4 / arg1 : arg4);
    @task_per_page[arg0] = quantize(arg1 > 0 ? arg3 / arg1 : arg3);
}

carrick*:::hvpatch-mm-maintenance-population
/(pid == $target || progenyof($target)) && self->site == arg0/
{
    @alias_pop[arg0] = avg(arg1);
    @task_pop[arg0] = avg(arg2);
    @extent_pop[arg0] = avg(arg3);
    @alias_pop_max[arg0] = max(arg1);
    @extent_pop_max[arg0] = max(arg3);
    self->site = 0;
}

carrick*:::hvpatch-backing-scrub
/pid == $target || progenyof($target)/
{
    @scrub_runs = count();
    @scrub_total = sum(arg0);
    @scrub_zeroed = sum(arg1);
    @scrub_remapped = sum(arg2);
}

tick-1s { seconds++; }
tick-1s /seconds >= 600/ { exit(0); }

dtrace:::END
/begins == 0/
{
    printf("ERROR: hvpatch-mm-maintenance-begin never fired: the census was not armed (or the workload did no maintenance)\n");
}

dtrace:::END
/begins != 0 && works == 0/
{
    printf("ERROR: census armed %d times but no -work record fired\n", begins);
}

dtrace:::END
{
    printf("armed=%d completed=%d\n", begins, works);
    printf("\n%-5s %10s %12s %14s %14s %14s\n", "site", "ops", "pages", "alias_visits", "task_visits", "extent_visits");
    printa("%-5d %@10d %@12d %@14d %@14d %@14d\n", @ops, @pages, @alias_visits, @task_visits, @extent_visits);
    printf("\n%-5s %12s %12s %12s\n", "site", "alias_max", "task_max", "extent_max");
    printa("%-5d %@12d %@12d %@12d\n", @alias_max, @task_max, @extent_max);
    printf("\n%-5s %12s %12s %12s %14s %14s\n", "site", "alias_pop", "task_pop", "extent_pop", "alias_pop_max", "extent_pop_max");
    printa("%-5d %@12d %@12d %@12d %@14d %@14d\n", @alias_pop, @task_pop, @extent_pop, @alias_pop_max, @extent_pop_max);
    printf("\nscrub runs / total bytes / zeroed bytes / remapped bytes\n");
    printa("%@d ", @scrub_runs);
    printa("%@d ", @scrub_total);
    printa("%@d ", @scrub_zeroed);
    printa("%@d\n", @scrub_remapped);
    printf("\nalias rows visited per page, by site\n");
    printa(@alias_per_page);
    printf("\nextents visited per page, by site\n");
    printa(@extent_per_page);
    printf("\ntask rows visited per page, by site\n");
    printa(@task_per_page);
}
