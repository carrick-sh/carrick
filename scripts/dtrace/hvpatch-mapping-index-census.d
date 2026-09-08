#!/usr/sbin/dtrace -qs
/*
 * Per-fault cost of the HVPatch mapping lookups: how many rows the two
 * structures a first-touch fault consults actually HOLD, how many rows their
 * walks VISIT for that one fault, and how many nanoseconds the fault service
 * takes.
 *
 * What it measures: every `carrick*:::hvpatch-mapping-index-fault` (one per
 * `HvfInner::ensure_sparse_mmap_backing` call -- the anonymous/private
 * first-touch service) with its `hvpatch-mapping-index-cost` companion, which
 * the producer fires immediately after on the same host thread. The question
 * it answers is the one
 * docs/perf-results/2026-09-08-mapping-index-measurement.md could not:
 * the ordered `TaskMappingIndex` made the reducer 2.4-5.9x faster but left 23x
 * cost at 8x depth, and wall time alone cannot say whether that residue is a
 * surviving full-table walk, a walk whose BOUND grows, or per-fault work that
 * is not a lookup at all. A visited-row count that tracks the row population
 * is a full-table walk; a visited count that stays flat while nanoseconds grow
 * is not a lookup problem.
 *
 * Provider ABI qualified live on macOS 26 arm64 against carrick-observability
 * (`crates/carrick-observability/src/probes.rs`, provider `carrick`):
 *   hvpatch-mapping-index-begin (uint64_t live_rows, uint64_t shadowed_rows)
 *       -- fires FIRST, and is the census ARM: the producer takes its start
 *          `Instant` inside this probe's closure, so nothing below fires
 *          unless this probe is enabled. THIS SCRIPT MUST NAME IT. DTrace
 *          enables only the probes a script mentions, so a census script that
 *          matches just `-fault` and `-cost` arms nothing and reports a
 *          perfectly formatted EMPTY table -- which cost one capture to learn.
 *          The `begins` counter below exists to make that failure loud.
 *   hvpatch-mapping-index-fault (uint64_t far, uint64_t index_live_rows,
 *       uint64_t index_rows_visited, uint64_t alias_rows,
 *       uint64_t alias_rows_visited)
 *   hvpatch-mapping-index-cost  (uint64_t nanos, uint64_t alias_widest_va,
 *       uint64_t index_shadowed_rows)
 * `index_rows_visited` and `alias_rows_visited` are DIFFERENCES of the
 * per-thread hot-path counters across the fault, so they are exactly this
 * fault's walk length, not a running total.
 *
 * Perturbation: real but bounded and one-sided. Row-visit counting for the
 * task mapping index is one thread-local `Cell` add per visited row and is
 * ALWAYS on (the alias-registry counter it joins has been always-on since
 * 2026-08-30); the two `Instant::now()` reads, the alias-registry lock and the
 * probe fires themselves happen ONLY while `hvpatch-mapping-index-begin` is
 * enabled -- i.e. only under this script. So the ns column is inflated
 * relative to an untraced run and only same-instrument ratios are citable; the
 * ROW columns are exact either way.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-mapping-index-census.d run ...
 * Reads as a table on exit: one row per (rows-in-index bucket) with the mean
 * visited counts and nanoseconds, plus quantized distributions.
 */

dtrace:::BEGIN
{
    live = 1;
    seconds = 0;
    complete = 0;
    begins = 0;
    faults = 0;
    printf("MAPIDX|start|ns=%d|target=%d\n", timestamp, $target);
}

/*
 * Self-termination. `carrick trace` fails a custom script that does not exit
 * within 60 s of the traced child ending, so the script must own its own
 * bound: leave it out and a perfectly good capture is thrown away with
 * "custom D script did not exit within 60 s".
 */
proc:::exit
/pid == $target/
{
    live = 0;
}

tick-100ms
/live == 0 && !complete/
{
    complete = 1;
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 1800 && !complete/
{
    complete = 1;
    printf("MAPIDX|TRUNCATED|seconds=%d\n", seconds);
    exit(3);
}

dtrace:::ERROR
{
    printf("MAPIDX|ERROR|cpu=%d|epid=%d\n", cpu, arg1);
    exit(2);
}

/*
 * Arms the census in the producer. Enabling this probe is the whole reason it
 * is here; the count is the receipt that it was enabled.
 */
carrick*:::hvpatch-mapping-index-begin
{
    begins++;
}

carrick*:::hvpatch-mapping-index-fault
{
    faults++;
    self->far = arg0;
    self->live = arg1;
    self->visited = arg2;
    self->alias_rows = arg3;
    self->alias_visited = arg4;
    self->have = 1;
}

carrick*:::hvpatch-mapping-index-cost
/self->have/
{
    /*
     * Bucket by decade of live row count so the table shows how per-fault cost
     * moves WITH the population -- the super-linearity signature.
     */
    this->decade = self->live == 0 ? 0 :
        (self->live < 10 ? 1 :
        (self->live < 100 ? 2 :
        (self->live < 1000 ? 3 :
        (self->live < 10000 ? 4 :
        (self->live < 100000 ? 5 : 6)))));

    @n[this->decade] = count();
    @rows[this->decade] = avg(self->live);
    @shadow[this->decade] = avg(arg2);
    @visit[this->decade] = avg(self->visited);
    @visitmax[this->decade] = max(self->visited);
    @arows[this->decade] = avg(self->alias_rows);
    @avisit[this->decade] = avg(self->alias_visited);
    @avisitmax[this->decade] = max(self->alias_visited);
    @ns[this->decade] = avg(arg0);
    @nsmax[this->decade] = max(arg0);
    @widest[this->decade] = max(arg1);

    @total_faults = count();
    @total_visit = sum(self->visited);
    @total_avisit = sum(self->alias_visited);
    @total_ns = sum(arg0);

    self->have = 0;
    self->far = 0;
    self->live = 0;
    self->visited = 0;
    self->alias_rows = 0;
    self->alias_visited = 0;
}

dtrace:::END
/begins == 0 || faults == 0/
{
    printf("\nMAPIDX|EMPTY|begins=%d|faults=%d\n", begins, faults);
    printf("MAPIDX|EMPTY|a capture with no events is a FAILED capture, not a result: either the guest never took an anonymous first-touch fault, or the census was never armed (see the header on naming hvpatch-mapping-index-begin)\n");
}

dtrace:::END
{
    printf("\nMAPIDX|end|ns=%d|begins=%d|faults=%d\n", timestamp, begins,
        faults);
    printf("\n%-8s %10s %10s %10s %12s %12s %12s %12s %12s %12s %12s %14s\n",
        "decade", "faults", "idx_rows", "shadowed", "idx_visit",
        "idx_vmax", "alias_rows", "ali_visit", "ali_vmax", "ns_mean",
        "ns_max", "alias_widest");
    printa("%-8d %10@d %10@d %10@d %12@d %12@d %12@d %12@d %12@d %12@d %12@d %14@d\n",
        @n, @rows, @shadow, @visit, @visitmax, @arows, @avisit, @avisitmax,
        @ns, @nsmax, @widest);

    printf("\nTOTALS\n");
    printa("MAPIDX|total|faults=%@d\n", @total_faults);
    printa("MAPIDX|total|index_rows_visited=%@d\n", @total_visit);
    printa("MAPIDX|total|alias_rows_visited=%@d\n", @total_avisit);
    printa("MAPIDX|total|service_ns=%@d\n", @total_ns);
}
