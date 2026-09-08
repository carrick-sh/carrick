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
 *          unless this probe is enabled.
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

BEGIN
{
    printf("MAPIDX|start|ns=%d\n", timestamp);
    @faults = count();
}

carrick*:::hvpatch-mapping-index-fault
{
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

END
{
    printf("\nMAPIDX|end|ns=%d\n", timestamp);
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
