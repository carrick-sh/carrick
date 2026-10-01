#!/usr/sbin/dtrace -qs
/*
 * hvpatch-process-teardown-scaling.d — what one HVPatch process teardown
 * costs, and what it scales with.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * The 2026-10-01 EL1 real-workload A/B found ~4.7 ms of carrier CPU per
 * cpython process in `retire_detached_address_space_with` (4.2% of carrier
 * CPU). Sampling names the functions; it cannot say whether the cost grows
 * with the process's mapping count, its alias rows, or its frames. For every
 * detached address-space retirement on the carrier this script prints one
 * line:
 *
 *   TEARDOWN|cpu_ns=<on-CPU>|wall_ns=<wall>|authorizes=<receipt checks>
 *     |alias_rows=<alias index removals>|class_removes=<class index removals>
 *     |inner_ns=<backend staging>|scope_ns=<alias scope retire>
 *     |apply_ns=<Kernel apply + receipt auth>
 *
 * `authorizes` counts `FrameInventoryRetirementReceipt::authorizes` calls,
 * one per expected (mapping, frame) pair plus pending fork receipts: it is
 * the retiring mm's inventory population n. `alias_rows` counts
 * `AliasRegistry::index_remove` calls (one per alias row of the mm's scope).
 * Ending with per-population aggregates (TEARDOWN|by-n|...).
 *
 * (b) PROVIDER ABI
 * ----------------
 * pid provider on the carrier. The `carrick run` process IS the HVPatch
 * carrier (it retitles itself `carrick:<name>: N containers`; guest forks
 * create no host processes), so `carrick trace` binds `$target` to it. The
 * pid provider lists DEMANGLED Rust names (`a::b::C::f::h<hash>`), qualified
 * live with `dtrace -l -p` on 313a1ab00; each wildcard below matches exactly
 * one function in module `carrick`. A `::` cannot appear in a probe
 * description (colons separate its fields: "Overspecified probe
 * description"), so each is spelled `??`. A release binary without
 * `get-task-allow` cannot be grabbed ("failed to grab pid"): build with
 * `just build-debug`. `retire_detached_address_space_with` and its callees
 * run on one host thread, so `self->` scoping is exact.
 *
 * (c) PERTURBATION
 * ----------------
 * HIGH inside teardown and nil elsewhere: `authorizes`, `index_remove` and
 * `AliasClassIndex::remove` fire once per mapping or row, so the per-call
 * fasttrap cost (~1 us) lands inside cpu_ns and grows with n. Use the
 * counts and the SHAPE of cpu_ns against n; take absolute teardown cost from
 * the unperturbed sampled profile (hvpatch-carrier-cpu-attribution), never
 * from this script.
 *
 * (d) USAGE
 * ---------
 *   carrick trace -s scripts/dtrace/hvpatch-process-teardown-scaling.d -o out -- \
 *       run --fs host localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 \
 *       -m test -v --randseed 0 test_threading
 * The capture ends when the carrier exits (`proc:::exit`).
 */

#pragma D option bufsize=16m

pid$target:carrick:*HvpatchTaskEngineBindingState??retire_detached_address_space_with??h*:entry
{
    self->rd = vtimestamp;
    self->rdw = timestamp;
    self->auth = 0;
    self->rows = 0;
    self->class_rm = 0;
    self->inner = 0;
    self->scope = 0;
    self->apply = 0;
}

pid$target:carrick:*FrameInventoryRetirementReceipt??authorizes??h*:entry
/self->rd/
{
    self->auth++;
}

pid$target:carrick:*AliasRegistry??index_remove??h*:entry
/self->rd/
{
    self->rows++;
}

pid$target:carrick:*AliasClassIndex??remove??h*:entry
/self->rd/
{
    self->class_rm++;
}

pid$target:carrick:*retire_task_state_process_mappings_inner??h*:entry
/self->rd/
{
    self->inner_t = vtimestamp;
}

pid$target:carrick:*retire_task_state_process_mappings_inner??h*:return
/self->rd && self->inner_t/
{
    self->inner += vtimestamp - self->inner_t;
    self->inner_t = 0;
}

pid$target:carrick:*AliasRegistry??retire_scope??h*:entry
/self->rd/
{
    self->scope_t = vtimestamp;
}

pid$target:carrick:*AliasRegistry??retire_scope??h*:return
/self->rd && self->scope_t/
{
    self->scope += vtimestamp - self->scope_t;
    self->scope_t = 0;
}

pid$target:carrick:*HvpatchTaskOnlyEngineState??apply_inventory_retirement??h*:entry
/self->rd/
{
    self->apply_t = vtimestamp;
}

pid$target:carrick:*HvpatchTaskOnlyEngineState??apply_inventory_retirement??h*:return
/self->rd && self->apply_t/
{
    self->apply += vtimestamp - self->apply_t;
    self->apply_t = 0;
}

pid$target:carrick:*HvpatchTaskEngineBindingState??retire_detached_address_space_with??h*:return
/self->rd/
{
    this->cpu = vtimestamp - self->rd;
    printf("TEARDOWN|cpu_ns=%d|wall_ns=%d|authorizes=%d|alias_rows=%d|class_removes=%d|inner_ns=%d|scope_ns=%d|apply_ns=%d\n",
        this->cpu, timestamp - self->rdw, self->auth, self->rows, self->class_rm,
        self->inner, self->scope, self->apply);
    this->bucket = self->auth < 256 ? 0 : self->auth < 1024 ? 256 :
        self->auth < 4096 ? 1024 : 4096;
    @count[this->bucket] = count();
    @cpu[this->bucket] = avg(this->cpu);
    @total = sum(this->cpu);
    self->rd = 0;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printa("TEARDOWN|by-n|authorizes>=%d|count=%@d\n", @count);
    printa("TEARDOWN|by-n|authorizes>=%d|avg_cpu_ns=%@d\n", @cpu);
    printa("TEARDOWN|total_cpu_ns=%@d\n", @total);
}
