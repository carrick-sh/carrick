#!/usr/sbin/dtrace -qs
/*
 * hvpatch-process-teardown-phases.d — where one HVPatch process teardown's
 * carrier CPU goes, phase by phase, without per-element probes.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * Companion to `hvpatch-process-teardown-scaling.d`, which COUNTS the
 * per-mapping and per-alias-row work of each teardown but perturbs its
 * timings (one probe per element). This script brackets only whole phases,
 * a few probe fires per teardown, so its on-CPU times are usable. One line
 * per detached address-space retirement:
 *
 *   TEARDOWNPH|cpu_ns=..|backend_ns=..|alias_scope_ns=..|stage_ns=..
 *     |owner_retire_ns=..|owners=..|apply_ns=..|kernel_apply_ns=..
 *
 *   backend_ns       `retire_task_state_process_mappings*` (outermost):
 *                    validation, staging, physical owner retirement, alias
 *                    retirement and mapping-row drop.
 *   alias_scope_ns   `AliasRegistry::retire_scope` (inside backend).
 *   stage_ns         `stage_retirement` (inside backend).
 *   owner_retire_ns  `retire_global_frame_host_owner_inner_in_using`, summed;
 *                    `owners` counts them (hv unmap + host unmap per lease).
 *   apply_ns         `HvpatchTaskOnlyEngineState::apply_inventory_retirement`:
 *                    the Kernel apply plus receipt authentication.
 *   kernel_apply_ns  `FrameInventoryAuthority::apply_retirement_with_receipt`
 *                    (inside apply). apply_ns - kernel_apply_ns is receipt
 *                    authentication (`authenticate_pending_retirement`).
 *
 * (b) PROVIDER ABI
 * ----------------
 * pid provider on `$target`, which under `carrick trace` IS the HVPatch
 * carrier (the run process retitles itself; guest forks create no host
 * processes). Names are demangled Rust (`a::b::f::h<hash>`); a `::` cannot
 * appear in a probe description, so each is spelled `??`. Qualified live with
 * `dtrace -l -p` on 313a1ab00 (legacy-mangling escapes such as `$GT$` survive demangling and
 * `$` is D macro syntax, so they are spelled `?GT?`). Needs a binary with `get-task-allow`
 * (`just build-debug`). All bracketed functions run on the retiring host
 * thread, so `self->` scoping is exact; nested entries of the backend
 * function are depth-guarded.
 *
 * (c) PERTURBATION
 * ----------------
 * Low: ~10 probe fires per teardown plus one pair per retired physical owner
 * (`owners`, tens to hundreds per process). Phase times are citable as
 * shares of this capture; compare absolute totals only to the unperturbed
 * sampled profile (hvpatch-carrier-cpu-attribution).
 *
 * (d) USAGE
 * ---------
 *   carrick trace -s scripts/dtrace/hvpatch-process-teardown-phases.d -o out -- \
 *       run --fs host localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 \
 *       -m test -v --randseed 0 test_threading
 */

#pragma D option bufsize=16m

pid$target:carrick:*HvpatchTaskEngineBindingState??retire_detached_address_space_with??h*:entry
{
    self->rd = vtimestamp;
    self->backend = 0;
    self->scope = 0;
    self->stage = 0;
    self->owner = 0;
    self->owners = 0;
    self->apply = 0;
    self->kapply = 0;
    self->depth = 0;
}

pid$target:carrick:*HvfVmState?GT???retire_task_state_process_mappings*:entry
/self->rd && self->depth++ == 0/
{
    self->backend_t = vtimestamp;
}

pid$target:carrick:*HvfVmState?GT???retire_task_state_process_mappings*:return
/self->rd && --self->depth == 0/
{
    self->backend += vtimestamp - self->backend_t;
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

pid$target:carrick:*HvfVmState?GT???stage_retirement??h*:entry
/self->rd/
{
    self->stage_t = vtimestamp;
}

pid$target:carrick:*HvfVmState?GT???stage_retirement??h*:return
/self->rd && self->stage_t/
{
    self->stage += vtimestamp - self->stage_t;
    self->stage_t = 0;
}

pid$target:carrick:*retire_global_frame_host_owner_inner_in_using??h*:entry
/self->rd/
{
    self->owner_t = vtimestamp;
    self->owners++;
}

pid$target:carrick:*retire_global_frame_host_owner_inner_in_using??h*:return
/self->rd && self->owner_t/
{
    self->owner += vtimestamp - self->owner_t;
    self->owner_t = 0;
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

pid$target:carrick:*FrameInventoryAuthority??apply_retirement_with_receipt??h*:entry
/self->rd/
{
    self->kapply_t = vtimestamp;
}

pid$target:carrick:*FrameInventoryAuthority??apply_retirement_with_receipt??h*:return
/self->rd && self->kapply_t/
{
    self->kapply += vtimestamp - self->kapply_t;
    self->kapply_t = 0;
}

pid$target:carrick:*HvpatchTaskEngineBindingState??retire_detached_address_space_with??h*:return
/self->rd/
{
    this->cpu = vtimestamp - self->rd;
    printf("TEARDOWNPH|cpu_ns=%d|backend_ns=%d|alias_scope_ns=%d|stage_ns=%d|owner_retire_ns=%d|owners=%d|apply_ns=%d|kernel_apply_ns=%d\n",
        this->cpu, self->backend, self->scope, self->stage, self->owner,
        self->owners, self->apply, self->kapply);
    @sum["cpu_ns"] = sum(this->cpu);
    @sum["backend_ns"] = sum(self->backend);
    @sum["alias_scope_ns"] = sum(self->scope);
    @sum["stage_ns"] = sum(self->stage);
    @sum["owner_retire_ns"] = sum(self->owner);
    @sum["owners"] = sum(self->owners);
    @sum["apply_ns"] = sum(self->apply);
    @sum["kernel_apply_ns"] = sum(self->kapply);
    @sum["teardowns"] = sum(1);
    self->rd = 0;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printa("TEARDOWNPH|sum|%s=%@d\n", @sum);
}
