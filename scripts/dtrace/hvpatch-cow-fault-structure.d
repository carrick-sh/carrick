#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-cow-fault-structure.d — how many frame COWs a workload takes, per
 * fork and per process, and whether they come in shapes a batch would serve.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * The 2026-10-01 EL1 real-workload A/B filed 18% of cpython-threading's
 * carrier CPU and ~12% of Node's under "COW fault service". That class is a
 * symbol match on the `cow_engine` module, so it also holds first-touch
 * materialization, munmap alias retirement and syscall memory accessors
 * (`docs/perf-results/2026-10-01-el1-real-workload-ab/cow-and-teardown.md`).
 * This script counts the COWs themselves, from the producer's own record,
 * and answers the structural questions a per-fault cost cannot:
 *
 *   COWSTRUCT|totals     committed COWs, by trigger class (0 stage-1
 *                        permission fault, 1 syscall guest write, 2 backing
 *                        maintenance, 3 privileged internal), forks, execs,
 *                        process exits.
 *   COWSTRUCT|region     committed COWs by guest VMA class of the faulting VA
 *                        (heap / mmap arena / image / stack / low), using the
 *                        fixed layout of `crates/carrick-mem/src/memory.rs`.
 *   COWSTRUCT|per-process  quantize of committed COWs per mm, recorded when
 *                        the mm's process exits (mms alive at the end are
 *                        reported as `alive`).
 *   COWSTRUCT|shared     a COW of an old frame that ANOTHER mm already
 *                        COWed: parent and child both writing the same
 *                        fork-shared page, each paying a copy.
 *   COWSTRUCT|child-gone a COW of a frame whose only fork sharer (the child mm
 *                        recorded by `hvpatch-fork-frame`) already exited or
 *                        began exec, so the writer was its last owner.
 *   COWSTRUCT|reusable   shared OR child-gone: a COW whose writer was the
 *                        frame's last owner. Linux serves that write fault by
 *                        reusing the page (no copy, no allocation).
 *   COWSTRUCT|adjacent   a COW whose 16 KiB neighbour (either side) was
 *                        already COWed by the same mm: the population a
 *                        fault-around/batch would have served with one exit.
 *   COWSTRUCT|repeat     a COW of a 16 KiB granule the same mm already COWed.
 *                        Split by the 4 KiB page: `repeat-same-4k` is the
 *                        same guest page COWed twice (a re-COW), and
 *                        `repeat-other-4k` is another 4 KiB page of a 16 KiB
 *                        granule this mm already COWed (per-4 KiB service of
 *                        one 16 KiB frame).
 *   COWSTRUCT|leaf-receipt  stage-1 leaf receipts by phase: 2 = a writer's
 *                        COW published (a copy), 7 = an authenticated
 *                        in-place write grant after a VM-wide last-owner
 *                        proof (no copy). The ratio says how often a write to
 *                        a fork-shared page found it already sole-owned.
 *   COWSTRUCT|fork-shape per fork: mappings already local, alias candidates,
 *                        aliases selected by the live page tables, selected
 *                        bytes (`hvpatch-fork-snapshot-end`).
 *
 * (b) PROVIDER ABI (qualified against crates/carrick-observability/src/probes.rs
 *     at 313a1ab00, provider `carrick`; fired live on macOS 27 / arm64
 *     2026-10-01 with the A/B campaign binary built from 2bfa005b6)
 * --------------------
 *   hvpatch-frame-cow-trigger-identity (int pid, int tid, u64 mm, u32 asid,
 *       u32 class) — fires once per COW request, before the split.
 *   hvpatch-frame-cow-identity (int pid, int tid, u64 mm, u32 asid, u32 phase)
 *       immediately followed on the SAME host thread by
 *   hvpatch-frame-cow (u64 va, u64 old_frame, u64 new_frame, u64 old_ipa,
 *       u64 new_ipa). `phase` is 0 stage-2 mapped, 1 stage-1 published,
 *       2 committed; only phase 2 is counted, once per COW.
 *   hvpatch-guest-lifecycle-identity (int pid, u64 task, u64 parent, u64 mm)
 *       immediately followed by hvpatch-guest-lifecycle (u32 phase, int pid,
 *       int ppid, int tid, u32 asid); phase 1 fork, 2 exec, 5 process exit.
 *   hvpatch-fork-frame-identity (int child_pid, int tid, u64 child_mm,
 *       u32 asid, u32 kind) immediately followed by hvpatch-fork-frame
 *       (u64 parent_mapping, u64 child_mapping, u64 frame, u64 ipa,
 *       u64 length); kind 0 = private COW share, 1 = Linux MAP_SHARED.
 *   pt-alias-receipt (u64 va, u64 leaf, u64 expected_ipa, u64 expected_ap,
 *       u32 phase) — phases per `scripts/dtrace/hvpatch-frame-cow.d`.
 *   hvpatch-fork-snapshot-end (int child_pid, u64 local, u64 candidates,
 *       u64 selected, u64 bytes).
 *
 * (c) PERTURBATION
 * ----------------
 * Every probe is scoped to `$target` and its progeny: `carrick*:::` alone
 * also matches every other carrick process on the host (a shared host
 * inflated forks 78 -> 264 and exits 79 -> 853 in one capture).
 * `proc:::exit` of `$target` ends the capture. USDT only, no pid-provider
 * probes and no stacks: three probe fires and a
 * few associative-array operations per COW, a handful per fork/exit. Counts
 * are exact and citable; wall/CPU time under this script is not. The arrays
 * hold one key per COWed 16 KiB granule per mm; a "dynamic variable drops"
 * line means the shared/adjacent/repeat counts are UNDER-reported and the
 * capture failed.
 *
 * (d) USAGE
 * ---------
 *   carrick trace -s scripts/dtrace/hvpatch-cow-fault-structure.d -- run \
 *       --fs host localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 \
 *       -m test -v --randseed 0 test_threading
 * Output lines are prefixed COWSTRUCT| (`grep -a`).
 */

#pragma D option dynvarsize=256m
#pragma D option bufsize=16m
#pragma D option aggsize=16m

dtrace:::BEGIN
{
    seconds = 0;
    /* Seed every associative array so its key/value types are fixed. */
    granule_owner[0] = 0;
    mm_granule[0, 0] = 0;
    mm_page[0, 0] = 0;
    mm_cows[0] = 0;
    sharer[0] = 0;
    gone[0] = 0;
}

carrick*:::hvpatch-frame-cow-trigger-identity
/pid == $target || progenyof($target)/
{
    @class[arg4] = count();
}

carrick*:::hvpatch-frame-cow-identity
/pid == $target || progenyof($target)/
{
    self->mm = arg2;
    self->phase = arg4;
    self->armed = 1;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target)) && (self->armed && self->phase == 2)/
{
    self->armed = 0;
    this->va = arg0 & ~0x3fffULL;
    this->old = arg1;
    @totals["committed"] = count();
    mm_cows[self->mm]++;

    this->region =
        this->va < 0x4000000000ULL ? "low" :
        this->va < 0x4008000000ULL ? "heap" :
        (this->va >= 0x6000000000ULL && this->va < 0x6800000000ULL) ? "mmap" :
        (this->va >= 0xff7fff0000ULL && this->va < 0xffffff0000ULL) ? "stack" :
        this->va >= 0x8800000000ULL ? "image" : "other";
    @region[this->region] = count();

    this->page = arg0 & ~0xfffULL;
    @shape["repeat"] = sum(mm_granule[self->mm, this->va] ? 1 : 0);
    @shape["repeat-same-4k"] = sum(mm_page[self->mm, this->page] ? 1 : 0);
    @shape["repeat-other-4k"] = sum(
        (mm_granule[self->mm, this->va] && !mm_page[self->mm, this->page]) ? 1 : 0);
    mm_page[self->mm, this->page] = 1;
    @shape["adjacent"] = sum(
        (mm_granule[self->mm, this->va - 0x4000] ||
         mm_granule[self->mm, this->va + 0x4000]) ? 1 : 0);
    this->shared = granule_owner[this->old] != 0 && granule_owner[this->old] != self->mm;
    this->child_gone = sharer[this->old] != 0 && sharer[this->old] != self->mm &&
        gone[sharer[this->old]];
    @shape["shared"] = sum(this->shared ? 1 : 0);
    @shape["child-gone"] = sum(this->child_gone ? 1 : 0);
    @shape["reusable"] = sum((this->shared || this->child_gone) ? 1 : 0);
    mm_granule[self->mm, this->va] = 1;
    granule_owner[this->old] = self->mm;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target)) && (self->armed)/
{
    self->armed = 0;
}

carrick*:::pt-alias-receipt
/pid == $target || progenyof($target)/
{
    @receipt[(uint32_t)arg4] = count();
}

carrick*:::hvpatch-fork-frame-identity
/pid == $target || progenyof($target)/
{
    self->fork_mm = arg2;
    self->fork_kind = arg4;
}

carrick*:::hvpatch-fork-frame
/(pid == $target || progenyof($target)) && self->fork_kind == 0/
{
    sharer[arg2] = self->fork_mm;
    @totals["fork-shared-frames"] = count();
}

carrick*:::hvpatch-guest-lifecycle-identity
/pid == $target || progenyof($target)/
{
    self->life_mm = arg3;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 1)/
{
    @totals["fork"] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 2)/
{
    @totals["exec"] = count();
}

/* ExecBegin: the identity still names the mm the exec is about to retire. */
carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 6)/
{
    gone[self->life_mm] = 1;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 5)/
{
    @totals["process-exit"] = count();
    gone[self->life_mm] = 1;
    @per_process["exited"] = quantize(mm_cows[self->life_mm]);
    @per_process_sum["exited"] = sum(mm_cows[self->life_mm]);
    mm_cows[self->life_mm] = 0;
}

carrick*:::hvpatch-fork-snapshot-end
/pid == $target || progenyof($target)/
{
    @fork_shape["local-mappings"] = quantize(arg1);
    @fork_shape["alias-candidates"] = quantize(arg2);
    @fork_shape["selected-aliases"] = quantize(arg3);
    @fork_shape_sum["selected-bytes"] = sum(arg4);
    @fork_shape_sum["selected-aliases"] = sum(arg3);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 900/
{
    printf("COWSTRUCT|bounded|seconds=%d\n", seconds);
    exit(0);
}

dtrace:::END
{
    printa("COWSTRUCT|totals|%s=%@d\n", @totals);
    printa("COWSTRUCT|trigger-class|%d=%@d\n", @class);
    printa("COWSTRUCT|region|%s=%@d\n", @region);
    printa("COWSTRUCT|leaf-receipt|phase%d=%@d\n", @receipt);
    printa("COWSTRUCT|structure|%s=%@d\n", @shape);
    printa("COWSTRUCT|per-process-sum|%s=%@d\n", @per_process_sum);
    printa("COWSTRUCT|per-process|%s%@d\n", @per_process);
    printa("COWSTRUCT|fork-shape-sum|%s=%@d\n", @fork_shape_sum);
    printa("COWSTRUCT|fork-shape|%s%@d\n", @fork_shape);
}
