#!/usr/sbin/dtrace -qs
/*
 * hvpatch-cow-fault-cost.d — on-CPU cost of one host-lane frame COW, and of
 * the guest-frame-commit reconciliation that the A/B profile filed with it.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * `hvpatch-carrier-cpu-attribution` files every stack through a
 * `cow_engine` frame as COW fault service. Two populations dominate that
 * class on cpython-threading and Node: real COW faults
 * (`HvfVmState::resolve_frame_cow_fault`) and EL1 frame-grant commit
 * reconciliation (`signal::reconcile_guest_frame_commits`, which revalidates
 * every dirty EL1-granted page with a full stage-1 debug walk). This script
 * brackets both, on-CPU (`vtimestamp`):
 *
 *   COWCOST|cow       count, total and quantized on-CPU ns per COW
 *   COWCOST|reconcile count, total and quantized on-CPU ns per call.
 *
 * Do NOT add a `PageTableManager::debug_walk_host` counter here: the COW
 * path walks too, and ~400k walk probe fires per cpython run perturbed both
 * brackets (2026-10-01: reconcile 1.85 s on-CPU with it). That capture did
 * show the walk shape: ~90% of reconcile calls walk nothing and ~6% walk
 * 128-255 pages, 392k walks over 26k calls.
 *
 * (b) PROVIDER ABI
 * ----------------
 * pid provider on `$target`, which under `carrick trace` IS the HVPatch
 * carrier. Demangled Rust names; `::` is spelled `??` and legacy escapes
 * such as `$GT$` as `?GT?` (`$` is D macro syntax). Qualified live with
 * `dtrace -l -p` on 313a1ab00: `ThreadedEngine::resolve_frame_cow_fault`
 * and `live_el1_grant_page` are inlined and have no probe, so the brackets
 * are `HvfVmState::resolve_frame_cow_fault` and
 * `reconcile_guest_frame_commits`. Needs `get-task-allow`
 * (`just build-debug`).
 *
 * (c) PERTURBATION
 * ----------------
 * Two probe fires per COW and per reconcile call. Per-call costs here include ~1-2 us of fasttrap
 * overhead each; cite shares and counts, and absolute per-call cost only as
 * an upper bound.
 *
 * (d) USAGE
 * ---------
 *   carrick trace -s scripts/dtrace/hvpatch-cow-fault-cost.d -o out -- run \
 *       --fs host localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 \
 *       -m test -v --randseed 0 test_threading
 */

#pragma D option bufsize=16m

pid$target:carrick:*HvfVmState?GT???resolve_frame_cow_fault??h*:entry
{
    self->cow = vtimestamp;
}

pid$target:carrick:*HvfVmState?GT???resolve_frame_cow_fault??h*:return
/self->cow/
{
    this->d = vtimestamp - self->cow;
    @n["cow"] = sum(1);
    @t["cow"] = sum(this->d);
    @q["cow"] = quantize(this->d);
    self->cow = 0;
}

pid$target:carrick:*reconcile_guest_frame_commits??h*:entry
{
    self->rec = vtimestamp;
}

pid$target:carrick:*reconcile_guest_frame_commits??h*:return
/self->rec/
{
    this->d = vtimestamp - self->rec;
    @n["reconcile"] = sum(1);
    @t["reconcile"] = sum(this->d);
    @q["reconcile"] = quantize(this->d);
    self->rec = 0;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printa("COWCOST|count|%s=%@d\n", @n);
    printa("COWCOST|oncpu_ns|%s=%@d\n", @t);
    printa("COWCOST|dist|%s%@d\n", @q);
}
