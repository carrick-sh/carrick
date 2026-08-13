# How much does vCPU reclaim churn cost? — bounding the threading-model win

**Recorded 2026-08-13.** Asked because the threading model is under review:
on HVF a "reclaim on block" destroys and later recreates the vCPU with a full
guest-state save/restore, so every proposal to change the threading model
turns on how much that churn actually costs.

## Method

`SHORT_TIMED_WAIT_RECLAIM_CUTOFF` (`vcpu_loop/mod.rs:60`) is the knob:
`should_reclaim_vcpu_for_timed_wait` reclaims for an untimed wait, or a timed
wait longer than the cutoff. Setting the cutoff to 0 makes **every** timed
wait reclaim, which strictly increases churn and is also the liveness-safe
direction (more slot release, not less).

Three runs of the cold `go build` on the signed binary, against the 4.410
CPU-s baseline.

## Measured

| cutoff | CPU-s | result |
| --- | ---: | --- |
| 250 ms (shipped) | 4.410 (baseline) | 10/10 pass previously |
| 0 ms (always reclaim) | 4.80, 4.87 | **one run of three FAILED** |

Forcing every timed wait to reclaim costs **about +0.4 CPU-s, roughly +9%**,
and destabilised the run.

## What this bounds

Reclaim churn is real and measurable, but it is **not** where the ~1.97 CPU-s
of overhead lives. The shipped 250 ms cutoff already avoids the bulk of it, so
the reverse move — eliminating *all* remaining reclaim, which is what a
"one permanent vCPU per guest thread, never reclaim" model buys — can save at
most something on this order, not two CPU-seconds.

That is a decisive input to the threading-model decision:

- **A threading-model change justified purely as a CPU win is not supported by
  this measurement.** The win is bounded at roughly the scale above.
- **A threading-model change justified on CORRECTNESS and LIVENESS is well
  supported.** Slot starvation has already produced one real deadlock (guest
  `wait4` pinning slots while sibling materializers starved), two further
  slot-pinning sites are known, and this experiment shows the current design is
  delicately balanced: moving the cutoff to a *safer* setting for liveness made
  a run fail outright.

So the honest framing is that the ten-slot pool plus destroy/recreate reclaim
is a **correctness hazard first** and a modest performance cost second. It
should be changed to remove a class of deadlock, and the CPU bar must be met
elsewhere — the syscall path, exec, and fault handling.

## Caveat

`+9%` is the cost of the ADDITIONAL reclaims that the cutoff currently
suppresses; it is not the total cost of all reclaims performed today. Bounding
that total needs a reclaim counter rather than a cutoff sweep — the direct
measurement, and the one to take before committing to any model that claims
to remove it.
