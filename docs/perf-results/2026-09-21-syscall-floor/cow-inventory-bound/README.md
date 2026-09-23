# Pinned-owner COW inventory lookup experiment

The old split planner starts at the beginning of the entire MM extent BTreeMap
for every compound. The candidate uses the authenticated pinned owner's physical
extent to range-seek to the first possible row and stops at the compound base.
Within that range it retains ascending first-cover selection and checks the
recorded stage-2 owner key and extent containment. Unpinned sources retain the
old scan. It does not substitute a predecessor-only lookup or assume all logical
inventory extents are disjoint. Owner bounds are resolved before acquiring the
inventory lock to avoid adding an inventory-to-owner lock ordering edge.

Red: with one unrelated extent the old lookup visits two candidates against a
one-candidate budget. Green: one candidate at 1/8/32/128 unrelated extents, plus
wrong-owner refusal through the real split-planning entry point. This counts
candidate predicate visits; the BTree range seek remains O(log N), and multiple
fragments within the same owner may still require multiple visits. It is not a
constant-total-work claim. 65 COW tests and 33 contract tests pass.

Matched signed arms differ only in whether the split planner passes its already
resolved owner bound to the lookup. Both include all preceding campaign work.
The control deliberately uses the old full scan. All source hashes, source
patches, artifact identity/signature metadata and raw timing runs are retained.
No absolute syscall floor or whole-goal completion follows from this experiment.

## Result and disposition

Two warmed ABBA blocks produced control 241/245/243/252 ms and candidate
267/235/247/232 ms. Both means are exactly 245.25 ms. Candidate/control mean
ratio is 1.0000; median ratio is 0.9877 with overlapping process variation.
No Node speedup is established. All ten warmup/measured processes passed their
app-smoke marker, and every run has scoped zero-residual cleanup. Artifacts
were unchanged before and after timing. No tracing, builds or Docker workloads
ran during measurement.

The production lookup changes, helper/test and experimental registry descriptor
were removed after this result. The draft descriptor is preserved here as a
rejected experiment, not a live contract. Existing campaign and DSR reader
changes were preserved. target/release/carrick was restored byte-for-byte from
the previously measured discard-retirement artifact (fd96c7d...). The matched
control/candidate binaries remain under target/lease-cost/cow-inventory-bound.
No signed semantic promotion was attempted for this rejected optimization.

This experiment rejects a workload-impact claim, not the fact that its candidate
scan visits fewer unrelated rows. Do not repeat this same scan optimization
based solely on recurring profile samples. The next Node experiment needs a
larger coarse cost component or a phase reduction that changes completed work.
