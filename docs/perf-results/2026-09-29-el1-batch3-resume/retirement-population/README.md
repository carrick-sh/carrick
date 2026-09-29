# Coherent terminal frame populations

Base: ed8dcb3ed. The original Go20 acceptance failure remains unresolved
pending signed candidate execution. This reduction proves a concrete
backend race shape; it does not establish retrospective Go crash attribution.

`process_retirement_does_not_combine_counts_from_different_populations`
failed before the production change: the staged commit included RetireFrame
for a frame whose sibling kernel unmap could still be pending. The test
injects one deterministic sibling transition through the real backend lock:
its backend reference was staged before the authority snapshot, its kernel
mapping publishes after the snapshot, then its backend retirement runs before
the retiring task reads the backend count. Both observed counts equal one,
but they describe different populations. The fixture models the authority
snapshot; it does not instantiate a second production kernel graph.

Acquire the existing InventoryFrameRegistry lock before the authority batch
query, preserving the already-used final_exec_physical_extents lock order.
Hold it through backend retirement bookkeeping, as before, and release before
physical cleanup and runtime publication. The FrameStillMapped refusal is
unchanged. No carrier-wide cleanup lock, wait, polling, or retry is added.

Red: one test failed on the stale RetireFrame assertion. Green: all 11
process_retirement tests passed, including the existing mapping-row work
budget, exact last-owner retirement and sibling-live refusal tests. The
prescribed serial HVF suite passed 598, with three existing ignores. Affected
Clippy passed. Contract registration is extended under
kernel.el1.anonymous-retirement; full scaling and signed cost acceptance are
not claimed by this single deterministic interleaving.

Retained invocation failures: an initial exact short-name filter selected zero
tests (not evidence; corrected before red); a mistaken parallel full-HVF
invocation failed five tests sharing carrier-global state. The prescribed
serial invocation inside the sandbox left only the ptrace test failing;
outside the sandbox all tests passed. Sandboxed Clippy could not generate the
DTrace provider; the unrestricted run passed. Initial contract check detected
the expected inventory drift before regeneration. These are retained, not
counted as successful gates.

Next: commit and reconcile line-pinned inventories on the clean candidate,
run required source gates, rebuild/sign a new CLI and run the fixed Go20
acceptance population against the pinned native oracle. Preserve the old
failing artifact. Further lifecycle, signed, conformance and cost gates remain.

Contract checker passed: 68 contracts, 15 claims, 148 surfaces. The existing
runtime no-carrier-lock-across-detached-cleanup test passed (one execution).
