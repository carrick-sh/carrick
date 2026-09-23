# Preserve the admitted executor during rejected admission — 2026-09-22

A rejected duplicate admission could replace the original executor's pause
endpoint before returning its error. When the replacement registry reported
idle, a page-table mutator could miss the real running owner and grant mutation
without draining it. This is a concrete correctness blocker on the path to
normal native execution admission.

The kernel census now inserts through `BTreeMap::Entry::Vacant`. An occupied
identity returns the same error while leaving the original endpoint, membership
and crash participation untouched. The normal admission algorithm remains one
ordered-map lookup; there is no new retry, pause, scan or scheduling policy.

**This continuation does not establish a new performance gain.** It fixes an
admission invariant used by the current runtime and needed before native data
can outlive the COW mutation scope. The existing carrier data grant remains
mutation-scoped, and the experimental ELF executor still uses private backing.

## Contract and red evidence

Contract: `kernel.mm.executor-admission`, a prerequisite of the still-open
`kernel.execution.native-synchronous-syscall` integration.

At N = 1/8/32/128 the fixture rejects N attempts to replace a running owner's
endpoint with an idle registry, then performs one explicit drain kick after
each refusal. It checks that the real owner remains visible, receives exactly N
kicks, and the rejected endpoint receives zero. The affine budget bounds total
calls to both kick backends by N; a semantic check prevents a zero-work run from
passing merely because it meets that bound.

The pre-fix `ContractObservation` records show both semantic assertions false
at all four scales. The evaluator returns `SemanticMismatch` for
`rejected_duplicate_preserves_running_owner`. These are direct observations,
not an inference from a recurring profile frame or an API-missing compile error.
After the fix, all four observations pass and record exactly 1/8/32/128 backend
calls, all to the original owner.

Additional regressions check a duplicate entrant with no pause endpoint and
compose the real page-table pause routine. In the latter, only the original
registered kick can make the owner leave guest execution; mutation permission
must be granted after that safe point, with exactly one kick. This deterministic
fixture uses no timing retry or sleep to manufacture success.

## Remaining integration boundary

The admission defect is fixed. A normal native execution/data grant is still
unimplemented. The next bounded implementation must:

1. Own the exact census membership and its in-guest handshake as one scoped
   execution capability, tied to the actual current task/execution lease.
   Registry membership alone and a caller-supplied independent flag are
   insufficient. Concurrent non-mutating execution must remain possible.
2. Keep prepared carrier backing opaque after releasing COW mutation authority.
   Activate pointers only inside the exact execution scope, rechecking current
   mapping, owner generation and every live leaf permission. In particular,
   fork can re-arm COW: a retained pin or restored VMA permissions alone must
   not authorize a later native store.
3. Drop pointer access before acknowledging mutation, cancellation or scheduler
   handoff. Connect the bounded native checkpoint to existing control delivery;
   a mutation-held whole workload cannot supply the performance result.

Then bind executable publication and alias-write invalidation before moving the
same bounded ELF subset onto the carrier. Do not grow the translator to avoid
this gate. Full inotify09 and Node/Go/Python results remain necessary to judge
progress toward 1x; keep native macOS I/O separate and raw Linux ratios visible.

## Verification

- Census suite: **11 passed**, including the red-first scale contract, missing
  replacement endpoint, and actual pause/drain composition.
- `just test-kernel`: **2,367 passed**, zero failures; the existing ignored
  controller-receipt test remains ignored.
- Runtime: **23 memory-composition and 26 quiescence tests passed**.
- Existing native executor: **11 passed**; this does not convert its private
  memory into carrier backing.
- Kernel libraries/tests Clippy with warnings denied, scoped formatting, and
  the whole-worktree diff check passed.

The only product source changed is `kernel/guest_execution.rs`. All 107 dirty
source files from the preceding carrier-grant checkpoint remain byte-identical;
its measured Carrick/HVF control and native-executor binaries also retain their
exact SHA-256 identities. No product guest run or timing sample was taken here.

`manifest.json` binds this delta to the preceding checkpoint archive. Red and
final green observations contain independently checked source hashes;
`implementation.patch`, exact source copies, `source.tar.gz` and all validation
logs are retained here. The new descriptor registers only its VM-free kernel
binding; it does not close the parent native-execution contract.

## Acceptance limits

No native execution binding or workload timing is promoted. The prior broader
campaign failures (fresh-publication-maintenance and generated inventory drift)
remain open; this change alters neither their implementations nor budgets.
Signed embed and Docker guest acceptance for this admission contract remain
explicitly unresolved. Work is local and uncommitted.
