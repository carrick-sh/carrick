# Typed contention refusal implementation plan

**Goal:** implement slice 1 of #1395, using the independently reviewed design.

**Spec:** https://github.com/carrick-sh/carrick/issues/1395#issuecomment-6566693478

**Architecture:** sched-core owns sealed attached-source probes and linear tickets.
Core-abi adapts those tickets to the existing object/portal wait paths; core
re-exports the neutral refusal vocabulary. The adapters retain exact source
identity and producer revision. A changed or retired source requests a rerun.

**Constraints:** no child-retire or exclusion migration, no mass portal-wire
migration, no new parking mechanism, no errno or fatal conversion of contention.
The existing portal wire remains a legacy crossing, authenticated by its owner.

## Steps

- [x] Add real-queue witnesses for changed revision, one wake, retired source,
  and switched release cause; demonstrate the switched-cause red case.
- [x] Implement Refusal, Settled, sealed ContentionSource and linear ReleaseTicket
  with explicit cancellation and bounded observe/reprobe cause selection.
- [x] Add ticket front doors to existing object and portal enrollment paths.
- [x] Migrate the two approved HVF/editor and EL1 fault source sites.
- [x] Add semgrep enforcement and a monotone contention-variant debt family.
- [ ] Run `just test-touched <main-sha>`, doctests, contract/debt checks,
  cross checks supported here, review the diff, and commit with evidence.

## Review focus

A cause switch must retain the second producer's pre-probe revision. A source
retired before park must return the same owned operation for immediate rerun.
Wake/cancel must consume ownership once. Foreign zones and MM incarnations must
fail authentication. No resource guard may survive entry into parking.

## Independent review corrections

The reviewer found three important boundary defects. The final slice adds an
unsafe-minted retained carrier/zone capability to prevent safe carrier relabeling,
restricts raw ticket-to-object-request conversion to the immediate enrollment
adapter, and makes ticket abandonment a counted invariant failure in every build.
The carrier and production-dependency drop tests failed before these fixes. The
raw-request compile-fail doctest also failed first because safe code could export
an unbound request. Focused suites verify the corrected boundaries.

The initial xtask suite needed runner setup: a locally extracted lsof and removal
of both empty launcher wrapper variables. Those changes live outside the tree.
Platform, range and final gate evidence is returned in the worker result and PR
proposal; this plan does not confer signed or runtime acceptance.
