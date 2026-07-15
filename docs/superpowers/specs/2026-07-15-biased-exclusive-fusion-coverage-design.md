# Biased Exclusive-Fusion Coverage — Design

**Goal:** Make exclusive-region fusion coverage measurable, then expand biased
(`linux4k`) fusion one evidence-ranked instruction/shape class at a time without
weakening AArch64 exclusive-monitor correctness or changing the safe emulator
fallback.

## Measured basis

- The exact `go-go_internal_srcimporter` c94 lane remained CPU-bound throughout
  a 2,700,584 ms Carrick timeout while the refreshed Docker oracle completed in
  3,069 ms (`879.96x`). The Carrick workload retained roughly 9.3–9.6 host cores
  and produced no crash or output, so this is active execution volume rather
  than a deadlock diagnosis.
- The current W1 profiled reducer ran for 19.14 s and recorded 12,400,639
  gateways. `sensitive_exclusive` accounted for 5,804,032 gateways (46.8% of
  the total), ahead of every other counted exit class. One hot thread reached
  exactly the 1,000,000-gateway profile ceiling, so this run is routing
  evidence, not a natural-completion performance result.
- Direct (`native16k`) exclusive-region fusion already removes the supported
  compiler CAS/RMW loops. Its remaining exclusive exits were observed in
  biased-mode Go compiler processes. Biased fusion is currently disabled before
  the recognizer runs, so the profiler can count exclusive traps but cannot say
  which regions are structurally fusible or why the rest were rejected.
- Ordinary biased memory lowering spills up to four guest registers into
  `DsrContext` and performs address-recovery bookkeeping. Reusing that lowering
  between `LDXR`/`LDAXR` and `STXR`/`STLXR` would introduce explicit memory
  accesses inside the reservation window and can destroy forward progress.

## Goals

1. Report both the runtime impact and the code-shape breadth of missed
   exclusive-fusion opportunities.
2. Separate structural recognition from address-mode lowering so biased
   candidates can be measured before they are enabled.
3. Add a correct biased lowering for the currently recognized compiler
   CAS/RMW regions without reserving a new persistent physical register.
4. Preserve a typed, observable reason for every non-fused exclusive load.
5. Use the measured rejection distribution to choose later coverage waves.

## Non-goals

- Do not turn arbitrary exclusive sequences into a coarse lock or a generic
  host atomic. Guest ordering, retry, and exclusive-monitor semantics remain
  native AArch64 semantics.
- Do not fuse an unproven region merely to increase a coverage percentage.
- Do not reserve physical x18 as a persistent host-bias register in this slice.
  The immediate materialization cost can be revisited only if an untraced run
  proves it is material after gateway removal.
- Do not raise the W1 gateway ceiling, the c94 timeout, or the `20x`/`10x`
  performance targets.
- Do not make profiled timings the authority for a performance win. Profiling
  identifies work; untraced runs decide whether the work helped.

## Typed fusion analysis

The current `try_fuse_exclusive_region` API collapses every miss into
`Ok(None)`. Replace that opacity with a typed analysis that has two stages:

1. **Structural analysis** decodes the load, scans the bounded region, and
   either returns an `ExclusiveRegionCandidate` or an
   `ExclusiveFusionRejection`.
2. **Lowering selection** asks the active address mode whether it can lower the
   candidate and returns a final `ExclusiveFusionDisposition`.

The exact Rust names can follow local conventions, but the domains must remain
separate. A structural rejection is not the same fact as an eligible candidate
whose backend lowering is not enabled.

The rejection enum needs stable protocol names and, at minimum, these classes:

- `not-load` — the trapped exclusive is a store or another non-entry form;
- `virtualized-base` and `virtualized-operand` — guest x18/x28 participates;
- `page-boundary`;
- `scan-limit-or-no-store`;
- `mismatched-store` — base, width, family, or load/store pairing differs;
- `unsupported-body-memory-or-sensitive`;
- `unsupported-control-flow` — extra/unconditional/indirect branches or an
  unrecognized early-exit shape;
- `invalid-retry-edge`;
- `biased-no-safe-scratch`;
- `biased-address-form-unsupported`;
- `backend-disabled` — structurally and lowerably eligible, but not yet
  promoted for this address mode.

These are deliberately semantic categories rather than error strings. Adding a
new reason requires updating the exhaustive protocol mapping and tests, so
coverage reports cannot silently bucket new gaps as “other.”

The existing direct-fusion acceptance rules remain the correctness baseline.
Direct mode consumes the same structural candidate as biased mode; it does not
fork a second recognizer that can drift.

## Coverage measurement

Coverage has two axes because neither one is sufficient alone:

### Runtime-weighted impact

When a profiled sensitive exclusive exit executes, attribute it to the stored
fusion disposition for `(guest_pc, generation)` and increment a per-thread
counter. This uses the same metadata lookup already required to recover the
`SensitiveExit`; profile-off execution performs no new counter or timer work.

The protocol emits exact counts per rejection/disposition. The performance
tool aggregates them across thread eras and processes and reports:

- each reason as a share of residual exclusive gateways;
- structurally eligible-but-disabled gateways;
- structurally rejected gateways;
- exclusive-load versus non-entry/store gateways.

This is the prioritization authority: a rejection affecting one extremely hot
loop should be visible as such.

### Unique-site breadth

At translation time, profiling records each exclusive site once per process
using its guest PC, instruction word, generation-safe identity, structural
outcome, and lowering outcome. Re-translation of an unchanged site must not
inflate the count. The protocol publishes exact unique-site counts per reason
as process gauges; aggregation takes one process value rather than summing the
same gauge from every thread.

A small bounded heavy-hitter list (for example, eight sites per thread era) may
also report `guest_pc`, instruction word/family, reason, and hit count. This is
diagnostic routing, not an exhaustive trace. Every frame must stay below the
existing atomic `PIPE_BUF` transport bound.

Unique sites prevent one hot loop from hiding broad missing coverage. Runtime
counts prevent a large cold-code catalog from driving optimization order.

### Coverage before and after fusion

Before a biased class is enabled, every execution still traps, so the census
provides exact runtime-weighted opportunity counts. After fusion, those
executions intentionally stop entering the gateway. Authority therefore comes
from three together:

1. residual `sensitive_exclusive` gateways versus the pinned pre-change run;
2. the residual typed rejection distribution and unique-site census; and
3. untraced wall/CPU for the same reducer and exact conformance case.

Do not add an always-on counter inside the fused region merely to count success.
Such a counter would perturb the path being measured and, if placed between the
exclusive pair, would be incorrect. A profile-only fused-entry counter may be
added before the reservation only if later analysis truly needs it, but it is
not required for the first promotion.

## Biased-region lowering

The first enabled biased class is the existing canonical bounded compiler
CAS/RMW candidate with ordinary GPR operands and enough unused scratch
registers. All other dispositions retain the current sensitive-emulation path.

For an accepted candidate:

1. Choose scratch GPRs that are not read or written anywhere in the region and
   are not x18, x28, SP, or the zero register. Failure to find them is the typed
   `biased-no-safe-scratch` rejection.
2. Before the exclusive load, save the guest values of those scratch registers
   into the existing typed DSR scratch storage. Context stores are safe here
   because no reservation exists yet.
3. Compute the effective guest address, check access-width overflow and the
   biased fast aperture, materialize the translation-time host bias into a
   scratch register, and form the host address. None of these operations may
   alter guest condition flags.
4. On an invalid or unsupported address, restore scratch state and take the
   existing sensitive-emulation exit at the original load PC. This retains the
   current Linux fault classification rather than inventing a new JIT fault
   path.
5. Rewrite only the exclusive load/store base field to the host-address scratch
   register. Preserve their transfer/status registers, width, acquire/release
   variant, and the accepted region body.
6. From the load through the store, emit no context access, ordinary memory
   operation, instrumentation store, helper call, or scratch spill. A failed
   store retries at the load while the materialized host address remains live.
7. After a successful store, restore scratch state and take the normal direct
   exit. A compare-failure edge that skips the store executes `CLREX`, restores
   scratch state, and exits.

This deliberately materializes the bias in the region prelude instead of
changing the gateway's physical-x18 contract. If gateway cost is removed but
the prelude becomes the measured bottleneck, reserving a reload-on-entry bias
register is a separate design with its own signal/ABI proof.

## Fault, kick, and recovery contract

Biased fusion temporarily replaces guest scratch values and changes one
register from guest-address to host-address coordinates. Recovery metadata must
describe those facts explicitly; a generic “noop” PC map is insufficient.

- A fault or asynchronous kick during the prelude restores every saved guest
  register and resumes at the original exclusive load.
- A fault or kick after the native load but before the store also restores
  scratch state and resumes from the load, never from the middle with a lost or
  stale reservation.
- Every edge that leaves without executing the store clears the monitor with
  `CLREX` before host code or another guest region can observe it.
- Store-success and store-failure edges rely on the store-exclusive operation
  having consumed/cleared the reservation, matching the existing direct
  lowering.
- Recovery must preserve guest x18/x28 virtualization, NZCV, transfer/status
  registers, and the exact guest PC used for signal delivery.

The recovery representation should be typed around saved scratch registers and
their current coordinate, following existing biased-memory recovery rather than
encoding register assumptions in unrelated booleans.

## Evidence-ranked expansion waves

After the first biased class is promoted, rerun the same profile and rank the
remaining typed reasons by runtime gateway share. Expand one class at a time:

1. current canonical region + available ordinary scratch;
2. additional load/store families already structurally understood, if the
   profile shows they remain hot;
3. virtualized operand/base forms only with a proof that all required guest
   values can be staged before the reservation and committed after it;
4. new control-flow shapes only after extending the typed region model and
   proving every leaving/retry edge;
5. scan-bound changes only when real hot sites show the bound, rather than the
   region shape, is the rejection.

Ordinary memory inside the exclusive pair, cross-page regions, mismatched
load/store pairs, and control flow that cannot be fully enumerated remain hard
fallbacks unless a later design supplies a new correctness proof. Coverage is
not a mandate to accept them.

## Correctness and promotion gates

- **Red-first recognizer tests:** each new accepted shape must first be shown as
  a typed rejection/fallback, then become a candidate after the change.
- **Fallback exhaustiveness:** every rejection reason must still produce the
  current sensitive exit and identical guest-visible behavior.
- **Emitter inspection:** generated instructions must show no explicit memory
  access between the exclusive load/store other than the pair itself.
- **Recovery tests:** inject/force prelude, in-region, early-exit, retry, fault,
  and kick paths; verify registers, NZCV, PC, and monitor cleanup.
- **Stress:** run the native atomic/CAS, futex, and threading probes at least ten
  times each, plus the real Go compiler reducer. Use the signed build path.
- **Oracle:** retain differential Docker evidence for guest-visible probe and
  workload output, with Carrick and Docker in separate phases.
- **Profile evidence:** the targeted rejection class and residual
  `sensitive_exclusive` gateways must fall as predicted. Record both hot-share
  and unique-site changes.
- **Performance authority:** rerun untraced W1 and the exact c94 case. A slice
  is a performance win only if wall/CPU improve without a new correctness
  regression, max-trap increase, timeout increase, or hidden fallback.
- **Full gate:** `just ci` and the relevant signed conformance lanes must be
  green before integration.

## Risks and mitigations

- **Misleading cold-site counts:** always pair unique-site breadth with runtime
  gateway share.
- **Profile self-perturbation:** all new hot counters are profile-only; use
  untraced runs for promotion.
- **Reason drift:** stable exhaustive enums and parser tests prevent silent
  renaming or catch-all buckets.
- **Reservation livelock:** keep the reservation window memory-clean and inspect
  emitted code in tests.
- **Scratch corruption on asynchronous exit:** typed recovery metadata plus
  forced kick/fault tests.
- **Wrong-address host access:** validate the guest aperture before adding the
  bias; invalid cases restore state and use the existing emulator/fault path.
- **Overgeneralizing from Go:** use runtime share to prioritize but unique-site
  and cross-workload conformance evidence to decide whether a new family is
  general enough to promote.

## Durable evidence

The campaign ledger records, for every wave:

- command and artifact path;
- commit and signed binary identity;
- runtime counts and shares by fusion disposition;
- unique-site counts by disposition;
- top diagnostic sites used to select the wave;
- untraced wall/CPU and exact c94 ratio/status;
- verification gates and any remaining fallback classes.

Measured results remain distinct from projected gateway removal. A candidate's
pre-change share is a projection until the post-change profile and untraced
workload actually run.
