# Owner-memory wait consolidation (#802)

This local two-layer consolidation separates process authority and ordering
from wait routing. Nothing was pushed or written to GitHub.
The contract invariants live in `docs/conformance-contracts.md` and
`conformance-contracts/contracts/owner-wait.toml`.

## Input disposition

No input commit was cherry-picked wholesale. Input branches were read only.

- `3170f9afa` (reuse killable physical waits): main already has its generic
  physical route and lacks the directory adapter being removed. Keep that
  single route; do not import the adapter or directory implementation.
- `ab69f6330` (settle physical waits before retry): port the owned physical
  phase and common immediate/scheduled settlement; rework it into the shared
  `OwnerWait` protocol used by zone and supply-ready paths too. Port its
  real content-writer witnesses to existing `pipe2` dispatch instead of
  importing directory preparation and cursor changes from #777.
- `702927e81` (cancel every physical waiter): retain fatal cancellation
  independent of delivery reservation and generalize terminal routing to
  zone waits. Non-leader witnesses use real same-task admission and a live
  carrier-owned leader. Replace the reservation-sensitive queue query with the durable process
  authority, covering actual leader reservation too.
- `66f94afca` (killable sleep copy-in): retain exhaustive killable policy and
  handled-signal production witnesses. It requires the retained sleep-input
  operation from `95d349cdd`; that prerequisite is included, excluding the
  scheduler fixture rewrites from the branch.
- `38e5a549c` (retained completion origin): retain typed zone saves and actual
  CPU materialization witnesses. Its direct-EL0 path requires the retained
  host IPC operation from `0f6a14835`, included here without its separate
  in-ring pipe-transfer correction.
- `34acd46d5` (native cancellation witness): port native zone/physical IPC
  witnesses and compile the production mailbox protocol in Linux unit tests.
- `53c46f5b2` (native completion origin): retain the HAL/engine/transport
  origin and durable native fatal entry PC across executor migration. Extend
  retirement to carrier-owned direct-EL0 cancellation, which the input tests
  did not exercise.

Private-file changes, directory copyout implementation and oracle fixtures,
CPU scheduler changes, and in-ring pipe-transfer changes remain in their
respective input branches. Those branches were not modified.

## Proof and limits

The initial physical witness run failed five assertions on main's unchanged
physical route: immediate cancellation committed one output; parked
non-leader cancellation installed two descriptors; both retry paths retained
writer count one. The old never-ready leader SIGKILL case passed.

With retained operation prerequisites installed, regression controls restored
unconditional trap retirement and ordinary sleep owner parking. Both native
IPC cases failed with missing guest completion ownership; sleep woke on a
handled signal before editor release. These are not claimed as builds of
pristine main, which lacks those retained operations. The same missing-trap
error was then reproduced for carrier-owned direct-EL0 zone and physical waits.
After the routing repairs, 56 focused owner tests passed.

The consolidation adds a per-process `CancellationAuthority` beside terminal
custody on the exact lifecycle page. Carrier and native signal owners retain
that page. Signal reservation and dequeue cannot clear it; fork admission
attaches the child to a fresh authority. Group exit closes the same authority.

## Ordering and model scope

A fatal request closes effect admission atomically. A typed publication waits
for already admitted bounded effects to finish before publishing the fatal
queue/wake. After securing output, `ProcessEffect` owns the interval covering
consumption, output and cursor/descriptor publication. Independent effects
remain concurrent. An already-ready waiter must acquire this custody too;
resumption alone is not permission to consume. No permit survives a guest
wait or a transfer of execution capacity. Notifications run after its release.

The six runtime loom models call the shipping generic settlement and core
atomic authority, substituting loom words. They explore editor release,
sibling effects, fatal publication, ordinary signal deferral, two waiters and
the already-ready shortcut. The strict assertion is still literal: physical
consumption cannot occur after fatal publication. There is no expected-panic
classification. The model does not instrument production lock graphs, signal
queues, scheduler enrollment or mailbox transport; production witnesses cover
those adapters. It is not a repository-wide editor-holder audit.

A late-kill witness publishes SIGKILL during re-preparation, after the shared
settlement's final sample. Removing effect admission commits one pipe2 output;
with custody it commits none. Actual leader-reservation sibling tests cover
both ready and parked physical dependencies. A native dequeue test checks
that removing the delivery record preserves cancellation and that fork gets
a fresh authority. Review also tests invalid destinations on empty IPC reads
and stale authorized signal targets.

Signed HVF execution is unavailable on this Linux worker; Docker is prohibited.
Exact-artifact signed acceptance remains director-owned. Local gate receipts
and the two proposed PR bodies are prepared under `/tmp`; nothing is pushed.

The final rebase preserves main's typed 1.5 MiB EL1 image region. The
interim nested-image wrapper workaround is dropped; image layout and build
policy remain owned by main. Prior image diagnostics belong to the earlier
main base and are retained only in the local verification report.

The ordering scope here is secured-output consumption and publication in the
listed owner-wait review edges. Blocking external writes after retained copy-in
keep #711 rule 1's existing post-wait syscall semantics. Extending strict
physical completion ordering to those writes would require their own bounded
I/O continuation design: a blanket effect guard spans capacity release and can
also deadlock synchronous fasync SIGKILL. This scope assumption was raised with
the director; it is not a claim that arbitrary external writes are ordered.
