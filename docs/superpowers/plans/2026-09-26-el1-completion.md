# EL1 migration: end-to-end execution controller

Status: active. Owner authorized this goal on 2026-09-26. Starting revision:
`d7393f6163adccbe001868b9056f2832813e10d2`.

Authority: [accepted EL1 design](../specs/2026-09-24-el1-kernel.md),
`AGENTS.md`, and [conformance contracts](../../conformance-contracts.md).
This controller tracks the whole goal; it does not replace the design or
turn proposed interfaces into accepted implementation facts.

## Goal

Complete the accepted EL1 migration through the x86 ring-0 venue. Carry each
increment through implementation, removal of superseded implementations,
conformance, measurements, and recorded acceptance. Preserve elastic memory,
host-scheduled CPUs, host-native I/O, and the substrate/personality boundary.
Prove Linux semantics and bounded operational cost, and measure the per-row
2x native-arm64 Docker objective without hiding host-platform I/O costs.
Neither a foundation nor a focused green test completes an increment.

## Checkpoints

| Checkpoint | Required outcome | Status at start |
|---|---|---|
| 0: existing scheduler and address-space switch | Preserve the implemented scheduler, futex handoff, GIC/timer, occupancy, and EL1 address-space switch; retain their contracts | Implemented on starting HEAD; acceptance receipts inherited from the design, not rerun by this campaign |
| 2: memory | EL1 owns anonymous mappings, first-touch/permission faults, brk/mmap/munmap/mprotect, elastic frame allocation/return, fork COW, and stage-1 publication; remove the host page-table pause once no host writer needs it | Next |
| 2a: host file operations | Reduce measured namespace-operation overhead while retaining containment, namespace transactions, and native macOS controls | Pending; finish before checkpoint 4 |
| 3: descriptors, IPC, signals | EL1 owns fd tables/descriptions, pipes, AF_UNIX, eventfd/timerfd, readiness waits and signals; preserve credentials, lifecycle and continuation semantics | Pending |
| 4: names and page cache | EL1 owns name resolution, dentry/stat cache and host-file page cache; host mutations/writers remain coherent; replace the existing file zone | Pending |
| 5: process lifecycle | EL1 drives fork/exec, image loading and process lifecycle; host supplies validated file bytes and process-boundary services | Pending |
| 6: x86 venue | Run the same neutral cores in guest ring 0 through the shared x86 engine, with real backend execution evidence | Pending |
| Final acceptance | Full declared conformance/workload population, exact-artifact provenance, performance accounting, dead-path removal, docs and unresolved-item closure | Pending |

The end-state ownership table is part of the denominator: credentials,
rlimits, process groups/sessions, in-zone loopback, ptrace/core capture, clocks,
and terminal boundaries must be assigned and verified during these checkpoints,
not omitted because they do not appear in a checkpoint's short title.

## First memory increment: goal brief

Outcome: execute anonymous first-touch and permission handling in EL1 using
one authoritative mapping/publication model shared with the host venue.
Start by resolving the interfaces below and recording semantic/structural red
evidence. An independent EL1 cache of host mapping decisions is not the result.

Current interfaces confirmed on the starting source:

- `carrick-runtime/src/vcpu_loop/signal.rs::resolve_mutating_fault` owns the
  host first-touch/protection commit sequence.
- `carrick-kernel/src/dispatch/mem/fault.rs::FirstTouchArming` stores pending
  first-touch permissions and supports bounded range lookup/splitting.
- `carrick-vmm-hvf/src/trap/sparse_materialization.rs` prepares backing under
  rollback ownership; `cow_engine.rs::materialize_sparse_mmap_extent_inner`
  authenticates exact owners and publishes the backing.
- `carrick-sched-core/src/spaces.rs::AddressSpaces` publishes roots and a
  pause/retirement gate; the occupancy protocol must still cover every vCPU
  executing the address space after an EL1 switch.
- `carrick-el1/src/entry.rs` currently dispatches SVC and IRQ entry; a data
  abort needs its own correctly preserved fault entry and continuation.

Constraints: distinguish semantic VA, stage-1 IPA, frame identity and owner
generation; do not expose a valid leaf before stage-2 and inventory commit;
roll back failed publication; no fixed RAM pool as the end state; zero recycled
anonymous frames; preserve host-backed shared aliases, foreign copyout, fork,
exec, mincore, mprotect and discard semantics. IRQ handling must not acquire a
page-table lock already held by interrupted EL1 code. Kernel exceptions remain
distinguishable from recoverable user faults.

Acceptance witnesses must include two live processes using overlapping virtual
addresses, concurrent first touches, denied accesses, mapping replacement and
retirement, foreign reads/writes, allocation refusal and rollback, and repeated
allocate/free cycles proving frame return. Structural evidence must distinguish
bulk grants from per-page host exits and use at least three scale points.
Choose and register the precise contract/bindings before implementation; do not
claim existing host-only fault tests prove guest page-table execution.

## Acceptance protocol

For each checkpoint, record source, fixture and oracle identities, observed
red/green results, and all outstanding gates. Run the cheapest capable semantic
and deterministic-work tests first; use signed embed for actual guest execution.
Run `just ci`, `just el1-gate`, and applicable probe/smoke/full promotion gates
on their exact recorded artifacts. Keep Carrick and Docker phases serialized.
Preserve SHA-256, CDHash, LC_UUID, entitlement, DOF, and run-scoped cleanup.

Compare uninstrumented release workloads with the previous accepted checkpoint
on Go build, cpython-threading and cpython-subprocess, and broaden to the full
declared ecosystem population for final acceptance. Keep Linux ratios and native
macOS controls separate. Document temporary migration regressions; do not turn
them into final acceptance, widen budgets, retry until green, or reduce concurrency.

Use one implementation in neutral cores with venue adapters. Retain host-venue
adapters needed by other backends until checkpoint 6; remove duplicate semantic
implementations as replacements land. Mechanically enforce the personality
boundary at its first split.

## Open obligations carried from the design

- Parked-EL1-thread registers are absent from crash snapshots.
- Entrant refusal bound is measured rather than derived.
- Personality boundary has no mechanical gate yet.
- SPI delivery / `hv_vcpus_exit` anomalies and wedged-vCPU recovery under GIC
  require evidence before dependent behavior is accepted.
- Durable paired carrier-CPU profiling across Go/Python/Node remains an entry
  criterion where migration ordering depends on those measurements.
- Idle-entry thread execution is not enabled because of the documented host
  control-claim race; change it only if measurements justify it and its contract
  proves the race resolved.
- Real x86 backend hardware and a native x86 oracle must be verified before
  checkpoint 6; translated amd64 Docker is not an oracle.

## Campaign record

2026-09-26: created isolated `el1-completion` worktree at the starting revision.
Read the accepted design and current memory publication paths. Started the
host-only scheduler/EL1 core baseline and a read-only Antigravity interface
audit. No implementation or signed acceptance is claimed yet.

Ruling: follow the accepted design's goal-brief format, rather than expand the
entire migration into speculative code-level steps. The first memory increment
will fix its interfaces from source and red evidence. Cost if wrong: revise a
bounded brief before implementation, rather than build to invented interfaces.

Baseline: `RUSTC_WRAPPER= cargo test -p carrick-sched-core -p carrick-el1
--lib` passed (41 scheduler-core tests and 46 EL1 tests). This is host-only
baseline evidence; it does not qualify a signed guest artifact.

2026-09-26: previous goal turn was progress (controller commit and baseline
evidence). Added first-touch witness in `2c0b989c0`. Native arm64 Docker and
signed Carrick both pass the three-scale two-process semantic checks; Carrick
is structurally red at about one host exit per page. Negative entitlement
control passes and cleanup is zero. Exact artifact and raw evidence:
[first-touch red receipt](../../perf-results/2026-09-26-el1-first-touch/README.md).

Next bounded implementation task: extract the existing stage-1 page-table
algorithm into a neutral `no_std` core, preserving its host behavior and
tests, and making layout constraints caller-supplied. This is a prerequisite
inside checkpoint 2, not its acceptance. Follow it with the single live-table
authority/mutation protocol, bulk grant integration and guest abort entry;
the first-touch witness must become green through actual guest service.

Ruling: do not adopt the audit's proposed guest-leaf/host-shadow split. Direct
inspection found current-read translation still using `PageTableManager`,
and `carrick-mem` depends on `carrick-abi` despite the audit's contrary claim.
Atomic guest PTE stores alone do not repair those authorities. Cost if wrong:
extra extraction work, but no knowingly stale host view is introduced.

### Live host-read authority prerequisite (2026-09-26)

A VM-free red test invalidated the hardware-visible leaf while preserving the
software image. The cached input window incorrectly copied the old bytes.
The reader now walks live descriptors from the authenticated root, resolving
at most four descriptor addresses through the MM inventory and exact live
owner generations. It retains the existing mutation/page-table guards through
copy, adds no allocation or owner pin on reuse, and rejects revoked leaves
before copying. Existing host-mutation fixtures now publish their edits to
hardware backing instead of changing only the shadow.

The 12 active native-buffer tests pass with `conformance-metrics`, including
all four cost scales; the existing research-ELF control remains ignored by its
pre-existing external-fixture requirement. This is VM-free prerequisite proof
only. Other shadow consumers, shared host/EL1 mutation exclusion, guest fault
service, full CI, signed promotion and paired workload timing remain open.

Verification of `28a096160`: the serial runtime library suite with
`conformance-metrics` passed 622 tests; eight existing manual/research diagnostics
were ignored. Targeted runtime/HVF all-target Clippy passed. `just lint-domains`
returned zero on the committed source; its host-authority census explicitly
reports Linux, FreeBSD and NetBSD profiles pending. Logs are retained beside
the red witness. These results do not confer signed or cross-platform acceptance.
The source-to-contract registry now names the live reader and its buffer tests.

### Extraction and boundary review (2026-09-26)

The previous turn was progress: live-read runtime correction `28a096160` and
verification receipts `e41965f3c`. The next turn revalidated the clean integration
tree and live `mmu-core` worker handle, then started the independent
`personality-boundary` worker in its own managed worktree at `e41965f3c`.
That task injects the scheduler timeout result and adds the first mechanical
substrate dependency/literal gate. It does not claim the signal/timer or EL1
personality split is finished; the MMU crate must be added to the gate on
integration.

Preliminary extraction review found all 70 existing page-table test names and
the same assertion counts, but acceptance remains withheld pending full tests
and diff review. Required corrections: preserve removed invariant/regression
comments; retain the original test-only visibility of three helper methods;
check whether hashbrown's sysroot-oriented `alloc` feature is unnecessary.
Do not integrate the in-flight tree or run signed acceptance against it.

Memory sequencing remains driven by the live-authority result. The relocated
`TableArena` still owns a `Vec` image; `read_desc`, clone/fork snapshots and undo
all depend on it. Updating one host reader does not authorize an EL1 leaf writer
beside this model. The next memory implementation must give mutation/snapshot
paths the same live authority, preserve exclusive structural allocation and
rollback, then wire fault entry and bulk grants. The existing ABI frame has no
saved FAR and the EL0 sync hook currently selects SVC only; fault entry must
preserve fault address and ELR/SPSR before nested EL1 work. Existing sparse
materialization and fixed pre-mapped frame pooling are host venue mechanisms,
not proof of the required EL1 allocator or elastic extent return.

Boundary review now has reproduced negative evidence, not just source concerns:
[four false passes in the initial checker](../../perf-results/2026-09-26-el1-boundary-review/README.md).
Integration is withheld until those cases reject. MMU extraction finished its
initial worker turn at `ea0230092`; the three documented review corrections
were sent as round 1 to the same worker. Neither candidate is integrated yet.

The next storage requirement now has a failing runtime witness:
`stage1_snapshot_observes_live_leaf_after_guest_publication` under
`kernel.fork.stage1-image`. After live-leaf revocation, a host fork/rollback
snapshot still translates that page (expected no translation). The existing
fork allocation and work budgets are unchanged. The contract wording now names
private stage-1 state rather than requiring an authoritative software shadow;
its runtime binding adds the live-snapshot control. This new red is intentional
and remains open alongside signed first-touch. The earlier 622-test green
receipt still belongs only to `28a096160`.

### Integrated MMU extraction (2026-09-26)

The extraction and bounded review corrections are now integrated as `41370ac96`
and `600e5c859`. The director stopped an off-scope worker revision, retained
its rejected patch, and preserved original invariant comments, test-only APIs,
and checked-overflow behavior. The normal no_std closure is hashbrown/foldhash.
All 70 MMU and 171 memory tests passed on the integrated tree, alongside the
bare-metal check, CLI/embed test compilation, warning-free MMU/memory docs,
contract registry validation and all five current-read runtime controls. Logs
remain in `target/el1-completion/mmu-integrated-*.log`. Earlier independent
extraction checks also covered 17 stage1-authority tests and targeted Clippy.

This is portability groundwork only. The live snapshot witness and signed
first-touch witness remain red. Live backing authority is the next bounded
implementation; full CI, signed promotion, paired workloads and the remaining
end-to-end stages are still open.

At `d500a98ae`, integrated `just lint-domains` exited zero after inventory
reconciliation. Its host-authority census explicitly remains partial: Linux,
FreeBSD and NetBSD CLI/runtime profiles are pending. The EL1 and EL1 ABI library
tests also passed (46 + 19). The corresponding MMU integration logs are preserved
under `docs/perf-results/2026-09-26-el1-first-touch/mmu-integrated-*.log`.

The live-table worker is running from `89c9fc55a` in the reused, isolated MMU
worktree, preserving the failing snapshot witness. Personality review round 2
requires resolved Cargo graph traversal: a path-only manifest walk cannot prove
registry or Git transitive closure. Both are implementation work in progress;
neither grants EL1 memory acceptance.

### Full host gate on the extraction

`RUSTC_WRAPPER= just ci` started at `2e5cce585`; only boundary-review evidence
documents changed during execution (`6214798f2`), not product/test source. It
exited 101 in `just test` at the intentional live-snapshot witness: 618 runtime
tests passed, one failed, and eight existing diagnostics were ignored. The
failure still reports a physical translation after revoking the live leaf.
Formatting, workspace Clippy, domain checks (with the documented partial
cross-platform census), dependency policy, matrix/check and warning-free docs
completed before that failure. Earlier host test groups also passed.
Later test groups and integration tests were not reached; this is not CI green.
The complete transcript is `docs/perf-results/2026-09-26-el1-first-touch/mmu-integrated-ci.log`.
The red remains unchanged while the isolated live-table worker implements the
shared storage authority.

### Scheduler personality split and mechanical gate

The reviewed scheduler split and checker are integrated as `26f104341` and
`1bc6c8900`. The substrate accepts the timeout result from its Linux caller;
both EL1 callsites still supply the existing -110 result. Three worker review
rounds were required. Director review then replaced three scratch-dependent
skipping tests with hermetic fixtures and proved two additional failures red
first: missing target fallback and metadata from another workspace. Both are
now rejected. The production checker consumes freshly generated locked/offline
all-feature Cargo metadata, follows normal/build graph edges, and audits Cargo
target source roots. The superseded lockfile/name-only walk is gone.

Enforcement now covers `carrick-sched-core` and `carrick-mmu-core`. Integrated
verification: 26 boundary tests, 46 EL1 tests and 42 scheduler tests passed;
targeted all-target Clippy and CLI/embed test compilation passed. The real gate
reports empty scheduler dependencies and MMU hashbrown/foldhash dependencies,
with carrick-mem explicitly dev-only. Raw review and integrated receipts are in
`docs/perf-results/2026-09-26-el1-boundary-review/`. The known-pattern source
ratchet does not expand procedural macros or prove arbitrary encoded semantics.

This is one personality-boundary increment, not migration completion. Signal,
timer, VFS and other substrate/personality separation, live memory authority,
signed gates, paired workloads and all later stages remain open. The initial
snapshot and signed first-touch witnesses remain unmodified and unresolved.

At `0c4ec58f4`, the integrated `just lint-domains` exited zero with both
substrate cores checked. The cross-platform authority profiles remain pending
as documented. Its full receipt is
`docs/perf-results/2026-09-26-el1-boundary-review/personality-integrated-lint.log`.

The first live-table candidate `6a538d49f` is deliberately not integrated. The
worker reports the snapshot witness and serial runtime suite green, but source
review found missing live backing silently treated as zero descriptors/empty
snapshots, insufficient retained ownership and generation/bounds checks in the
resolver, non-atomic byte copying of live descriptors, and restore paths that
discard snapshot bytes when rebinding. Review round 1 requires explicit errors,
a sound backing lifetime, live-bound restore controls and root/extension
retirement tests without weakening current-read budgets. A single green
snapshot test is not acceptance of live stage-1 authority.

`RUSTC_WRAPPER= just test-integration` on `b95b3bfb0` exited zero: 465 tests
passed across 15 result groups, with no failures or ignored tests. The three
guest-running shard entries were filtered by the existing host-only recipe.
This covers the runtime/kernel integration, syscall-process, prepare compile-fail
contract, CLI/trace, engine/image and probe-inventory consistency suites. Receipt:
`docs/perf-results/2026-09-26-el1-boundary-review/personality-integrated-host-integration.log`.
It does not replace the still-red snapshot library test or signed memory gates.

### Live authority review round 2

Candidate `1dfe55a5d` remains unintegrated. The worker reports 623 serial
runtime tests passing, but independent reruns against that committed MMU source
still reproduce silent live-state fallback from failed snapshot cloning and
compile the safe resolver-replacement witness. Final source still validates only
eight bytes before callers add descriptor offsets, and caches structural owners
without coordinating pooled-root retirement/reuse. Root and extension tests do
not yet exercise cached entries after same-slot reuse. Exact rerun receipts are
in `docs/perf-results/2026-09-26-el1-live-table-review/round1-final-*`.

Review round 2 was sent to the same live-table worker with explicit failure,
complete-range access, sound resolver installation, coordinated retirement and
behavioral test requirements. Existing work budgets and full migration scope
remain unchanged. No signed or performance acceptance is claimed.

### Occupancy witness repair and signed evidence

Integrated `8bafb145b` / `77b044194` repair false-pass paths in the existing
occupancy fixture without reducing writer concurrency. Director independently
verified 16 parser tests, cross-build, embed check, Clippy and formatting. Native
arm64 Docker passed the exact fixture, then signed Carrick passed the default
case and three separate scheduler/futex/GIC-disabled controls on one unchanged
signed executable. Negative entitlement and all scoped cleanup checks passed.
Exact evidence: `docs/perf-results/2026-09-26-el1-occupancy-witness/README.md`.
This is witness acceptance only; the live-snapshot and first-touch failures,
full promotion and end-to-end stages remain open. No timing ratio is claimed.

2026-09-26, continued review: `5d612ffb5` preserves the independent round-2
live-table draft snapshot failure (Cargo exit 101, panic rather than the older
silent live fallback). Round 2 ended without a committed candidate. Final
review round 3 is active on the same worker, requiring fallible snapshots,
non-silent restoration/rollback failure, and actual pooled-root retirement and
reuse evidence. It remains unintegrated. If that round does not converge,
stop the delegated review loop and resolve the remaining runtime work directly;
do not open a replacement worker to evade the review cap.

Started the explicitly parallel checkpoint 2a task `host-namespace` in the idle
`el1-personality-boundary` worktree, clean at `5d612ffb5`. Its bounded scope is
rename/unlink host opens and metadata work under the existing admitted namespace
transaction. It must establish red-first structural counts with existing counter
coverage, then remove demonstrated redundant work while preserving containment,
revalidation, hardlink behavior, tombstones and error propagation. No guest or
Docker runs are authorized for the worker. The director retains serial native
and signed differential acceptance. Openat, remaining host-file work, and all
higher checkpoint gates remain pending. The previous occupancy worker commits
are preserved on `el1-occupancy-witness-accepted`; their accepted changes were
already integrated. No memory/host-namespace source files are shared between
these two active worker tasks.

### Namespace integration and director rollback correction

Integrated the reviewed namespace candidate through `0d8bf00cd`. Its complete
VFS split passes (253 parallel, 38 serial), as do Clippy, registry, and the
post-integration work-budget witness. The original unlink cost is preserved;
rename eliminates repeated backend directory opens. Exact receipts are under
`docs/perf-results/2026-09-26-el1-host-namespace/`. Stage 2a remains open.

On separate `el1-memory-corrections`, based on unaccepted candidate
`22323a343`, director correction `878d3a69e` retains the undo journal through
failed/partial host restore. Two real-crate controls failed before the fix;
82 MMU, 171 memory, and 20 authority tests pass afterward, as does MMU Clippy.
This candidate remains unintegrated pending live-owner access/retirement
exclusion and snapshot recovery. No fourth worker review is authorized;
remaining corrections belong to the director. The original goal scope,
first-touch structural red, signed gates, and workload objective remain open.

Namespace integration follow-up: domain lint initially rejected the missing test-only counter ledger entry. Reviewed and registered it in `f664e7e02`; the full `just lint-domains` rerun exits zero. The memory worker is now terminal at `55bdfc220`; its product code equals candidate `22323a343` and only four inventories differ. Its final output contains waiting statements, so acceptance continues to rely on director evidence, not that report.

### Live-table source integration after director corrections

Integrated the reviewed worker product and director corrections through
`d51e1915a`. Corrections retain rollback journals, preserve caller-owned
snapshot recovery, prevent partial restore on unresolved destinations, hold
root retirement exclusion in publication lock order, and record live extension
prefixes so pooled reuse zeroes written bytes. The final correction's serial
HVF suite passes 564 tests with 3 existing ignores; Clippy and abort ledgers
pass. Every reproduced defect has its red/green receipt under the live-table
review directory. The worker's terminal `55bdfc220` changes only inventories
relative to its product candidate; reconciliation was rerun on combined source.

The previously red `stage1_snapshot_observes_live_leaf_after_guest_publication`
now passes on the integrated source. Inventories preserve all 588 host-authority
rows. Full CI and signed acceptance remain pending; the earlier withheld-source
status is superseded by this integration, not by a claim of guest execution.
After those gates, the critical path is EL1 metadata allocation, abort entry,
elastic frame grant/return, and real guest first-touch service. Keep all later
checkpoints and the per-workload native-Docker objective in scope.

### Snapshot allocation correction and matching-image fork oracle

Integrated `12246bbd5` as `54f3167a7`. The allocator witness observes zero
large snapshot-buffer allocations after warmup at all four scales, replacing
the old live-conversion behavior that allocated once per fork. Live descriptors
remain authoritative; retained buffers contain no readable snapshot contents.

The preceding full CI on `899873310` exited zero (6,179 passing tests across
101 result groups; 12 existing ignores). Its transcript remains at
`target/el1-completion/live-integrated/ci.log`, SHA-256
`73d09acfd5ac0012fa7493f15021e1a0acb54bd447927721f09b75b5755d6d03`.
That result does not cover the allocation correction. Full CI for `54f3167a7`
is in progress at `target/el1-completion/live-integrated/ci-54f3167a7.log`.

Fresh image inspection found different Ubuntu image versions behind Docker's
and Carrick's cached tags. The native fork runner now pins Carrick's exact
manifest and verifies equal root filesystem layer digests. All 12 native rows
pass with cleanup proved. Receipts:
[matching-image fork authority](../../perf-results/2026-09-26-el1-live-table-review/native-fork-54f3167a7/README.md).
Signed validation and every remaining migration checkpoint remain open.

Full CI for `54f3167a7` now exits zero: 6,180 passing tests across 101 result
groups, zero failures and 12 existing ignores. Only evidence documentation
changed to `b6ce9ab26` during the run. The complete transcript and hash are
preserved in the [integrated receipt](../../perf-results/2026-09-26-el1-live-table-review/integrated/README.md).
Signed fork validation is running separately from `b6ce9ab26`, run ID
`el1-live-fork-20260926-b6ce9ab26`; do not treat its in-progress build as
signed acceptance. After it completes, preserve the exact signed artifact and
receipt, then run the occupancy contract. Actual EL1 fault service remains the
next implementation milestone, with no broader goal scope removed.

### Signed live-table foundation proof

The integrated memory source now passes the signed fork structural gate:
three launch modes times four scales, fresh image counts bounded by two,
complete work measurements, negative entitlement and zero scoped leftovers.
The matching-image native fork controls also passed. The independent allocator
witness remains necessary because image-pool misses omit buffer allocations.

The two-process occupancy fixture passes native Docker and signed Carrick,
then three disabled-feature controls on one unchanged frozen signed executable.
Both processes complete 150 forks with positive editor work and zero failure
counters. Exact artifacts, commands and logs are preserved in the
[signed memory receipt](../../perf-results/2026-09-26-el1-live-table-review/signed-memory/README.md).
No timing ratio or full migration acceptance is claimed. Public probe/smoke/full
promotion and the first-touch structural red remain open. Next implementation
work must establish EL1 metadata allocation/reclamation, fault entry and elastic
frame grant/return, then service first-touch in the guest; all later checkpoints
and inherited acceptance obligations remain in scope.
