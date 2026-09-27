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

### Public probe regression: exec successor resolver

Public probe promotion on `33b590cd8` aborted at the first case of every shard
in brk heap expansion. LLDB established that the replacement exec tables were
being read through the predecessor MM resolver. The initially displayed
zero-length ledger key was an optimized-debugger artifact; real register bounds
were valid. Do not weaken bounds or generation authentication.

Binding the replacement resolver in `execve_rebuild_inner` turns the existing
`accessx` signed probe green for musl and GNU. Fresh matching-image native
Docker output also matches both committed oracles, negative entitlement passes,
and cleanup is empty. Exact red/green artifacts and the correction are in the
[exec resolver receipt](../../perf-results/2026-09-26-el1-live-table-review/exec-resolver/README.md).
Full probe promotion and CI still need rerunning; smoke/full and actual EL1
first-touch service remain open. The complete migration scope is unchanged.

### Shared exec resolver isolation

Full CI on `aa5d55dd6` passes 6,180 tests. Public probe promotion passed generic
shards 0 and 1, then aborted on GNU `forkexecstorm` after 798 completed probe
rows: anonymous discard could not resolve the parent root. A focused core
capture reproduces it; fresh native Docker passes both libc variants.

The VM-free shared-exec inventory test now proves parent translation survives
child exec preparation. It failed before correction because preparing the
child installed its empty-ledger resolver on the parent's shared authority.
Removing that premature binding turns the witness green, preserves 564 serial
HVF test passes, and makes signed `forkexecstorm` pass both libc variants with
negative entitlement and zero leftovers. The successor resolver remains bound
when exec creates its independent authority. See the
[shared exec receipt](../../perf-results/2026-09-26-el1-live-table-review/shared-exec-resolver/README.md).
Full CI and public probe promotion on this correction remain pending, followed
by smoke/full and real EL1 first-touch service. No scope or budget is reduced.

### Qualified public probe result after both exec corrections

`just --no-deps conformance-probes` exits zero on clean `863e81757`: 912 unique
generic arm64 executions, dedicated signed cases and the CLI boundary pass.
Retained musl passes 33/33; GNU passes 31/33 with two report-only discrepancies:
`ppollwaitset` wake latency bucket (`lt100` versus `lt1`) and `sigprofvdso`
timer text sampling (`1` versus `0`). Preserve both findings for controlled
attribution; the zero exit status is not strict closure. The CLI remains byte
identical and frozen, and final scoped cleanup is empty. Separate signed-stage
receipts are preserved, with the generic artifact re-signing limitation stated
in the [public probe receipt](../../perf-results/2026-09-26-el1-live-table-review/public-probes-863e81757/README.md).
Full CI on this revision is running. Smoke/full, strict probe acceptance and
actual EL1 first-touch remain open with the full goal scope intact.

### Retained GNU attribution and authority inventory reconciliation

Two fixed samples per retained probe on each frozen Carrick artifact
(`aa5d55dd6`, `863e81757`), followed by matching-image native arm64 Docker,
all exit zero with empty cleanup. Every venue reports `ppollwaitset` wake
bucket `lt1` and `sigprofvdso` timer text sampling `1` in both samples. Thus the
public latency difference did not reproduce in the isolated screen, and the
timer value also occurs in native Linux despite cached `0`. These observations
support probe/oracle investigation; they do not repair the original receipt or
close strict acceptance. No oracle or threshold changed. See the
[bounded attribution receipt](../../perf-results/2026-09-26-el1-live-table-review/retained-attribution/README.md).

CI stopped on three source-position changes in the host-authority inventory.
Reconciliation preserves 588 reviewed rows, classifications and rationale
bodies, updating only the shifted spans/location prefixes and machine capture.
Non-macOS authority profiles remain pending. Full CI rerun, artifact-preserving
strict probe acceptance, smoke/full and actual EL1 first-touch remain open.

2026-09-26: dispatched bounded fault-entry implementation to Antigravity
worker `fault-entry`, conversation `7b92561f-8c12-400a-9c0d-82f515281049`,
in the reused isolated `el1-memory-corrections` checkout at `a7d3138df`.
The prior checkout tip is preserved by
`archive/el1-memory-corrections-before-fault-entry`. The exact task is
[the fault-entry plan](2026-09-26-el1-fault-entry.md); worker execution is
limited to host tests and image compilation. Director owns diff review,
signed red/green witnesses, native controls and integration. This new entry
task does not reopen the exhausted live-table worker review rounds.

The existing full CI process remains live against `d35c88001` (only plan
documentation changed afterward); it has reached runtime tests. No final
CI success or fault-entry acceptance is claimed. The latest status-only turn
was no implementation progress; this dispatch advances the next prerequisite.

2026-09-26: the existing authority-reconciled `just ci` process completed
with exit 0 on `d35c88001`: 6,180 passed, zero failed, 12 ignored across
101 result groups. Raw evidence is in
`docs/perf-results/2026-09-26-el1-live-table-review/ci-authority-reconciled/`.
The dedicated public-probe executables were frozen and hash-verified (four
executables, 32 passing execution rows). The earlier generic-stage artifacts
remain unavailable in their original signed form; a stale-receipt capture
was rejected before copying. Fault-entry worker turn 1 remains active.

2026-09-26: fault-entry worker produced `99610317a`, but director review
round 1 rejected acceptance. The 239 host tests pass independently; the real
guest fixture fails cross-compilation (invalid assembly output constraints
and siginfo accessor). Review also requires sound register capture, deliberate
stage-1 fault construction, bounded handler failure, EL1-off control, precise
EC classification and truthful red-first/provenance evidence. The same worker
is active on turn 2. Details are in
`docs/perf-results/2026-09-26-el1-fault-entry-director/`. No implementation
was integrated and no signed acceptance was attempted. The initial reset
concern was withdrawn after inspecting its pointer/snapshot lifecycle.

2026-09-26: while fault-entry review round 1 runs, static MMU allocation
audit identified an additional prerequisite beyond the existing heap-overlap
red: journal/staged/dirty collection growth is infallible, including returned
arena bookkeeping after rollback consumes its journal. A reclaiming allocator
alone cannot prove metadata-refusal recovery. Evidence and required witness
cases are in `docs/perf-results/2026-09-26-el1-first-touch/allocator-prerequisite/mmu-allocation-audit.md`.
No current guest OOM reproduction or new allocator acceptance is claimed.

2026-09-26: director review round 2 of fault-entry at `eb2d4f6a3` confirms
244 host tests and fixture cross-compilation pass. The frozen fixture also
passes on the pinned matching-image native arm64 Docker oracle with exit 0
and no remaining container. Acceptance remains open: the bare-metal entry
duplicates rather than calls its tested dispatch helper; the fixture captures
but does not assert SP; and claimed semantic red has no preserved raw receipt.
The same worker is addressing these narrow findings on turn 3 (review round 2).
Evidence: `docs/perf-results/2026-09-26-el1-fault-entry-director/review-2-*`.
No worker implementation has yet been integrated.

2026-09-26: fault-entry review round 3 at `8c5bd3ee1` found a fixture
regression: SP capture overwrites x16 before recording its canary. The pinned
native arm64 oracle confirms exit 1 with x16 containing SP instead of the
canary. The same worker is addressing this narrow correction on turn 4, its
third and final review round. Real-entry dispatch wiring and raw dispatcher
semantic red evidence are now present; the latter does not prove vector tests
ran red because Cargo stopped at the earlier failed crate. Native evidence
and review are preserved in the director review directory. No guest runtime
regression is inferred from this fixture failure.

2026-09-26: final fault-entry worker revision `a6fe8d4af` passes director
fixture cross-compilation, host/image/contract/format/embed compilation checks
and the pinned native arm64 fixture run. Three review rounds are complete;
no further worker rounds are authorized. Imported only the ABI instrumentation
and final fixture/test to prepare signed red against the existing dispatcher
and vectors. The actual fault-entry implementation remains unintegrated until
this witness proves the missing entry. Full signed and performance gates stay
open. Final worker verification is retained under the director evidence tree.

2026-09-26: signed fault-entry red is established at `d409be2c7`: Linux
fixture checks succeed, but the expected positive EL1 entry counter is zero.
Negative entitlement control and scoped cleanup pass. Frozen signed identity
and exact native-matching fixture hash are retained in the director signed-red
receipt. Merged reviewed worker `a6fe8d4af` as `0c30348a2` and started signed
green using the same fixture. The worker converged in three review rounds;
EL1-off/GIC-off controls and higher promotion gates remain outstanding.

2026-09-26: signed fault-entry green completed on `0c30348a2` using the
exact red/native fixture. The tested signed executable was frozen; both
EL1-off and GIC-off controls pass on that same artifact, with negative
entitlement and scoped zero-process cleanup evidence preserved under
`docs/perf-results/2026-09-26-el1-fault-entry-director/signed-green/`.
This closes focused fault-entry acceptance, not first-touch service or full
promotion. Integrated CI is the next check; the broad EL1 gate still includes
the deliberately red anonymous-first-touch contract.

2026-09-26: fault-entry integrated CI exposed test-only Clippy errors, fixed
in `a3fe1bd12`, then three position-only authority inventory shifts. Capture
reconciliation retains all 588 reviewed rows. Raw failed runs and correction
evidence are preserved in the director integrated-ci directory. Full CI is
rerun after reconciliation; no full integration acceptance is claimed yet.

The next bounded task is the MMU metadata-refusal plan. Antigravity worker
`metadata-refusal` (cid `8b754593-3510-4caf-995f-76732c475fdd`) runs in the clean
reused el1-memory-corrections checkout at plan base `cb2a854bf`. This is a new
task with zero review rounds used; the completed fault-entry worker remains
terminal at its three-round cap. The task requires real allocator refusal,
zero-allocation rollback and complete edit/publication recovery. It permits
host tests only, with director-owned integration and signed execution.

2026-09-26: integrated fault-entry full CI passed on `084c9a272`: 6,188
passed, zero failed, 12 ignored across 101 Rust result groups. Complete log
and hashed receipt are preserved under the fault-entry director
`ci-reconciled/` evidence directory. The six non-macOS authority profiles
remain explicitly pending. Signed promotion and actual guest first-touch
service are still open; the independent metadata-refusal worker is active.

2026-09-26: signed integrated EL1 gate on `3667731b2` exits 1 solely on
anonymous first-touch work: 614/2148/8293 host exits at 512/2048/8192 total
pages, slope 0.9987 versus <0.125. Forty-one other EL1 tests and the negative
control pass; cleanup is zero. All eight executed artifacts are frozen and
CLI identity is unchanged. Public probes/LTP/inotify recipe steps did not
run. Exact failure evidence is under fault-entry-director/el1-gate/.

Metadata-refusal worker `32b0ad50f` passes the five prescribed commands but
fails independent semantic review: under actual allocation refusal,
coalescing drops a valid translation by freeing a still-linked child after
ignoring the failed parent write. The retained director reproducer exits 101.
Review round 1 also requires real live/adapter bindings, nonallocating error
propagation and complete provenance/work evidence. The same worker is active
on turn 2; implementation remains unintegrated. Evidence lives under
`docs/perf-results/2026-09-26-mmu-metadata-refusal-director/review-1/`.

2026-09-26: compiled ABI layout census confirms the nominal 48 MiB heap
contains only 1.75 MiB outside named reservations; 9 MiB more is unassigned
before it. Evidence and exact source/ABI hashes live in first-touch/
allocator-prerequisite/layout-census/. These are possible bootstrap intervals,
not an elastic allocator or guest execution proof. Keep extent growth/return,
pointer-domain identity and IRQ/lock ordering in the allocator prerequisite;
do not fix the dormant bump allocator by moving it into another reserved table.

2026-09-26: metadata-refusal director review round 2 confirms all five
prescribed commands pass on `0f395e825`, including the prior coalescing
corruption witness. Acceptance remains withheld: genuine adapter refusal,
nonallocating engine error conversion, aligned injection/counting scopes,
same-instance recovery, bounded admission work and authentic raw red evidence
need correction. The same worker is active; one review round remains after
this response. Evidence is preserved under metadata-refusal-director/review-2/.
Keep the task bounded to edit/publication/rollback; inventory remaining
lifecycle allocation obligations for subsequent guest migration. The next
impact milestone remains actual in-guest first-touch, not another host-only
foundation checkpoint. The preceding user-facing status turn changed no code.

2026-09-26: metadata-refusal candidate `f27a3f644` passes all five
independent host checks and now exercises actual authority refusal and
same-instance recovery. Review round 3 remains necessary: publication error
conversion still allocates, conversion tests duplicate rather than call
production logic, admission caps lack a data-structure derivation, and raw
red/green files with source/fixture identity are not preserved. The same
worker received its third and final review round; no fourth round is
authorized. Evidence is in metadata-refusal-director/review-3/. Candidate
integration and guest acceptance remain withheld. Previous turn was a
verified wait on the same live worker; this turn completed independent
verification and dispatched bounded corrections.

2026-09-26: integrated metadata-refusal through director correction
`1f6b71619` as `0687248fb`. The final worker `68bb6dc79` passes host checks
but its claimed derived budgets were absent; director correction installs
actual structure-derived bounds and authentic production-mutation controls.
Exact growth fails at scale 32 (112 > 99 allocations); new rollback storage
fails at scale 1 (one > zero). Restored source passes all four scales with
zero rollback allocations/bytes; all five prescribed commands pass. The
unused test-only public converter is removed. No fourth worker round occurred.
Full integration CI and signed promotion remain open. First-touch remains red.

The next bounded allocator/grant outcome is documented in
2026-09-26-el1-elastic-metadata.md, committed as `b5df14f93`; it requires
actual guest allocation, dynamic growth and return rather than host-only
proof. All later checkpoints and original performance objectives remain open.

Post-merge inventory reconciliation updated four existing abort fingerprints
without changing verdicts or rationale, but host-authority compiler capture
produced no candidate. Inspect the direct capture diagnostics before accepting
inventory or CI closure; this is a verification failure, not a reason to bless
an old capture. Implementation source is otherwise integrated.

2026-09-26: direct compiler-capture diagnostics identify the integration
failure as a missing MetadataAllocation arm in runtime clone TID output
classification. Added the explicit result and appended provider ordinal 6;
all five serial clone TID tests and the provider ABI test pass, including
refusal with restoration of both preimages. This is a compile correction,
not a semantic-red claim. Raw failure and validation evidence are under
metadata-refusal-director/integrated-runtime/. Fresh clean-source capture,
full CI and signed promotion remain pending.

2026-09-26: clean-source inventory capture after `3b45df0ee` succeeds.
Reconciliation moves 31 authority sites and one K1 operation position;
mechanical comparison confirms all 588 authority rows retain classifications,
identities and rationale bodies. The four earlier abort fingerprints remain
reviewed. Full integrated CI starts after committing these inventory updates;
no full CI or signed acceptance is yet claimed. Non-macOS profiles remain
pending as before.

2026-09-26: full CI on `bc5500391` stopped at generated contract inventory
validation after workspace Clippy and earlier domain checks passed. Regenerated
inventory adds only the metadata-refusal claim to mmap/munmap/mprotect; full
CI reruns after commit. Failure evidence is under metadata-refusal-director/
integrated-ci/. No full CI acceptance is claimed.

Dispatched the next distinct implementation, `el1-elastic-metadata`, through
Antigravity (cid `bce3369a-a045-4632-a3f0-736bab05eae1`) in the clean reused
el1-memory-corrections checkout at `bc5500391`. Its director-written brief is
2026-09-26-el1-elastic-metadata.md. It requires real guest allocator/grant/
return wiring and an embed fixture, not host-only allocation. Worker runs host
checks and compilation only; director retains signed execution and acceptance.
This task has zero review rounds used; metadata-refusal is terminal after
three rounds and director correction, not reopened.

2026-09-26: full integrated CI on clean `b8a3ccea7` exits zero: 6,201
passing tests, zero failures, 12 existing ignores across 101 Rust result
groups. Complete hashed evidence is under metadata-refusal-director/
integrated-ci/green/. This closes the host gate only; signed guest validation,
first-touch structural acceptance and every later checkpoint remain open.
The separate elastic metadata worker is active on its first turn; its exact
dispatch brief is preserved under el1-elastic-metadata-director/dispatch.md.

2026-09-26: the preceding user status turn was no implementation progress.
Resumed the same live elastic metadata worker, with no replacement or review
round consumed. A read-only in-progress core screen reproduces two behavioral
failures: 64-byte alignment returns remainder 32, and payload-only grant sizing
cannot fit its header. Raw source and red output are preserved under
el1-elastic-metadata-director/in-progress-screen/. Recheck against the terminal
candidate before review; no worker source was modified. Signed release build
on a6ac6935c completed and its exact CLI artifact is frozen. The integrated EL1
gate is running; no result or first-touch acceptance is claimed yet.

2026-09-26: signed integrated metadata gate on a6ac6935c finishes with only
the existing first-touch failure: 621/2150/8294 exits at 512/2048/8192 total
pages; slope 0.9954 versus <0.125. Forty-one other EL1 tests and negative
control pass, including the 30-round oversubscribed kick witness. Both scoped
cleanup counts are zero. CLI and eight executed test artifacts are frozen;
raw logs/manifest are under metadata-refusal-director/integrated-signed/.
Public probes/LTP/inotify steps did not run; no timing acceptance is claimed.

2026-09-26: elastic metadata candidate ae6c3a17b passes all eight independent
host verification commands but fails allocator review. Final-source screens
reproduce alignment and grant-overhead failures; actual guest stage-1 mapping,
owner lifetime, global allocation wiring, growth/refusal fixture and structural
bounds are incomplete. Documentation claims absent footer/counter structures.
Integration is withheld. Same worker received review round1 (turn2), with
all evidence under el1-elastic-metadata-director/review-1/. No signed allocator
acceptance is claimed and no later goal stage is removed from scope.

2026-09-26: allocator candidate dc2b83706 passes all eight independent host
checks and fixes the original alignment/grant-sizing reds. Acceptance remains
withheld: standalone fixture cross-build fails an undeclared dependency; a
real host slot-policy screen proposes overlapping extents for >512KiB grants;
bootstrap initialization, process-root mapping, token/register ABI, owner
lifetime and denial-phase ordering remain incomplete. Evidence is under
el1-elastic-metadata-director/review-2/. Same worker received review round2
(turn3); one review round remains. No signed allocator candidate was run.

### Delivery acceleration ruling (2026-09-26)

Owner asked how to expedite delivery after two allocator reviews exposed
host-green candidates with a broken standalone fixture and incomplete guest
transport/lifetime. The critical path stays allocator -> signed guest
growth/return -> actual first-touch; all later goal stages remain required.

Let the currently live elastic metadata turn3 (review round2) finish; do not
restart or replace it. Review its actual source and reproduce decisive checks.
The director will directly resolve remaining integration defects rather than
send another broad allocator repair round. This ends that broad delegation
loop earlier than its maximum three reviews, not by accepting unfinished work.
Do not edit the worker's tree until its process is confirmed terminal.

Build the modified standalone Linux fixture alongside the cheap focused
contracts. Once source review rules out known unsafe grant/lifetime paths, run
the focused signed guest growth/return witness immediately; compile-only embed
checks are insufficient. Fix the first decisive failure before broadening.
Run full CI and required exact-artifact promotion at stable integrated
checkpoints, not repeatedly on intermediate rejected implementations. Do not
weaken semantics, work budgets, concurrency, provenance or final acceptance.

No additional cleanup or architecture extraction is admitted unless a
reproduced blocker directly prevents guest allocation or first-touch service.
Report milestones in guest behavior and host-exit slope, not commit/test count.

2026-09-26: elastic metadata worker is terminal after initial implementation
plus two review rounds (three turns); the broad delegation loop is now closed
per the delivery ruling. No third review is dispatched. Its uncommitted final
changes are preserved in worker checkpoint83972685e, explicitly unaccepted.
Director takes over the same now-idle correction checkout. Fixed the actual
Linux fixture to execute exactly one requested basic/growth/denial phase in
2d3b55cc9; the prior fixture ignored the phase argument and ran all three.
The static fixture cross-build passes. Started the focused signed witness via
`CARRICK_RUN_ID=el1-allocator-director-red-20260926 RUSTC_WRAPPER= just test-embed
el1_metadata_allocator_grows_and_returns_extents --nocapture` on that source.
Log is in correction checkout target/el1-completion/allocator-director-red/.
Do not edit its product source or relink while the run is active. No signed
allocator result, integration acceptance or first-touch improvement is claimed.
Remaining review includes coherent shared host backing and carrier-owned
lifetime; use the actual focused failure to order direct corrections.

2026-09-26: the director reproduced and corrected two guest integration
failures in the correction checkout. bd604a876 restores maintenance HVC #1
routing after strict syscall classification; c33e1d152 removes the extra PC
advance after HVC #6 (LLDB and exact guest disassembly prove the skipped
status comparison). The focused signed allocator witness now passes on
c33e1d152766d5802e1b6b86f152ccb204b8ab10: basic alignment/writes, 10 MiB
allocation beyond the 9 MiB bootstrap, three grants/returns totaling 5,767,168
bytes, and one denied grant followed by recovery. Negative entitlement control
and both scoped cleanups pass. Exact identities and raw log are preserved in
[focused guest evidence](../../perf-results/2026-09-26-el1-allocator-focused-guest/README.md).

This is focused guest proof, not allocator integration or memory checkpoint
acceptance. Source remains in the correction checkout (receipt commit
188114c43). Next directly close carrier-owned coherent backing, exact VM/owner
lifetime and failed-unmap retention, then concurrency/IRQ and bounded-work
witnesses. These are required by the accepted allocator brief, not new scope.
Use the resulting allocator for shared MMU publication and EL1 first-touch;
the existing <0.125 host-exits/page target remains red. No end-to-end speedup
is claimed and all later checkpoints remain required.

2026-09-26: correction checkout advanced through coherent metadata backing
(fa557cc7d), exact carrier ownership/generation (1c22dcdb3), and shared stage-2
record publication/retirement (b61195767). Five focused metadata and 48 existing
custody tests pass. The exact signed sequential allocator witness passes on
b61195767, including denial recovery and complete return of 5,767,168 bytes.

8fc9c913a adds a concurrent signed witness: four allocator users, sixteen rounds
of growth/free, and 1,024 successful host-forwarded uname calls. Both allocator
tests pass with matching grant/return counts and bytes, no concurrent grant
denial, the unchanged watchdog, negative entitlement control and zero scoped
processes. See [concurrent evidence](../../perf-results/2026-09-26-el1-allocator-concurrent/README.md).
This is concurrent completion/progress proof, not an interrupt-latency measurement.

5b2da6bef gates private allocator controls behind an explicit embedded-image
test feature enabled by embed dev dependencies. Default and enabled shared
dispatcher tests (57 each), both image builds, embed compile-check and Clippy
pass. Signed verification is running in the correction checkout at
target/el1-completion/allocator-gated-signed/signed.log. No allocator product
changes have been integrated into this controller checkout.

Remaining required allocator work: IRQ/host-wait protocol and complete
deterministic work/retention witnesses. Source confirms EL1 intentionally
never unmasks IRQs; restoring saved DAIF before synchronous HVC #6 therefore
does not prove the brief's no-host-wait-while-masked requirement. Current-EL
IRQ slots fail loud, so simply unmasking interrupts is not a valid correction.
Resolve this protocol before claiming allocator acceptance. Then continue
shared MMU publication/frame grants and real first-touch handling. The first-touch
exit-slope gate and full per-workload 2x acceptance remain open, as do all later
checkpoints.

### Accepted EL1 metadata allocator boundary (2026-09-26)

The correction line closes the remaining allocator obligations through
`7e08a6108`. Metadata capacity misses now publish one carrier-wide
single-flight request and unwind through the ordinary pending-host-work
boundary before the host maps or unmaps storage. A participant observing
unfinished mailbox work forces its own boundary, refusal stays with the
capacity miss that owns it, fully unused dynamic extents return exactly once,
and no synchronous metadata HVC runs on the masked allocator stack.

Exact signed source `ef5764582` passes sequential 10 MiB growth beyond the
9 MiB bootstrap, complete return, refusal with preserved live data and retry,
four-user concurrent progress with 1,024 unrelated host services, and the IRQ
boundary witness together. Real grant and return accounting matches with
`inline_hvc_traps == 0`; the entitlement negative control and both scoped
cleanup checks pass. Checked-arithmetic controls reject oversized guest and
host requests without mutation or panic, metadata tokens cannot wrap or issue
zero, and registered VM-free budgets prove constant allocation/deallocation
work at scales 1, 8, 32, and 128. Exact identities and raw evidence are under
`docs/perf-results/2026-09-26-el1-allocator-host-boundary/`.

This closes the allocator prerequisite, not checkpoint 2. It does not improve
the signed first-touch slope, which remains about 0.9954 host exits per page
against the `<0.125` target. The next bounded implementation is shared MMU
publication and frame grants: define the live-table publication/rollback
contract, prove stage-2 and inventory readiness precede a valid stage-1 leaf,
then connect recoverable EL0 data-abort entry to that authority. Re-run the
existing three-scale first-touch witness after actual guest service. Further
allocator work is out of scope unless this next contract exposes a direct
allocator regression.

### Shared stage-1 publication groundwork (2026-09-26)

`5c1319222` establishes the first production boundary of
`kernel.el1.stage1-publication`. Each published address space now has one exact
guest editor token. Guest admission rechecks the MM gate after claiming the
token, while host mutation and retirement raise or close that gate and drain
the admitted editor before proceeding. The production `PtQuiesce` mirror and
address-space retirement path use this protocol. A live `PageTableManager`
also discovers occupied hardware-visible spare pages instead of resetting its
allocation cursor over them.

Red-first evidence captures the missing editor/drain API and the live cursor
collision. All 45 scheduler-core tests, all 94 MMU-core tests, the focused
production pause witness, warning-denied targeted Clippy, formatting and the
contract registry pass. Exact evidence is under
`docs/perf-results/2026-09-26-el1-stage1-guest-editor/`.

This is VM-free mutation-exclusion and live-image-adoption groundwork. It does
not grant frames, publish a guest leaf, execute a recoverable EL0 data abort in
EL1, or improve the signed first-touch result. The signed structural slope
therefore remains about 0.9954 host exits per page against `<0.125`.

Next implement the authenticated bulk frame-grant state machine red-first.
Bind each request and ready grant to the exact MM key and request generation,
semantic VA/span, physical IPA/span, mapping/frame identity and owner
generation. The host may publish `Ready` only after stage-2 ownership and
inventory are committed and authenticated; refusal must roll those resources
back. EL1 must reject stale or mismatched grants before leaf publication. Then
connect the existing host fault boundary to grant preparation and the guest
data-abort retry to grant consumption. Re-run the three-scale signed
first-touch witness immediately after actual guest leaf service; do not open
another allocator or extraction campaign unless that decisive path exposes a
specific prerequisite failure.

### Authenticated frame-grant host authority (2026-09-27)

`cc3647b4a` defines a carrier-wide single-flight frame-grant mailbox. A guest
request carries one exact MM key, request generation, fault VA, bounded length
and fault access class. The host response separately carries authoritative VMA
permissions plus semantic and physical spans, frame and mapping identities,
owner generation and inventory revision. Wrong-MM, stale-generation and
unauthenticated responses cannot be consumed.

`3b1a110d4` adds the kernel-side publication authority. It applies an exact
inventory transaction, authenticates its returned revision against the live
MM/mapping/frame/GPA/span and an independently retained current owner, and can
roll back an unpublished grant through the opaque receipt. The dispatcher now
plans one same-protection span clipped to the VMA and one 2 MiB window, then
commits residency for that complete span under existing MM/alias exclusion.
ABI, kernel fault, runtime inventory, Clippy, contract registry and generated
inventory checks pass. The exact product diff also passes the contract-change
gate with a revision-bound exemption for unchanged contracts sharing the ABI,
HAL and runtime files. Evidence is under
`docs/perf-results/2026-09-26-el1-frame-grant-mailbox/` and
`docs/perf-results/2026-09-26-el1-frame-grant-inventory/`.

This is VM-free host authority. It does not yet prepare real HVF stage-2
backing, publish mailbox Ready, install a guest stage-1 leaf or change the
signed first-touch slope, which remains about 0.9954 host exits per page versus
the `<0.125` target. The next bounded task is the direct production join:
claim the request at the existing forwarded-fault boundary, reuse sparse
stage-2 preparation, apply and authenticate the inventory receipt, retain the
alias/backing, and publish Ready last. Then implement guest leaf publication
and rerun the signed three-scale witness before broadening checkpoint 2.

### Authenticated frame-grant host service (2026-09-27)

`a90315d59` completes the host half of the direct production join. The existing
forwarded-fault boundary now claims only the current MM's exact request, clips
it through the same-protection 2 MiB planner, and calls a neutral VMM service.
HVF quiesces and reauthenticates that MM, creates real zeroed stage-2 backing,
stages the backend inventory row, applies and authenticates the kernel receipt
and owner generation, retains the alias, and returns the leaf IPA. The runtime
publishes mailbox `Ready` last and commits the whole semantic resident span.
Backend refusal stays in the mailbox until guest consumption before the
ordinary host fallback can resume.

Red-first request-claim, backend-validation and Linux permission controls are
green. Focused ABI/runtime/HVF/AArch64 tests, targeted warning-denied Clippy,
formatting, the 62-contract registry, syscall inventory and exact product-diff
gate pass. A serial HVF library run passes 571 tests with three existing ignores
and one unchanged GIC source-shape assertion filtered out. That assertion also
fails on the checkpoint base because it expects the old `run_to_exit_inner`
signature; the two inventory failures from an invalid concurrent run disappear
under serial isolation. Exact evidence is under
`docs/perf-results/2026-09-27-el1-frame-grant-host-service/`.

This does not improve the signed first-touch slope: the guest still never
publishes or consumes the request, so the new host service is dormant. The next
bounded task is the impact-bearing guest transaction. On a recoverable EL0 data
abort, publish one exact request and forward; on retry, claim the exact response,
handle refusal without reissuing it, acquire and reauthenticate the live MM
editor, install the existing invalid leaf span with the returned IPA and current
permissions, perform required TLB maintenance, and acknowledge success. Preserve
rollback for every path that does not publish a leaf. Re-run the signed
three-scale witness immediately after that path is live; do not return to
allocator work unless this transaction exposes a specific allocator regression.

### Signed guest-leaf diagnosis (2026-09-27)

`dae6f092c` connects the exact EL1 request/response/editor transaction, and
`afdf58039` repairs its release-only host-service build without widening the
permit's authority. The exact signed release CLI build passes and its SHA-256,
CDHash, LC_UUID, entitlement and DOF identity are retained under
`docs/perf-results/2026-09-27-el1-guest-leaf-publication/`.

The first signed first-touch execution reaches the guest publication invariant
and aborts before the first scale can complete. A durable panic bridge preserves
source coordinates and a stable publication error across HVC; the diagnostic
rerun reports detail 3, `MissingTable`. This proves the request, authenticated
host backing, Ready response and exact guest-editor admission are live, while
falsifying the plan's assumption that the anonymous range already contains an
invalid L3 leaf span. The dirty diagnostic artifact is discovery evidence only,
not signed acceptance, and the impact measurement remains the earlier roughly
0.9954 host exits per page against the `<0.125` gate.

Keep the correction bounded: add a red-first live-manager contract for a range
with a missing L3 table, transactionally allocate and publish the missing
hierarchy under the admitted editor, preserve RW/UXN/nG permissions, synchronize
child-before-parent, and roll back or refuse cleanly on exhaustion. Run the
256-page signed witness immediately. Broaden to the other two scales only after
that passes; do not reopen general allocator design unless the focused witness
proves the existing elastic table source cannot satisfy this transaction.

The bounded correction is now implemented in the isolated line. A red-first
MMU contract required a live range with no L3 table to publish three private
pages as RW/UXN/nG while adjacent pages remained invalid. The shared live
`PageTableManager` now preflights the complete range, journals the edit, allocates
the missing hierarchy from the currently backed pool, publishes terminal
descriptors before table pointers and descendant pointers before ancestors,
then commits. A second control exhausts the table pool and proves the call
returns `OutOfTables` with byte-identical hardware backing. Production EL1
adopts the exact TTBR0 primary arena through its fixed alias and uses this
transaction before the existing ASID invalidation.

The full 97-test MMU and 174-test memory suites, focused EL1 stable-error test,
bare-metal EL1 release build, targeted warning-denied Clippy and contract
registry pass. This is still an unsigned candidate. Preserve one committed
source, build and sign it, and run the 256-page witness next; a green VM-free
manager test does not replace that acceptance boundary.

The committed missing-hierarchy candidate was then built, signed and run. It
crossed the `MissingTable` boundary and faulted one dependency later while EL1
wrote the first new table descriptor through the fixed primary-table alias at
alias plus `0xc008`. The root slot/extent and alias already cover that page;
the initial allocator-backed root carried read-only stage-2 permissions from
the semantic table region. A red-first production-shaped contract now requires
the physical table backing to admit EL1 writes while keeping the EL0/syscall
view non-writable. That narrow correction and warning-denied HVF Clippy pass.
Freeze it as one commit, rebuild and re-sign, then rerun the 256-page witness;
do not broaden into arena work unless the signed result reaches primary-pool
exhaustion or names an extension-arena dependency.

### Guest-published hierarchy in fork snapshots (2026-09-27)

The exact signed `4a939f00f` witness crossed both missing-hierarchy allocation
and the primary-table stage-2 write boundary. It reached fork child preparation,
where the child snapshot resolved `0x6000001000` to the inherited identity IPA
instead of the newly granted global frame. The host manager had been created
before EL1 allocated the new table page, so its cached populated prefix ended
before the now-live hierarchy and the fork image truncated it.

`9d521e6be` is the bounded correction. A red-first dual-editor MMU test publishes
the same missing hierarchy through a guest live manager and snapshots it through
the older host live manager. Snapshot discovery now follows only reachable
table descriptors across the four architectural levels, using live physical
capacity to discover a child beyond the cached cursor, and extends the copy
through that highest primary page. It performs no full-arena scan and allocates
no traversal metadata, preserving the recycled image-allocation budget. All 98
MMU tests, the warmed recycling witness, warning-denied Clippy and formatting
pass.

Build and sign one exact artifact containing this commit, then rerun the
256-page witness. A green result promotes the same frozen artifact to 1,024 and
4,096 pages for the `<0.125` exits-per-added-page decision. Do not open a new
allocator or fork campaign unless that signed witness names a new direct
boundary; checkpoint 2 and measured impact remain open.
