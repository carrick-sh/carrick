# EL1 migration step 2: memory ownership completion

Design pass, 2026-10-02. Source inspected: `4c4d06b4c345550da68b4b8cd44dfd8f6e53457b`.
This is a plan, not implementation or acceptance. Assume `work/s3-t3b`
lands with anonymous reservations, capacity service and prepared-page
retirement. Re-inventory its merged tree before implementation; do not
restore a path that branch deleted.

Authorities: [accepted EL1 design](../specs/2026-09-24-el1-kernel.md),
[rulebook](../../../AGENTS.md), [contracts](../../conformance-contracts.md),
[current controller](2026-09-26-el1-completion.md),
[lifecycle plan](2026-09-30-el1-thread-lifecycle.md), and
[fork investigation](../../perf-results/2026-10-01-el1-forkexit-investigation.md).
The whole design, including historical as-built sections, applies. In
particular occupancy and address-space switching are already shared
EL1 authorities; this plan must not recreate an executor census.

## Outcome and ownership

At completion, an admitted MM has no host stage-1 editor, host page-table
shadow as a competing authority, or host page-table pause. Admission is
irreversible for that MM incarnation. Resource pressure requests capacity
or returns a Linux error through the personality; it never transfers the
MM back to a host editor. Unadmitted boot roots and other backends may use
the shared MMU implementation through their venue adapters. They cannot
obtain an edit capability for an admitted root.

| Object | Sole owner after this step | Host responsibility |
| --- | --- | --- |
| Live root, table pages, leaf permissions, software access/dirty/COW tags, ASID TLBI | EL1 MMU substrate | supply table-frame capacity; no descriptor stores |
| Private frame sharing, COW references, sole-owner reuse, fork table projection | EL1 | bulk stage-2 custody and authenticated extent receipts |
| Anonymous reservations, brk, mapping placement/protection/retirement | EL1 Linux personality over neutral memory core | enforce host resource quotas; no parallel VMA policy |
| Physical allocator and free-frame watermark | EL1 substrate | grant/map and reclaim/unmap complete extents |
| Host-file shared alias bytes | host mapping | retain exact backing generation; EL1 installs its stage-1 alias |
| Fork identity, wait/zombie graph, lifecycle admission | existing kernel/lifecycle authority until later migration | issue a memory request and consume its completion; no COW planning |
| Occupancy, address-space installation and retirement gates | existing shared `Occupancy`/`AddressSpaces` protocol | lifecycle closure and diagnostics, not page-table edit fencing |

Frame custody is not guest mapping authority. Stage-2 extents can contain
multiple 4 KiB guest pages within a 16 KiB host granule. Returning one guest
page cannot unmap its neighbours. EL1 maintains references until all leaves,
borrowed copyout pins and table uses are retired; host unmap consumes the
exact extent generation once. Linux flags/errors stay in personality code;
MMU, extents, queues and watermarks introduce no Linux dependency.

## Grounded deletion inventory

Paths below are relative to `crates/`. Delete the admitted-MM branches and
their host semantic bookkeeping, not legitimate stage-2/file custody. Where
a shared method serves another backend, retain only its venue adapter to the
same core. A boolean lane check beside a writable host pointer is insufficient:
the admitted root must not yield the host edit capability.

| Current venue and symbols | Replacement and deletion milestone |
| --- | --- |
| `carrick-vmm-hvf/src/trap/frame_inventory.rs`: `CowInventorySplitShape::write_route`, `CowWriteRoute::ReuseSoleOwner` | M2: EL1 reference authority chooses copy/reuse; remove host choice for admitted MMs |
| `carrick-vmm-hvf/src/trap/cow_engine.rs`: `perform_frame_cow`, `resolve_frame_cow_fault`, `ensure_frame_cow_write_routed`, `reuse_sole_owner_cow_in_place` | M2: delete admitted-MM copy, host allocation per fault, AP store, shadow authentication and host TLBI paths; privileged copyout requests EL1 privatization |
| Same file: `fork_cow_ranges`, `arm_frame_cow_ranges`, `frame_cow_arm_snapshot`, `restore_frame_cow_arm_snapshot` | M2: delete host COW projection/arming/rollback state for admitted roots; EL1 fork transaction owns it |
| `carrick-vmm-hvf/src/trap/process_plan.rs`: `build_process_plan`, `invalidate_projected_fork_omissions`, `repoint_inherited_invalid_alias`, `disarm_independent_fork_mappings`; `restore_quiesced_snapshot_to_host` call | M2: delete child-table host copy/edit/publish for admitted roots; retain host task/backing preparation only |
| `carrick-runtime/src/vcpu_loop/lifecycle.rs`: `arm_parent`; `vcpu_loop/quiesce.rs` fork call to it | M2: replace host-generated fork-arm transaction sequence with one EL1 memory-fork completion; keep task sibling/register drain until lifecycle replaces it |
| `carrick-runtime/src/vcpu_loop/signal.rs`: `resolve_mutating_fault`; callers in `vcpu_loop/binding.rs` | M2/M3: remove admitted-root fault repair and fallback; retain capacity request settlement, authenticating exact MM/extent/generation |
| `carrick-el1/src/memory.rs`: `MmapProtectionRoute::HostUnrepresentedBits` (bits outside `ReservationProtection`, committed `memflagmatrix` oracle) | M3: move this explicit host mmap decode into EL1; mprotect validation remains separate |
| `carrick-kernel/src/dispatch/mem/mmap.rs`: `mmap_served`, `munmap_served`, `mprotect_served`, `mremap_served` | M3: delete admitted-root host stage-1 mutation/duplicate anonymous policy; EL1 handles anonymous operations; host-dependent mapping operations request EL1 installation/retirement |
| `carrick-vmm-hvf/src/trap/cow_engine.rs`: `materialize_retired_reuse`, `materialize_sparse_mmap_extent_inner`, `publish_private_repoint`, `publish_shared_repoint`, `publish_guest_host_alias`, `restore_guest_shared_identity`, extension-arena publication/retirement | M3: remove host descriptor fallback and shadow edit; keep backing provisioning and EL1 requests with receipts |
| `carrick-vmm-hvf/src/trap/guest_alias.rs`: `publish`, `retire`, `restore_identity`, `publish_host_alias`, `roll_back_host_alias` | M3: retain authenticated request preparation; delete admitted-MM host publication/rollback alternative |
| `carrick-vmm-hvf/src/trap/foreign_mm/el1_publication.rs`: `authenticate`, `publish`, `for_target`; `trap/host_writes.rs` access admission | M3: one target-MM EL1 privatize/pin request, then host byte transfer; no borrowed host stage-1 editor |
| `carrick-vmm-hvf/src/trap/execve_rebuild.rs`: `execve_rebuild_inner`, `prepare_global_exec_plan_with_root_backing`, `reapply_global_exec_page_spans` | M3: host may prepare image bytes/backing, EL1 builds and installs the new root; delete host edits of admitted predecessor/successor roots |
| `carrick-kernel/src/dispatch/mm_quiesce.rs`: `with_sole_mm_stage1`, `acquire_mm_stage1_authority`, `acquire_frame_cow_quiesce`, `acquire_host_write_mutation_quiesce`, `acquire_foreign_mm_mutation_quiesce`, exact-MM lease/TLS and pause drain | M4: remove admitted-MM use and authority types once all writers above are gone |
| `carrick-thread/src/fork_quiesce.rs`: `PtQuiesce`, `bind_mirror`; `carrick-kernel/src/dispatch/mod.rs`: `pause_current_mm_for_capture` | M4: remove page-table edit fence/mirror for admitted roots; replace snapshot use with read-only EL1 snapshot completion. Do not delete independent task/register/crash lifecycle drains |

This inventory includes host *requests* that already publish through EL1.
Those are not necessarily descriptor writers, but their host COW/VMA policy
and fallback still need retirement. Conversely `process_plan.rs` directly
maps child aliases and restores a table snapshot: parent guest arming alone
does not finish fork ownership. Existing `DescriptorOp::Terminal`,
`MapAlias` and `CowRepoint` are available vocabulary; this plan does not
claim that a complete memory-fork or bulk-extent request API exists today.

Before M3 acceptance, mechanically enumerate every reachable
`PageTableManager` edit, `sync_to_host`,
`restore_quiesced_snapshot_to_host`, descriptor pointer store and
stage-1 exclusive acquisition under HVF. Include backend/engine adapters,
file BUS tags, growdown, brk, madvise/discard, mremap, kernel-hole/metadata
mapping, rollback and teardown. Classify each as boot-only, other-backend,
EL1 request or deleted, with an exclusion proof. Any unclassified writer
blocks M4; a search for these spellings alone is not a completeness proof.

## Milestones

Each milestone is landable only with its local ownership deletion, red-first
proof, and the acceptance packet below. Keep stable contract IDs already
registered; new scenarios below are proposed contracts, not existing APIs.
Capture behavioral reds on the preceding artifact, not merely a compilation
failure for a missing API.

### M1 — Elastic extent capacity, without changing stage-1 ownership (Sol)

Extend the S3 capacity service into the one bulk frame service used by
first-touch, COW and table allocation. Current starting points are
`trap/guest_cow.rs::{provision_guest_cow_grants,refill_guest_cow_pool,
allocate_grant_compound,settle_guest_cow_completions}` and
`trap/cow_engine.rs::{prepare_el1_frame_grant,complete_el1_frame_grant,
roll_back_el1_frame_grant}`. Reuse their custody/receipt guarantees; replace
per-compound provisioning with extent provisioning. Do not add a second pool
beside them. Delete superseded per-grant allocation/refill policy once both
consumers use the extent service; keep host map/unmap transactions.

EL1 owns low/high free-capacity thresholds. A low crossing queues one bounded
capacity request, not one request per fault. Excess wholly free extents above
the high threshold are returned promptly at a scheduler/service boundary,
without requiring another user syscall. Partial extents stay resident. Specify
thresholds, extent size, maximum outstanding requests and retained-free bound
in contracts before coding; derive these from granule and quota constraints,
not from a chosen fixture ceiling. Requests release execution capacity.

Red-first: two live MMs/carriers with equal addresses and distinct generations;
reject cross-owner grants/returns and duplicate completion; partial unmap
failure retains backing; return cannot race a COW reader, copyout pin or table
page; zero provenance survives reuse correctly; 16/64/256-page burst/idle
cycles bound host maps by extents and retained free capacity by the watermark.
Pool exhaustion must preserve forward progress or exact ENOMEM without host
stage-1 fallback, spinning or polling. Run VM-free allocator/custody tests,
then signed concurrent touch/COW/return and same-source Docker semantics.

Hatch: reuse the capacity/admission bisection boundary from S3, exact `=0`
only before root admission. It cannot demote a live root. Delete the hatch
and old provisioning implementation in this milestone's proven landing.
Acceptance: packet A in full, including all three per-op impact workloads.

### M2 — EL1 owns fork table copy, write protection and all private COW (Sol)

Use `carrick-el1/src/cow.rs::resolve_guest_cow` and its `GuestCowVenue` as
the existing guest resolver, not a new fault engine. EL1 takes the exact
parent MM memory transaction, allocates child table pages from M1, copies
and filters live terminals (including DONTFORK and retained/invalid leaves),
creates shared frame references, write-protects parent and child, completes
broadcast ASID invalidation, and publishes the child root only at commit.
Rollback restores references, permissions and table capacity before the child
becomes runnable. Task identity stays on the lifecycle authority; the memory
completion is its commit prerequisite. A concurrent EL1 editor or writer must
serialize through the same MM transaction, never the host pause.

Delete the M2 rows of the inventory in this landing. Move sole-owner reuse
into the guest reference authority, including delayed sibling retirement:
no host registry count may authorize an AP upgrade. Foreign/privileged host
copyout requests guest privatization and pins the completed physical result;
its bytes may still be copied by the host. No `perform_frame_cow` escape for
admitted children or non-anonymous private pages.

Red-first: existing `kernel.el1.fork-cow`, `kernel.fork.stage1-image`, and
`kernel.mm.address-space-occupancy`; two live processes with multiple writers,
simultaneous faults to the same compound, child exit vs parent reuse, nested
fork, fork during mapping edits, read-only mprotect, file-private COW and
DONTFORK. Fail allocation at every transaction boundary and prove parent
unchanged/child unpublished/no leaked references. Signed guest fault entry
and zero carrier-wide host COW transactions are mandatory; fault-exit class
zero is not that metric. Preserve 16/64/256 scale points and all ceilings.

The 2026-10-02 investigation records 3442 exits at 20x16 against 144;
isolation passed. Keep `el1_fork_cow_resolves_in_guest` and its <0.125
per-added-page slope unchanged. Ownership can land as a bounded submilestone
only if the controller explicitly records the total-exit failure and its
external lifecycle/IPC blocker; it cannot call packet A green or step 2 done.
Full M2 acceptance waits for those dependencies, rather than rewriting the
fixture or relaxing the 64 syscall-exit or 144 total-exit budgets.

Hatch: exact `=0` selects the preceding nonadmitted configuration at carrier
creation for bisection only. Never enable both COW owners in one admitted MM.
Remove the hatch and admitted host COW implementation after proof.
Acceptance: packet A, with the fork-COW signed command retained separately.

### M3 — Close all host stage-1 venues for admitted roots (Sol; Flash cleanup)

Convert/delete every M3 inventory row. Anonymous personality operations stay
entirely in EL1. Host-file alias, image loading, external I/O copyout and
metadata backing are host services that request an EL1 stage-1 operation and
consume its authenticated completion. This reverses no ownership: a host
request is input to the guest owner, not permission for the host to edit.
Do not invent a second mmap/mremap semantic implementation in the request
adapter. Reuse the neutral MMU transition logic and existing descriptor
transactions, including rollback and exact terminal attributes.

Red-first: a mechanically enforced inability to acquire a host edit capability
for either of two admitted roots; wrong MM/root/ASID generation refusal;
concurrent MAP_FIXED over COW, mprotect/munmap vs first touch, prepared-page
retirement, foreign copyout vs target fork/exec, exec rollback and file truncate
BUS behavior. Register additional missing bindings in conformance-next.
At least three scales must bound work by affected range/table height, not all
unrelated mappings. Preserve `kernel.mm.delegated-residency` and
`kernel.mm.delegated-root-reader-cost` expectations. Signed tests must exercise
the production route, not force an otherwise refused fixture admission.

Delete host shadow writes, direct descriptor publication and fallback branches
for admitted roots in the same commit that activates each request route. A
boot builder may initialize a new unpublished root only before a typed handoff;
it cannot regain ownership after publication. M3 completes only when the
expanded writer census has no admitted host writer, including failure paths.

Hatch: no per-operation fallback hatch. An exact-zero pre-admission bisection
switch can exist during proof, then is removed with the replaced code.
Acceptance: packet A for each landed venue group, then again on the combined
M3 artifact. Sol owns semantic conversion; Gemini Flash can remove unreachable
adapters and update census/contracts after Sol supplies exact capability and
request signatures, with compilation and signed proof reviewed by the director.

### M4 — Retire the host page-table pause (Sol; Flash mechanical deletions)

Prerequisite: M3 writer census zero. Remove the admitted-MM exact-stage1 TLS,
sole/editor pause acquisition, kick-and-drain loops, fairness workaround for
host edit election and `PtQuiesce` mirror binding. Retain occupancy and closed
address-space retirement gates: they are required for TTBR/ASID lifetime, not
host editing. Preserve fork task/register quiescence, lifecycle ForkClosing,
crash thread capture and other-backend adapters until their own replacements
are proven. Do not rename a host page-table pause as a snapshot pause.

`pause_current_mm_for_capture` must become an EL1 read-only coherent snapshot
request before its admitted-MM dependency on `PtQuiesce` disappears. The known
omission of parked EL1 thread registers needs explicit lifecycle/capture
coordination; removing the pause is not a fix for it. If coherent snapshot
cannot be implemented within this slice, M4 is blocked, not exempted.

Red-first: two live MMs continuously editing/touching/forking while EL1
switches their threads across shared vCPUs; unrelated MM never fenced by an
edit; no stale translation after BBM or ASID reuse; crash snapshot vs exec
retirement; IRQ/timer arrival during edits cannot acquire the MM lock.
Negative control omits broadcast TLBI and must detect stale bytes. Existing
occupancy embed test passed with drain removed in the design record, so use
discriminating VM-free and signed witnesses, not that test alone. Counters
require zero host page-table pause elections/drains on admitted workloads.

Hatch: none after M3. Reverting this milestone must revert the complete
ownership boundary, never resurrect a host editor for the admitted root.
Acceptance: packet A; Flash may delete enumerated dead pause plumbing after
Sol reviews all remaining capture/retirement consumers. Sol owns synchronization
proof, snapshot protocol, signed debugging and final acceptance.

## Packet A — required for every milestone

These are future implementation acceptance commands, not commands executed by
this documentation pass. Run from the repository root. Use unique
`CARRICK_RUN_ID` values; no Carrick/Docker overlap, no rebuild over live guests.

```sh
RUSTC_WRAPPER= just test-kernel
RUSTC_WRAPPER= cargo test -p carrick-mmu-core -p carrick-el1 --lib
RUSTC_WRAPPER= just ci
CARRICK_RUN_ID=step2-MN-el1 ./scripts/test-signed.sh carrick-embed el1_ --nocapture
CARRICK_RUN_ID=step2-MN-cow ./scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --nocapture
just el1-gate
just --no-deps conformance smoke
just --no-deps conformance full
```

MN is a unique milestone/run label, not a shared identifier. `el1-gate`
builds the CLI and signs the embed executables separately; record every
artifact's own identity. It is not proof that CLI and embed are one binary.
Capture HEAD, SHA-256, CDHash, LC_UUID, entitlement, DOF, source/probe/image
hashes, exact row denominator, negative control and run-scoped cleanup.
Preserve the CLI artifact from its probe through smoke/full rungs, checking
SHA/CDHash without re-signing. A known red in the signed `el1_` batch remains
red with a named dependency; no partial batch is a green acceptance packet.

Paired ecosystem runs use previous-main and candidate signed CLI binaries,
retained outside build output before rebuilding, on the same quiet host.
Use the declared `go-build`, `cpython-threading`, `cpython-subprocess`
commands/images in `scripts/conformance/suites.toml`, same fs/CPU settings,
fixed ABBA schedule (three rounds, six runs per arm), recording wall and
carrier user+sys separately. The harness differential command is:

```sh
cargo run --locked -p carrick-conformance -- --tier full --suite go-build --suite cpython-threading --suite cpython-subprocess --refresh-oracle --jsonl target/step2-MN-ecosystem.jsonl
```

The harness command supplies serialized Linux semantics, not the paired
artifact A/B schedule. Run each declared command with each retained binary
for the pairing, preserving exact argv in receipts. Pin the native-arm64
Docker image digests; cache alone cannot establish current timing authority.

Run the existing xtask impact protocol against those same retained binaries:

```sh
just xtask impact carrick --artifact /absolute/path/base-carrick --workload spawn-loop --workload thread-spawn --workload fork-exec --samples 10 --out target/step2-MN-impact-base.json
just xtask impact carrick --artifact /absolute/path/candidate-carrick --workload spawn-loop --workload thread-spawn --workload fork-exec --samples 10 --out target/step2-MN-impact-candidate.json
just xtask impact docker --workload spawn-loop --workload thread-spawn --workload fork-exec --samples 10 --out target/step2-MN-impact-docker.json
just xtask impact report --base target/step2-MN-impact-base.json --candidate target/step2-MN-impact-candidate.json --docker target/step2-MN-impact-docker.json --out target/step2-MN-impact.md
```

`crates/carrick-xtask/src/impact.rs` and
`scripts/perf/manifests/impact-creations.toml` define these flags/workloads.
Use production operation counts, not `--operations` smoke overrides. Preserve
one excluded warm-up and all fixed samples; inspect guest-window per-op
seconds/ratios, completeness and cleanup. Docker client CPU is not container
CPU. xtask labels performance report-only: it does not enforce the design's
≤2x native-arm64 objective. The director evaluates that objective separately;
≥10x returns to correctness triage, timeout is not a ratio, noisy overlap
permits only a qualified observation. Report any temporary migration regression
explicitly; do not compensate with retries, larger timeouts or less concurrency.

## Dependencies, risks and handoff

1. S3-T3b must land and its default production admission, child inheritance,
   reservation capacity/rollback and prepared-page receipts must be verified.
   M1 extends that service; it does not duplicate its implementation.
2. Lifecycle Phase A is partial in the investigation. Phase B birth/exit
   settlement, admission closing and teardown must land before total-exit
   closure. ForkClosing remains necessary while memory-fork becomes EL1-owned.
   Ptrace TRACECLONE remains separately red; it must be implemented or explicitly
   left as a blocker to full-suite acceptance, never silently excluded.
3. Pipes/fd close/poll and fork/wait placement remain forwarded work identified
   by the lifecycle plan. If they keep 144 red after M2, coordinate increment 3
   or fork lifecycle work; do not pretend memory ownership removes their exits.
4. M1 precedes M2; M2 precedes final M3 closure; M3 precedes M4. Writer conversions
   can be prepared earlier but cannot enable a second owner. Rebase onto each
   accepted landing and rerun the census on the merged clean tree.
5. x86 ring-0 remains deferred. Shared cores and other-backend compilation must
   stay viable; their thin venue adapters do not authorize admitted HVF roots.

Main risks are stale generations across carrier/kernel boundaries, compound
page alias/refcount errors, incomplete fork rollback, lock/IRQ inversion,
reclaim before TLBI/pin completion, frame over-retention and unclassified
file/exec/diagnostic writers. Stage-2 map growth is a separate measured
resource problem: the investigation's 128 metadata-slot exhaustion and later
slab correction concern retained lifecycle backing, not proof of bulk COW
capacity. Avoid conflating their pools. Watermark hysteresis must bound both
map churn and retained RAM without turning elasticity into a fixed RAM pool.

Gemini Flash is suitable for exact symbol deletions, documentation/inventory
rebinding and pre-specified test extensions after capability signatures and
red cases are fixed. None of M1-M4 as a whole is a Flash implementation brief.
Sol owns authority design, fork/COW algorithms, host-request protocol,
rollback, synchronization and live attribution. The director reads diffs,
re-verifies the worktree, and owns signed acceptance; worker reports alone
cannot land a milestone. Implementation must update the design's as-built
sections with deletions, receipts and remaining failures. This task commits
only this plan and authorizes no implementation, merge or push.
