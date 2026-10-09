# Conformance contracts

Carrick treats Linux semantics and non-pathological operational complexity as
one correctness obligation. A syscall that returns the expected value by
polling, copying unbounded data, serializing unrelated work, or using a worse
complexity class is not conformant.

This guide is normative for every change that can affect guest-visible behavior
or cost. Use the
[`carrick-conformance-contract`](../.agents/skills/carrick-conformance-contract/SKILL.md)
skill before planning or implementation.

## Definition of correctness

A guest-visible operation is correct only when all applicable claims hold:

- return values, errors, ordering, blocking, wakeups, and lifecycle match Linux;
- host work follows the intended bounded complexity and resource amplification;
- signed execution preserves those properties through guest memory, scheduling,
  signals, carrier lifecycle, and the active VMM; and
- end-to-end performance stays inside the accepted same-workload Docker ratio.

A semantic pass cannot excuse a structural or timing failure. A valid completing
case at or above 10x Docker returns immediately to correctness triage. A case
that finishes exactly on its timeout budget is a hang or refusal, not a timing
sample.

## Evidence ladder

Use the cheapest layer that can prove the claim, then add higher-layer evidence:

1. Compile-time ABI checks prove byte layouts and static invariants.
2. `just test-kernel` proves VM-free kernel semantics and deterministic work.
3. Signed `carrick-embed` proves real guest execution and runtime integration.
4. Pinned same-image Docker supplies Linux output and timing authority.
5. CLI, probe, and ecosystem gates prove composition and release acceptance.

Higher layers add evidence; they never turn a lower-layer failure green. The
VM-free backend cannot prove guest instruction execution, page-table projection,
guest signal handlers, or VMM behavior, so contracts name unsupported layers
explicitly rather than implying coverage.

Routine reduction uses committed, source-hash-validated Docker results. Refresh
the oracle deliberately, with every Carrick phase stopped before Docker starts.
Never run Carrick and Docker concurrently.

## Contract descriptor

Every contract has a stable ID and records:

- the guest surfaces it owns;
- Linux semantic authority;
- exact fixture and scale points;
- VM-free, signed embed, Docker, and optional ecosystem bindings;
- structural budgets and their architectural rationales; and
- the applicable runtime ratio and statistic.

Scenario implementations remain typed Rust. The descriptor links different
proofs; it does not pretend that a scripted dispatcher trace and a guest ELF are
the same execution.

Each completed runner emits an observation containing the contract ID, layer,
source revision, fixture identity, semantic assertions, structural snapshot or
timing distribution, and measurement completeness. Missing identities, unknown
counters, overflow, dropped events, or absent required bindings fail closed.

## Work budgets

The VM-free loop uses deterministic units rather than elapsed time. The initial
taxonomy covers dispatch and redispatch, continuation enrollment/park/wake/resume,
guest-memory bytes, backend calls, VFS visits, page-table work, backing
allocation, task/vCPU transitions, and subsystem-specific stable units.

Budgets have three forms:

- Exact: `guest_memory_copy_bytes == 0`.
- Upper bound: `host_backend_calls <= 2`.
- Affine scaling: `queue_visits(n) <= base + per_unit * n`.

A structural budget may set `layers = ["vm-free"]` or
`layers = ["embed-structural"]` when the evidence fixtures have different
fixed scaffolding costs. Omitting `layers` enforces the budget in both
structural layers. Layer-specific budgets must describe the same guest
operation and may account only for measured fixture overhead; they must not be
used to hide different per-operation slopes.

Use at least three deterministic scale points for a scaling claim. Prefer a
formula justified by the intended algorithm over a fixed ceiling that allows a
small fixture to hide quadratic behavior.

Counters are scoped to one kernel graph, container, or execution generation.
Never infer them from process-global deltas. Instrumented structural runs do not
supply timing evidence. Timing runs use an uninstrumented release build and do
not claim structural completeness.

## Failure classes

Contract evaluation reports one of these typed failures:

- `SemanticMismatch`: Linux-visible output or ordering differs.
- `WorkBudgetExceeded`: an exact or upper-bound work limit failed.
- `ScalingViolation`: the smallest failing scale exceeded its formula.
- `IncompleteMeasurement`: required evidence is missing, dropped, or unknown.
- `FixtureMismatch`: source, image, probe, lane, or oracle identity differs.
- `RuntimeRatioExceeded`: the selected distribution statistic exceeds policy.
- `UnsupportedLayer`: a required layer has no approved binding.

An absent binary, missing oracle, unknown counter, or unsupported unregistered
layer is not a skip.

## Red-first workflow

1. Read `AGENTS.md`, this guide, the active controller, and the applicable
   contract.
2. State the Linux semantic authority and Carrick structural invariant.
3. Add or extend the cheapest capable binding.
4. Run it against the known-bad implementation and retain the semantic or
   structural failure.
5. Fix the underlying ownership, algorithm, or lifecycle seam.
6. Rerun the focused contract and `just test-kernel`.
7. Run the signed embed binding and applicable Docker differential.
8. Promote the same final signed artifact through probe, smoke, and full gates.
9. Record exact receipts, cleanup, and every higher-layer gate still open.

A generated schedule records its seed and shrinks to a deterministic regression.
A timing-only regression first needs a semantic or structural reduction; a wider
timeout is not a reduction.

## Changing a budget

Budget changes are architecture reviews, not baseline refreshes. Increasing or
removing a limit requires a rationale explaining why the intended algorithm
changed, red evidence proving the old contract is no longer the right one, and
fresh evidence for every applicable layer. A measurement tool may refresh
observations; it must never rewrite a limit.

Do not close a failure with retries, longer timeouts, reduced concurrency,
polling, symptom serialization, or an instrumented timing comparison.

## Exemptions

Only changes proven not to alter guest-visible behavior or cost qualify:

- byte-identical moves;
- comments and documentation;
- mechanical generated-inventory rebinding; or
- host-only code outside the guest execution path.

An exemption names exact paths, revisions, affected contract families, and the
reason no semantic or work expectation changed. Broad globs and statements that
performance is out of scope are invalid. If classification is uncertain, add or
run the contract.

## Commands

Use the repository recipes; they preserve signing, serialization, and test
partitioning:

```sh
just test-kernel
just test
just ci

just test-embed
just conformance-probes
just --no-deps conformance smoke
just --no-deps conformance
```

The final three promotion rungs use one exact signed artifact. Record source
HEAD, SHA-256, CDHash, LC_UUID, hypervisor entitlement, `__dof_carrick`, and
run-ID-scoped cleanup. A focused contract proves only its named family; it does
not close the frozen suite or ecosystem denominator.

## Filesystem cache cohort

`kernel.fs.cache-cohort` covers cached path, directory topology, root-marker,
and guest-metadata observations. Independent backing namespaces must not
invalidate each other; observers admitted to the same backing cohort, including
host-fork descendants, must observe its publications. The structural budget is
zero additional dentry host opens in kernel B after kernel A mutates its own
namespace. VM-free bindings are
`independent_kernels_keep_all_fs_generations_and_cached_names_isolated`,
`independent_backing_namespace_mutation_keeps_other_cache_generation`, and
`cohort_generation_words_survive_host_fork`.

Host self-reexec preserves the historical anonymous-mapping boundary: reopening
the durable root establishes a fresh coherence cohort. The binding
`host_backend_reexec_authority_reattaches_exact_root` pins this distinction.
Pre-admission layer-cache extraction publishes no coherence generations;
backend-owned extraction publishes to its observing cohort. Signed file probes
provide integration evidence; full oracle and promotion remain director-owned.

External binds have no dentry/stat or capacity cache: `BindVfs::lookup`,
`lookup_nofollow`, and `real_stat` read host metadata per call. The rootfs
dentry cache is bypassed by mount routing. Ordinary host rename/unlink/create
visibility already passes on `4a2307912`, pinned by
`independent_bind_cohorts_observe_shared_host_namespace`.

The resolve cache does retain intermediate-symlink rewrites and formerly
trusted only the rootfs generation. On `4a2307912`,
`independent_bind_cohorts_observe_replaced_intermediate_symlink` fails:
after replacing `link -> old` with `link -> new`, B keeps `/bind/old/file`.
A carrier-owned `BindCacheCohorts` registry admits each bind source by the
host root's `(st_dev, st_ino)` identity, pinning that inode while observers
remain. Prepared rootfs cohorts in that carrier join the same source cohort;
fork descendants retain it. Resolve entries stamp only the bind authorities
actually read, before their component reads, including nested resolutions.
Bind namespace publications invalidate those dependent entries while unrelated
rootfs generations and cache work remain independent.

The historical external-writer boundary remains explicit: host mutations that
do not publish through an admitted cohort can still leave a cached symlink
rewrite stale. There is no process registry or cross-carrier authority, and
self-reexec starts fresh admission. Failed source admission leaves ordinary
host lookup errors intact rather than manufacturing a shared authority.

## Executor empty host queue

`kernel.scheduler.runnable-progress` also covers pool admission and guest CPU affinity.
Linux authority: `sched_setaffinity(2)` restricts a runnable thread to the
allowed CPUs; `sched_getaffinity(2)` and `nproc` must describe CPUs that can
execute it. Every scheduler CPU requires at least one bound executor; spares
do not cover CPUs without a bound executor to lend them its slot. Invalid
configuration must create zero workers and publish no preemption driver or
resolver. The VM-free binding
`insufficient_bound_workers_cannot_strand_a_pinned_task` explicitly requests
two workers for four CPUs and pins a runnable task to CPU 3. Before the fix,
the task makes no progress within five seconds; exact-generation cancellation
keeps teardown bounded. Signed execution and full promotion remain
director-owned; no Docker phase is authorized on cloudmac.

Admission preserves the installed policy and rejects insufficient bound capacity
with `ExecutorPoolConfigError::InsufficientBoundWorkers` before starting the
preemption driver, installing the resolver, or publishing any worker. Silently
clamping a custom policy would change the CPU IDs and affinity topology it
promises. The count includes the backend ceiling and reserve; spare executors
cannot substitute for bound workers. Even a one-CPU policy is rejected when
reserve consumes the entire budget.

Configuration audit: `carrier_scheduler` publishes the installed policy count;
the default uses `default_guest_cpu_count`, hence `CARRICK_EXPOSED_CPUS` or the
host's logical/performance-core count, clamped to `MAX_GUEST_CPUS`.
`configured_bound_executors` defaults to that same count; its explicit env
request is validated after the backend cap. Invalid text falls back to the
policy count and zero requests one worker, as before. HVF supplies
`vcpu_budget()` from its hypervisor ceiling (already reserving its overhead),
not its physical-core count; the production pool adds no reserve.
`pool_admission_covers_overrides_ceilings_reserves_and_small_hosts` checks these
admission combinations, including a two-CPU policy with two workers, execution
on the highest CPU, and corrected startup after refusal. CPU publication and
`sched_setaffinity` validation retain their existing single policy authority.

`kernel.executor.empty-host-steal` covers an executor seeking host-runnable
work while runnable tasks are held by the in-guest scheduler. Linux blocking
and wakeup semantics remain the authority: a guest wait releases executor
capacity, and a wake must make the exact runnable generation claimable without
waiting for another guest task. The VM-free structural binding is
`zone_only_steal_has_zero_host_cpu_scan_visits` in `scheduler.rs`, at 1, 8 and
32 guest CPUs. Its budget is exactly zero host CPU queue visits per empty
steal attempt, even when a zone-held row contributes to lifecycle drain.
Host-runnable rows must remain stealable. Signed execution, same-image Docker
timing, and full promotion remain open for the integration director.

## Delegated anonymous root contracts

`kernel.mm.delegated-metadata-capacity` covers shared reservation metadata
pressure. Linux authority: `mmap(2)` ENOMEM when kernel mapping metadata cannot
be allocated. Admission first secures the existing eight-node forwarding
reserve; failure leaves the MM unadmitted and returns all imported/reserved
nodes. After admission, a bounded capacity-service failure answers ENOMEM
without changing the VMA, backing, or generation and without handing the MM
back to a host arena. A later request succeeds when retirement returns metadata
capacity. VM-free bindings: `reservation_admission_secures_one_forwarding_request`,
`reservation_failed_admission_returns_import_and_reserve_nodes`,
`delegated_initial_reserve_refusal_leaves_the_mm_unadmitted`, and
`delegated_carrier_exhaustion_returns_enomem_without_handback_and_recovers`.
Each metadata node has one owner: a return must atomically claim its live
custody before publishing a free link, and two roots may never acquire the
same node. `repeated_node_return_must_not_allocate_one_id_to_two_roots` is the
VM-free two-root witness; `simultaneous_returns_claim_exactly_one_node`
checks the competing-return boundary. This is an exact ownership budget of
one successful return per checkout, independent of metadata capacity.
`delegated_host_brk_uses_secured_metadata_when_the_shared_pool_is_empty`
checks that host-forwarded heap moves use the same secured reserve rather
than incorrectly returning the old break while metadata remains available.
`delegated_host_mremap_uses_secured_metadata_when_the_shared_pool_is_empty`
checks in-place growth and byte preservation under the same condition.
`delegated_brk_capacity_refusal_returns_old_break_and_recovers` checks one
capacity request before refusing heap growth, the raw Linux unchanged-break
failure convention, allocation-free queries, and recovery without handback.
The retained-bank signed binding remains
`el1_reservation_metadata_grows_beyond_bootstrap`.

`kernel.mm.delegated-residency` covers `mincore(2)` and first-touch planning
on an MM whose EL1 anonymous root is admitted. Linux authority: `man 2 mincore`,
`man 2 munmap`: a new anonymous mapping holds none of the pages a previous
mapping at the same address had. Structural invariant: a host residency fact
names the root node incarnation it was observed under (`ResidencyOwner`), so a
guest-venue retire kills it without any guest-to-host notification. VM-free
bindings: `delegated_guest_venue_munmap_then_mmap_retires_host_residency` and
`delegated_residency_of_two_adjacent_mappings_survives_only_where_unretired`
(delegated MM against a host-setup twin).

Pre-exclusion fault classification probes the reservation root once. A busy
guest editor routes the fault to the existing exact-MM mutation authority;
it supplies neither a mapping answer nor a polling wait. The mutation route
excludes EL1 edits before reading the live owner again. VM-free binding:
`delegated_fault_classifier_routes_busy_root_to_mutation_without_waiting`
holds an EL1 root through classification of both a mapped page and a hole,
then verifies that the hole remains unmapped after release.

`kernel.mm.copyout-owner-gate` covers a peer closing the MM gate between
SELECT and PREPARE. The hardware preamble must observe the exact Gate
producer before probing and return its owned suspension, never a raw
EAGAIN completion that the host lowers to EFAULT. No source byte may be
consumed before a semantic permit. The production-entry VM-free bindings
are `owner_wait_release_before_enrollment_never_parks_a_lost_edge`,
`owner_wait_unrelated_release_cannot_reschedule_and_real_release_delivers_once`,
and `prepare_entry_refuses_another_incarnation_before_gate_wait`.
They cover both release/enrollment orders, unrelated release isolation,
exactly one handback, and resumed admission of the original operation.
Work is bounded by one gate probe/enrollment per owner release; no polling,
timeout, or retry budget is a substitute. Signed binding:
`el1_host_copyout_into_and_out_of_untouched_reserved_memory` (300 rounds).

`kernel.mm.bootstrap-table-custody` covers initial roots created after the
carrier's first container. Every root must be physically accessible to the
maintenance lane before owner admission, using this MM's exact table-slot
lease and authenticated stage-2 backing. Relocation is one cold publication
of one primary table arena; it preserves user leaves and never expands the
maintenance window to arbitrary global frames. Publication/switch failures
retire backing before returning capacity; a same-address image replacement
or owner admission invalidates preparation. VM-free bindings:
`later_bootstrap_roots_use_distinct_maintenance_accessible_table_custody`,
`bootstrap_root_publication_failure_returns_capacity_without_switching`,
`bootstrap_root_same_address_replacement_cannot_commit_stale_preparation`,
`bootstrap_root_admission_during_publication_refuses_host_commit`, and
`relocated_boot_root_custody_survives_exec_and_reuse_rejects_old_lease`.
Signed multi-container and exec acceptance remains required.

Exec adopts the backend's exact successor table authority. A retained
predecessor keeps its image, publisher and capacity through detached cleanup;
a snapshot installed into the old authority cannot stand in for the new MM.
`exec_successor_preserves_retained_predecessor_table_authority` is the
red-first engine binding; `two_live_mm_exec_successor_keeps_predecessor_table_retirement_custody`
proves physical retirement releases only the predecessor's pooled slot while
the successor's exact record and bytes remain live. Signed sibling-exec
promotion of this repair remains pending.

Physical retirement covers every arena this exact authority published,
including a relocated bootstrap primary outside the inventory's mapping rows.
Source capacity cannot be returned while its exact stage-2 record is pinned;
terminal retirement revokes the software image under the same exclusion before
reuse. Work visits each owned published arena once, with no carrier-wide scan.
The two-live-MM VM-free bindings are
`two_live_mm_bootstrap_retirement_releases_only_its_published_root_slot` and
`two_live_mm_pinned_table_retirement_cannot_return_physical_capacity`: retirement
releases one slot, retains the other MM's bytes and identity, and a pin allows
zero capacity returns. These do not qualify full-crate parallel host fixtures.
`two_live_mm_empty_inventory_releases_already_terminal_table_capacity` covers
an earlier exact physical retirement followed by MM teardown without data rows:
the old record permits release of only its still-retained capacity.

`kernel.mm.delegated-root-reader-cost` covers the host readers of a delegated
root: proposal charging (`RLIMIT_AS`/`RLIMIT_DATA`), `mincore`, fault plans,
`madvise` range metadata, lock accounting, the arena high water and the host
`mmap`/`mprotect`/`munmap`/`mlock` paths. Structural invariant: root node reads
scale with the queried range and the tree height, never with the unrelated
node population. VM-free binding:
`delegated_readers_cost_the_queried_range_not_the_root_population` at 16 and
512 unrelated nodes; the budget is reads(512) <= 3 x reads(16) per query
(heights double; a population walk grows 32x). Signed, Docker and timing
layers remain open until the root is admitted in production.

## Futex example

`kernel.futex.contention` is the first vertical contract. Its VM-free binding
checks exact wake cardinality, no lost wake, one continuation enrollment and
park per blocking episode, no redispatch while parked, and queue work
proportional to affected waiters rather than historical population. It runs at
1, 8, 32, and 128 waiters.

`recycled_owner_wait_record_resumes_a_completed_futex_without_an_owner_continuation`
adds an incarnation-reuse witness at the runtime residency boundary. An
owner-memory wait and a subsequent futex wait reuse the same zone record,
but only the owner wait retains a syscall continuation. Exactly one host
wake restores the futex's completed EL0 context without replay or refusal.
Allocation resets completion flags in constant work; previous owner flags
must not change the next Linux futex wait's result or require another wake.

Carrier shared-word keys compare the full `(st_dev, st_ino, file offset)` for
file mappings, or the exact host word address for direct and mirror mappings.
A hash may select a shard but cannot decide queue equality. The VM-free
`file_words_with_colliding_hints_have_distinct_carrier_queues` witness forces a
legacy hash collision and proves separate wake cardinality; the continuation
`two_live_owners_of_one_shared_word_receive_one_wake_each` witness proves that
two real waiters on one key each require their own counted wake. Key admission
uses one sharded map lookup per futex operation, with no live-waiter scan.
Shared bucket entries hold weak references and disappear when their final wait,
subscription, wake or requeue destination reference leaves. The VM-free
`ten_thousand_retired_shared_words_leave_no_live_keys_per_table` witness waits
and wakes 10,000 distinct direct and file words in each of two tables, then
requires zero live shared entries in both.

The shared table belongs to one kernel instance. Linux tasks in that kernel
must rendezvous on the same file word across fork, while two live kernels
must never consume each other's wakes even for identical `(dev, ino, offset)`
and host backing. The VM-free continuation witness
`two_kernels_with_the_same_file_word_do_not_share_wakes` enrolls B before A,
requires A's wake to reach only A, then requires zero additional waiter entries
in A while B remains enrolled. This is an exact zero cross-instance budget
under `kernel.futex.contention`, independent of timing or host process identity.
`two_shared_authorities_have_no_cross_instance_entries` exercises cloned
descendant authorities with fresh private tables at 1, 8, 32 and 128 file
words. Each table holds only its own live keys and returns to zero after
retirement. Embed host-buffer leases carry the carrier's same typed authority,
including leases minted before the first kernel root boots.

The signed binding reuses Carrick's futex probes to prove guest execution. A
separate uninstrumented release run compares the pinned futex distribution with
same-image Docker. The existing tests remain until the contract has demonstrated
equivalent or stronger failure detection.

## Fork stage-1 image example

`kernel.fork.stage1-image` also requires owner-selected physical custody to
authenticate the selected IPA through the carrier's exact extent record, VM
generation and logical-owner generation. A carrier-MM alias index is not the
extent authority; guest VAs cannot substitute for physical selections. The
VM-free binding
`owner_fork_retains_live_structural_capacity_without_carrier_mm_alias_index`
retains two real structural records for a bounded copy with an empty legacy
index. `owner_selected_same_va_in_two_mms_retains_exact_physical_frames` guards
same-VA isolation. Lookup work follows the physical extent index and selected
records, without scanning other MM populations. Signed fork acceptance remains
required.

`kernel.fork.stage1-image` is the first contract whose structural budget lives
entirely in the VMM layer. Every forked child owns a private stage-1
page-table software image (a 1.75 MiB arena set) for its lifetime; `ltp-fork14`
creates 16k children this way, and allocating a fresh image per fork produced
~28 GiB of host `mmap`/`madvise(MADV_FREE_REUSABLE)` churn. The fixture is
`forkserial <n>`: `n` serial fork/`_exit(0)`/`waitpid` rounds from one parent.

- Linux authority: `man 2 fork`, `man 2 wait4`. Every child exits 0 and each
  `waitpid` returns its own child's pid.
- Structural invariant: `task_admissions` is exactly one per fork, and
  `page_table_image_allocations` (fresh image allocations, counted where the
  parent clones its image for the child) is bounded by the number of
  concurrently live child images, `2 + 0·n`, never by the fork count. Retired
  images return to the process tree's bounded `Stage1ImagePool` and the next
  fork clones into a recycled buffer. `host_mapping_allocations` (fresh host
  `mmap`s for the child's per-mm backing) is `0 + 1·n`: the root tables come
  from the carrier's pre-mapped root-slot pool and only the child's private
  EL1 kernel-state page is still a per-fork host mapping.
  `fork_projection_rows_visited` is `32 + 24·n`: the COW projection scans the
  process's own rows, and rows superseded by earlier COW splits (the parent's
  post-fork stack and data writes) are pruned before the scan, so the work per
  fork never grows with the forks already performed (before the prune the
  fixture visited 15455 rows at 128 forks; after it, 2430).
- Layers: the VM-free binding has no stage-1 projection, so it proves the
  semantics and the admission budget and reports the image metric as an
  exact zero. The signed embed structural binding runs the probe on the
  runtime's own work scope at 1, 8, 32 and 128 forks. The timing binding reads
  the probe's per-fork p50 from an uninstrumented signed run against the
  pinned same-image Docker measurement recorded beside the binding.
- Status (2026-09-20): structural bindings green at 1/8/32/128. The timing
  binding is red: 205 µs per serial fork under the signed carrier versus
  88 µs under Docker (2.33x against the 2.0x policy), and `ltp-fork14` sits at
  3.41x (5.6 s versus 1.6 s; it was 15.4x), `ltp-epoll-ltp` (the same serial
  fork shape: 12,468 clone/exit/wait rounds) at 3.07x from 11.5x, and
  `ltp-fork09` at 1.63x from 3.2x, each measured alone on a quiet host. The root-slot pool is now created at VM
  creation and an exec'd image's root table is drawn from it too, so the
  `sh -c` launch shape every harness LTP row uses no longer pays a 2 MiB host
  `mmap` per fork (the `via_shell` structural binding proves it). Named
  remaining levers: the executor boundary audit issues about five
  `pthread_sigmask` and four `thread_selfusage` host calls per fork, and the
  parent's post-fork COW splits cost about 15% of carrier CPU. The timing
  gate stays red until the ratio meets policy; it is not widened.
- A pre-mapped carrier pool owns its whole IPA range. Once the root-slot pool
  is created at VM creation, every consumer of that arena — a forked child's
  root table, an exec'd image's root table, and a live stage-1 extension
  arena — must take its slot from the pool, and a retiring owner must hand
  the slot back at its retirement proof rather than at its last reference.
  A missed consumer maps private backing over the pre-map, and that
  `HV_ERROR` reaches the guest as a SIGSEGV: CPython's
  `test_compiler_recursion_limit` died that way while Docker passed. The
  `pagetablegrow` probe and the `kernel.fork.stage1-image` bindings are the
  standing guards; `scripts/dtrace/hvpatch-stage1-faults.d` names the exact
  refused mapping when one slips through.
- The next pathology class above the fork family is the guest syscall floor,
  not another algorithm. `ltp-inotify09` issues about 15 million syscalls
  (2.99 million each of `inotify_add_watch`, `inotify_rm_watch`, `lseek`,
  `clock_gettime` and `write`; LTP's fuzzy-sync helpers use raw syscalls, so
  `clock_gettime` never reaches the vDSO) and spends 5.5 microseconds per
  syscall against Docker's 0.69. No per-operation budget is violated there,
  so a contract for that class must budget the syscall round trip itself.

## Root tty activation

`runtime.root.tty-activation` covers first-root carrier activation racing a
completed root command. Linux authority is the cached CLI exit-status contract:
`exit 42` must return 42 regardless of how quickly the task exits. Launch tty
session and foreground authority must be initialized before guest execution;
relay acknowledgement derives from that published authority, not a fresh lookup
of a possibly retired root thread. The deterministic VM-free binding is
`root_tty_publication_survives_root_exit_before_activation` in the runtime, which
retires the root before service publication. The structural budget is zero
root-thread registry captures during tty service publication, with no wait,
retry, or guest-execution barrier added. The signed bindings are
`case_01_exit_status_propagation` (embed) and
`conformance_default_run_contract` (CLI). Docker refresh and broader signed
promotion remain the integration director's responsibility.

## Partial retirement during anonymous grant settlement

`kernel.el1.anonymous-first-touch` requires a verified bulk grant's surviving
pages to keep their exact physical owner when EL1 retires a neighboring page
before the host settles the receipt. The retired page must never reappear in
the residency index; the authenticated fault page must retain its committed
bit and host residency. Settlement partitions only the bounded deferred-return
journal, publishes at most one more fragment than overlapping returns, and
performs no carrier-wide residency scan. An untouched surviving fragment stays
prepared rather than becoming resident. The VM-free bindings are
`delegated_partial_retirement_settlement_preserves_the_unretired_fault` and the
published-grant settlement cases in `mem/delegated_tests.rs`. Signed binding:
`el1_anonymous_reservations_stay_in_guest`; copyout also exercises the peer
resident selection that consumes this committed evidence.

## Pending heap retirement backing maintenance (open)

`kernel.mm.pending-brk-backing-maintenance` covers heap shrink and later
regrowth: removed pages must become inaccessible before their physical bytes
are scrubbed, and regrowth must not expose the old bytes. The existing
`brk_shrink_scrubs_backing_before_regrowth` and restrictive-ordering tests
cover the host semantic sequence. An admitted root additionally requires a
typed maintenance operation tied to its exact pending retirement, carrier/MM
incarnation, live descriptor output and retained physical owner. It cannot
select ordinary UserWrite or wait for its own transaction's Gate. Wrong-MM,
stale request/physical generation, reused VA, and fork-shared physical pages
must not authorize a scrub. Selection and cleanup scale with touched backing,
not carrier-wide mappings; no lock spans host I/O or a scheduler wait.

The signed red is `el1_anonymous_reservations_stay_in_guest` on `77b7d5e71`:
4 KiB heap contraction reaches PREPARE and receives its own Gate wait before
aborting. A VM-free reproduction and its failing assertion are preserved in
the 2026-10-05 backing-maintenance handoff. The typed production binding now
uses `PortalBackingMaintenance` and the existing retained physical grant pool:
EL1 authenticates the pending heap retirement, replaces each backed invalid
leaf with private zero backing, and leaves it invalid until regrowth. The
VM-free witness checks the original Gate red, ordinary user-copy exclusion,
request corruption and VA reuse, a live COW peer, adjacent bytes, and bounded
descriptor work. Signed green remains pending; this contract is not accepted.

## Exact physical grant completion

`kernel.mm.copyout-owner-gate` also covers the interval between physical
alias publication and its EL1 descriptor receipt. An exact live provisional
owner is a completion dependency, not a permanent supply refusal. A contender
must allocate zero extra frames, hold no host I/O lock while suspended, and
reselect through the semantic owner only after that exact publication commits
or rolls back. A reused VA or physical generation cannot satisfy its wait.
The VM-free bindings are
`concurrent_transfer_waits_for_exact_uncommitted_physical_grant` and
`transfer_partial_remap_keeps_dirty_neighbor_in_same_compound`; they cover
rollback, applied settlement, late enrollment and distinct owner completions.
Both settlement paths release the publisher's temporary physical pin before
publishing readiness or invoking callbacks; a waiter may immediately retire
that exact owner. The witnesses sample the exact stage-2 pin count inside
the callback and require zero, rather than checking only after producer Drop.
The same copyout signed fixture remains the required production binding.

## Terminal clear custody

`kernel.thread.clear-tid-custody` covers `set_tid_address(2)` and
`CLONE_CHILD_CLEARTID`: the exiting thread clears its registered word and
wakes its joiner before exit becomes observable. Runtime registry identity
and Linux TID are separate domains; nonleader exec may promote the Linux
identity while retaining the registry runner. The Kernel thread supplies
that mapping. Capture retains the exact thread and MM; an unrelated runner
or retired MM cannot complete the clear. Work is one prepared clear and at
most one wake per retained obligation; a graph refusal cancels the permit
without either operation, and a memory wait releases executor capacity.

The VM-free `child_tid_owner_tests` include a real nonleader exec followed by
capture, clear, wake and terminal publication. `terminal_clear_loom` models
clear/wake ordering and graph refusal. The signed anonymous and fork-COW
comparison fixtures bind the terminal runtime path; broader pthread and exec
acceptance remains open.

`kernel.process.wait-owner` covers selection and consumption of a process's
children by wait4/waitid. Linux authority is wait(2)'s clone-child partition,
WNOWAIT observation, and consuming reap; wait4(2) supplies subtree CPU charging.
The shared registry must authenticate exact task serials, preserve live and
retiring children in a blocking wait, and sample the parent's wake generation
in the scan that found no event. Revision or topology admission failure must
leave the zombie, child edge and CPU ledger unchanged.

Consuming reap returns the removed non-cloneable consumer payload alongside
the semantic exit receipt, retaining exact numeric/native custody until the
caller releases the result. `consuming_wait_retains_only_selected_owned_claim_until_result_release`
proves two selected claims remain independent and release exactly once. The
same selection consumes topology and charges CPU once, with no extra scan.
The host drops its returned payload under the registry guard before observers.

The VM-free binding is `carrick-sched-core::process::wait_tests`, exercised by
`just test`. It covers two children, stale serials, observe/consume, ptrace
stops outside the child class, reservations and revision exhaustion. At 1, 8,
32 and 128 live children, with 512 unrelated processes present, unrelated
identity/event reads are exactly zero. Child identity reads are bounded by
`2*n`, and event reads by `n`, per scan; registry lookups follow only parent
edges. Consuming read prechecks accept a non-Clone UID receipt, making receipt
cloning unnecessary until the write admission. Host kernel-semantics suites
exercise the same owner through the public wait APIs. Signed ARM and live
CPL0 process bindings remain required; these inner-loop checks make no
runtime-ratio or guest-instruction claim.

`kernel.process.birth-owner` covers fork publication under retained exclusive
registry custody. Exact caller and selected-parent serial/revision, child
population collisions, group/session membership and immutable payload identity
must be authenticated before irreversible claim publication. A valid exit
participant reservation cannot license new process topology; already-admitted
thread membership remains allowed. `process::birth::tests` binds these rules,
including dropped admission, external peer roots, a genuine exit reservation
red-first refusal and zero identity reads across 512 unrelated tasks.

`kernel.process.exit-owner` covers reserved exit topology. Linux authority is
exit(2), wait(2), PR_SET_CHILD_SUBREAPER and SIGCHLD's SIG_IGN/SA_NOCLDWAIT
rules. The shared registry chooses exact-generation live ancestry, reparents
both live and zombie children, and removes the exiting child edge for autoreap.
Topology reservations retain one publication credit per live participant;
admitted thread births and nonfinal exits may advance their revisions without
closing those participants' membership gates. Dropping admission leaves their
revision unchanged; publishing topology advances the current revision.

The VM-free binding is `carrick-sched-core::process::exit_tests`, plus existing
host exit/thread-reservation tests through the same owner. Selection visits
only the exiting task, its ancestry, its children and its affected parents;
it does not scan the registry population. Private prepared-plan fields keep
adopter and child-set selection in the shared owner. Terminal zombie publication,
exit-group member selection, reservation release and parent notification ordering
use the same owner. Cancellation authority requires the exact opaque reservation
incarnation; its parent permit is available only after cancelling those members.
Notification selection authenticates the exact parent, then snapshots signal
state outside the registry guard through the existing shared signal policy.

The structural exit-effect test uses 0/1/8/32/128 own members and 512 unrelated
processes: it visits each own member once, performs at most four identity reads
for the exiting task, and performs zero unrelated identity/member reads. A full
population-scan mutant fails this budget. An unrelated reservation is refused
before exit begins, and a rebound reservation with the same numeric transaction
cannot release old effects or be erased by old rollback. Signed ARM binding and
the live CPL0 two-MM witness remain open; no runtime-ratio claim is made.

## X86 retained shootdown debt (`x86-shootdown-reentry`)

Surface: shared-MM page retirement on two live x86 KVM CPUs. Architectural
translation coherence requires a CPU to drain its old non-global translations
before using the edited address space. Carrick retains exact root/MM owner and
request generation; a stopped CPU can owe a published generation, but cannot
use that translation on reentry before native KICK settlement. A user #PF must
settle already published debt before reporting its fault doorbell.

The cheapest capable binding is the real KVM `cpl0_entry` fixture: the reader
warms the retired leaf, then signals running admission while waiting on a
fixture control byte. The selected hold releases that byte only after the
editor's unmap reaches rendezvous. The reader faults on a never-mapped address,
so neither forced ordering depends on incidental eviction of the warmed TLB.
Hold IPI until the first fault word to force fault-entry settlement; hold
publication until the complete record stops the reader to force reentry debt.
The latter must owe exactly generation 2 after serving generation 1, and must
serve generation 2 and increment the native KICK check once on reentry. The
original two-running-CPU fixture checks either exact served settlement or this
exact stopped debt followed by settlement. The retired-page load must fault.
The existing stopped CPL3 and CPL0 fixtures additionally witness absence of
stale bytes after reentry into either privilege level.

Budget: two CPUs, one editor and one reader, no retry, at most 32 editor exits,
fifteen fault words, and five seconds per guest interval and ordering hold.
The terminal fixture fault suffix emits one completion exit after unmasking
KICK; production keeps its terminal halt and contains no fixture hold polling.
No VM-free runner can witness real TLB contents. HVF signed execution and Docker
are outside this x86 KVM binding; this lane uses `CARRICK_REQUIRE_KVM=1`.

## process-record-lifetime-v1

Surface: shared process-record lookup for PID namespace translation, child
wait/ptrace classification and `/proc` run-state rendering. An owned read must
contain fields from one published process generation; release or same-PID slot
reuse during the read returns typed `Stale` (mapped to absence by lookup APIs).
This is the arena binding of the existing exact-task identity rule, rather than
a promise of transactional snapshots of ordinary metadata changes within one
live generation.

Retirement invalidates the state and generation, then fences before clearing
body fields. Readers acquire publication, copy owned values, fence, and validate
both generation and published identity after their last body load. Borrowed
record references cannot escape the higher-ranked read callback. Mutation paths
that can act on foreign records hold the existing record transition claim and
revalidate identity before reading and acting.

VM-free bindings: `prefork_registration::observation_cannot_mix_publication_with_reap`,
`observation_rejects_reuse_even_with_the_same_host_pid`,
`observation_rejects_release_in_another_host_process`,
`namespace::pid::tests::member_read_rejects_release_between_identity_and_parent`,
`run_state::tests::published_rejects_reuse_after_identity_read`, and
`guest_cpu::tests::child_read_rejects_reuse_after_identity_read`.
The fill-hook fork test separately proves incomplete initialization stays hidden.
The storm retains 200 children per run and immediate record reuse.

Structural budget: one callback invocation and one trailing validation per
published slot, zero retries; scans visit at most `PROCESS_RECORDS` slots.
There is no observer lock, cross-record serialization, deadline or sleep.
These bindings use real shared arena memory and host fork where applicable,
without guest execution. Signed guest composition and Docker timing are not
claimed by this VM-free lane and remain the director's batch acceptance work.


## Process entry native custody (`kernel.process.entry-owner`)

CPL0 process calls use the existing Linux lifecycle dispatcher and completion
owner. Before invoking native fork, wait4 or exit_group custody, the pending
family must authenticate task, task generation, MM and thread generation.
A mismatch invokes zero native effects. A matching entry invokes its one
native operation; native custody returns a LifecycleOutcome, never publishes
a second completion. Existing ARM consumers supply no process venue.

The VM-free `process_native_hooks_require_every_execution_identity_component`
test independently changes each binding component and checks all three hooks.
The native hook absence is red before the bridge. The
`x86_parked_context_roots_clone_through_shared_fork_owner` fixture inherits a
real anonymous reservation through the existing shared fork traits with CPL0
parked contexts and aligned, co-located reservation/zone storage. The previous
ARM-only trait implementations are structural red; context parameterization
preserves the ARM default. This is adapter and owner-custody evidence; CPU1
execution and the live two-MM PRIVATE witness remain required.

The native owner does not support ptrace attach or non-child tracees. It has
no attach venue or mutator establishing a tracer relationship. On the x86
CPL0 path, ptrace is outside `AllowedHostCrossing` and is refused with counted
ENOSYS (38). Accordingly waitpid(nonchild) has no ptrace relationship and
returns ECHILD (10), as Linux does without ptrace. This does not claim parity
with Linux waiting on an attached tracee. The VM-free
`nonchild_wait_has_no_ptrace_relationship_and_preserves_own_children` binds
that scope with two live sibling processes and the caller's own live child.

Exit preparation must remain reversible until publication: abandoning an
owned pending exit leaves live topology, revisions and resources unchanged.
`early_error_after_exit_begin_preserves_live_graph_and_reservation_custody`
checks this with both a live child and a zombie. Shared effect preparation
retains the exact exiting-task membership revision; activation refuses a
snapshot invalidated by an admitted birth without changing lifecycle.
`prepared_exit_effects_reject_stale_membership_snapshot` binds this and verifies
fresh cancellation includes both members. `PreparedExitEffects` exposes neither
cancellation nor resource transfer before activation (compile-fail witnesses).
Publication wakes the direct
parent and adopter once each, including inherited zombies;
`blocked_adopter_wait_resumes_with_an_inherited_zombie` binds this through
a parked native wait continuation.
A competing reap retains the original Any or process-group selector and
requires fresh status copying before consuming a replacement zombie;
`competing_reap_keeps_original_any_and_group_query` checks both selectors and
live/zombie replacements. Child job groups are resolved in the caller's
namespace, including groups different from the caller's own. These operations
visit the caller's children and affected exit topology, never unrelated rows.

## X86 MM-private COW copy window (`kernel.mm.private-cow-window`)

Linux private mappings preserve independent bytes across fork. A physical
replacement at 8 GiB must be usable without a permanent supervisor data alias.
Each MM owns one supervisor branch and two idle copy leaves. Fork clones that
branch while retaining shared supervisor branches. Under the exact-MM editor,
copy maps a read-only source and writable destination, both inaccessible to
users, then restores both idle words and drains translations before release.
A failed restoration is indeterminate and forbids backing reuse.

The VM-free bindings are
`x86_fork_clones_private_upper_branch_and_keeps_supervisor_sharing`,
`x86_cow_maps_private_scratch_pair_for_high_physical_replacement`,
and `private_copy_pair_has_bounded_work_and_restores_before_completion`.
Provisioning takes three exclusive zero table grants, 1537 descriptor reads
and three comparisons. Copy takes five descriptor reads, four comparisons
and two fixed-span drains. Fork adds exactly 1536 census reads for the private
branch. Admission authenticates all three actual table frames against the
launch grants separately from user mapping transaction identities.

The production KVM binding is
`mounted_static_x86_two_live_mms_have_private_anonymous_leaves`: shared-owner
fork, CPU1 child, CPL0 wait/exit, sixteen new PRIVATE pages in each MM, distinct
roots and physical pages, and an active peer. Kernel-owned user-copy crossings
carry their selected user address explicitly; hardware CR2 is not their demand.
The existing five-second bound is unchanged. No ARM runtime or ratio claim is
conferred by this x86 binding.

## Initial ELF private-page ownership

`mm.initial.elf-private` owns private frame publication for the initial x86
ELF image, including data and text. The initial anonymous stack already
used this ownership. Authority: mmap(2) MAP_PRIVATE and fork(2). The VM-free
`fresh_owner_maps_static_text_data_and_stack_with_publications` test failed
with PRIVATE=0 on the data leaf before correction. The initial builder now
uses the private descriptor operation for every owned initial page; the KVM
receipt reconstruction mirrors that exact operation without relaxing any
transaction, live-descriptor or inventory authentication.

This changes no population or work budget: one frame initialization,
descriptor edit and publication per initial page. A forked signal wait found
the defect when a COW write correctly refused an unowned source descriptor.

## ARM signal return privilege boundary

`signal.arm.resume-privilege` owns ARM `rt_sigreturn` routing and the
supervisor resume-state publication boundary. Linux authority is
`sigreturn(2)`: return restores a userspace context, never a supervisor
execution context. Until ARM delivery moves in-ring, syscall 139 forwards
to the carrier that owns the delivered frame ABI.

VM-free bindings are `arm_sigreturn_stays_with_host_frame_owner` in
`carrick-personality-linux` and
`forged_supervisor_or_masked_pstate_is_refused` in `carrick-el1`. The latter
rejects EL1 and each DAIF masking bit, while accepting EL0 with NZCV.
The structural budget is one constant-time PSTATE check before any register
publication, with no additional copies, waits, or allocations. Both tests
were red before the routing and validation corrections.

Signed ARM execution and same-image oracle bindings remain outstanding;
VM-free evidence does not establish full signal frame compatibility. The
in-ring ARM restore path remains unrouted until Linux ucontext and FPSIMD
restore and forced SIGSEGV on invalid frames are implemented together.
