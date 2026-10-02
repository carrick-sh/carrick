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
