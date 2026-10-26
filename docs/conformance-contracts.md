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
run the contract. `scripts/conformance/check-contract-change.py` automatically waives pure moves across files when every removed and added block matches verbatim in order (split only at blank lines, modulo indentation and with exact multiplicity) plus allowlisted `mod`/`use` declarations.

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

`kernel.el1.deferred-handback-identity` also covers a pinned service record
evacuated when its executor enters an inline host wait. Linux affinity limits
execution to eligible CPUs; lending a CPU must leave runnable work claimable
by its borrower. The vacating actor can return and enter another inline wait
without taking service work. Requeueing a captured service record behind
that actor or another eligible driver repeatedly captures the same incarnation
and delays its readiness.
The ARM affinity venue in #703 exposes this path when the fixture's pin starts
succeeding instead of returning ENOSYS.

`service_capture_publishes_once_across_repeated_step_aways` drives real
slot evacuation and host settlement at 1, 8 and 32 turns. It requires one
capture, one host publication and zero zone queue rows, with either a pinned
or broad mask. `service_capture_does_not_bounce_between_eligible_drivers`
alternates eight step-aways between two drivers, on the same or different
eligible CPUs. It was RED with eight captures even after the away-slot
fallback was removed; service handback must end zone custody. Initial service
placement is unchanged.
`hold_is_captured_exactly_once_at_the_next_step_away` drives the same
test-only hold and production step-away hooks as the signed witness, now over
three consecutive inline waits; its RED was three identical captures.
Only first-entry births retain the fallback queue because they have no host
row to release. These assertions do not change the retired-delivery budget.
The signed binding is
`el1_sched_deferred_handback_capture_observes_guest_records`; signed execution
and end-to-end runtime acceptance remain director-owned.

Returning the service row also requires an executor wake on the mailbox
leased by its current idle entry. A persistent hardware handle can retain
a relinquished creation-time mailbox after fork or task migration. The
runtime publishes an owned idle-wake target before its final host queue
scan and holds that target through delivery and idle teardown. Zone wakes
mark durable host work on that mailbox before kicking it; physical idle
lanes retain their backend wake route.

`serial_host_captured_service_after_self_affinity_and_futex_wakes_current_idle_slot`
executes self `sched_setaffinity`, real shared-futex enrollment and wake,
service capture and scheduler publication, then the production EL1 idle
loop and host claim. The wake lands after the final queue scan but before
effective guest entry, after the mailbox moved from slot 0 to slot 12.
Its RED enters WFI without an event on both the pre-#765 fixed stack and
the rebased stack. GREEN requires no WFI, one capture, and a claim on CPU 0
after self-affinity excluded CPU 1. The supplied pre-fix signed comparison
failed with `Cannot fork` before exercising the handoff, so it cannot
establish absence of the hang under a successful fork. Signed acceptance
of both properties remains open.

`kernel.scheduler.runnable-progress` also covers pool admission and guest CPU affinity.
Native service custody extends this contract: two real fork children can publish
simultaneous requests through the fixture's sole execution slot. Each park must
release that slot. The witness rejects a stale execution generation, cancels one
request before physical acknowledgment, completes the other first, and requires
one ring consumption per request before its terminal claim is released. A member
retains at most one signal or service wait in the shared continuation table;
one retained member allocation also preserves a saved signal mask after its
wait completes, until signal delivery consumes that mask. Host
records retain backing and observe exact identities; they do not adopt children
into another process graph. Intake reuses the birth-bound MM identity even
when another admitted participant holds the reservation root. The bindings include
`native_service_intake_does_not_reacquire_the_busy_mm_root` and
`two_native_children_service_waits_release_the_only_execution_slot` in
`carrick-el1-linux`. Its companion cases preserve a completed result through
cancellation, retry an effect-free syscall with its original arguments, and
resume an interrupted instruction without changing its registers. The shared
personality receipt distinguishes effect-free deferral from a metadata commit
already owed. The runtime binding
`native_service_waits_do_not_exhaust_the_default_executor_pool` uses the real
native owner with four fork children and the default one-CPU pool (one bound
worker, two spares). All four requests must park before any acknowledgment;
no child gets a host task binding, and every worker must join. Its physical-idle
test adapter does not exercise HVF metadata pin intake. Fault supply and signed
child syscall acceptance require separate witnesses. Unsupported native requests return to the ring for its errno
or signal decision; no generic host syscall dispatcher is introduced.

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

An unported affinity venue may admit a native process before carrier topology
or its control mask is published. Fork inherits that unpublished zero mask;
binding its live authority must not turn absence of policy into an empty CPU
set. `unpublished_live_affinity_does_not_restrict_placement` checks placement
before publication and enforcement after a nonempty mask is installed.
`missing_venue_affinity_alias_refuses_placement` separately requires refusal
when the current venue cannot read a bound authority. Both paths use at most one
authority load, without scanning CPUs or substituting another venue's pointer.
`child_exit_releases_control_custody_before_retire_mm_reclaims_stock` binds
this to production x86 fork, idle-peer migration and child MM retirement with
unpublished topology. Published masks still follow Linux fork inheritance;
empty `sched_setaffinity` requests remain invalid. Signed execution remains
director-owned.
For ARM native fork, `arm_native_fork_child_reinstalls_mm_after_service_ack`
binds the same runnable-progress contract after the parent has left its host
continuation: the forked record must enter through an idle executor with no
host task, park for service, and resume the same child after acknowledgment.
The witness models idle entry resetting TTBRs to the carrier root and requires
exactly one child-root installation before its first child syscall. Service
park switches to the maintenance root before releasing installed occupancy.
The signed shell and exec
probe remain the execution-layer binding.

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

The pending owner-fork table is runtime metadata, initialized once in place on
the EL1 metadata heap before ARM entry routing. Its publication state alone
must fit in one page of the code image
(`pending_fork_image_storage_fits_one_page`);
`concurrent_initialization_retains_one_table_and_slot_locks` proves concurrent
bring-up retains one empty table and does not reset or share slot locks.
Initialization visits each CPU slot once; later entries load one pointer.
The image build reports CEL1's loaded footprint (including `.bss`) and headroom
under the unchanged 1 MiB ABI limit. These VM-free structural witnesses do not
replace the signed ARM fork binding.

The fork image's identity/control publication uses a named kernel window,
not Linux user-copy authority. VM-free witnesses exercise copied-child identity,
shared-MM gate closure and parent handback, exact live MM translation, retained
physical writer custody, and refusal of user/image windows or stale translations.
The scoped signed bindings include fork/exec shared backing and inotify09 vfork.

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

Fresh physical-grant inventory mappings start at their own initial generation;
the carrier allocation generation remains with physical backing custody.
Shared `StagedPhysicalGrants` owns initialization and accepts no generation
from a backend. `native_child_empty_supply_resumes_cow_without_changing_parent`
and `native_backing_reply_observes_a_competing_valid_publication` compose
carrier generations 5, 6 and 7 with fresh inventory publications, USED
settlement and neutral physical retirement. The former was red when carrier
generation 5 was submitted as the fresh mapping's generation. The existing
two-grant refill and bounded page-copy assertions remain unchanged.

Native USED receipts authenticate completed ring publications, not descriptors
that must remain installed until host settlement. MAP_FIXED and unmap may
replace those descriptors while the physical grant remains retained. The
shared physical owner settles exact grant epoch, MM and live inventory identity
without a backend page-table verdict. The two-live-process witness
`native_child_fixed_over_cow_preserves_parent_bytes_and_retires` replaces a
COW-shared page at a sub-16K offset, checks both processes' bytes and returns
stock through terminal retirement; a foreign MM cannot settle the receipt.
Final-MM root retirement consumes its deferred-return journal together with
its tree, under retained whole-MM physical custody. Host and native exits
use that same neutral operation; ordinary retirement still refuses owed
returns. Refusal must leave the journal intact.

Native backing selection must exclude live or prepared inherited neighbors,
even when the child's lazy-grant residency table has no row for them.
`native_child_backing_selection_excludes_inherited_live_neighbor` forks an
actual child from a two-page reservation with one resident parent page and
requires the first supply window to contain only the absent page. The neutral
grant owner selects the contiguous available span under the exact MM editor,
using the same predicate that authenticates publication. Work is bounded by
the selected window (at most 512 pages, four descriptor loads per page), not
the MM population. The adapter submits that exact window and never crops a
decoded transaction or changes its receipt digest.

The KVM vfork VM rebuild also publishes each selected shadow pointer to the
host-side window descriptor under its write lock. The real-KVM binding
`vfork_rebuild_host_reads_shadow_bytes` reads distinct child bytes through
`GuestRam` after rebuilding, while a shared window retains its original bytes.
The pre-fix host read returned the parent's private bytes. This publication
visits each window once and adds no backing copy; the retained shadow remains
the source for both host reads and guest memslots. Full vfork/exec and signed
acceptance remain the existing higher-layer bindings.

Native fork stock reserves that same physical custody before child publication.
`native_stock_reserve_refuses_retiring_stage2_record_and_rolls_back_earlier_pin`
drives the HVF stock crossing and the stage-2 retirement owner without booting a
VM: retirement before Reserve refuses admission, drops earlier row pins, and
permits a clean Abort and subsequent fork; retirement after Reserve cannot
revoke the admitted child's pin. Commit only consumes that reservation, never
reconstructs custody. The HAL binding
`unreserved_commit_cannot_bypass_physical_custody_admission` rejects the former
inline-Commit path. ARM settlement keeps the child space closed on a typed
Commit refusal, failed crossing, or missing acknowledgment; these are invariant
faults after publication, not successful forks. These host witnesses do not
replace signed guest or KVM acceptance.

Physical-custody destruction must not retain the grant-accounting lock (#569).
`child_reclaim_and_terminal_finalization_do_not_invert_accounting_lock` drives
that same neutral stock owner against a second executor finalizing a directory
entry. The bounded witness rejects the ledger-to-directory edge captured on
hardware. The HVF accounting authority exposes only completed accounting
operations to fork callers, never a guard or a callback under the guard.
Exact terminal receipt publication remains serialized with IPA reuse inside
the accounting implementation; it does not admit or reclaim fork custody.

Custody arrays may be allocated in either the fixed EL1 bootstrap/heap region
or a retained dynamic metadata grant. The dynamic path shares the lifecycle
record venue, rather than imposing a fixed-region-only allocation limit.
`native_stock_reserve_accepts_custody_in_dynamic_metadata` drives the production
stock service with its four-word custody array in a dynamic grant, including
retirement refusal, rollback and successful subsequent Reserve/Commit.

Owner-selected fork leaves retain the parent's exact physical inventory extent
once per extent, independent of the selected leaf count. A 4 KiB semantic leaf
must not shrink a 16 KiB compound's custody to 4 KiB: child bootstrap COW and
exec retirement need that exact record. Guest access stays limited by the
owner's stage-1 leaves. The VM-free binding
`owner_selected_fork_leaf_retains_vvar_compound_for_child_bootstrap` runs the
production owner projection, child inventory staging, privileged RNG COW and
old-MM exec retirement while the parent's backing remains live and unchanged.
It requires one inherited inventory mapping for the selected parent extent,
a bounded compound copy, and zero retirement of parent-owned physical leases.
The owner's table capacity has no bootstrap guest-VA alias. Bootstrap COW
resolves the manager's actual physical root through the current MM's arena
resolver, and a second owner fork retains the refreshed overlay's exact extent.
Linux authority is [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html)
and [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

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

The signed red is `el1_anonymous_reservations_stay_in_guest` on `083a815f7`:
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

`kernel.copyout.owner-refusal` also requires a native fatal signal to survive
an ordinary owner-release wake and carrier continuation cleanup. The VM-free
runtime binding
`serial_host_native_owner_wait_release_wins_then_tgkill_survives_recontention`
lets release win Ready, reacquires the real sibling editor, posts native
`tgkill(SIGKILL)` and settles its doorbell before resuming the continuation.
Native terminal custody must be entered before the renewed editor releases.
Carrier and native queue projections have distinct publication capabilities;
the shared pending observation is their read-only union. Native custody admits
one writer per control slot, even across independent retains. The writer cannot
be cloned; its destructor alone releases the claim and clears the projection.
`native_pending_writer_admission_is_exclusive_until_drop` and
`duplicate_member_projection_must_preserve_pending` exercise refusal, retained
SIGKILL and final cleanup; `NativePendingCustody` doctests reject move duplication
and cloning.

`serial_host_native_owner_wait_fatal_callback_budget` binds deterministic
publication work at 1/8/32/128 live thread wait registrations in one process.
One native process-fatal host-work publication must invoke exactly N persistent
task callbacks for N subscriptions: each exact TaskKey is notified once,
regardless of its eligible waiter population. The budget counts callback
invocations, including redundant invocations hidden by runnable latches.
Signed HVF and Docker promotion remain director-owned.

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

`kernel.process.fork-child-tid` covers `clone(SIGCHLD | CLONE_CHILD_SETTID |
CLONE_CHILD_CLEARTID, ..., ctid)` as a process fork. Linux authority is
[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html) and
[set_tid_address(2)](https://man7.org/linux/man-pages/man2/set_tid_address.2.html):
the child sees its TID at `ctid` before returning to user mode, the parent's
private word is unchanged, and child exit zeros the word and wakes its futex.
One process birth, at most one child-MM TID store, and at most one clear and
wake are the work budget; the fork never scans or writes the parent's MM for
these effects. The VM-free bindings are
`common_linux_entry_calls_native_process_custody` for admission and
`process_clone_child_tid_lives_in_child_mm_and_clears_on_exit` for two live
processes and terminal effects. The signed bindings are the five EL1 cases
named by #491; the Docker oracle for this exact flag family remains a
separate, serialized authority check.

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
a second completion. ARM native process returns and the host-published getpid
projection cross the existing completed-with-work boundary. The host consumes
one `SyscallCompletionToken` and publishes the actual return through
`publish_return`; it never replays the already served call. Admission refusals
that return errno use the same completed boundary. Suspended and terminal
transfers do not invent a syscall return.

The VM-free runtime witness `owned_arm_process_return_is_observed_once` binds
ARM getpid with and without a process venue, native fork/wait success and errno,
and unported process-call refusals. Each returning call records exactly one
audit return and one engine completion, with at most one native effect; a
second completion is refused. Boundary publication and consumption are constant
work. EL1's `refused_owned_process_return_retains_one_completed_boundary` also
binds the pre-dispatch refusal transport.

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

The public ARM frame codec is shared by the carrier and dormant EL1 backend
in `carrick-personality-linux::signal::arm`, under
`kernel.el1.signal-delivery-owner`. `arm_public_signal_frame_roundtrip_has_no_private_magic`
restores the public prefix without a private trailer. The extension witnesses
cover reordered FPSIMD, duplicate FPSIMD/ESR, malformed lengths, missing or
half terminators, truncated extents, and refusal before GPR/SIMD publication.
The parser walks the entire admitted 4 KiB reserved area through the null
record, advancing by at least 16 bytes per nonterminal record with checked
bounds, no allocation and no guest-pointer chasing. The admitted lane carries
FPSIMD and optional ESR; SVE/SME and out-of-line extra context are refused.
Authority for this record format is the [public arm64 SVE signal ABI
documentation](https://www.kernel.org/doc/html/latest/arch/arm64/sve.html#signal-handling)
and [Arm's Linux Plumbers 2017 signal-frame diagrams](https://blog.linuxplumbersconf.org/2017/ocw/system/presentations/4671/original/plumbers-dm-2017.pdf),
alongside [sigreturn(2)](https://man7.org/linux/man-pages/man2/sigreturn.2.html)
and the Arm Architecture Reference Manual for A-profile (`SPSR_EL1` / `PSTATE`
EL0 condition and execution-state fields `NZCV[31:28]`, `DIT[24]`, `SSBS[12]`
versus privileged `M[4:0]` and `DAIF[9:6]`). On signal delivery, `arm_signal::build`
masks internal EL1/EL0 execution-control bits (`0x3c0` in masked mode or `0x340`
in GIC mode) out of `uc_mcontext.pstate` via `AARCH64_EL0_USER_PSTATE_MASK`
while preserving legal guest EL0 flags, and `SignalFrameParams` carries
`interrupted_sp` separately from the selected placement `sp` so `uc_mcontext.sp`
records the interrupted user SP even when `SA_ONSTACK` places the handler frame
on the alternate stack (matching native arm64 Linux oracle
`sha256:5e927c284bf55a7dc796262e311a0703344f62f41f5621eb56843111b1d37e15`:
`sa_onstack frame_on_alt=1 saved_sp_on_alt=0 pstate=0x60000000`). On `rt_sigreturn`,
`arm::decode` rejects any non-EL0-user `pstate` bit before register or FPSIMD
publication, and `arm_signal::restore` / `apply_restored_context` re-apply the
canonical internal EL0 DAIF mask (`0x3c0` on bits `[9:6]`, `AARCH64_EL0_VISIBLE_DAIF`;
cleared of `PSTATE.I` at the `write_el1_hook` `eret` boundary when `El1IrqMode::Gic`
is active so `(spsr & 0x3c0) | PSTATE_I == 0x3c0` holds across both modes) while
preserving legal guest EL0 flags in `AARCH64_EL0_USER_PSTATE_MASK`
(`arm_signal_delivery_masks_internal_daif_and_preserves_el0_user_pstate_flags`,
`arm_public_return_restores_internal_daif_and_preserves_el0_user_flags`,
`arm_signal_delivery_separates_interrupted_sp_from_altstack_placement`, and
`production_deliver_signal_with_control_preserves_interrupted_sp_and_masks_daif`).

The ARM `sigaltstack` setup case of `kernel.el1.signal-delivery-owner`
uses the VM-free `sigaltstack_serves_off_the_alternate_stack` witness. Native
arm64 Docker oracle confirmation is still required at the atomic cutover.
The arm64 minimum is 5120 bytes (5119 returns ENOMEM); x86_64 retains its
separate 2048-byte minimum. Linux treats input SS_ONSTACK as a no-op and
ignores SS_AUTODISARM when SS_DISABLE is set. For the downward-growing stack,
the base SP is off-stack and the initial top SP is on-stack. The setup witnesses
also require a new rt_sigprocmask mask to remain committed when writing oldset
returns EFAULT, with any newly owed signal work preserved. These VM-free
checks do not establish signed ARM delivery.
Bad flags plus undersized
storage return EINVAL (-22); undersized storage alone returns ENOMEM (-12);
SS_DISABLE ignores size. Input and output may alias: the entire new stack is
read before the old stack is written, and the old value is returned while the
new value is installed. Bad input and output pointers return EFAULT (-14).
A valid replacement (including SS_DISABLE) is committed before writing old_ss,
so an old_ss fault returns EFAULT with the new stack state retained.
Bad flags beat a bad output pointer with EINVAL, and output remains untouched
on validation errors. While executing on the alternate stack, input copy-in
runs first (so an invalid ss pointer returns EFAULT (-14)), and any readable
change (valid, bad flags, undersized, or disable) returns EPERM (-1), even with
a bad output pointer; no output is written. An on-stack query reports
SS_ONSTACK. SS_AUTODISARM is accepted and is returned in the old flags at bit
31. The structural budget is one fixed-size input read, one fixed-size output
write, and one slot publication after validation, with no carrier handback,
task scan, allocation, or wait.

## Signal return result ownership

`signal.return.no-result` owns successful in-ring `rt_sigreturn` completion.
Authority is [sigreturn(2)](https://man7.org/linux/man-pages/man2/sigreturn.2.html):
the operation restores the interrupted context and never returns a syscall
result. Its completion settles the same entry without a scheduler handoff or
result installation, including when carrier return work is pending.

VM-free binding: `signal_return_contract` in `carrick-personality-linux`.
Native x86/KVM binding: `x86_signal_handler.S` compares a nonzero restored
accumulator against native execution. The VM-free result-ownership assertion
failed before correction. Completion adds no memory copies, allocation, or
waits; result publication count is zero. Signed ARM binding is unavailable on
Linux and ARM still uses its host frame owner.

## x86 signal resume validation

`signal.x86.resume-validation` owns x86 signal-context publication and
invalid-frame SIGSEGV. Authority: sigreturn(2), sigaction(2), and signal(7).
The VM-free return contract rejects a normal errno outcome on frame failure;
scheduler tests check the RFLAGS privilege boundary. The native/KVM flags and
bad-RIP witnesses both failed before correction and compare to native Linux.
The bad-RIP witness also found that root completion rejected signal wait
statuses; its ABI test now admits only exited or signaled terminal states.

Publication validates RIP/RSP and flags before writing any saved register.
Frame failure queues one exact-thread forced SIGSEGV; disposition and queue
changes use the retained task's sighand lock. The budget is constant-time
validation and one queue admission, without retry, polling or timeout growth.
C3's native/KVM fault witness additionally checks architectural RIP, MAPERR,
saved mask, handler mask, and mask restoration. Its synchronous-SEGV policy
binding checks blocked and ignored actions in the VM-free EL1 library.
Signed ARM acceptance remains outstanding and these witnesses do not claim it.

## x86 signal FP state custody

`signal.x86.fp-custody` owns signal XSAVE save/restore for the admitted
XCR0=7 native lane. Authority: sigreturn(2), signal(7), and the existing
clean-room Linux XSAVE wire records in `carrick-abi`. The native/KVM SSE
witness failed before correction; it compares preservation across a handler
that overwrites XMM0 and checks both FP_XSTATE_MAGIC markers.

Entry, fault and IRQ captures initialize their 832-byte storage before XSAVE.
Delivery copies one bounded XSAVE image and emits the Linux software extent
descriptor. Restore validates lengths, feature bits, compact/reserved header
words, trailing magic and MXCSR before publishing the FP image or GPRs.
No wait, retry or allocation occurs. The deterministic bound is one fixed
832-byte capture initialization plus at most 836 FP wire bytes per delivery
or restore; the ucontext and GPR-frame copies are independently fixed-size.
ARM delivery remains host-owned; this does not enable an ARM signal frame.
The shared wire crate now builds for `x86_64-unknown-none`; host and ring
signal records refer to that one definition. Signed ARM acceptance and
runtime-ratio measurement remain outstanding.

## In-ring signal handler admission

`signal.handler.admission` owns handler masks, reset disposition, alternate
stack selection and failed-frame escalation. Authority: sigaction(2) and
sigaltstack(2). Native/KVM witnesses check nested delivery with SA_NODEFER
clear, SA_RESETHAND publication, DF clearing/restoration, a SIGSEGV handler
on the retained alternate stack after stack overflow, and default SIGSEGV
when handler frame construction fails. The first four admission witnesses
failed before correction; the VM-free reset-action contract failed before
the action was committed at selection.

Action selection and reset share the sighand lock. Frame publication saves
the old mask and stack before applying the handler mask. Stack selection is
constant work; failure admits at most one forced SIGSEGV frame, whose own
failure terminates the task. No allocation, sleep or polling is introduced
in successful frame construction. Signed ARM acceptance remains outstanding.

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

### Owned in-ring signal waits

`signal_wait_owns_context_and_shared_deadline` checks that a finite signal
wait retains its saved context, releases its executor and completes only
when the shared timer reaches its deadline. The mounted native/KVM
`sigsuspend` and `sigtimedwait` witnesses retain three fork/reap iterations;
they must not be shortened to hide fork-stock exhaustion. Their second fork
currently depends on the separately owned shared child-MM retirement work.
The signal-free `x86_fork_stock_reuse.S` reduction records this dependency.

The current single-owner timer still refuses a concurrent finite wait on
that slot; this is unfinished admission work, not Linux timeout semantics.

## Fork live-children limit (`kernel.fork.live-children-limit`)

Surface: `fork`/`vfork`/`clone` without `CLONE_VM` on the in-kernel fork
path (HVPATCH), on both carriers. Linux authority: fork(2) fails with
`EAGAIN` when a system-imposed limit is reached (`RLIMIT_NPROC`,
`threads-max`, `pid_max`). Carrick adds a narrower limit, a candid
divergence: each live fork child holds one carrier lifecycle record until
its MM is retired and reclaimed, and the stock is fixed at boot. x86 CPL0
has 8 records, AArch64 31 (see the
[fork stock design](design/arm-fork-stock-crossing.md)). A workload with
more concurrently live children than that (`make -j16`, a long shell
pipeline) sees `EAGAIN` from the extra forks where Linux would succeed.
Zombies do not count: a child's record returns once it has exited and left
every slot, whether or not it was reaped.

Invariant: a fork beyond the limit is refused with a counted `Capacity`
refusal and returns `EAGAIN` (-11). It never hangs, never faults the
carrier, never strands a loan, and never returns another errno. The limit
counts live children, not forks: retiring one child admits the next fork.
A terminal receipt remains `Retiring` until exact member cancellation and
MM retirement have completed. A parent entering wait in that interval
parks through the existing wait continuation; it cannot reap and issue a
new fork against the retiring child's charged tables. Completion publishes
readiness and selects the current receipt parent in one graph projection
before notification/wakeup; an adopter owns the wake after reparenting. This adds one
acquire read per examined terminal receipt and no polling, retries, wider
stock, or wall-clock deadline. Autoreaped children retain the same pending
receipt, exact child edge and numeric claim. Each pending automatic removal
owns one preadmitted parent revision credit; adoption replaces it with an
admitted credit for the exact adopter. Retirement atomically removes that
receipt and edge without charging CPU usage, before the existing channel
wake. Dropping the exit publication leaves retirement pending. Admission itself
drains reclaimable stock once through the existing stopped crossing.

Every refusal is attributable in the run report's
`execution_witness.fork_stock_families` (`capacity_refusal`, and for a
withdrawn dirty record `inventory_refusal` with `withdrawn_lifecycle`).
The last exact capacity resource and all quarantined children at refusal
are retained in `execution_witness.fork_admission_refusal` and emitted by
`fork-admission-refusal` / `fork-quarantine-state` USDT probes. Their absence
means no recorded capacity refusal, not evidence of a dropped trace.

VM-free bindings:
- `process_owner::tests::exit_status_is_not_waitable_before_mm_retirement_completes`
  (carrick-el1): pause at owner publication, assert wait remains running,
  complete retirement and assert the same status is available. Red before
  the readiness publication gate, without load.
- `process_owner::tests::retirement_completion_notifies_the_adopter_of_a_pending_zombie`
  (carrick-el1): reparent while retirement is pending, then complete it;
  notification targets the adopter, not the exited original parent.
- `carrier_cpu::tests::child_owner_grant_on_root_executor_is_a_physical_boundary`
  (carrick-vmm-kvm): a registered child crosses for physical service while
  the executor retains its root-task custody. Select the live registered
  child root; an unregistered root still refuses. Red on the retirement-only
  selection policy. Physical service separately authenticates the CPL0
  binding and context incarnation.
- `fork_stock::tests::kvm_live_children_beyond_lifecycle_records_are_counted_refusals`
  (carrick-hal): eight live children, the ninth loan is one counted
  `Capacity` refusal, and after one child is retired and reclaimed the
  ninth loan is granted.
- `aarch64_process_tests::capacity_refused_loan_is_eagain_with_nothing_to_settle`
  (carrick-el1): the guest lowers the carrier's typed refusal to
  `Exhausted`, errno -11, with no loan to settle. It was red (`EFAULT`)
  while the guest trusted x0 over the typed reply.
- `aarch64_process_tests::failed_prepare_after_the_loan_aborts_it_and_a_later_fork_succeeds`:
  a refusal after the loan was granted aborts it, so later forks on the
  CPU are not refused for capacity.

Native lazy backing uses the same fixed table stock. Each descriptor supply
may preclaim the bounded eight-page grant record, but only the prefix named by
the authenticated EL1 receipt becomes live child custody. The unused suffix,
and every grant from a refused, rolled-back or unclaimed transaction, returns
before the service continuation releases. If child exit wins the service race,
reply application returns before settlement, or receipt settlement fails after
consumption, the neutral retirement owner absorbs every remaining grant for
that child into terminal table custody. Quarantine clears those possibly linked
pages before reclaim; retirement never refuses this ordinary race. Capacity
exhaustion is a counted `descriptor_capacity_refusal`; it refuses the fault
service without a carrier fatal and without changing stock. The VM-free bindings
`many_native_backing_supplies_return_unused_tables_across_two_children` and
`native_backing_table_exhaustion_is_counted_without_losing_stock` drive 512
alternating supplies across two live children and the exact exhaustion edge.
`child_exit_racing_native_supply_quarantines_pending_pages_with_peer_live` and
`early_fault_reply_return_quarantines_every_pending_supply_with_peer_live`
keep a second process live while proving unfinished grants clear through
quarantine rather than causing a terminal refusal or premature reuse.

ARM routing keeps root and native fork-child ownership distinct. Admitting the
root for its first fork does not move the root's own `execve` into the native
child owner: the root continues through the host exec boundary. Until native
child exec is implemented, only a fork child's `execve` is refused with
`ENOSYS`. `arm_unadmitted_thread_runs_ordinary_calls_and_refuses_owner_calls`
binds the owned-root case, while
`native_child_exec_refusal_parks_once_and_resumes_with_enosys` binds a real
registered child and the single park/resume boundary.

KVM binding:
`native_runtime_wait_wakes_once_only_after_real_mm_retirement` holds the
real CPL0 child-retire crossing pending. The parent observes WNOHANG zero,
successfully forks again, and enrolls its blocking wait through the native
runtime. The scheduler census remains parked with zero completion wakes
until MM retirement and slot absence publish; completion queues that exact
waiter with one wake and resumes it with the child's exit status. Reordering
runtime readiness before `retire_mm`, or omitting channel publication,
fails this witness. The existing carrier watchdog bounds guest execution;
the host census only observes atomic enrollment and never publishes readiness.

`native_nocldwait_blocks_until_every_child_mm_retires` and
`native_sigign_blocks_until_every_child_mm_retires` exercise real native
`rt_sigaction` and `wait4(-1)` with two autoreaped children. Linux authority:
[wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html) and
[sigaction(2)](https://man7.org/linux/man-pages/man2/sigaction.2.html).
The parent admits a second fork with the first MM retirement held pending,
enrolls a real wait, and must enroll again after the first completion while
the second MM remains charged. Only the last completion may return errno
10 (`ECHILD`), followed by another successful fork. Each completion wakes
the enrolled waiter exactly once; no observer publishes readiness. The
VM-free binding `autoreap_keeps_wait_population_until_retirement` retains
the child edge and numeric claim even if the exit lane is abandoned.
`autoreap_completion_removes_only_the_retired_child` covers a new birth
between retirement publications, exact removal and zero CPU charging;
`pending_autoreap_moves_removal_credit_to_adopter` checks credit ownership
and numeric-claim release after adoption. Mounted fork-rounds reuse covers
normal waits, SA_NOCLDWAIT and SIG_IGN, each over twelve sequential rounds;
the autoreap children attest successful private-page verification through
the existing owned signal-wait protocol with a zero timeout, because their
exit status is unavailable.

`child_born_on_idle_peer_can_fault_and_retire_on_root_executor` forces a
fork loan and commit on the idle peer, then places that queued newborn on
CPU 0 through the real scheduler claim/run queues. The fixture does not
require the unported CPL0 sched_setaffinity syscall.
Its private first-touch and physical MM retirement must authenticate the
newborn's live binding while CPU 0 retains the root task's executor lease.
The carrier's CPUs share one child-binding authority; executor detach does
not retire a live child, and a conflicting live-root registration refuses.

`mounted_static_x86_fork_rounds_beyond_lifecycle_stock_reuse_retired_children`
(12 sequential fork/exit rounds, each child first-touching fresh private
pages that must read zero; native output and exit; `loan` 12,
`returned_child` at least 4, no refusal family). The live-concurrency
refusal itself has no mounted binding yet.

Budget: a refusal does one loan crossing and no reclaim retry; reclaim
visits each quarantined child once per loan. Signed HVF execution and
Docker timing are not claimed by these bindings; the signed ARM fork gate
records `withdrawn_lifecycle` and `retire_refusal` as zero.

## Native short-lock contention (`process.native.short-lock`)

Surface: wait4, signal waits, SysV IPC enrollment, committed exit and record
retirement in the CPL0/EL1 process runtime. Linux authority: wait(2),
msgrcv(2), semop(2), exit(2); internal scheduler lock contention is not a
guest admission error. In particular wait4 has no EAGAIN result.

VM-free bindings: `pending_default_stop_does_not_interrupt_wait4`,
`bucket_contention_msgrcv`, `bucket_contention_semtimedop`,
`child_exit_retains_wake_custody_across_parent_bucket_contention` and
`child_signal_exit_retains_wake_custody_across_parent_bucket_contention`.
The fixture holds all 1024 buckets until the wait-policy probe observes the
old refusal threshold. No sleep, load generator or wall-clock deadline
decides lock release. A completion guard also releases on the red refusal
or assertion unwinding.

The structural invariant is zero contention-to-errno or contention-to-run-
failure transitions and one enrollment/retirement per operation. The tests
retain the owned handoff, queue registration, terminal status and wake
assertions; the probe measures contention, not a runtime ratio. Native KVM
mounted wait/IPC fixtures are the CPU execution bindings; the #231 owner
decision requires their receipt from the merge queue. No local KVM result
is claimed. Signed HVF and Docker ratio evidence require their respective
hosts and remain outstanding here.

## Native reparented exit notification (`kernel.process.exit-notification`)

Surface: delayed SIGCHLD and wait-channel publication after native child MM
retirement. Linux authority: [exit(2)](https://man7.org/linux/man-pages/man2/exit.2.html),
[PR_SET_CHILD_SUBREAPER(2)](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
and wait(2): orphaned children are adopted
by the nearest live subreaper or init, which receives their termination signal
and can reap their status. A concurrently exiting parent is not a run failure.

The real `NativeProcessRuntime` binding
`delayed_child_exit_notifies_adopter_when_selected_parent_exits_on_peer`
forks R -> P -> C, parks R in wait4, and runs P and C on distinct compact
scheduler slots. A test-only boundary after MM retirement releases P
on a peer host thread through actual exit_group before C reacquires graph
custody. The witness checks the reparented receipt, no run failure, C's SIGCHLD
siginfo at R, no notification or channel publication to departed P, one wake
of R's enrolled waiter, and both terminal statuses through real wait4.
The companion bindings
`delayed_child_exit_uses_adopter_interest_when_old_parent_ignored_default` and
`delayed_child_exit_does_not_inherit_departed_parents_signal_interest` require
the current adopter's signal policy, even when it differs from P's.

These witnesses are registered as VM-free bindings of
`kernel.el1.signal-delivery-owner` (all three), `core.entry.completion`,
`process.native.terminal-child` and the supplemental
`process.native.short-lock` list (the peer witness), and as
the process-exit interleave note of `kernel.el1.thread-lifecycle`. Two
owner-level bindings in `process_owner_tests.rs` cover the same
pending-retirement reparent window for `kernel.wait.process-group`
(`pending_reparented_zombie_keeps_process_group_until_adopter_reaps`) and
`kernel.wait.child-rusage`
(`pending_reparented_child_charges_adopter_once_and_never_departed_parent`).
The native runtime records no per-task CPU, so the rusage binding proves the
shared charge ledger, not native CPU measurement.

Structural budget: exactly one final notification publication per exit, no
retry or unrelated-task scan, exact TaskKey generation selection, and zero
stale-parent-to-run-failure transitions. Current recipient selection, signal
publication and wake-channel capture form one graph projection; wake execution
runs outside graph custody. Signed HVF and Docker evidence require their
respective hosts; this Linux worker binding does not claim either.

## x86 VMX segment entry (`x86.vmx.segment-entry`)

Authority: Intel SDM volume 3, §§26.3.1.1–26.3.1.4 (order 325384),
clean-room architectural checks, not host kernel source. Every long-mode
entry and restore must publish representable segment limits and matching
access rights, including a busy 64-bit TSS with byte limit 0x67 and G=0.
The VM-free validator visits exactly eight descriptors once; constructors
perform constant work and no I/O. Kernel and user entry/restore bindings
must pass the same checks. The red witness is a TR Granularity violation
on both shared states and the grouped KVM restore builder. Capability
fixed masks and interrupt injection remain backend responsibilities.
Intel live acceptance belongs to #253's GCP lane; AMD and signed HVF
runtime receipts are separate evidence and are not inferred from unit tests.

## Terminal native child (`process.native.terminal-child`)

Linux authority is exit(2)/wait(2): release the child's resources before
notification, retain the parent's wait, and consume its terminal status once.
The VM-free ARM production service witness
`arm_terminal_child_retirement_and_parent_handback_once` was red on main:
the child became reapable while ARM `retire_mm` performed zero retirements.
Its parked-parent case also requires the runtime handback venue when no guest
slot can place the parent. It asserts one accepted retirement and one host
handback, resumes the original wait with the child's status, and refuses a
second reap with -10/ECHILD.

The shared entry transition retains the exact task, execution generation, MM
and thread generation in CPU-slot terminal custody before the freed record can
be reused. A new slot entry invalidates that custody.
`terminal_retirement_cannot_retire_a_reused_record_or_slot_generation` proves
record reuse preserves the released authority, while a stale generation cannot
retire the new slot execution: four stale controls each differ from the
retained custody in exactly one of task, execution generation, MM and thread
generation, so dropping any one comparison admits a stale retirement. It also
refuses completion authority while
that CPU still has the child's MM installed; the host additionally validates
the hardware maintenance root before a parent handback.
`unplaceable_parent_host_handback_consumes_one_park`
asserts one host wake, no remaining queue entry, and zero duplicate handbacks.
Authentication reads one exact CPU-slot authority and one committed child root;
there is no population scan, polling, syscall redispatch, or timeout change.

The ARM physical crossing checks the retained committed root incarnation and
live hardware root before accepting the existing child-retirement wire record.
Physical table stock stays quarantined; its reclamation belongs to the next
stock slice. The zone ABI signature changes with the retained custody storage,
so signed verification needs fixtures admitted against the new input identity.
VM-free Linux tests do not prove the ARM HVC, hardware root switch, full process
adoption, or native ARM runtime ratio. Those gates remain director-owned.

## Carrier teardown after executor failure (`runtime.carrier.failed-drain`)

`runtime.carrier.failed-drain` covers successive containers in one host process.
A failed task remains a failure; draining its executor pool must join every
worker before destroying the VM and closing carrier admission. This is a
Carrick hardware-lifecycle invariant, with no Docker timing or Linux syscall
output claim. The structural budget is exactly one VM destruction per carrier,
including repeated shutdown calls, and one fresh generation for the next VM.

The VM-free binding
`failed_executor_drain_still_completes_vm_teardown_before_next_container`
runs the production executor pool with a failing test backend in container A,
then an exiting backend in container B. The hardware substitute uses the
production vCPU topology state machine: B's pool must be admitted on generation
2, after generation 1 ends. It also checks one create, destroy and join per pool
and consecutive carrier identities. This does not prove HVF destruction;
the director's signed EL1/embed and probe batch supplies that integration gate.

The VM-free binding
`failed_worker_releases_its_loaded_binding_before_pool_shutdown` also covers
`kernel.vcpu.vm-lifetime`: both backend error and panic release the loaded
task before the failed worker waits for pool shutdown. Its vCPU stays alive
until that shutdown. Logical failure publication must not retain a binding
whose physical receipt the carrier is waiting for. This retirement gap was
already present before native signal setup allowed these guests to progress.

The VM-free bindings
`abandoned_running_lease_drains_and_closes_its_lifecycle_window` and
`abandoned_implicit_lease_stays_reachable_until_process_shutdown` cover a
running lease dropped before normal container retirement. Its custody passes
to carrier teardown: join workers, retire the exact container graph, destroy
once, then finalize the lifecycle window. The implicit owner stays reachable
until this completes. The state updates its abandoned population during the
ownership transfer and final retirement, so repeated close admission checks
are constant work rather than rescanning all prior abandoned records.
`mixed_owned_and_abandoned_leases_keep_terminal_custody_exclusive` covers
1/8/32 staggered lease drops: the remaining owner prevents destruction,
and final teardown releases the transferred population exactly once.
Failure stays visible, and a subsequent carrier can acquire a new window. Actual HVF destruction and root-slot pool invalidation
remain signed bindings; the production HVF custody owner invalidates that
pool only after successful VM destruction.

### Idle execution custody (`kernel.el1.thread-lifecycle`)

An idle slot can run a native record without loading a host task. Its installed
MM is translation authority, not execution custody for host-owned records in
that MM. Neutral scheduler admission sends such successors and stolen records
to the executor before publishing `OnCpu`; native successors remain runnable.
The two `idle_native_mm_*` scheduler witnesses fail on the prior installed-MM
shortcut and preserve the exact saved context through handback and driver
release. Signed lifecycle, parked-thread, pipe and fork-COW populations remain
the hardware binding; VM-free admission alone does not qualify those runs.

A served EL1 frame may observe host work only after its handler has returned.
In every interrupt mode that late edge is still scheduler work: the vector
preserves the final EL0 return state, recasts the retained frame as an IRQ,
and re-enters the common scheduler IRQ boundary. A native owner therefore
parks and publishes its handoff before the driver can reach a host boundary. The emitted-byte
`served_native_frame_with_late_host_work_reenters_irq_boundary` witness and
the instruction-boundary interpreter's
`native_signal_work_cause_never_replays_a_served_syscall` row bind the
transition without a VM; the signed populations above remain the hardware
binding.

## Native close with a host-loaded member (`kernel.el1.thread-lifecycle`)

A native process close publishes cancellation for every exact outstanding
member before publishing its exit wait. A host-loaded member can have no live
zone record after its admission home was released; record cancellation alone
cannot reach an EL0 compute loop. The host applies the owner's requests with
scheduler control wakes before settling the exit owner's zone wait. It scans
the process members once per exact retained lifecycle page and delivers at
most one control wake per member, including a loaded member whose own boundary
observes the close. Late host adoption retains the cancellation request.

`arm_two_live_threads_exit_group_ends_group_with_status` exercises the ARM
native owner with two live threads and requires a host cancellation request
after the adopted sibling's zone record is released. It was red before this
fix. `native_terminal_request_kicks_loaded_member_without_zone_record_once`
separately exercises the production host adapter and exact scheduler binding:
no close means no wake, close delivers one kick, repeated observation delivers
none. It does not claim to execute the HVF kick or the whole exit receipt path.
`arm_signal_setup_then_timed_futex_keeps_its_deadline` is a passing timer
control on the signal stack, requiring an in-guest timeout after native signal
setup. The signed `el1_files_kick_delivery_spin_loop` census's untimed park
was the native exit receipt wait, not the preceding 50 ms sleep. Signed
`el1_sched_timed_wait_times_out_in_guest` remains required alongside it.

Closing requests retirement of live members; only their host withdrawal can
return the exact receipts it owes. It must preserve their zone records until
the host control wake and its deferred vCPU/producer handback complete.
`Handback::Cancelled` retires a plain futex record without a handback, so it
belongs after logical withdrawal, never to the pre-settlement wake request.
The VM-free
`serial_host_arm_exit_group_preserves_deferred_control_handback` binds ARM
dispatch to three real Kernel threads and their Scheduler continuations. A
host-parked sibling and a sibling switched in from a zone wait must both reach
host withdrawal before the third thread completes exit with status 42. Its
bounded missing-handback check was red with the switched-in sibling still
Blocked and its record gone. No timeout, retry or polling supplies progress.

An uninitialized EL1 birth also owns first-entry activation capacity. The same
one-shot host batch claims its exact record for Control and publishes immediate
handbacks through the existing first-entry route; an active vCPU or producer
owns deferred handbacks. The VM-free
`serial_host_native_terminal_wake_routes_uninitialized_parked_member` binds a
real ledger birth to that runtime batch and the service record offered to its
first-entry executor. It was red when the batch skipped uninitialized threads.
Work remains one process-member scan per retained page and at most one control
request per member. Signed parked-thread exit and first-entry execution remain
required director gates.

## Host fork versus terminal close (`kernel.el1.thread-lifecycle`, #441)

An admitted host fork either loses to terminal close before its commit gate
check, or holds a neutral publication claim until the new process is fully
published. Closing observes that claim through `claimed_count` and cannot
settle until publication or rollback finishes. The winning child is an
independent process and is reparented normally; it is never a member of the
parent's thread cancellation set. Seccomp/ptrace decline to `HostOnly`, which
permits host forks and cannot reopen a terminal `Closed` page.

The five `arm_exit_group_*host_fork*` VM-free bindings use production ARM
`arm_call` and host `PreparedFork::commit` on one exact KernelContext lifecycle
page/control, with a second live process. The admitted, prepared, and committing
losers retain parent status 7 and release the child record, MM, file table,
reservation and publication claim. The commit-wins binding keeps Closing parked
through backend publication and proves that the live child is subsequently
reparented. The backend-rollback binding retains the claim after kernel
rollback, and the real host Drop path wakes the ARM continuation. HVPatch keeps
the same owned publication scope through its backend transaction; terminal
refusal restores parent outputs and pidfd state before returning EAGAIN (11).
One page-local claim and one gate observation suffice; no population scan,
retry, polling or child cancellation is introduced. Signed HVF execution remains
the director's gate.

## Software vCPU linear placement, SoftTlb, and x86-64 walker (`softmmu.x86.tlb-walker`, #580)

Surface: `carrick-softmmu` (`AuthenticatedDescriptorWords`, `AuthenticatedGpa`,
`ExtentTable`, `LinearPlacement`, `MmioHoles`, `SoftTlb`, and `SoftWalker`) and
`carrick_mmu_core::x86::descriptor_txn::translate_leaf_hardware`. Architectural
authority: Intel SDM Vol. 3 §4.5 (4-Level Paging) and §4.10.4 (TLB invalidation).
`LinearPlacement::host` is the single GPA-to-host pointer conversion in the
workspace, accepting only `AuthenticatedGpa` minted by `SoftWalker` through
crate-internal `ExtentTable` authentication via the sealed `PlacementGpa` trait
and refusing MMIO holes (default xAPIC `0xfee0_0000..0xfee0_1000`) and
out-of-span extents. `ExtentTable::remove`, `ExtentTable::replace`,
`ExtentTable::remove_root_generation`, and `ExtentTable::replace_root_generation`
publish a domain-wide invalidation that every seated soft vCPU owes
(`softmmu.x86.physical-retirement`, below), `ExtentTable::set_root_generation`
refuses re-registering an existing root or a root still pending retirement, and
`ExtentTable::expected_generation` refuses unregistered roots (`None`, no
fallback generation). `SoftTlb` provides three 1024-entry direct-mapped planes
(`read`, `write`, `exec`) with 16-byte `SoftTlbEntry { tag, addend }` records
and large-page span tracking so `SoftTlb::evict_va` (`invlpg`) evicts all
sibling 4 KiB slots of a 2 MiB or 1 GiB leaf; `SoftTlb::fill_plane*` are
`pub(crate)` and `Execute` walks fill only `exec` (never `read`, preserving
`CR4.SMAP` on subsequent supervisor data reads). `SoftMmuMemory` does not expose
`LiveDescriptorWords`; `SoftWalker` uses the production
`AuthenticatedDescriptorWords` adapter to perform atomic `AtomicU64` `load` and
`A`/`D` `compare_exchange` directly at `LinearPlacement::host(table_frame) + (pa & 0xfff)`.
It binds `translate_leaf_hardware` in a single pass while enforcing non-present
precedence (`P == 0` ignores bits `63:1`), `MAXPHYADDR` reserved-bit checks on
bits `[51:MAXPHYADDR]`, hardware-ignored bits `11:8` and `62:52`, CR-gated
`EFER.NXE`, `CR4.SMEP`, `CR4.SMAP`, and `CR0.WP` checks, same-word CAS retries
for `A`/`D` bits when `PRESENT`, output address, and permission bits are
unchanged (restarting the walk on a material change and counting every failed
CAS against `MAX_AD_CAS_RETRIES`, with typed `AdCasRetryExhausted` counted in
`SoftWalkerStats`), non-canonical `#GP(0)`/`#SS(0)` and MMIO outcomes, leaf
extent authentication over `[leaf_base, +leaf.size)`, and frame-keyed code-page
write invalidation across explicitly supplied `SoftTlb`s (cross-vCPU code-page
publication is #684, slice 3 of #681).

VM-free bindings in `crates/carrick-softmmu/tests/softmmu_contract.rs` cover
all permission, CR-gating (including `Execute` -> `Read` SMAP isolation), and
fault classes, red-first witnesses against bare `translate_leaf`, 2 MiB / 1 GiB
huge-page authentication and `invlpg` span eviction, hardware `A`/`D` bit CAS
updates (including same-word retry against an ignored-bit-toggling peer,
concurrent `P`-clear walk restart, and bounded `AdCasRetryExhausted` at
`MAX_AD_CAS_RETRIES` against an adversarial concurrent writer flipping
software-available bits `9..=11`), cross-page split accesses, MMIO hole exclusion,
production `AuthenticatedDescriptorWords` `LinearPlacement`-backed atomic access
(rejecting disagreeing raw-PA mappings, retired table frames, and unregistered
roots), `ExtentTable` `remove` / `replace` / `remove_root_generation`
retirements served by both seated CPUs at block entry, frame-keyed code-page
alias invalidation across supplied TLBs, a two-thread
`invlpg` + `mov cr3` shootdown test, a concurrent PTE writer
snapshot-consistency race witness, and structural budget bounds across
`{1, 16, 256}` extents and `{2, 3, 4}` page-table levels.

## Software vCPU physical retirement (`softmmu.x86.physical-retirement`, #681 slice 2, #607)

Surface: `carrick-softmmu::retirement` (`SoftVcpu`, `SoftVcpuSeat`, `RunningSeat`,
`SeatAdmission`, `PendingRetirement`, `SoftRequester`), the `ExtentTable`
retirement edits, and the soft CPU's `RunningCpu`, `RunningContext`, block entry and
`HostAccess`-gated guest access in `carrick-softcpu-x86`. Authority: Intel SDM
Vol. 3 §4.10.4 and AMD APM Vol. 2 §5.5: a processor may keep using a cached
translation until it is invalidated, so software invalidates on every
processor that may hold it before the frames are reused.

The venue runs on the neutral invalidation domain
(`kernel.mm.invalidation-domain`); it replaces PR #678's bespoke coordinator.
`ExtentTable` owns one `ServedTable<64>` through an owning `SoftDomainHandle`.
Each soft vCPU holds a `SoftVcpuSeat`; physical retirement is a domain-wide
request (`stage_domain`) every seated member owes. The kick is the member's
exit flag, the safe point is block entry (own-line `has_debt` loads), and the
local invalidation is `SoftTlb::flush_all` or `flush_write_plane`. Running is
a scope: a CPU runs only inside a run guard whose drop parks it, host access
goes through a `HostAccess` whose drop parks a parked CPU again, and a CPU's
own thread waiting without itself as requester is refused. A pending
retirement holds its whole span, a replacement publishes its new owner only on
completion, a later completion recovers a dropped retirement, and an exhausted
domain stops every CPU. The protocol takes no lock per block; the carrier's
per-block `&mut M` still implies an embedder lock when CPUs share a memory,
which the soft carrier (#578) removes.

The red-first witness is the #607 shape: a running peer holding a translation
of a retired extent kept serving `Some(stale_host_address)` on main. Structural
budgets at 2, 16 and 64 seated members: zero shared RMWs plus stores per
debt-free block entry (`invalidation_steady_state_shared_writes`), one owed
raise per seated member per retirement, and at most one kick per running
member. Signed and Docker layers wait for the soft carrier.

## Host bridge process-signal custody

`kernel.el1.signal-delivery-owner` also binds `carrick-signal-linux`'s
`single_mask_*` tests and the real HAL fallback-timer wake reentry test.
Linux authority is standard-signal coalescence and lowest eligible delivery
(`signal(7)`, `sigwaitinfo(2)`). The existing `PendingSet` is the only mask:
queries load it; async publication only ORs it, including zero/multi-bit input.
A normal custodian owns 64 inline complete origins (Host, interval timer, or
POSIX timer with full id/overrun/value). Timer preparation/publication, removal
and payload copy/reset, clear, wake claim and exact-tid retirement use that
custodian. Claim rechecks eligibility after acquisition; normal owner-gated
take checks ownership there. Thread-first delivery and masked-wait bypass stay
distinct; pure queries reserve nothing. No universal joint ordering with
thread/xsignal queries or universal timer-OR linearization point is asserted.

Valid timers, including coalescence, add one normal acquisition. Nonempty
process-take attempts, eligible wake-claim attempts, clear and exact-tid
retirement each add one; invalid timer inputs, async OR, pure queries and proven
empty take/claim paths add none. This introduces cross-signum blocking between
normal producers/consumers/clear/claim/retirement. A paused holder can delay all
of them. Callers holding a HAL timer transition gate acquire custody after
that gate; custody never acquires a timer lock. Origin release precedes backend,
graph and wake callbacks. There is no application callback, I/O, guest wait,
allocator/free or table traversal inside production custody. First use allocates
one process-local backing before lock acquisition; no per-event heap owner is
created. A dequeue copies/resets one inline origin and uses the existing
whole-word strong CAS. With normal removals/clear excluded, at most 63 newly
set bits can interfere with a nonempty take; mutex acquisition/fairness has no
proven bound. Clear resets 64 origins. These are work descriptions, not new
contract budgets: `structural_budgets=[]` remains unchanged.

The normal backing uses the same neutral `ForkResetBacking` authority as HVF's
waiter registry. Fork preparation allocates clean replacements before bundle
locks. Parent and failure unlock then dispose the unused allocation; child
Drop publishes its preallocated backing and abandons the copied held guard
and queue without unlocking, destroying or byte-resetting mutex state. Only
the backing changes; the authoritative pending atomic stays at the same
address. Published backings are retained until process exit, one additional
old backing per child transition, preserving every borrowed reference and any
copied waiter queue. Ordinary concurrent clear never replaces backing;
already-held reset borrows its guard. The VM-free child-branch test is not a
platform fork proof. Active carrier launch re-execs and HVPatch guest fork is
in-process; this does not claim an active inherited-lock production defect.
The existing real contended HVF fork artifact test, independent review, full
CI, signed guest delivery and the unchanged <=2x p50/20-sample runtime gate
remain required integration follow-ons.

## EL1 clock transport phase discovery (`kernel.el1.gic`)

Kick normalization must classify the clock handler without publishing code or
requiring a scratch page. `mailbox_clock_layout_matches_every_emitted_variant`
was red on the signal stack: metadata discovery invoked the guarded installer
on zero-filled storage and panicked at vector offset `0xc20`. Layout discovery
now runs the same emitter without a byte sink; real installation retains its
NOP-only overwrite guard. The VM-free binding compares start, completion and
end across both fd-ceiling settings, EL1 settings and IRQ modes, and checks
handler classification boundaries. Emission and guest instruction placement
are unchanged. The signed EL1 suite remains the integration acceptance gate.

## Carrier birth source prerequisite

The birth-identity prerequisite of `kernel.el1.signal-delivery-owner`,
`kernel.el1.thread-lifecycle`, `core.lifecycle.publication` and
`process.native.arm-admission` also has VM-free word bindings in
`carrick-sched-core`: `zero_valid_issuer_burns_unpublished_births_and_never_wraps`,
`issuer_imports_reserved_births_idempotently_including_terminal_value`,
`shared_issuer_reserves_before_publication`,
`shared_issuer_concurrent_borrowers_have_one_complete_population`, and
`zone_birth_issuer_is_shared_by_borrows_and_isolated_between_carriers`.
One checked atomic RMW issues a birth, with contention-dependent retries;
rollback never returns a serial. The negative control
`late_observation_cannot_repair_independently_issued_tickets` proves that
post-allocation cursor advancement cannot merge independent live sources.
Production source bindings additionally exercise the actual host registry and
native fork paths: `process_receiver_survives_internal_task_id_reuse`,
`process_receiver_reserved_before_admission_and_native_unpublished_before_host_supply`,
`carrier_births_cover_reserved_unpublished_replenished_and_two_roots`,
`initial_birth_handoff_captures_burned_values_and_refuses_live_join`, and
`shared_birth_transfer_revokes_only_old_handle_and_partial_exhaustion_burns`.
The two-root native fork witness checks distinct carrier births. Full boot
export controls cover exclusive and shared sources; physical source controls
cover retained bytes with revoked custody and independent generation-one owners.
Host issuance costs also include its registry read lock and the backend custody
mutex or revocation read guard. Signed, cross-host and final runtime acceptance
remain required. See [the integration handoff](design/carrier-birth-issuer-handoff.md).

## ARM entry stack composition

`kernel.el1.signal-delivery-owner` and `kernel.el1.thread-lifecycle` also bind
compiled ARM entry-chain stack envelopes. The image build includes the vector
record and nested descriptor, copy, notification and allocator frames in a
12 KiB budget on the unchanged 16 KiB per-CPU stack. Signal encoding borrows
and fills admitted storage; native contexts and retained aggregate results use
heap custody. See [the stack contract](el1-stack-budget.md) for the exact scope
and remaining #369 work. The existing anonymous mapping retirement signed
witness remains the macOS integration binding.

### Carrier-wide MM identity composition

`kernel.el1.address-space-switch` and `core.lifecycle.publication` require MM
keys to be distinct across live roots, native children, reservations and later
host supply in one carrier. Linux `fork(2)` separates child address-space identity;
carrier address-space and occupancy tables cannot alias unrelated MMs.
`two_live_roots_keep_native_and_later_host_mm_keys_distinct` retained a real
production-bound RED: active keys `[1,2,3,5]`, later host keys `[3,4]`. The adapted
older baseline passed the same schedule, without proving universal baseline MM
safety. The repair routes both producers through a distinct typed zone MM word,
bound before issuance or under the actual stopped global MM allocation authority.
`two_live_roots_concurrently_publish_native_mms_before_host_supply` additionally
covers concurrent real graph forks, later host supply, unpublished rollback and
exhaustion without child publication. Existing kernel bootstrap/handoff/export
and retained physical-source controls cover the owner and revocation protocol.
No receiver authentication, wait4 behavior, work budget or graph-lock scope is
weakened. See the carrier issuer handoff for custody and per-ticket costs.

### First-entry claim custody under Closing

`kernel.el1.thread-lifecycle` has production-code loom bindings in
`carrick-sched-core::loom_models`. The scheduler's atomics (including run-queue
locks, incarnation, eligibility and kick debt) use loom storage in this test
build. A single usable index and slot bound the population, not the protocol;
ordinary tests keep the shared-memory layout and full-capacity bindings.
Object waits and address-space edits are outside these first-entry models.

The initial RED exploration at preemption bound 2 exposed these schedules:

- `release_races_closing_without_losing_custody`: producer reads
  `Placing(false)` for release; Closing CASes it to `Placing(true)` and
  returns Deferred; producer's release CAS fails and consumes the sole token.
  Both actors end with `Placing(true)` and no future owner.
- `requested_fallback_on_wfi_owes_a_kick`: producer admits placement; the
  previous slot enters WFI; Closing requests the placement and returns
  Deferred; producer cannot place, releases to Host, then requeues on the
  previous slot. The queue is nonempty but `take_resched` returns false.
- `mint_rejects_recycled_incarnation` and
  `placement_rejects_recycled_incarnation`: stale admission validates
  incarnation 1; an executor activates, retires and frees that birth; the
  allocator reuses the same index as incarnation 3; stale admission reads its
  Host claim and CASes it to Activating/Placing, returning an incarnation-1
  token for incarnation-3 storage.

Each focused RED test exited 101. These are assertions over the shipping
scheduler methods, not replicas of the transition function. The lifecycle
composition and competing-executor models additionally assert eligible or
terminal final ownership, one adapter delivery/adoption and retirement per
birth, rejection of the old token after reuse, and no queue links after free.
Graph-ledger adoption and physical interrupt delivery remain kernel/runtime
and signed integration bindings; the model counts their effects only under
real scheduler activation custody.

The final scheduler suite uses preemption bound 3 for focused race pairs and
bound 2 for the three composed producer/Closing/executor cases, with a 10,000
branch failure budget and no duration or permutation cap. These ownership
transfers use CAS and the WFI handshake uses a slot lock, not a Dekker pair.
`closing_producer_executor_sleep_and_reuse_preserve_delivery` counts returned
kick receipts and their consumption, while requiring every surviving queued
WFI record to have owed or delivered wakeup debt. The replacement-Closing
case also checks that stale admission cannot poison replacement custody. These
cases run through `just test-loom` and the existing CI loom job.

`current_handback_preserves_birth_incarnation_for_mint` covers non-cancelled
`OnCpu` and `OnCpuRequested` handback through the real `HostTransfer`
publication, racing a minter at bound 3. A generation-zero birth with lifecycle
and control storage returns to `FirstEntryHost` with the same incarnation;
an adopted thread returns to `Host` with its park sequence and refuses
first-entry mint. Born-in-zone entry completion does not supply a host adoption
generation, so it does not change that distinction. Publishing ordinary `Host`
for the birth would lose incarnation authentication at the acquisition CAS.

`stale_mint_cannot_consume_reused_service_head_delivery` adds a stronger P3
RED control. A stale incarnation-1 call is suspended until an executor retires
that birth, allocates incarnation 3 on the same index and queues it. The real
service-head take removes incarnation 3 and publishes Host. The stale caller
wins Host -> Activating, the legitimate executor fails to mint and returns no
delivery, and stale validation restores an unqueued Host record. There is no
remaining delivery event. This fails at focused bound 3 even with validation
under exclusive custody: eligibility alone is not delivery. The acquisition
CAS must reject a different incarnation without taking its ownership.

The repair encodes the full non-wrapping 60-bit incarnation in first-entry
claim words (`FirstEntryHost`, `Placing`/requested, `Activating`, `Retiring`).
Admission compares that exact word: a stale caller cannot acquire a new
birth even transiently. Ordinary parked and queued states retain their
slot/sequence encoding; the retained `last_seq` supplies that sequence when
first-entry custody queues a record. The ABI hash includes the claim protocol
version. Closing publishes a tagged intent, and the exclusive owner applies
its handback reason before release/publication; a delayed old requester
cannot overwrite a replacement's untagged handback. Placement release retains
custody across the single request-bit transition. Fallback publication and
its owed kick occur under the slot lock, returning a receipt to the adapter.

`delayed_closing_cannot_overwrite_replacement_handback` holds the old birth
in Placing while Closing reads its word and incarnation. The producer then
releases it, the executor retires it and a replacement reuses the index.
The old requester resumes its untagged Control write before its failed CAS,
overwriting the replacement's Service handback despite returning Stale.
This is RED on the under-custody repair at focused bound 3; publishing tagged
intent and applying payload only under exact owner custody preserves Service.

## One owner for memory waits (`kernel.memory.owner-wait`, #802)

Owner-backed stream `recvfrom` reads and validates `addrlen` after payload
copyout, including when the pointers alias and under `MSG_PEEK`. Empty sockets
still return errno 11 or wait before touching address completion. The VM-free
recvfrom witnesses cover zero/negative post-copyout lengths (success/errno 22),
invalid length pointers (errno 14), and retained read/write waits after copyout.
Address completion resumes its exact phase and never receives again; payload
and metadata each use one bounded prepared copyout, with no permit held while
waiting.


The #711/#802 owner contract is:

- Owner waits are killable-only; stops and handled signals never complete them.
- Fatal process-wide cancellation (SIGKILL or group exit) stops every waiter's
  resume, regardless of the thread selected for signal delivery.
- Cancellation uses native terminal custody for every completion origin:
  mailbox trap, direct-EL0 IPC record, and physical dependency. A typed origin
  prevents the direct-EL0 route from publishing a mailbox response or retiring
  a guest trap completion it does not own.
- Nothing is consumed before secured copyout, or after cancellation is pending.
- Writer exclusion is released before re-preparation.
- All users share one settlement path, including already-ready enrollment.

`vcpu_loop::owner_wait::OwnerWait` owns dependency release and settlement for
physical, zone and supply-ready resumes. Every cancellation query consults the
exact lifecycle page's monotonic `CancellationAuthority`; signal delivery
reservation and native dequeue cannot erase it. Native signal state binds the
root or freshly admitted child page. Terminal custody consumes the obligation
without clearing its cause. At owner-wait enrollment and task-wake edges,
bridge SIGKILL eligibility is authenticated against the exact native recipient
and promoted to that same authority before settlement. Native ingress retains
signal delivery. The atomic publication elects one subscription rebroadcast so
siblings checked earlier also observe cancellation. The bridge witnesses cover
two live parked members, a sibling-selected process signal and a thread-directed
signal, without dependency release or signal polling; dequeue cannot undo
cancellation. Nonfatal wakes perform exactly one bridge query per parked member
at populations 1, 8 and 32 (the initial membership scan measured 1, 64 and 1024).
The core concurrent-publication model proves that only one caller owns the
rebroadcast, even after terminal consumption.

A validated fatal request atomically closes effect admission. Its typed
publication drains existing bounded effects outside signal/topology locks,
then publishes before queue/wake delivery. `ProcessEffect` is non-cloneable
and non-Send; prepared output retains it through consumption, copyout and
cursor/descriptor publication, releasing it before notifications or waits.
An already-ready resume must acquire effect custody after securing memory.
This orders actual effects before fatal publication, not merely the earlier
cancellation sample. Rejected stale targets cannot request cancellation;
accepted targets that retire during drain fall back to the process queue.

The physical witnesses use real `pipe2` dispatch and `PendingContentWrite`,
with a live carrier leader and a separately admitted non-leader waiter.
Against main's physical route, ready SIGKILL committed output, non-leader
SIGKILL installed descriptors, and immediate/scheduled retry retained writer
exclusion. The actual leader-reservation tests exercise the delivery gap.
Native IPC and sleep witnesses need #735's retained-operation prerequisites:
restoring unconditional trap retirement fails direct-EL0 completion; ordinary
sleep owner parking wakes on a handled signal before editor release. These
are regression controls with prerequisites, not pristine-main builds.
A late-kill test publishes during re-preparation: without effect admission it
commits one output, with admission none. Empty IPC reads and stale authorized
SIGKILL posts also have red-first review regression controls.

Six runtime loom models call shipping settlement and cancellation code with
loom atomic words. They explore editor release, sibling effects, process
cancellation, nonfatal deferral, two waiters and already-ready enrollment.
The strict model asserts no consumption after fatal publication. It is not
an expected panic. There is no preemption/permutation/time cap; each execution
has a 1,000-branch bound. Core models separately exercise concurrent admission, two admitted effects,
request/publication and terminal consumption. Production queues, mailbox
transport, scheduler enrollment and the complete editor-holder audit remain
outside these models; the production witnesses bind the modeled protocol to
its adapters. See [input disposition and scope](design/owner-wait-handoff.md).
Signed HVF acceptance remains director-owned on this Linux worker.
### Private fixed file segment replacement

`kernel.mm.private-file-fixed-replacement` covers the libpython loader shape
reported in #759: a real file mapped PROT_NONE over `0x65ee48` bytes, fixed
RX text over `0x64ee48`, then fixed RW data at `+0x47a000` over `0x1d4000`.
Linux `mmap(2)` requires replacement and private stores, including guest-page
aligned addresses and offsets that are not host-page aligned. Internal copy
bounds and host-page congruence cannot introduce ENOMEM. The descriptor records
open reproduction and signed/oracle bindings explicitly until demonstrated.

The production-source VM-free binding is
`libpython_fixed_file_segments_use_owner_source_without_eager_copy`. It uses
`AddressSpace`, a real host file, the shared dispatcher and the admitted
reservation root. Its pre-fix RED is eager compatibility-image initialization;
it does **not** reproduce the ARM ENOMEM return. The code path that makes such
fallbacks invalid is the whole-length `write_bytes_unchecked` in `mmap.rs`,
which reaches the admitted owner's UserWrite PREPARE (bounded to 4096 bytes).
It also asks the old root/placeholder for write permission before replacement
has committed. The trace's backend refusal and omitted offset still need Mac
attribution; this finding alone cannot certify the recorded ARM failure.

The binding also forces a real nonroot `RLIMIT_MEMLOCK` refusal on a fixed
LOCKED replacement. It requires errno 12 while retaining the predecessor's
file source and permissions; the pre-fix implementation removes that mapping.

Admitted regular private host files now retain one source in the existing
owner root and retire old physical backing before committing new metadata.
First touch uses the existing private frame-grant service; no VA is reused as
an IPA and no host-page congruence is imposed on the source offset. Fixed
host-served placement preserves the predecessor until successful publication.
POPULATE, LOCKED, GROWSDOWN and nonregular objects keep their existing paths.
The source lease is secured before physical retirement. A typed retirement
result proves whether a refusal preserved the predecessor: preparation and
authenticated clean descriptor refusal can return ENOMEM before any chunk
commits. Any partial or unknown retirement, failed TLBI, or backend failure
after descriptor retirement fails stopped while source custody remains held.
`retirement_refusals_are_clean_only_before_any_chunk_commits` exercises the
production progress classifier with refused, rolled-back and unsettled
receipts. Signed first touch, private-store/fork
integration, the exact observed ENOMEM attribution, Python startup, native
ARM64 oracle and full artifact promotion remain required.

The local signed trace records reservation flags **0x822**, including
MAP_ANONYMOUS; file text and data use **0x812**. The fixture now covers both
that anonymous reservation and the requested file-backed variant. The
production-component binding `libpython_old_deferred_recipe_and_owner_copy_refusals`
registers the RX file view, applies the derived alignment trims, and proves
that a fixed data overlap is refused by `reserve_private_file` with
`InvalidRange`. Both tested data offsets then exceed `PreparedStreamRanges`'s
unchanged 4096-byte limit. In the old dispatcher the lowering error selects
whole-map snapshot fallback; `write_bytes_unchecked` reaches that owner
PREPARE refusal and the dispatcher converts it to ENOMEM (12). This is a
production registry plus production admission reproduction, without a fake
memory backend. The trace carries only four mmap arguments and no backend
refusal message, so exact-offset/branch live confirmation remains for the Mac.
The fallback first requests writable physical protection, which can itself
refuse before the bounded copy is reached; the component witness establishes
the incompatible fallback, not which downstream ENOMEM exit the Mac took.
The signed static case reads the actual immutable OCI libpython file; a new
mutable /tmp file would not bind the original lowering path.

Run the signed selectors with
`CARRICK_RUN_ID=759-libpython-map env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just test-conformance-next case_libpython_ --nocapture`.
The [fixture instructions](../crates/carrick-conformance-next/tests/fixtures/libpython-map/README.md)
describe source and executable identity and the pending native ARM64 bless.

## Directory copyout into untouched private memory (#759 stage 2)

`kernel.fs.directory-copyout` covers record publication and the selected
open description across an owner-memory wait. The director's signed Python
log at `c94769c21` reaches importlib `_fill_cache` and reports EFAULT for
`/usr/local/lib/python3.12`; that log alone does not identify the syscall.
The production getdents64 path submits the entire assembled result to
`write_bytes`; the ARM owner adapter passes it to `prepare_owner_write`,
whose production `PreparedStreamRanges` admits at most 4096 bytes. Larger
results become `HostMap`, then the blanket MemoryError conversion lowers
that internal condition to EFAULT. Untouched pages can also return a typed
supply/wait through this same unsuitable direct-copy path.

The VM-free RED witnesses use the production directory encoder and bounded
PREPARE admission, plus an actual immutable HostFs lower directory and sparse
AddressSpace. The first fault consumed all 402 entries before copyout:
retry into a never-touched private buffer returned zero (`exit 101`,
`/tmp/759-directory-red.log`). The bound witness checks the actual encoded
batch through production admission; it does not simulate an ARM backend.
The signed `case_libpython_directory_copyout` reports openat/fstat/getdents64
separately for mmap and malloc buffers. Its pre-fix owner failure, exact
ARM64 oracle bless, runtime work/timing and Python startup verification remain
explicit director gates on the Mac; this Linux worker cannot claim them.

The reviewed stage-2 repair splits complete records at guest-page/transfer
boundaries, calls the existing owner `prepare_write`, commits bytes, then
advances the shared description cursor. A refusal before progress retains the
exact description lease and thread, drops the description guard, and uses the
existing supply/owner-zone resume machinery. A refusal after progress returns
only the complete records already delivered. Internal preparation failures are
runtime errors; only `OutOfBounds` becomes EFAULT. EOF does not access the
buffer. No owner permit or editor guard is stored in `OwnedDirectoryRead`.

Directory I/O retains its selected description in the existing owner-resume
route. Owner receipts, supply and physical dependencies all settle through
#802's shared `OwnerWait`; there is no directory-specific wait adapter or
cancellation query. Resumption consumes the saved operation and releases its
physical dependency before preparing a new destination. Fatal settlement
releases the operation without output or cursor progress.

Secured directory output acquires the same `ProcessEffect` admission as other
owner copyouts. It retains custody through bytes and cursor publication, then
releases it before the next batch. Fatal publication during re-preparation
therefore cannot authorize output from a prior readiness sample.

The VM-free bindings cover cursor retention after a real address fault,
mixed-width records at 10/100/400/4096 entries, unaligned output, existing
PREPARE limits, page-proportional work, and retained descriptions across sibling
fd reuse. Runtime bindings use production dispatch, scheduler enrollment,
shared settlement and terminal publication with real `PendingContentWrite`.
They cover unready SIGKILL, a non-leader waiter with a live leader, readiness
during enrollment, writer release before both retry paths, and cancellation
during destination re-preparation. None uses a second memory-wait path.

The committed native ARM64 oracle and its source fingerprint are preserved.
Fresh signed HVF execution, live sibling-editor contention, handled-signal
delivery, final runtime ratios and exact-artifact promotion remain
director-owned. VM-free evidence does not close those integration gates.
