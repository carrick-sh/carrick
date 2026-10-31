# Delegated anonymous root contracts

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
