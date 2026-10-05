# Order-2 fork refusal mapping audit

The fork move introduced a catch-all owner-refusal conversion in
`crates/carrick-el1/src/personality/mm_portal/fork.rs`. A metadata-exhausted
publication changed from `MmError::MetadataRequired` (errno 11) to
`MmError::Core` (errno 5). The correction preserves owner failures in neutral
core types and leaves Linux errno lowering in the personality adapter.

The before-extraction authority is `5dc76a53352ecbe9189ec7fe3279afd11005902f`
(parent of the publication/commit/abort move `89f3e708f`). Its owner calls use
`MmError::from(Refusal)` directly. The reviewed bad implementation is
`5edb380d5c17c9e05235423b0702d61e39c55560`.

## Every Refusal variant

| Owner Refusal | Before extraction: MmError / errno | At 5edb380d5: MmError / errno | Corrected neutral core error | Corrected MmError / errno |
| --- | --- | --- | --- | --- |
| `Busy` | `Busy` / 16 | `Busy` / 16 | `ForkError::Busy` | `Busy` / 16 |
| `PreparedConflict` | `Busy` / 16 | `Busy` / 16 | `ForkError::Busy` | `Busy` / 16 |
| `Stale` | `Stale` / 3 | `Stale` / 3 | `ForkError::Stale` | `Stale` / 3 |
| `Invalid` | `Reservation(Invalid)` / 5 | `Core` / 5 | `OwnerRefusal(Invalid)` | `Reservation(Invalid)` / 5 |
| `Collision` | `Reservation(Collision)` / 5 | `Core` / 5 | `OwnerRefusal(Collision)` | `Reservation(Collision)` / 5 |
| `Hole` | `Fault` / 14 | `Core` / 5 | `OwnerRefusal(Hole)` | `Fault` / 14 |
| `ForeignMapping` | `Reservation(ForeignMapping)` / 5 | `Core` / 5 | `OwnerRefusal(ForeignMapping)` | `Reservation(ForeignMapping)` / 5 |
| `Limit` | `Fault` / 14 | `Core` / 5 | `OwnerRefusal(Limit)` | `Fault` / 14 |
| `MetadataRequired` | `MetadataRequired` / 11 | `Core` / 5 | `ForkError::MetadataRequired` | `MetadataRequired` / 11 |

`OwnerRefusal(...)` abbreviates
`ForkError::OwnerRefusal(ForkOwnerRefusal::...)`. These types carry no errno or
Linux reservation types. Adapter matches are exhaustive, so a new owner
variant cannot silently become `Core`. Core's existing `Invalid` (malformed
fork inputs), `NoMemory` (scratch capacity), and `Core` (descriptor/invariant
failure) lowering remains unchanged at errno 22, 12, and 5 respectively.

## Boundary call audit

All fallible `Reservations` methods newly bound to `ForkChildRoot` or
`ForkParentRoot` use the same conversion:

| Boundary method | Current reachable Refusal variants |
| --- | --- |
| `reserve_fork_certificate` | `MetadataRequired` through family-header allocation |
| `set_fork_origin` | `Stale`, `MetadataRequired` |
| `clone_into` | `Invalid`, `Stale`, `Busy`, `MetadataRequired` |
| `finish_fork_publication` (parent and child) | `Stale` |
| `commit_fork_generation` | `Stale` |
| `retire` | `Busy`, `Stale` |

The audit includes transitive host-node/shared-pool allocation, source backing
metadata, notification admission, and notification identity checks. Shared
pool contention can surface as `Busy` during copied-node allocation;
`secure_host_nodes` reports an insufficient reserve as `MetadataRequired`.
`PreparedConflict`, `Collision`, `Hole`, `ForeignMapping`, and `Limit` are not
currently emitted by those methods, but their conversion is preserved and
covered alongside every other variant. Guard acquisition outside the shared
transaction continues to use the original direct `MmError::from` conversion.

## Red-first production binding

Three VM-free witnesses invoke the real `MmPortal::publish_fork` and
`Reservations` owners:

- `owner_fork_metadata_child_reserve_preserves_original_refusal` exhausts the
  pool after leaving one node for the child's certificate, then refuses its
  eight-node host reserve.
- `owner_fork_metadata_copy_node_preserves_original_refusal` keeps that reserve
  live and leaves no node for the first copied reservation.
- `owner_fork_metadata_partial_copy_preserves_original_refusal` permits one
  copied reservation and exhausts capacity on the second.

The fixtures fill the actual shared pool with unrelated unpublished imports.
No allocator limit, retry count, timeout, or execution concurrency changes.
On unchanged `5edb380d5` production code all three fail with errno **5**, expected
**11**. After the correction they require `MmError::MetadataRequired`, unchanged
parent generation, full parent descriptor rollback, no admitted child or copied
child mappings, and a closed child gate. Returning the unrelated imports' actual
metadata permits the same exact fork request to publish and abort successfully.

`fork_refusals_preserve_original_mm_error_and_errno` compares all nine variants
through the new boundary against the pre-extraction direct conversion. It is
red on `5edb380d5` (`Core` versus `Reservation(Invalid)`) and green after the fix.

Commands and raw logs are recorded in `target/x86-b4-review/`. This Linux
worker proves VM-free portal behavior; signed ARM/HVF and Docker acceptance
remain with the director. No runtime timing claim is made.
