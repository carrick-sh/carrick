# Native anonymous discard needs the physical return owner

Part of #1035. This is a diagnostic slice, not a runtime fix. The director
requested an ignored real-fork witness and this design handoff if integrating
the shared physical owner would exceed approximately 1,500 changed lines.
The signed `el1_anonymous_discard_and_exit_return_frames` remains unresolved.

## Existing behavior

Source inspected: main `8f895a44b27168806d050289b5bd599b892dedfb`.

The host dispatcher in `crates/carrick-kernel/src/dispatch/mem/madvise.rs`
validates alignment, advice, mapped segments and locked ranges. For each
private anonymous segment, it calls `CurrentMmMemory::discard_private_anonymous`
and falls back to COW-safe backing zeroing only if the backend declines that
operation. Discard preserves VMA permissions, including read-only mappings.
Shared backing is never zeroed. Covered segments are processed before an
unmapped hole produces ENOMEM (12); locked ranges produce EINVAL (22).

`crates/carrick-aarch64/src/engine.rs::discard_private_anonymous` prepares
exact-MM alias retirement, retires the stage-1 range, commits backing retirement
and publishes fresh-zero deferred provenance. The HVF adapter in
`crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` prepares and commits process
alias retirement with the exact MM. Neighboring pages in a host frame and
fork peers retain their own aliases. There is no scrub of a shared COW source.

Native Linux routing has no madvise family in
`crates/carrick-personality-linux/src/dispatch.rs::route_shared`, and the
reservation decoder in `crates/carrick-el1/src/memory.rs` has no madvise case.
The native ARM boundary turns the resulting forwarded SVC into
`ServiceOperation::Crossing` in
`crates/carrick-el1-linux/src/dispatch.rs::native_service_operation`.
`NativeService::refuse` in
`crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs` refuses unsupported
services without host syscall replay. The retained native continuation in
`crates/carrick-el1-linux/src/native_process_runtime/service.rs` converts
`Crossing + Refused` to ENOSYS (38).

The ARM crossing allowlist still describes madvise as a temporary host
crossing. That does not supply a native service. This PR changes neither
`crossing.rs` nor `arm-ring-first-flip.tsv`. A future service must complete
in ring or remain unrouted, without a Forward fallback.

## Why neither decommit nor a routing change is a fix

`Reservations::decommit_range` in
`crates/carrick-core/src/mm/reservation/root.rs` publishes protection NONE.
MADV_DONTNEED must preserve each VMA's protection and attributes, and arrange
zero-fill on the next permitted touch. Decommit cannot stand in for discard.

`serve_delegated_anonymous` retires resident mappings with an owed-return
journal. `complete_deferring_return` explicitly leaves stage-2 and inventory
custody retained until host acknowledgment. The legacy reconciliation owner,
`crates/carrick-kernel/src/dispatch/mem/el1_reservations/returns.rs`, performs
backend unmap, host metadata cleanup and sequence acknowledgment under the MM
mutation authority. Its cleanup also removes mapping metadata: a retained
discard VMA needs a distinct, explicit preservation rule.

Native `CarrierWork` handling in
`crates/carrick-runtime/src/vcpu_loop/executor/backend.rs::finish_native_service`
only calls `settle_host_work_boundary` and acknowledges work. That boundary
settles ledger/wake work; it never invokes `reconcile_el1_deferred_returns`.
Native child physical custody instead belongs to the existing fork-stock
owner, with supplied backing retained in `NativePhysicalGrants`. Routing a
discard to the legacy retirement editor would therefore not establish physical
return or correct next-touch behavior. A journal entry is not a returned frame.

## Shared owner and the #1030 design

The approved design is
[`docs/design/anonymous-reservation-supply.md` on `work/fix-898-slope`](https://github.com/carrick-sh/carrick/blob/work/fix-898-slope/docs/design/anonymous-reservation-supply.md).
The inspected revision names **proposed**, not implemented,
`PrivateSupplyTransaction`, `stage_backing_reply` and `settle_backing_reply`.
Main has `NativePhysicalGrants::retain_backing` and descriptor-table settlement;
those do not provide the combined backing-reply transaction.

The design already requires per-MM private stock, owned physical settlement,
retained masks for partial chunks, owed-return exclusion, MAP_FIXED/unmap
retirement, lifecycle cancellation and exact-generation release. It therefore
covers returns as a lifecycle requirement. It needs a concrete **native discard
and return transaction** section specifying the retained-VMA case and its
request, apply, acknowledgment and cancellation receipts. Discard must extend
that owner, rather than acquire a second native return journal.

The neutral physical transaction owner should own native return reconciliation,
alongside supply settlement. The existing fork-stock owner retains each native
child's exact physical custody; the host dispatcher and both ISA adapters
consume the same neutral discard/return operation. The backend applies
stage-2 and inventory changes, never decides discard policy or frame eligibility.
The required transaction is:

These publication/rollback boundaries govern each admitted backing operation,
not whole-syscall atomicity. Linux's covered-segment effects before an unmapped
hole must survive the final ENOMEM (12); clean transaction rollback must not
undo those already completed segments.

1. Admit the exact MM incarnation, root generation, operation sequence and
   range under its editor. Validate private anonymous coverage, locks and
   each VMA's permissions/attributes. Reserve undo and return capacity before
   any descriptor or ownership mutation.
2. Retire only this MM's translations and residency/adoption masks; invalidate
   translations before retiring backing. Preserve the VMA and publish a fresh
   backing incarnation, with no shared-zero source. Keep parent COW edges and
   surviving neighboring 4 KiB pages within a 16 KiB compound frame intact.
3. Settle stage-2, inventory and allocation custody through the same owned
   transaction used by `settle_backing_reply`. Return only this MM's retired
   aliases. Release an allocation only when no peer, retained subpage, pin or
   unsettled receipt owns it. A shared frame is not freed by child discard.
4. Authenticate the apply/settlement receipt before acknowledgment. Next touch
   obtains private zero backing through the existing supply owner, retaining
   the VMA's original access ceiling. Duplicate or stale receipts cannot
   release a peer's bytes or attach backing to a successor.
5. On clean failure, restore the root, descriptors, residency, stage-2 and
   inventory preimage together. On indeterminate undo, retain custody and
   quarantine through the neutral retirement owner; never acknowledge success.

This depends on the physical reply transaction, exact per-page return masks,
retained-VMA publication, both ISA adapters and failure/duplicate/lifecycle
witnesses. That is broader than a justified 1,500-line correction on main.
No part of that unimplemented protocol is enabled in this diagnostic PR.

## Witnesses and limits

`owner_fork_child_dontneed_must_select_discard_with_two_live_mms` performs the
production fork census, preparation, COW descriptor publication and child
admission. It verifies two live roots sharing two non-identity COW outputs,
then asks the production decoder to admit the child's discard. It is ignored
with a #1035 reason at the director's request and fails explicitly when selected:

```sh
cargo test -p carrick-el1-linux --lib owner_fork_child_dontneed_must_select_discard_with_two_live_mms -- --ignored --nocapture
```

`native_child_madvise_crossing_refusal_returns_enosys` uses the existing
two-native-child service fixture. It checks routing, parks the native owners,
refuses one real Crossing request, cancels the other, and resumes both retained
continuations. It requires ENOSYS (38) and EINTR (4), respectively. This is a
characterization test, not acceptance of ENOSYS as correct discard behavior.

The first witness does not execute physical discard, zero-fill, byte readback,
stage-2 release or inventory return. The second does not run the complete
guest syscall dispatcher or a VMM. Neither proves frame-accounting acceptance.
They localize the missing operation without inventing a physical return service.

The eventual enabled binding must retain two live MMs, write distinct nonzero
contents before real fork, discard in the child, read zeros in the child and
unchanged bytes in the parent, then exit in both orders. It must count exact
live aliases, retained subpages and released allocations after each settlement,
including a partial compound frame, mixed protections, holes, failures and
duplicate/stale completion. No COW source scrub or per-page replacement copy
is permitted. Signed execution of the original fixture and Linux differential
remain director gates; this Linux worker has neither HVF nor Docker.
