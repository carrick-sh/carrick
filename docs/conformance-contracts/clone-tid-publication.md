# Clone TID publication transaction (#1719)

Status: design and red regression reduction only. The aggregate transaction
is not implemented. Existing clone refusal behavior remains unchanged;
clone3 remains unrouted. This document does not confer acceptance.

The applicable contract is `kernel.el1.thread-lifecycle`, together with the
exact-owner copy rules of `kernel.memory.owner-wait`. Linux's clone ABI
defines the parent and child TID outputs. The additional Carrick invariant
for #1719 is that a refused birth exposes neither output, and a memory wait
cannot leave an unborn TID visible to another thread.

## Why per-copy preparation cannot satisfy the contract

`TidOutput::capture` reads two preimages. `TidOutputs::publish` writes the
parent and then the child; a later copy or birth refusal restores preimages.
A peer can read the first publication, revoke the second destination's write
access, or update the first word before restoration. Restoration then loses
the peer's store. A CAS avoids some lost updates but cannot prevent the peer
from observing the unborn TID between the two words.

The confirming reviews of [#1697](https://github.com/carrick-sh/carrick/pull/1697)
also identify parked rollback bypass, stale clone3 argument revalidation,
equal-address double restoration, and an alignment restriction introduced by
word CAS. The replacement must not add alignment restrictions to the byte
copy ABI. Unequal, overlapping destinations need byte-range treatment too.

`MmPortal::write_user_bytes` fences one selected page at a time. The fence
ends before another output or child birth. `prepare_user_write` does not
retain a fence. `SpaceEditor` excludes another editor, but a running guest
can still execute ordinary loads and stores. Raising its gate prevents new
installations; it does not itself drain already running peers. Holding only
one of these capabilities across both writes would not prove atomicity.

## Proposed ownership boundary

One owned clone operation should retain decoded inputs, exact execution/MM
identity, both destinations and birth admission across preparation waits.
Preparation uses the existing `UserCopy` / `CopyOutcome` protocol. Before
commit it may return `NotYet`, with no guest output and no retained editor,
physical copy fence, root lock or graph lock. A supply refusal completes this
owned operation without replaying output or invoking a rollback syscall.

Once both destinations have backing, commit must acquire an exact-MM
exclusion that drains peers already executing user instructions and blocks
new entries. It must also exclude sibling kernel copies and mapping edits.
All destination permissions, live translations, mapping incarnations and
physical owner generations must be revalidated under that exclusion.
Preparation before exclusion is only a candidate observation.

The aggregate capability must keep this exclusion until both TID writes and
birth settle. Capture the preimage under the capability, after peers drain;
never restore a preimage captured before admission. Retain both destinations
at once, including all pages of an unaligned four-byte word. Equal
destinations are one byte range. Partially overlapping ranges must preserve
the ordered parent-then-child byte result and restore each original byte
once on refusal.

Continue to move bytes through `UserCopy`. Aggregate admission must authorize
the existing copy implementation rather than installing a raw-pointer or CAS
copy path beside it. A copy cannot park after the first visible store. The
capability must make rollback infallible until birth's irreversible point,
or birth must be prepared far enough that no refusal remains after output.
A broken capability invariant is terminal, not an ordinary clone errno.

The irreversible point is `publish_born`, including graph/credential
publication and runnable enqueue. An observer must not see either TID until
this succeeds; the new child must not run before both words are ready.
Release exact-MM exclusion after settlement, then deliver deferred wakes.

## Revised borrowed admission (review prerequisite)

This is a proposed interface, not an existing capability. The aggregate owner
belongs in the neutral memory transaction layer; Linux retains the clone
arguments and birth operation. ISA adapters provide exclusion acknowledgments
and guarded byte-access mechanics, not a separate publication algorithm.

`AggregateCopyOwner` owns the exact carrier, MM key, MM incarnation, root
generation, execution binding, a unique operation identity, execution-exclusion
custody, mapping/editor custody, and the admitted union of destination bytes.
Its constructor is private to the memory owner. It cannot be cloned or rebuilt
from numeric identities. Acquiring it requires draining existing user execution
and in-flight kernel copies before acquiring the mapping editor. A raised
installation gate alone is not an execution-drain acknowledgment. The caller
must release its own execution occupancy before waiting for the drain.

The owner lends `BorrowedCopyAdmission<'owner>` for one access, including its
intent and checked byte subrange. The borrow cannot outlive, consume, release,
or reopen the aggregate. It is neither `Copy` nor `Clone`, has private fields,
and authenticates the exact owner identity and live editor, not simply a slot
number, matching MM key, or a boolean "already locked" flag. Capturing
preimages, publishing either output and restoring bytes all require this same
borrow. The union contains at most eight bytes across at most four pages;
range construction uses checked arithmetic and merges overlap before capture.

Extend the existing neutral `UserCopy` admission context with an optional
borrowed admission. A scoped adapter borrows both the existing copier and the
aggregate, then implements the same `UserCopy::copy_in` / `copy_out` methods,
returning the same `CopyOutcome`. It is not another memory implementation:
selection, permission checks, translation, physical-owner authentication,
guarded byte access and cursor advancement remain in the current transfer
machinery. The ordinary and borrowed cases join before those checks. The
ordinary case acquires per-copy admission; the borrowed case validates the
loan and borrows the aggregate's existing editor instead of acquiring it again.
The existing owning `ValidatedChunk` must accept a lifetime-bound borrowed
editor custody variant; completing a borrowed chunk cannot release the editor.
This change must cover reads as well as writes, including preimage reads.

The borrowed selector accepts only the gate raise owned by that aggregate.
Another host pause, terminal close or retirement is not bypassed. Authenticate
this with owned gate custody and its generation, never by ignoring all raised
gates or subtracting a raw pause count. A foreign exclusion discovered before
the first store releases aggregate admission and waits on that producer. Once
commit starts, competing exclusions wait for this aggregate's settlement;
terminal cancellation also settles through this owner. No borrowed access may
supply backing, reacquire an editor, enroll a waiter, or return `NotYet` after
the first store. Such a result means the admission invariant is broken and
terminates the run; it is not EFAULT and must not attempt best-effort rollback.

Preparation remains interruptible and uses ordinary `UserCopy` admission. A
`NotYet` retains the original decoded clone/clone3 operation and exact memory
request; before enrollment it releases every aggregate, editor, root, graph
and physical fence. It enrolls on the existing owner dependency and probes
once. On wake it revalidates all ranges and permissions; it never trusts a
pre-park preimage. To avoid waiting on its own gate, final admission either
finds every page already prepared or releases the aggregate before requesting
supply. Mapping contention similarly retains this operation rather than
returning errno. A genuine permission refusal before stores leaves both
outputs untouched.

## Release order, including notification queues

Thread-stock admission is done before aggregate admission and without an
aggregate or process graph guard. Its production `park_object_record` save
closure takes the graph while the member-release object queue is held (in
`native_process_runtime/thread_stock.rs`). Therefore **object queue -> graph**
is an existing lock edge. No transaction path may introduce graph -> object
queue, including a destructor or a notification revision reservation.

After preparation and execution drain, the commit nesting is execution
exclusion -> mapping/copy admission -> graph birth publication. None of those
steps waits while holding a lock needed by a draining peer. Acquisition Busy
releases earlier admission and retains the owned operation on the actual
release source. Birth must reserve all fallible resources before the first
store. The new child can be enqueued only while its execution remains barred.

Settlement, on both success and refusal, has this order:

1. Finish the graph mutation or unwind its unpublished birth, then drop the
   graph guard. No scheduler queue, memory release source, thread-stock
   notification or completion callback runs under that guard.
2. With both exclusions retained, finish output settlement (restore the merged
   byte preimage on refusal) and birth settlement (return the claim/control
   reservation on refusal, or finish Born and runnable enqueue on success).
   Split `lifecycle_admission_settled` into state settlement and owned deferred
   notification custody; its current immediate publication cannot be called
   unchanged. Settle graph-owned state in a fresh short graph scope if needed,
   return its notification intents, and drop that guard before doing queue work.
3. Release mapping/copy admission and its editor without delivering callbacks.
   Return owned release receipts to the aggregate instead. Source revision
   reservation and queue enrollment also happen outside every graph scope.
   Preserve each source's enroll/reprobe ordering: advance its revision before
   the resource becomes available, then release the resource, retaining the
   publish receipt. Do not wake first and hope the waiter retries.
4. Release execution exclusion, preserving other owners' gate raises. Retain
   its release receipt too. At this point peers and the child may execute and
   all final output and birth state is settled.
5. Deliver the deferred memory, execution, stock, exit and runnable wake
   notifications through their existing queues. Callbacks can now reenter the
   graph or request memory admission. Consume every receipt exactly once;
   dropping the transaction cannot silently discard a promised wake.

`SpaceEditor::drop` currently reserves an Editor notification and publishes
it, and `SpaceExclusion::drop` lowers the gate with notification custody.
Neither destructor provides the above split. Add explicit consuming deferred
release operations to these existing owners; do not suppress notification by
using a source-free venue. The aggregate's unwind path must use the same
settlement state machine and order. Before the first store it may unwind
without output restoration; after that point loss of settlement authority is
a typed terminal invariant failure, never a normal clone result.

The host exact-MM pause in `dispatch/mm_quiesce.rs` is evidence for the needed
drain semantics, not an in-ring capability to import. ARM and CPL0 must share
the neutral aggregate owner and differ only in stop/acknowledgment mechanics.

## Required replacement witness (not yet implemented)

The current reduction below is insufficient for the revised design. Its
replacement must admit both actors through `NativeProcessRuntime` and its
registry with distinct live thread records, control slots and execution
bindings in the same process/MM. Both syscall entries must carry
`process: Some` with authenticated production venues; a `ProcessNative` fake
or a host thread that merely reads fixture atomics does not establish this.
Set both actors' affinity explicitly and bound coordination waits.

Use the production reservation root, live page tables and physical owner
service. Map two writable output pages but leave their backing absent. Drive
clone with both TID flags through normal dispatch and observe the actual
`CopyOutcome::NotYet`, retained clone operation, queue enrollment and released
execution capacity. While it is parked, admit the sibling to read both words
and issue real mprotect and munmap through normal dispatch. The reader's own
fault may materialize backing: record that supply and do not claim both pages
remain unbacked afterward. Protect or replace the selected child mapping,
then restore writable mappings through the production edit completion path.
Resumption must reselect that incarnation rather than reuse a stale grant.

At final aggregate admission, hold a sibling edit attempt on the production
release dependency and verify it cannot complete until output and birth
settlement. The sibling's loads must execute through admitted execution, not
through the test driver's unguarded physical-memory view. After notification
delivery, require successful child birth and both TIDs, exactly one birth,
no replayed output, and no observation of a refused child's TID. A separate
schedule refuses birth after admission and verifies both preimages unchanged,
then admits the waiting edit and a sibling store to prove no stale restoration
can overwrite it. Observe all actor and queue progress before asserting the
expected red result so an early refusal cannot masquerade as contention proof.

A VM-free test can control physical supply and execution acknowledgments but
must use real admission and mapping-edit owners. Signed guest execution must
additionally prove ordinary sibling loads cannot escape exclusion. The test
must fail on the current code because clone refuses `NotYet` instead of
retaining and resuming; it must also distinguish publication escape and lost
sibling stores. No new test is claimed here: constructing this witness is
still a prerequisite before implementation, along with independent review of
this cross-crate lock order.

## Current red reduction and remaining acceptance

`clone_tid_refusal_does_not_erase_a_live_siblings_store` creates a real sibling
through the production clone owner, then drives a second clone through that
owner. A separate host actor uses atomic fixture words to observe the gap,
writes a newer parent value and lets the second copy refuse. Its combined
assertion requires no unborn observation and preservation of that newer
store. Channels have five-second bounds and the actor is joined.

This test injects refusal at the copy boundary. It does not execute the
sibling's guest instructions, call production mprotect, exercise `NotYet`,
or prove a memory-wait resume. It is a reduction of two hazards, not the full
issue acceptance witness. A completed implementation needs:

- two real live threads with both output pages initially unbacked;
- production `NotYet`, enrollment, supply, resume and successful birth;
- a peer reader and production mprotect/unmap at the admission boundary;
- birth refusal after admission with both original byte ranges intact;
- equal, unaligned, partially overlapping and cross-page destinations;
- the same clone3 transaction after a retained decoded-argument snapshot;
- exact-MM isolation from a second live process;
- bounded work proportional to the pages touched, no polling or retries.

Signed embed, CPL0 build, native Linux, KVM and Docker evidence must remain
separate from the VM-free reduction. No current result proves those layers.
