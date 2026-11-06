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

## Cross-crate lock order requiring review

The proposed nesting is exact-MM execution exclusion, exact-MM mapping/copy
admission, then process-graph birth publication. Birth's scheduler enqueue
must remain after release of the process graph guard, as it is today.
Runnable execution stays barred until aggregate settlement.

This order is a proposal, not a verified lock order. In particular,
`publish_born` may acquire process-owner and scheduler authorities, whereas
the memory owner has reservation-root/editor and completion authorities.
Neither memory supply nor graph admission may wait for a peer while holding
a lock that peer needs to acknowledge exclusion. A Busy admission retains the
owned operation and enrolls on the existing release source before probing;
it must not spin, return errno or enlarge the executor pool.

The existing host exact-MM pause in
`carrick-kernel/src/dispatch/mm_quiesce.rs` drains occupancy and holds its
fence, but is not an in-ring aggregate-copy capability. Wiring a host-only
pause into the clone owner would create another execution path. The neutral
owner needs an ISA-independent protocol with ARM and CPL0 mechanics before
this design can be claimed implemented.

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
