# Remove the duplicate shared-repoint descriptor writer

Development on adapter parent `09afdd4c5` under
`kernel.el1.stage1-publication`. This removes one production host writer;
it does not activate descriptor admission or accept checkpoint 2.

The existing engine `repoint_shared_leaf` publishes `map_aliased`, completes
stage-1 maintenance, then calls the backend ownership hook. That hook repeated
the same descriptor write. It now checks the complete expected writable,
executable translation and commits only alias/mapping metadata. Verification
walks terminal spans, so a coarse block does not expand into per-page work.
Physical-owner and backing authentication remain in the existing hook.

The observation verifies the descriptor projection; it does not independently
prove a TLB acknowledgement. Publication and maintenance sequencing remains the
engine caller's obligation. With live-backed tables the manager reads their live
descriptors; the unit fixture uses the manager's owned test image.

Evidence:
- The red test failed with `bookkeeping wrote an unpublished leaf`: the old
  backend repaired a target that its engine caller had never published.
- Green refuses unpublished targets, wrong physical outputs, missing later
  pages and read-only mappings without adding mapping metadata.
- After the fixture models engine publication, it selects Guest descriptor
  ownership (which prohibits host edits). The same production backend hook
  succeeds and retains the covering physical-owner identity for the subpage.
- Focused test, 11 COW backend guard/accounting tests, affected all-target
  Clippy, formatting and diff checks pass; raw logs are retained alongside.

No signed guest run was performed. The fixture proves backend metadata-only
behavior, not actual EL1 publication or end-to-end alias lifecycle acceptance.

Remaining immediate work: the engine private/shared map_aliased callers still
use the host editor. Convert that actual writer through the existing EL1 journal
with authenticated, pinned backing and completion before metadata publication.
An alias-only operation must not copy bytes like CowRepoint. Private bookkeeping
is not a descriptor writer, but its lane guard still needs the caller conversion.
Then replacement/retired/sparse/foreign publication and protection/discard/exec
writers remain. Admission stays disabled. No main advancement or x86 work.
