# Red-first fresh publication contract

The actual production sparse publisher invokes stage-1 maintenance once for a
fresh inaccessible local extent. All scales 1/8/32/128 completed the semantic
assertions before evaluation reported PageTableInvalidations scale1 actual1
maximum0. See test.log. This is the intended structural red, not a build failure.
The earlier setup-error and stale-fixture-snapshot logs are preserved separately.
Publication changes the inventory revision, so the fixture now authenticates the
retained old owner and compares its bytes directly instead of reusing a stale
foreign access snapshot. No guest/runtime retry was added.

The test uses stage-2 mapping stubs and a test authority, but calls the real
publication implementation and counts the supplied maintenance callback. New
backing remains inaccessible, retained outputs exist, and old owner identity and
bytes remain unchanged. This does not prove signed guest semantics, actual HVF
maintenance cost, concurrency correctness or a speedup. No runtime code changed.
The contract is intentionally red in the working tree; no acceptance claim.

Next implementation decision: classify changes against LIVE descriptor preimages
before publication, not intermediate shadow validity. A host-preimage comparison
of dirty descriptors would conservatively retain maintenance for any changed
valid descriptor, including table splits; invalid-to-invalid shadow construction
would not itself require maintenance. It must run while exact-MM exclusion and
pinned table backing are held, before sync. Retain the existing barrier ordering,
rollback maintenance and replacement/foreign paths. Add explicit positive tests
for valid-leaf replacement, permission restriction and structural table changes.
Only then run the fresh-publication contract green and proceed to signed proofs
and paired workload timing. The existing foreign-copyout failure on the rejected
lock experiment remains unattributed and is not waived by this lower-layer test.
