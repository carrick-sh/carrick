# Delayed metadata grant return (#1572)

The `kernel.el1.metadata-allocation` invariant includes grants that arrive
when their original allocation demand has disappeared. A carrier-wide mailbox
response can be consumed by another participant's deallocation or drain.
Admission creates an Active extent with zero live allocations. Previously,
only deallocation changed an extent to PendingReturn, so a grant that was
never allocated remained resident after drain reported no work. This explains
a missing return without a wrong-participant FREE or a lost host completion.
It is an ordering-dependent allocator lifetime defect; this reduction does
not establish which historical signed change first exposed it.

Return selection now includes empty Active dynamic extents. It removes the
whole free block from the segregated bins before changing it to PendingReturn;
mailbox contention retains that state for the next ordinary boundary. Exact
base, size, token and descriptor identity still authenticate completion. Live
grants and bootstrap storage are excluded. Selection scans the same fixed
128-descriptor table as the previous pending-return selector, with one
constant-time free-list unlink for an unused grant. No retry, wait budget or
concurrency change is required.

`MetadataStorage::allocate` consumes the response, attempts allocation, then
selects returns. This gives newly requested capacity first use. Deallocation
and drain have no such demand and can immediately select an unused grant.
The native tests inject only a mailbox and omit the unavailable EL1 zone
mapping and pending-host-work mark; allocation, response consumption,
deallocation, return selection and wire request identity use production code.

The deterministic production-path witness
`delayed_grant_consumed_by_last_deallocation_returns_both_extents` holds one
extent live, publishes a second capacity request, delays its response until
the first allocation's final deallocation, and requires FREE for both tokens.
`allocation_uses_fresh_grant_before_return_selection` requires a capacity miss
to succeed on its delivered grant before any FREE can be published. Core
bindings additionally require exact-once return, removal from allocatable
bins and preservation of live and bootstrap extents.

This VM-free reduction cannot prove vCPU parking, stage-2 unmapping or signed
fixture completion. Final acceptance still requires the original signed HVF
test and two consecutive main signed runs. There is no Docker comparison for
this internal allocator operation.

On the admitted main's return-selection implementation, the production-path
witness fails deterministically at its second request claim: `both grants must
return, including the never-allocated response`. It first returns token 71;
token 72 remains Active and empty. With the correction it returns both tokens
and ends with zero active extents. Restoring the old service-before-allocation
ordering with the new selector fails `requesting attempt must get first use`.
The unchanged admitted-main suites pass 174 core and 114 native EL1 tests;
the candidate passes 176 and 116 respectively, with no failures and no tests
in either serial-host partition. These are native observations, not signed
acceptance receipts.
