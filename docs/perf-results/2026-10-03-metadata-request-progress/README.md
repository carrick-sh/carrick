# Metadata request progress

The reported decimal failure 3397911809 is `0xCA880501`, not
`0xCA870001`. `metadata_allocator_phase` constructs it after 258 pending
results. It is a fixture progress failure, not a host allocation refusal.

Losing host service boundaries previously returned immediately while the
single-flight owner mapped backing. Merely crossing a host boundary did not
ensure progress: a transaction could consume its finite attempt budget before
that owner completed. The allocator-control adapter now parks its exact zone
record with a request-incarnation operation token, unwinds to the host, and
releases execution capacity through the existing zone-wait continuation.
Completion publishes the response and wakes the admitted records under the
same queue lock. Cancellation unlinks the reserved queue, and re-entry resumes
the original transaction rather than returning a spurious result.

The scheduler tests include a switched slot occupant and exact record wake;
all 91 scheduler-core tests pass. The ABI tests prove admission precedes host
claim, duplicate publication cannot replace the incarnation, and exhaustion
cannot wrap its identity. Allocator search/split/merge budgets, the fixture's
258 attempts, four workers, sixteen rounds, and 30-second watchdog are
unchanged. This adapter change does not claim all production allocation
callers suspend: existing production metadata preflight remains separate.

The initial signed red witness holds the real request owner and observes zero
parked records after 258 losing host boundaries when the new guest park branch
is removed. The workload completes after owner release; that run does not
claim the original workload itself exhausted its attempt budget. Its frozen
executable remains under ignored `target/meta-alloc-evidence/red-el1-sched`:
SHA-256 f5b5da31a9fde5a562a9965d92194e332637b60bd495378a956c66fff0688b00,
CDHash f5540087daba19c895705e08d310684d1e2601a7,
LC_UUID CC32C1D6-7844-3601-9E70-E216FA4BE1FD. The hypervisor entitlement
and DOF section were inspected. A failing wrapper does not publish a standard
successful artifact receipt.

The first attempted verification batch stopped on a new witness timeout.
Characterization exposed an owner claim with zero contender observations.
The test latch initially admitted arbitrary startup requests and observed only
losing boundaries. Its corrected admission selects the barrier-synchronized
10 MiB fixture transaction and observes the winning boundary's record census
as well. That admission-only correction still failed with one parked record:
holding a host executor inside the trap service prevents deterministic admission.
The final feature-only delay injector retains exact carrier metadata access,
returns from the host boundary, and invokes the identical production completion
function from a test-owned thread after monitor release. Both access and service
re-authenticate the generation; a VM-free retirement-after-claim witness rejects
service, publishes an invalid response, and installs no backing. The undelayed
concurrent/growth/IRQ tests remain in the same signed invocation. The monitor
requires three parked records under one fixed observation deadline; unrelated
host-service counts are diagnostic only. Bounded observation failure prints the
observed state and is never acceptance.

All signed invocations use the Carrick host lease and a distinct run ID. The
wrapper's entitlement negative control and scoped cleanup remain required.
No Docker, timeout expansion, pool expansion, or retry-to-green is used.
The director narrowed repeated verification to five focused allocator invocations
plus canonical `just accept`; the initial full EL1 characterization had exactly
the six checked-in known reds (base checkout `a257cdf9d`, not a reproduction
of the original `ce408011c` signed artifact). Final acceptance and its receipt are reported
separately after the final gate.

The final matching red uses the deferred injector: without the guest park
branch it observes zero parked records across 21,950 host-service boundaries
and fails its fixed observation deadline. These are host-service observations,
not a count of allocator attempts. Both scoped cleanup checks report zero.
Its manually inspected signed artifact is described in `signed-red-artifact.json`;
no successful wrapper receipt is invented for the failed run.

Capacity review also found that the whole-zone debug census truncated its
queue bitmap after admission of the reserved queue. The switched-record test
now requests that census while linked: red is an index-64/length-64 panic.
Rounding the bitmap up includes the reserved queue; all 91 core tests pass.

Final five-run proof uses one frozen signed executable, authorized by the
director, with `RUST_TEST_THREADS=1`, unique run IDs and Carrick leases.
All twenty test executions pass, each delayed-owner witness observes at least
three parked records, both cleanup counts are zero, and SHA-256 is unchanged.
The source wrapper also passes its entitlement negative control.

Artifact SHA-256: 37b37c30b4bf2a67c62686221b27aff2e10c8350fb17c883f2d9be1eefb3f7b2
CDHash: 3b5b7ea6ef46fa50171ec317890eea35769927e3
LC_UUID: 9868B07A-38B5-33A7-9936-0342D781E8B5

The source wrapper receipt, artifact identity, five logs/cleanup receipts and
`fixed-five-runs.json` bind the executions explicitly. The fixed-artifact
manifest is a manual binding, not a fabricated wrapper receipt.
Repeated `test-signed.sh` invocations with unchanged Rust sometimes relink every
embed executable (approximately fourteen minutes); this is recorded as tooling
cost, not changed or attributed to the allocator.
