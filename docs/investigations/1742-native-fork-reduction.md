# Native fork refusal reduction for #1742

The reported signed `go version` failure is **not reproduced or fixed** by
this investigation. The native suite passes, but its passing result does not
identify which authority moved in the failing signed run. No production
refusal policy has been changed.

## What the native controls establish

`just test-el1-native` completed with 732 passed, zero failed and one ignored.
This includes `vfork_parent_stays_suspended_until_child_execs_or_exits`,
the production AArch64 fork-service tests, and the tests that deliberately
refuse commit, omit its reply, or fail its crossing. Those commit controls
verify that a refused settlement keeps the child's space closed; they do
not establish why a real settlement refuses.

The current vfork implementation gives the child a distinct COW MM and
retains the requested stack address. See `ProcessForkChildTid::vfork` in
`crates/carrick-personality-linux/src/lifecycle.rs` and the vfork test in
`crates/carrick-el1-linux/src/native_process_runtime.rs`. A shared stack
address must not be mistaken for evidence of shared writable stack backing.
The runtime-only `host_test_support::Physical` substitutes MM preparation,
commit and settlement; it cannot validate physical fork admission.

## Two different generation checks

The production AArch64 service snapshots the reservation root's policy
generation and operation sequence while holding the parent editor in
`Aarch64NativeProcessService::prepare_mm`. It releases that editor before
crossing for the stock loan. `NativeForkPortal::prepare_fork` subsequently
checks the root incarnation, policy generation and operation sequence
(`crates/carrick-el1-linux/src/mm_portal/fork.rs:302`). A mismatch there
returns `MmError::Stale`. Publication also checks the descriptor observations
and those identities in `PreparedOwnerFork::publish`
(`crates/carrick-core/src/mm/fork.rs:354`). The reported `Prepare` or
`Publish` stage does not distinguish these checks by itself. An edit in
that interval is a candidate explanation, not an observed root cause.

Stock settlement uses a different identity. `ForkStock::settlement_loan`
compares the loan's `GrantExecution` with the execution supplied at settlement.
`GrantExecution::matches` compares CPU, execution binding and the complete
address context. Its context generation is the root incarnation, not the
reservation policy generation. These generations must not be substituted
for each other to make a refusal disappear.

`ForkCustodyRefused` also has two callers in `fork_publish`: a failed
`release_birth` and a failed `settle_mm`. The fatal name alone does not prove
that the stock service rejected an execution identity.

## What the current reduction does not exercise

The physical-stock native fixture captures `GrantExecution` from the loan
request in `PhysicalStock::loan`. Both `reserve` and `commit` reuse that
captured value (`aarch64_process_tests/native_retirement_tests.rs:215`,
`:233`, `:265`). The nonphysical crossing directly accepts settlement.
Neither path independently reconstructs execution from the stopped carrier.

On the Mac, `service_native_fork_stock` instead reconstructs execution on
each crossing through `stopped_execution`, `root_execution` and
`diagnostic_identity` in `crates/carrick-vmm-hvf/src/metadata_grant.rs`.
That observes the executor's current task binding, installed MM grant and
hardware root. This entry point is macOS/AArch64-only. The Linux native
fixture also does not execute Go instructions, the vfork stack accesses,
or the carrier's live table/backing resolution.

No deterministic two-live-process schedule that performs a legitimate
parent policy edit between census and birth settlement was added or run.
Consequently this investigation supplies neither the requested red witness
nor evidence that live execution reauthentication is the failing check.
Forcing a different generation into a fixture would only test rejection
of a forged context and would not establish the reported defect.

## Signed handoff

The director's evidence under `/Volumes/CaseSensitive/carrick-evidence/1733/`
is not available on this Linux runner. Use the existing bounded
`scripts/dtrace/native-fork-refusal.d` profile through `carrick trace` on the
director's signed artifact. Its stock-refusal records already contain
requested and cached bindings and contexts. Preserve both workload streams
and the failing run's fatal record; distinguish birth-reservation release
from stock settlement before changing either authority.

For a preparation/publication failure, the remaining observation is which
of incarnation, policy generation, operation sequence or descriptor read
set differs, and which real operation changed it. Reduce that operation
with two live processes through the production native service. For a stock
failure, reproduce the observed requested/cached execution difference rather
than unconditionally accepting or refreshing a stale context.

HVF execution and the required signed 10/10 population remain unrun. Docker
is unavailable here. `/dev/kvm` exists, but KVM guest execution was not used
as evidence for this ARM/HVF failure. This document changes no guest
behavior or work budget; existing fork contracts remain required.
