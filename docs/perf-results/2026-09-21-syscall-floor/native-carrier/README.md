# Scoped carrier data grant — 2026-09-22

The approved data grant is implemented. A bounded native AArch64 load/add/store
now runs on real, pinned carrier backing after the existing kernel/carrier COW
transaction. Its bytes are then read through the kernel API, while an explicit
pin proves the original shared backing remains unchanged.

This is an ownership integration result. **No new inotify09 or workload speedup
is claimed.** The experimental ELF executor still uses its own private backing;
its prior 2.12 ns memory-loop and watch-loop timings remain diagnostic results
from [native-memory](../native-memory/README.md). Neither measured release binary
was rebuilt or re-signed here.

Contract: `kernel.execution.native-synchronous-syscall`. Its execution bindings
remain unresolved and its structural budgets are unchanged. The user explicitly
approved [this precise scope](../native-carrier-review/README.md).

## Implementation boundary

`KernelContext::borrow_current_native_data` borrows the actual context,
`ThreadExecutionLease`, mutable `CowBroken` witness and its existing exact-MM
mutation guard. It authenticates task, kernel graph, MM, COW kernel proof, full
range permissions, backend/VMA/inventory revisions and the MM-installed carrier
endpoint. It checks the live snapshot and execution authority again before
returning. No caller-supplied pointer or independent memory object is accepted.

The returned `CurrentNativeData` owns the carrier pin and supplies range metadata
plus an unsafe pointer accessor. It cannot be cloned, copied, sent or shared
across threads. The pointer caller must obey range/lifetime and aliasing rules,
and must not re-enter dispatch, mutate the MM, or publish executable code while
using it. The grant is held only inside an existing COW mutation transaction;
it is not yet a normal concurrent execution permit.

The HAL capability defaults to refusal. The HVF implementation checks every
crossed guest leaf for user RW permission and the full protection range for
write denial. It then reuses prepared-write checks for current stage-1
translation, contiguous physical extent, exact mapping/frame/owner generation
and resident owner pin. A valid foreign-write COW receipt alone cannot grant
native stores. The prepared-copy check sequence is unchanged apart from
extracting a shared helper and replacing source length with an explicit length.

## Evidence and its limits

Focused tests cover:

- Real copied COW, original-backing preservation, subsequent already-private
  identity grants, and equal guest VAs belonging to distinct real MMs.
- Wrong execution lease, another kernel with matching numeric identities, and
  another valid current-MM context paired with the wrong COW witness.
- Execute-only, RX, RWX, inaccessible and read-only VMAs; a changed VMA revision
  even after restoring RW permissions; kernel-hidden VMAs at the kernel layer.
- A range crossing into a read-only or absent second leaf, a denied protection
  range, and changed owner generation without changing semantic VMA permissions.
- Default refusal for a transport that supports COW/prepared copies but cannot
  grant resident pointers; all three stale revision domains reject before any
  prepared copy or commit.
- Compile-time non-Send/non-Sync/non-Clone/non-Copy assertions and compile-fail
  examples for escaping the grant or transferring its borrowed execution lease.

The runtime fixture uses the actual public kernel graph, execution lease, VMA
and frame inventory, carrier transport and COW transaction. It supplies fixture
host backing and stage-2 map operations. Its native instruction check does not
boot or translate a guest ELF. The signed HVF regression is a separate existing
carrier lifecycle test, not a native execution binding.

The saved pre-implementation failure is an **API red only**. A proposed temporary
removal of the leaf guard for a behavioral negative control was rejected by
automatic approval review and never executed. The guard remains present. These
refusal tests are positive evidence of the final implementation, not a claimed
red-against-missing-guard result.

One expanded runtime test initially expected kernel-hidden metadata from a
fixture that only modifies R/W/X bits. Source inspection identified that fixture
limitation. The hidden-VMA check now uses the existing kernel fixture, which can
represent it; the failed run is retained, and no runtime permission check was
weakened to pass the test.

## Attributed campaign failure

The broad signed foreign-MM run completed **74 passing tests and one failing
existing structural contract**: `kernel.mm.fresh-publication-maintenance`,
`PageTableInvalidations`, scale 1, actual 1, maximum 0. The unentitled negative
control passed and run-scoped cleanup reported zero remaining processes. The
signed runner withheld its published success receipt because the suite failed.
This is a failed broader gate, not a green checkpoint.

A paired attribution run used the exact five-file pre-approval backup, then
restored and byte-verified the approved source. The failing sparse-publication
test reproduced **2/2 before and 2/2 after**, with the same metric/scale/value.
The helper's extraction does not account for this pre-existing campaign failure.
No sparse-publication implementation, fixture or budget was changed here.
`source_sha256` maps in `sparse-attribution.json` bind both arms; raw logs remain.

## Final validation

| Check | Result |
|---|---|
| Runtime memory composition | 23 passed |
| Kernel MM authority | 30 passed |
| HAL foreign-MM contract | 1 passed |
| Lifetime examples | 2 compile-fail cases passed; standalone diagnostics confirmed lifetime escape and E0505 lease-transfer rejection |
| Signed HVF carrier lifecycle | 1 passed, unentitled negative control passed, exact receipt and zero-process cleanup retained |
| `just test-kernel` | 2,364 passed across 19 libtest processes, 0 failures; one pre-existing ignored controller-receipt test |
| Existing native executor | 11 passed, including the 12,288-case scalar access differential against checked memory |
| Clippy on the four changed crates, libraries and tests | passed with warnings denied |
| Scoped formatting and whole-worktree diff check | passed |
| Broad signed foreign-MM suite | 74 passed, 1 pre-existing sparse-publication failure; not a green gate |
| Contract checker | registry loaded, then existing inventory drift rejected |

The inventory drift is contract-list metadata on 12 syscall entries. Scratch
inventory generation with the prior archived native-execution descriptor and
with this update produced byte-identical output. The checked-in inventory is
unchanged. Both descriptor variants load; neither registers a native execution
binding. `inventory-attribution.json` records this comparison.

`manifest.json` records source HEAD, all dirty implementation-source hashes,
compiler/host details, unchanged measured executable identities and evidence
hashes. `dirty-source.tar.gz` and `tracked-source.patch` preserve the campaign
source; `implementation.patch` is only the approved five-file delta against the
saved pre-approval source. `contract-status.patch` changes unresolved-status
prose only. The signed lifecycle receipt binds its precise executable SHA,
CDHash, UUID, entitlement and DOF section. It does not attest the native ELF
executor or promote the product CLI.

## Next decisive work

Integrate the same bounded instruction subset with **normal carrier execution
admission and revocation**. The current mutation scope is suitable for proving
backing ownership, but holding it over a workload would serialize that MM and
cannot establish the performance goal. Reuse the existing execution census,
quiescence acknowledgements and cancellation lifecycle so foreign mutation waits
for exactly the active execution and stale backing cannot resume.

Then tie code publication to that authority, including writes through aliases,
foreign writes, unmap, mprotect and exec. Repeat the identical ELF controls with
these real services before expanding the instruction subset. Signal handling,
migratable register/TLS state, concurrent scheduling, signed embed, fixed-work
original inotify09 and Node/Go/Python remain open. Keep raw Linux ratios and the
separate native macOS I/O control visible.

Work is local and uncommitted. No CLI default or execution backend changed.
Full CI and product probe/smoke/full promotion are not claimed.
