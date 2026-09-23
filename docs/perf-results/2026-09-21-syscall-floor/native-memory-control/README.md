# Native carrier memory control and bounded ELF composition

Native execution now completes a real carrier COW mutation while admitted, and
a bounded ELF performs **169 carrier load/add/store operations, memory-control
safe points and `close(-1)` dispatches** at scales 1/8/32/128. The old COW path
aborted; the old private-backed ELF executor left the carrier bytes unchanged.
Both failures were captured before their respective corrections.

This closes two execution-composition gaps. It supplies **no new inotify09,
Node/Go/Python speedup or Linux ratio**. The prior activation timing remains a
measurement of the prior artifact; this continuation is not a new timing run.
The 1x goal remains open.

## COW pause membership

An exact-MM pause must drain every executing native or hardware endpoint.
Hardware invalidation acknowledgements have a smaller population: native
execution has no hardware TLB and cannot acknowledge an ASID ticket. Previously
`publish_foreign_cow_invalidation` used every pause endpoint as an expected
hardware acknowledgement. Even an idle admitted native endpoint made both COW
publication and rollback time out; rollback raised a fatal carrier error.

The census now provides a separate hardware-invalidation projection. Admission,
running flags and the all-endpoint drain are unchanged. Native entries never
create hardware residency or consume pending ASID tickets. The production COW
fixture passes with 1/8/32/128 native participants, including a historical
hardware resident on the same executor whose ticket remains pending through
native execution. The mixed native/hardware fixture still invokes the hardware
owner's invalidation callback exactly once and clears its ticket.

[Red COW execution](red-cow-execution.log) captures SIGABRT in the rollback path;
its exact executable is retained under `target/lease-cost/native-memory-control`.
The initial compile errors remain archived separately and are not red execution
evidence.

## Native memory-control service

Native census kicks now set a memory-pause bit distinct from an external stop.
The host service authenticates the execution lease and exact endpoint, parks on
the existing exact-MM condition variable if a pause is active, authenticates
again, and clears only the memory bit. It neither fabricates hardware receipts
nor delivers signals/fork/cancellation. Entry still performs the existing
publish-before-check running handshake, so a new pause racing with service
cannot be bypassed. Mutable admission borrowing prevents an active data grant
from surviving into this wait.

The first implementation locked the wait state even without a pause and failed
`kernel.mm.native-execution-scope` with **one allocation at scale 1**. The final
service checks the barrier first; entry, external-stop observation, no-pause
memory service and acknowledgement allocate **zero at all four scales**, with
the allocator positive control retained. No warmup, budget, timeout, retry or
concurrency setting was changed to obtain that result.

The kernel tests cover an active pause and wake, sticky requests after a failed
drain, external-stop preservation, wrong execution leases, admission replacement,
unwind cleanup and simultaneous native readers. The existing condition variable
implements waiting; there is no new polling loop.

## Actual ELF data path

The research executor has one new method taking a borrowed `ActiveNativeData`.
It validates the immutable ELF publication and requires the grant to match the
entire declared writable data segment. Emitted scalar accesses use the grant's
carrier pointer only for that bounded interval. SVC, a slow operation, or a
backedge checkpoint returns to the host; the pointer is cleared before return.
There is no private-memory fallback or in-scope dispatch callback.

The test executes an ELF containing `ldr w9,[x2]`, `add w9,w9,#1`,
`str w9,[x2]`, `svc #0`. Each iteration:

1. Enters the exact native scope and activates the production COW span.
2. Requests a real zero-budget drain while the scope is live and proves refusal.
3. Executes the ELF to its SVC checkpoint, then ends the grant and scope.
4. Services the sticky memory request and dispatches `close(-1)` through the
   ordinary admitted kernel path, observing Linux errno **9 (`EBADF`)**.
5. Reads the actual carrier bytes through the foreign-MM API and verifies the
   increment, then restores the same stage-1 image under mutation exclusion so
   the next activation must revalidate its changed generation.

There are 169 completed increments and dispatches. The original COW source
remains `same`, and the private ELF data segment remains zero. Complete-access
boundary misses at offsets +5/+8 and `u64::MAX` checkpoint before the load and
preserve its destination. A wrong code owner, revoked private text publication,
and revoked carrier write permission are refused.

[Red ELF execution](red-elf-execution.log) proves the old private-backed path
cannot satisfy the carrier-byte assertion. The final generated ELF and source
revision are retained with the final receipts.

This is a **host execution fixture with production carrier COW and mocked
stage-2 operations**. Text still has a private immutable research publication.
`close(-1)` has no guest buffer; its use does not validate carrier-backed syscall
buffers. It is not signed native guest acceptance, real `mprotect`/fork syscall
coverage, general code publication, or a complete native executor.

The diagnostic crate remains excluded from the main workspace and is a macOS
AArch64 **dev dependency** of runtime tests. The product dependency/feature
layering check passes. Its old 20 ELF controls still use private data backing.

## Contracts, validation and limits

The existing `kernel.mm.native-execution-scope` and
`kernel.mm.native-data-activation` descriptors now name these supplemental host
composition tests. Their registered work-budget runners remain unchanged in
scope except for inclusion of no-pause memory service in the scope contract.
Both zero-allocation and zero-repeated-leaf-check budgets remain unchanged.
Higher execution bindings remain unresolved; supplemental semantics are not
promoted to a signed contract pass.

- Final runtime memory composition: **29 pass**, one diagnostic ignored. The
  nested subprocess success is not double-counted. This includes mixed COW,
  carrier ELF, revocation and zero-allocation/leaf-check activation controls.
- Runtime hardware quiescence: **27 pass**.
- Separately completed kernel semantic suites: **257 pass**, including the
  zero-allocation native scope/memory-service contract at all four scales.
- Compile-fail lifetime controls: **four memory and two execution-scope pass**.
- Existing private-backed ELF controls: **20 cases pass**, plus **11 unit
  tests**; all 20 complete 560-byte output streams and exit/count reports are
  retained. They are not relabeled as carrier-backed controls.
- Kernel/runtime changed-package clippy and diagnostic-executor clippy pass.
  Product layering, exact-file formatting and diff whitespace checks pass.
- Contract package: **33 pass**; registry/inventory check: **29 contracts,
  15 claims, 59 surfaces, 338 syscall rows**, unchanged claim/support states.
- Both final work-budget observation sets carry source revision
  `sha256:8375bd73642bca6e4dd0cd6e018412b696508ed5ed40f07cd3c5dcf77bf167e2`, positive controls, complete measurements and no
  unknown/dropped work.

The broad kernel gate is **not green**. Its final run has 2,119 passes, one
failure and one existing ignored test. The failure is the unchanged
`kernel::control::tests::exec_table_capacity_refuses_new_admission`: its 50 ms
admission deadline returns `Unavailable` instead of the expected `Rejected`.
The exact failed executable passes that case in isolation. The earlier kernel
run in this continuation passed all 2,120 kernel tests before failing the new
scope allocation budget. These observations and unchanged source identity
support a timing-sensitive existing test, but the isolated pass does not repair
the failed full gate. No test or timeout was changed; the semantic suites that
the failed recipe did not reach were run separately.

The signed foreign-MM gate remains **73 pass, one fail, one ignored**. Its
existing `kernel.mm.fresh-publication-maintenance` failure is still
`PageTableInvalidations=1`, maximum 0, at scale 1. The unentitled negative control
passes, scoped cleanup reports zero remaining processes for both run IDs, and
no success receipt was issued. The selected signed executable is retained with
SHA-256, CDHash, LC_UUID, hypervisor entitlement and DOF identity. The separate
post-run identity inventory is explicitly **not** a successful execution
receipt; unexecuted helper binaries are identified separately. No signed native
ELF test or new native workload gate is claimed.

Full CI, product probes, smoke/full conformance, signed native execution and
end-to-end native workload acceptance remain uncompleted. No claim or budget is
weakened, and no source commit or push was made.

## Next decisive work

Connect the invalid-call, unchanged-watch and watch-churn ELF controls to this
same carrier data path. That needs an authenticated carrier-backed syscall
buffer adapter: current ELF controls hand `Memory` backed by private vectors to
the dispatcher. Preserve the native scope boundary and release active grants
before dispatch/mutation. Reject unsupported mappings/control rather than
quietly falling back to unrelated private bytes.

Then measure those exact completed controls with matched Linux and native macOS
I/O controls, reporting absolute syscall cost and raw Linux ratios separately.
The current fixture does not justify more work on the remaining activation
nanoseconds. Carrier code publication/revocation, signals, cancellation and
scheduler integration remain explicit requirements before general native
inotify09 or common-workload acceptance.

## Provenance

Worktree: `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`.
Source HEAD: `9bb2392396b8531e93f5262657bf3aa9c5767488` plus the
[13-file continuation patch](implementation.patch). The
[manifest](manifest.json) records final source, exact diagnostic executable,
fixture, test and frozen-control identities. Source archives preserve this
continuation and its parent checkpoint. Raw executables remain under
`target/lease-cost/native-memory-control`; durable receipts and logs are copied
alongside this report. The cumulative parent audit checks 124 source files: 113 unchanged and 11
intentional shared edits, with no unexpected drift. The other two files in this
continuation were preserved directly before editing. All four measured
product/native control executables remain unchanged.
