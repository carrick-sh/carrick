# Descriptor admission and failed exec — 2026-09-17

Status: descriptor admission and post-no-return exec settlement are corrected
and independently verified through the probe and smoke rungs. The full gate is
red on the remaining conformance population, so no full acceptance is claimed.

## Discovery

The fresh 2,127-row [Unicode pathname batch](2026-09-17-unicode-path-amplification.md)
exposed two resource-failure paths worth reducing. `ltp-open04` reports ENFILE
(23) where its guest descriptor-limit test expects EMFILE (24). The same
assertion is present in the earlier run, so this is not attributed to the
pathname change. `ltp-file_attr05` instead crashed after host ENFILE during
private executable artifact creation. Its failed exec then returned without
execution lease authority, attempted to settle an already exited predecessor,
and lost an executor worker; another worker subsequently failed an ASID
retirement broadcast because that worker's command channel had closed.

The file_attr05 Docker run lacks its required device and reports TBROK. That
limits differential test acceptance, but does not excuse a carrier crash.
Focused reruns did not reproduce the full-load crash. The original raw evidence
is preserved at `target/conformance/raw/conf-54276-c341.{out,err}`; its absence
of normal result metadata remains an original ledger provenance gap.

## Bounded descriptor reduction

A pinned CPython image lowers only its guest soft RLIMIT_NOFILE to eight,
fills the small guest table, then tries to truncate an existing file, create a
new one, and open a missing path. It restores the soft limit and examines the
filesystem before cleanup. No host limit is changed or host-wide descriptor
exhaustion attempted.

| Observation | Carrick | Native ARM64 Docker |
| --- | --- | --- |
| Rejected truncate errno | EMFILE (24) | EMFILE (24) |
| Existing bytes afterward | Empty | `preserve` |
| Rejected create errno | EMFILE (24) | EMFILE (24) |
| New pathname afterward | Exists | Absent |
| Missing-path errno with full table | ENOENT (2) | EMFILE (24) |

The assertion-bearing two-phase run is `nofile-red.jsonl`, with Carrick run ID
`conf-64750-c00` and Docker run ID `conf-64750-d00`. It records Carrick failure
and Docker success. The harness classifies an unbaselined custom suite as
non-gating NEW, so its zero process status does not mean conformance. An earlier
print-only diagnostic also returned zero on both sides: the shell verdict
checks exit status, not stdout equality. Its output was read directly; the
assertion-bearing reduction is the red proof.

The new VM-free backend reproduces all three defects on both memory and host
filesystems. Tests-only commit `365b7651189e3f2e29ec9289b92bce6afa19c2ba`
contains six failing tests and three passing controls for slot reuse, failed
path lookup, and forked limits/tables. The director independently reran it:
3 passed, 6 failed. The operation currently installs its guest descriptor only
after filesystem side effects; admission must precede them.

## Reservation and continuation contract

An early capacity check alone is racy. The operation must atomically reserve a
specific slot in its exact FileTable before pathname work, commit that slot on
success, and release it on failure or cancellation. A reservation is not a live
file descriptor and must not appear in descriptor enumeration or be inherited
as an occupied slot by fork. Other allocation paths must exclude reservations.

A separate bounded native ARM64 Docker check confirms the blocked-open rule:
while a thread is blocked in FIFO openat, slot 3 is reserved, `dup2(0, 3)` returns
EBUSY (16), and the completed open returns slot 3 after its peer arrives. The
check observes the thread in arm64 openat via `/proc/self/task/<tid>/syscall`
and bounds synchronization at five seconds. The retained open continuation
must carry its reservation across parking and cancellation; a loose thread
stash or a fresh admission on redispatch is insufficient. The additional
tests-only commit `521d5bd73` exposes the reserved-slot collision through the
new backend: `dup3(0, 3, 0)` succeeds on Carrick instead of returning EBUSY.
The director independently replayed that failure. The test still needs an
explicit successful-reader completion check before it can qualify the fix.

## Failed-exec ownership contract

The predecessor execution lease is consumed before a fallible image
replacement; a successor lease is published later. The outer executor worker
currently requires a live lease unconditionally when a quantum returns. A
post-publication failure therefore needs authenticated terminal ownership for
the consumed predecessor, including exact thread, execution generation, and
executor identity. Treating any missing lease or any Exited state as success
would hide genuine authority loss. Validation must exercise production exec
failure through worker settlement, preserve guest SIGSEGV, keep another task
and ASID broadcasts working, and leave pool shutdown clean.

## Signed pre-fix exec reproduction

An isolated signed build at tests-only commit
`18ffd4fba6666abc72d2d3b62458373d595b1dc0` adds the path-qualified
`image-replace@/bin/true` diagnostic hook without correcting production
ownership. Its SHA-256 is
`de66e30d4e03a94725ba22e1cc656c7494cd8c05e05a3810ae74f537028a2127`,
CDHash `8f69897d1c46eff629b82bdc15cd06179d6eb7c5`, and LC_UUID
`30D2E0AD-C235-346A-A5DF-57C05BD8D2B1`. Entitlement, DOF presence and strict
signature verification are recorded in `exec-red/artifact.json`. The PATH's
non-Apple dwarfdump rejected `--uuid`; LC_UUID was read from the Mach-O load
commands instead, and the failed tool output is retained.

The control (`eco-exec-red-control-20260917`) successfully execs `/bin/true`,
reaps it, then execs `/bin/echo` in another child and exits zero. The same
workload with injection (`eco-exec-red-injected-20260917`) aborts with host
SIGABRT (subprocess return -6). Its stderr repeats the exact missing-lease and
invalid settlement-from-Exited chain, then reports an active HVPatch inventory
dropped before exact retirement. The empty stdout is a crash outcome, not
proof the guest did not run. No host resource exhaustion is involved.
The native ARM64 Docker control exits zero with identical stdout. Scoped
cleanup reports zero remaining processes for both Carrick run IDs. This is a
red reproduction, not acceptance of either candidate correction.

The same signed artifact separates the failure stages:

| Injected point | Pre-fix result | Follow-on exec |
| --- | --- | --- |
| replacement inventory reservation | child SIGSEGV as required | succeeds |
| begin frame inventory | child SIGSEGV as required | succeeds |
| image replacement | carrier SIGABRT after missing-lease settlement | never reached |
| identity-page publication | carrier SIGABRT during successor retarget | never reached |

The `old-capacity` setting did not arm for this workload: `/bin/true` exited
normally, so the diagnostic script's injected-failure assertion exited one.
It is not counted as evidence for either outcome. This stage split rules out a
blanket interpretation of missing execution authority; the replacement and
begin-inventory paths already terminate the child and keep the worker pool
usable on the uncorrected binary, while the later two paths require distinct
pre-commit and post-commit ownership settlement.

## Corrections and production validation

Descriptor admission now reserves a typed slot in the exact file table before
filesystem side effects, commits it on success, and releases it on failure or
cancellation. Retirement rejects late commits, and the retained blocking-open
continuation owns its reservation across park/resume. The red descriptor and
`dup3(...)=EBUSY` tests are green, including fork/table isolation and slot reuse.

The exec crash had a second, narrower cause after predecessor-MM retention was
corrected. A post-no-return failure returned terminal SIGSEGV while the trapped
syscall continuation was still installed. `detach_loaded_task` then attempted
ASID invalidation with that continuation present; settlement dropped the active
task-only MM authority and the resulting fatal masked the injected exec error.
The threaded-engine contract now has an explicit terminal-continuation discard:
AArch64 consumes the mailbox continuation and clears pending syscall/fault
state, while x86 clears its pending resume/sysret fields. The post-no-return
failure path invokes it before SIGSEGV settlement. A red production-shaped
runtime test required exactly one discard before the implementation and is
green afterward.

Implementation and inventory commits:

- `e4f799155` — keep failed exec on the predecessor MM.
- `7ef39686a` — discard terminal exec continuations.
- `300e1d96d`, `16f6ecbb5`, `843c9afbb`, and `7a678c866` — reconcile the
  authority and inventory ledgers for those contracts.

The corrected signed artifact has source
`7a678c8663231cfa7270568634d4d6a812add709`, SHA-256
`a8fca0a4f7152c6180af5d9e2da8a8ce915aebb9dfbb96d4d9628cf648ac22eb`,
CDHash `58a29e25e731201c801a1e5becad23b4370fe39f`, and LC_UUID
`ACFB28BF-E390-3AD9-B5ED-45B726098648`. Its signature identifier is
`carrick.tmp.99180`; strict signature verification, Hypervisor entitlement, and
`__dof_carrick` presence all pass.

The production five-point matrix is
`target/conformance/eco-fd-exec-20260917/fixed-after-image-replace/exec-failure-matrix.json`.
For replacement-reservation, begin-inventory, image-replace, and identity-page
injection, the first child dies with guest SIGSEGV 11, a follow-on exec succeeds,
the parent completes, and scoped cleanup reports zero processes. The control
execs both children normally. No run emits the earlier fatal or retained-
continuation signature.

`just ci` is green. The unchanged signed artifact passed
`just --no-deps conformance-probes` and the 23-row smoke gate. Its 2,127-row
full gate then exited one with 15 current gating verdicts. One is `execve03`, a
separate pre-return pathname-ordering defect: the overlong-path case returns
`ENOENT` instead of `ENAMETOOLONG`, while its other five errno cases pass. The
serialized focused rerun in
`target/conformance/exec-priority-attribution-20260917.jsonl` reproduces it.
That row does not invalidate the post-no-return crash correction, but it blocks
full promotion and is being fixed forward without a gap or retry.

## Scope and evidence

The small guest-limit defect and the host-wide ENFILE exposure are distinct.
Fixing admission ordering does not remove host descriptor amplification or
establish that a guest's full advertised descriptor limit can be backed.
No performance improvement or closure of ltp-open04 is claimed here.

Local diagnostic evidence is in `target/conformance/eco-fd-exec-20260917/`.
The pinned image is
`localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30`.
The diagnostic Carrick binary has source `5b4a20661`, SHA-256
`1f03f7fd5eb215ae99382bacc2014cd8e18b819a837c53ca0dcc00dae76f9656`,
CDHash `d9efcc76f474aa13f58b91f48fc842aac4c6d559`, and LC_UUID
`6B46AFD4-4806-3308-9B75-34CC72AE3A39`; its signed provenance is recorded in
the preceding batch. These receipts describe discovery, not a corrected build.
