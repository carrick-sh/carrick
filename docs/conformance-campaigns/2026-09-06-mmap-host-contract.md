# macOS private file mmap: host mapping contract

The parked mmap branch is not accepted. File/anonymous timing targets, zero
internal write bytes per whole-file mmap, full serial runtime tests, the mmap/COW
probe family, and the Ubuntu launch receipts remain required before landing.

## Proven copy-fallback cause

The `mmap-lowering-verdict` and `mmap-lowering-error` probes distinguish an
installed view from entry into its installer. On the rebased parked branch
(`0a589a2e9` plus diagnostic probes), the Python loader reaches the installer but
HVF returns `0xfae94001` at its stage-2 map. The dispatcher therefore takes its
byte-snapshot fallback. This code is `HV_ERROR`, not `HV_BAD_ARGUMENT` (the latter
is `0xfae94003`, verified in the installed Hypervisor.framework header).

A signed host-only reducer on the same macOS host maps the same regular file
through different descriptor access modes. It does not run guest code:

| Host mapping | Host descriptor | HVF R / RX / RWX |
| --- | --- | --- |
| shared file, PROT_READ | O_RDWR | all succeed |
| shared file, PROT_READ | O_RDONLY | all return HV_ERROR |
| private file or anonymous | O_RDWR | all tested protections succeed |
| file overlay inside anonymous extent | O_RDWR | succeeds |

Reducing stage-2 RWX to RX did not fix the runtime failure and was reverted.
Neither mixed host extents nor the selected stage-2 permission explains this
failure. The next fix must respect the host mapping authority while preserving
guest read-only descriptors and Linux private clean-page/COW semantics.
Immutable lower file authority must not be made writable as a shortcut.

Director reducer source and transcripts are under main checkout
`target/conformance/eco-final-ledger/hvf-file-map-contract.c` and
`hvf-file-map-{contract,mixed,rofd}.log`. Runs were stamped respectively
`eco-hvf-map-contract-20260906`, `eco-hvf-map-mixed-20260906`, and
`eco-hvf-map-rofd-20260906`; each returned zero after destroying its HVF VM.
These are mapping-contract results, not timing receipts.

## Diagnostic change validation

The outcome probe uses a typed enum. Error messages are formatted only inside
the enabled USDT closure. `scripts/dtrace/trace_lowering_verdict.d` names the
four-argument ABI, rejects DTrace errors, labels an empty capture unusable, and
bounds collection at 25 seconds. Per-event diagnostic printing perturbs failing
mappings; no latency result from this script is accepted.

`cargo check -p carrick-runtime`, signed `just build -p carrick-cli`, and the
live Python `print(1)` diagnostic capture passed. The capture remains RED for
lowering: actual error events confirm the unresolved fallback. Logs are in the
mmap worktree's `target/conformance/eco-mmap-resume/director-instrumentation-*`
and `director-diagnostic-receipt.log`. This is an instrumentation checkpoint,
not a runtime-fix or branch-landing receipt.

## Immutable lower view checkpoint

The VFS now carries immutable-lower provenance with host descriptors from its
cached dentry and immutable absolute-open paths. The memory trait passes that
provenance to HVF; immutable inodes use a host private view, while mutable
inodes retain the shared page-cache view. No writable descriptor is obtained
for the immutable cache. Guest page permissions and Carrick's first-write COW
remain in force.

Signed candidate SHA-256:
`47c2ef6cc8c92270f10c3179c950642e7bc66f0452608feabf994b68c7acb647`.
Python `print(1)` passed and all eight loader lowerings changed from error to
installed. The exact 100-mmap fixture recorded zero internal-copy bytes;
`CARRICK_MMAP_FILE_BACKED=0` on the same binary/fixture recorded 661,504,000
bytes and 161,500 copy chunks. Both selected exactly 100 mmap returns, with no
errors and scoped cleanup reporting zero remaining processes. The trace needs
the service-begin probe enabled before its argument companion will fire.

Receipts in the mmap worktree's `target/conformance/eco-mmap-resume/`:
`immutable-launch.log`, `lazy.{json,out,err}`, `eager.{json,out,err}`,
`mmap-copy-fixture.py`, and `run-mmap-check.py`. The successful run IDs are
`eco-mmap-immutable-lazy-1788712014738617000` and
`eco-mmap-immutable-eager-1788712049506751000`. Compile check, signed build,
and six serial runtime dentry tests passed.

This checkpoint is still NOT ready to land. Untraced five-trial medians for
mmap plus close were 551.981 us (whole libpython file), 610.702 us (6 MiB mutable
file), and 410.885 us (1 MiB anonymous). These fail the requested 10/6 us gate.
The resolved carrier samples identify repeated host arena resolution during
page-table synchronization and whole alias-registry cloning/diffing during
unmap as further amplification. Raw/resolved samples and LLDB image slides are
in `symbol-stacks2.log`, `resolved-stacks.json`, and `profile-images2.lldb.log`.
The full serial runtime suite and whole probe-family acceptance remain pending.


## Page-table publication amplification

The deterministic red-first test resolved one arena 1,122 times for one edit.
The missing-extension test also proved partial descriptor publication before
returning `UnresolvedArena`. `sync_to_host` now preflights each touched arena
once per publication, preserves the dirty journal on resolution failure, and
keeps descriptor order, atomic stores and barriers unchanged. The common case
uses stack storage; extension counts above eight also receive populated-prefix
notifications. No pointer survives this publication call.

Both tests failed before the fix (`pt-resolve-red.log`); all 190 carrick-mem
lib tests passed afterward (`pt-resolve-green.log`). These are host tests,
not the required signed page-table integration acceptance.


Signed `d7920a810` artifact SHA-256
`3841daa9542d26c96060d95c4f7abf159c8144b3da9bc2e871abb424e0b07610`
passed Ubuntu `sh -c /bin/true` and Python `print(1)` with scoped cleanup
(`pt-launch.json`). The unchanged five-trial benchmark measured 352.008 us
whole-file mmap+close and 276.501 us anonymous mmap+close, versus 551.981 and
410.885 us before arena preflight. This is a useful reduction, still a failed
10/6 us gate. Run `eco-mmap-immutable-bench-1788713258061447000`, receipt
`pt-bench.log`; earlier benchmark files are preserved as
`immutable-before-pt-bench.*`.


## Alias unregistration amplification

The full `unregister_alias` wrapper visited 2,052 rows when removing one alias
with 512 unrelated owners live (`unregister-red.log`). The bounded path
snapshots overlapping old keys and possible suffix keys, compares their
first effective rows, and invalidates only changed alias keys plus their old
and new physical replay owners. Replay epochs still advance on an alias-only
change even when replay rows themselves are unchanged. The remaining scope
bucket scan is not claimed constant-time.

The work-count test passes with a bound of 16 visited rows. Thirty split,
full-removal, duplicate-key, suffix-collision and no-op cases compare all alias,
replay and live version state against the old full-snapshot algorithm; overflow
also leaves state untouched. The signed full HVF library suite passed
437 tests with 3 ignored (`hvf-lib-signed.log`, run
`eco-mmap-hvf-lib-1788713559871706000`). Full runtime and probe acceptance,
latency gates and main landing are still pending.


## Handoff after alias checkpoint (Sep 6)

Source `6e6c0393e`, signed artifact SHA-256
`61f9859cb8540c6350012d93b628c4f2301aeab5956fe3fc12c320fc4d276853`:

- Whole-file mmap+close 141.083 us; anonymous 1 MiB mmap+close 70.968 us.
  Same five-trial Python fixture, `alias-bench.{json,out,err}` and
  `alias-bench.log`, run `eco-mmap-immutable-bench-1788713785496764000`.
- Exact 100-map copy contract remains count=100, errors=0,
  write_guest_bytes=0, chunks=0. `alias-copy.log`, run
  `eco-mmap-immutable-lazy-1788713942158072000`.
- Ubuntu shell true and Python print passed again (`alias-launch.{json,log}`).
- Carrier-scoped profile: 218 samples, run
  `eco-mmap-stacks-1788713819884859000`, carrier PID 47153, LLDB image slide
  0x2870000 / load base 0x102870000. `alias-stacks.log`,
  `alias-images.lldb.log`, `alias-resolved-stacks.json`. The repeated global
  clone/diff is gone; remaining work includes scope-index rebuilding,
  page-table edit/validation and host mapping retirement. Of the 23 closest
  Carrick fstat frames, 22 are inside host `fgetxattr` (PC 0x185121478,
  resolved against the same-boot shared cache with dladdr); fd stat assembles
  mode/owner from host xattrs each time. These are diagnostic samples, never
  acceptance latency.

The branch is clean apart from preserved untracked diagnostic scripts. No
mmap fast-forward has happened: 141/71 us still fails 10/6 us. Cap-std remains
accepted on main. The next bounded index improvement should avoid rebuilding
all `exact_first_by_scope` entries when unmapping a suffix: preserve first-row
semantics and shifted positions, prove index equivalence against a full rebuild,
and retain the existing partial-unmap/version tests. That is a candidate from
samples, not a completed fix. Further lazy-anonymous or page-table work must
retain exact owner generations, barriers and rollback; do not weaken validation
to meet timing. The stat xattr cost also needs attribution before changing its
metadata coherence behavior.

Still required before landing mmap: complete timing contracts; register/bless
`mmapanonreuse` on both libc lanes if retained; full serial runtime lib suite;
whole cached probe family; exact signed artifact receipts and Ubuntu/Python
launches; clean committed-tree inventory reconciliation, commit, then lint.
Only afterward fast-forward main from the main checkout, rebuild/recheck, take
the quiet-host fork number and full 2,127-row cached-only ecosystem ledger.


## Scope-index suffix repair

The tail-unmap regression visited 1,026 rows with a 512-row untouched prefix
(`index-red.log`). Unregistration now preserves that prefix tree and repairs
only changed suffix positions, including duplicate first-row masking. The
work-count test passes with the prefix scan plus a 16-row bound; a full index
rebuild is also compared after every existing differential unmap case. Full
signed HVF lib suite: 438 passed, 3 ignored (`index-hvf-lib.log`). This is a
local source checkpoint; fresh signed CLI timing and launch receipts follow.


## Handoff after scope-index measurement

Source `4856777d6`, signed SHA-256
`aa9249dd2963f78c37a1558af86bc3ad9c6ede9be100511b95a1d5e6e02e23a0`:
whole-file mmap+close 125.426 us and anonymous 1 MiB mmap+close 54.370 us
(`index-bench.*`, run `eco-mmap-immutable-bench-1788714494457057000`).
Ubuntu shell true and Python print pass (`index-launch.{json,log}`). Still
fails the 10/6 us contracts. All processes were scoped-reaped.

A new structural red receipt uses 100 untouched 255-page anonymous mappings
(the unusual length excludes CPython's own 1 MiB allocator arenas).
`scripts/dtrace/mmap-anon-host-allocation.d` observed exactly 100 successful
guest mappings, **100 host mmap calls requesting 281,804,800 bytes**, with zero
DTrace errors. Run `eco-mmap-immutable-anon-allocation-1788714737804181000`,
`anon-allocation.{json,out,err}` and driver log. This counts requested host
virtual mapping bytes, not resident memory. The initial attempt used the
reserved D identifier `count` and failed compilation before a guest ran;
the corrected probe ABI fired live. Never cite instrumented elapsed time.

The current anonymous branch calls `memory.protect_range(..., prot)` in
`dispatch/mem.rs`, then may call it again with PROT_NONE for mincore first-touch
tracking. AArch64 `protect_range` unconditionally calls
`ensure_sparse_mmap_backing` for accessible protection. Thus the parked
`zero_anonymous_reuse` scrub skip does not make mmap lazy. The branch already
has a demand-zero path in `HvfVmState::resolve_frame_cow_fault`, but wiring
metadata-only mmap into it requires correctness proof, not just deleting the
eager call. In particular:

- Preserve permission/executable and sharing metadata, MAP_POPULATE/mlock,
  MAP_FIXED failure handling, full/partial reuse zero-fill and neighboring
  mappings within a 16 KiB compound.
- Keep unmaterialized stage-1 descriptors invalid. `apply_protection_edit`
  cannot blindly make an old identity/retained output accessible.
- Verify mincore first-touch accounting: the runtime currently records a
  resident-fault range, while the backend demand-zero resolver runs before
  that runtime fallback. Do not let a resolved backend fault lose residency.
- Existing anonymous MAP_FIXED code discards `unmap_range` errors; review
  failure atomicity before relying on that operation to prove a hole.
- Guest buffer reads/writes, mprotect after partial materialization and fork
  must retain exact owner generation and logical permissions.

For the file path, samples also show per-page
`observe_frame_cow_protection` authentication (shadow walk, live walk and
translation repeated at 4 KiB even when a block descriptor covers more), plus
fd-stat xattrs. Any block-wise authentication must prove the same descriptor
covers every skipped address and stop at COW permission boundaries; validation
must not be weakened. These are next investigations, not implemented changes.

Full serial runtime, full probe family, inventory reconciliation/lint and
mmap main landing remain pending, followed by the quiet-host fork and fresh
2,127-row cached-only ecosystem ledger. Cap-std remains accepted on main.

## Anonymous dispatcher first-touch preparation

The red test `lazy_anonymous_mmap_arms_first_touch_without_accessible_backing`
observed RW publication followed by PROT_NONE for an untouched private mapping
(`lazy-anon-red.log`). The dispatcher now supports publishing PROT_NONE once
and recording the existing first-touch plan when a backend explicitly supports
unbacked anonymous mmap. MAP_POPULATE, MAP_LOCKED and fixed replacement retain
the eager path. The regression passes (`lazy-anon-green.log`); full serial
runtime lib suite: 2,468 passed, 2 ignored (`lazy-anon-runtime.log`).

**No production backend enables this capability yet; this is not a latency
improvement or a landing receipt.** The existing parked backend demand-zero
handler cannot be accepted unchanged: its 16 KiB compound publication can
replace neighboring live pages, lacks exact executable-permission handling,
and commits its undo journal before all fallible publication steps finish.
Anonymous faults should use the canonical resident-fault transaction instead.

Kernel copyin also needs an explicit proof for unmaterialized anonymous bytes.
The current foreign-reader fallback fills zeros for any readable VMA whose
translation fails, and its owner-generation receipt can contain only page-table
owners. Readability is not anonymous-zero provenance. Track exact deferred-zero
ranges by retained MM/VMA identity and authenticate every copied or zero-filled
span; never infer anonymous zeros from a failed translation. Preserve logical
residency separately from pending physical allocation through mprotect, fork,
unmap/replacement and exec. Do not relax the existing rejection of nonempty
foreign reads without owner generations. These are unresolved prerequisites to
production opt-in, not completed features.

## Isolated mmap counter measurement

The existing Python fixture measures mmap **plus close**, including Python's
extra fd-stat/dup work. Preserve it for application comparisons; do not label
that total as isolated mmap service time. The new durable
`scripts/perf/fixtures/mmap-contract.rs` uses the guest's enabled 24 MHz
architectural counter, brackets mmap and munmap separately, and keeps setup,
fstat and output outside both intervals. It runs five trials of 1,000 untouched
mappings per case. Counter-pair mean was 0.008917 us, reported without subtraction.

On the exact `4856777d6` signed artifact (SHA-256
`aa9249dd2963f78c37a1558af86bc3ad9c6ede9be100511b95a1d5e6e02e23a0`),
median trial means were file mmap **59.882667 us** / munmap **25.230167 us**,
and anonymous 1 MiB mmap **26.577625 us** / munmap **14.289875 us**.
Both mmap targets still fail. This is a separate reducer/process footprint,
not a replacement or speedup of the previous Python measurement. Run
`eco-mmap-counter-1788716163327720000`, exit 0 and scoped cleanup;
`counter.{json,out,err}` retains command, exact executable hashes and raw trials.
The current source HEAD was `b57b5ff34`, but the measured binary was explicitly
not rebuilt from that source; its producing source remains `4856777d6`.

## First-touch access gate

The canonical resident-fault handler now checks the decoded access before
materialization or residency commit. A denied write/execute or unknown access
leaves the pending plan intact. Existing effective read access for WRITE-only
and EXEC-only mappings is preserved; a backend protection failure preserves
the existing fallback path. The real dispatcher-plan regression failed red
with an incorrectly successful denied access. Final full serial runtime suite
passed 2,470 tests, 2 ignored, run `eco-first-touch-runtime-final`.
Receipts: `target/conformance/first-touch-access-{red,green}.log` and
`first-touch-runtime-final.log`. An initial unprivileged full run failed on
host socket/directory permissions; the final full run used host authority.
This prerequisite does not enable anonymous lazy backing or satisfy a guest
landing gate.

## Authenticate block coverage once

The deferred protection observer authenticated the same L2 descriptor once
per 4 KiB address. A red work-count test required two checks for two 2 MiB
blocks and observed 1,024 (`block-auth-red.log`). After the unchanged live /
shadow / expected output / AP / UXN checks succeed under Stage1Authority,
the observer now advances to the earliest block, receipt or COW-arm boundary.
Invalid descriptors and L3 tables retain per-page checks. No owner cache,
barrier or publication change was introduced.

Tests cover arm entry/exit, overlapping unaligned arms in both orders, L1
receipt bounds, and actual interior live L3 IPA/AP/UXN corruption. Independent
read-only review found no blocker. Full signed HVF lib suite passed 442 tests,
3 ignored (`block-auth-final.log`), using the shipped post-link signer and
scoped cleanup. Runtime timing has not yet been remeasured on this source;
the structural count is not a latency or landing claim.

## Block authentication signed CLI receipt

Committed source `fd2121d51`, signed SHA-256
`16f0c64400cdc366b95d8a95d0916d22830d18ce1733652d0c2c2c5a543398b9`,
LC_UUID `7B2CFC87-225E-382B-A244-55552CBEF091`. CDHash, hypervisor entitlement
and DOF section recorded in `block-artifact.json`.

Isolated median trial means: file mmap **44.774958 us**, munmap **22.357958 us**;
anonymous mmap **27.350042 us**, munmap **13.879875 us**. File mmap is about
25% below the previous 59.882667 us observation; anonymous did not improve.
Raw five-trial results and exact run identity are in `block-counter.*`.
The unchanged Python benchmark reports file mmap+close **110.572875 us**
(previous 125.425584), anonymous **55.543917 us** (previous 54.3695), with
raw trials in `block-bench.*`. These are separate fixtures and still fail the
10/6 us acceptance targets.

Ubuntu `sh -c '/bin/true'` and `python:3.12-slim print(1)` both exit 0 on
this binary (`block-launch.json`). Fresh whole-file zero-copy trace:
100 mappings, zero errors, zero `write_guest_bytes`, zero chunks;
run `eco-mmap-immutable-lazy-1788717301168007000`, `block-copy.*`.
All runs were serialized and scoped-reaped. No mmap main landing occurred.

Remaining: true anonymous lazy backing with authenticated kernel/foreign reads
and correct first-touch residency; residual file-map cost; complete latency
contracts; full final serial runtime and whole probe family on the final
artifact; line inventory reconciliation/commit/lint; only then mmap FF from
main, quiet-host fork and fresh full cached-only ecosystem ledger.


### Deferred anonymous state foundation (not a landing)

Added an exact-MM pristine-range authority in `carrick-guest-mem`: explicit
reservation and retirement, logical zero-read residency, fork-private copying,
and a locked materialization transition consumed only after publication.
Missing translation alone does not authorize zeros. The caller must acquire
quiescence before the transition lock and completely roll back backend changes
before dropping an uncommitted transition.

Red lifecycle/concurrency tests are retained in
`target/conformance/deferred-state-red.log`; independent full guest-memory
validation passes 42 tests (`deferred-state-root.log`,
`CARRICK_RUN_ID=eco-deferred-state-20260906b`). The foundation's binding hook is
default-noop and does not itself enable production lazy mmap.

The in-progress integration passed the full serial runtime library suite,
2470 passed / 2 ignored (`deferred-runtime.log`,
`CARRICK_RUN_ID=eco-deferred-runtime-20260906a`). This is not guest acceptance:
foreign writes into pristine unbacked memory still require a new exact-target
materialization transaction, and writable syscall-buffer validation must accept
explicit pristine provenance without allocating or changing residency. Runtime
integration remains uncommitted; the signed timing artifact is still fd2121d51.


### Executor-independent backing preparation

Extracted the existing sparse backing allocation and provisional stage-2
owner into `trap/sparse_materialization.rs`. This step preserves allocation
shape and file-view behavior; the returned owner rollback keeps preparation
provisional until the existing caller publishes inventory and stage-1.
The full signed HVF lib suite passes 442 / 3 ignored on the in-progress source
(`eco-mmap-resume/materializer-extract.log`, run
`eco-mmap-materializer-extract-1788718992648724000`), scoped cleanup zero.
The extraction is staged separately from the still-uncommitted anonymous
integration. No new release binary or main landing is claimed.


### Bounded anonymous fault allocation

Red: `anonymous_first_touch_never_allocates_a_block_of_padding` requested
2097152 host bytes for the 4096-byte semantic extent at offset 0x1ff000;
expected 16384 (`target/conformance/materializer-shape-red-bytes.log`).
The allocator now uses 16 KiB congruence for anonymous extents smaller than
2 MiB; file views and bulk anonymous extents retain 2 MiB congruence. The
test checks every 4 KiB offset in a 2 MiB span, not only the failing endpoint.

Full signed HVF lib suite passes 445 / 3 ignored in
`eco-mmap-resume/materializer-shape-green.log`, with scoped cleanup zero.
This proves the allocation-shape correction and host tests, not a guest
first-touch timing or the final 10/6 us contracts. The shared publication
transaction and lazy anonymous integration are still in progress.


### MM-owned structural arena preparation

Moved extension arena publication to MmAccessState. Existing exact structural
owner entries now determine whether backing already exists; the local executor
only extends its mapping cache with newly published rows. This removes the
executor dependency from arena allocation, a prerequisite for sharing sparse
publication with a foreign writer. Descriptor/inventory transaction extraction
and structural rollback journaling remain unfinished.

Full signed HVF lib suite passes 445 / 3 ignored in
`eco-mmap-resume/mm-arenas.log`; scoped cleanup reports zero. This mechanical
extraction is committed separately from anonymous integration and has not
landed on main. No new guest latency result is claimed.


### Shared sparse publication extraction

The local adapter now invokes `sparse_materialization::publish`, which owns
backing preparation, stage-1 edits/sync/authentication, inventory publication
and alias registration. Its context carries the caller's existing quiesce
lifetime, MM-owned state, carrier custody and inventory authority. Executor
mapping rows are returned cache updates. Foreign entry and permission-aware
ready publication still need implementation; local deferred protection remains
explicit in the adapter. Existing inventory apply/fatal failure semantics are
preserved; receipt-based foreign publication and structural rollback journaling
are not claimed complete.

The MM resolver now retains exact structural owners and stage-2 pins during
table editing. Its lifetime test rejects another carrier, keeps pointers valid
after MM lookup removal, defers retirement while pinned, and allows retirement
after release. Full signed HVF suite: 446 passed / 3 ignored,
`eco-mmap-resume/shared-publish-final.log`, run
`eco-mmap-shared-publish-final-1788720196445898000`; scoped cleanup zero.
No main landing or new latency acceptance is claimed.
