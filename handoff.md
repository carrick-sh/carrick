# Native-lane performance handoff

**Date:** 2026-07-28
**Branch:** `codex/native-aarch64-container-cache`
**Scope:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default). No VMM/HVF/KVM/bhyve behaviour was touched.

> Supersedes the FreeBSD native x86 bring-up handoff (`1b55b4b0`, branch
> `perf/native-xstate-transfer`). That work is unrelated to this and still open;
> read it from git if you are picking up x86. Its live caveat still stands:
> **`neutral-domains` remains opt-in — do not make it the production default
> until Tasks 43, 55 and 58 close.**

---

## Current state

Goal in flight: **get carrick's overhead on real workloads toward 2x.** The
first session took the reference workload from **15.7x to 10.7x** under its
CPU-overhead convention. The continuation on
`codex/native-aarch64-container-cache` reduced the authoritative wall median
from **21,786 ms to 19,485 ms** (−10.56%). This is meaningful progress, but it
is not close to the 2x destination and must not be presented as completion.

The current implementation tip is `564dd281`. It retains the first
syscall-reframe filesystem wave: ordinary Darwin host-backed `lookup_kind` and
no-follow metadata probes use one descriptor-contained open plus `F_GETPATH`
and exact-name validation, while symlinks, non-regular host types, aliases,
escapes, and errors retain the cap-std path. Five alternating untraced spike
pairs moved the contemporaneous median **19,660 → 19,163 ms** (−497 ms,
−2.53%); the candidate won 5/5 and every candidate sample beat every control.
The user explicitly approved retaining durable filesystem improvements below
the earlier conservative 3% screen. A subsequent clean committed five-sample
campaign measured **19,680 ms** (19,953/19,313/19,688/19,465/19,680), 305 ms
slower than frozen `C0=19,375 ms`; it is valid evidence but supplies **no
official `C1` or ratio win**. Native smoke and `just ci` remain pending.

The mechanism is independently live. Exact image-base-keyed `ustack(64)`
attributed the pre-change host-open population to `lookup_kind` (35,235
calls), `open_raw_fd` (12,877), `read_link` (11,435), and
`resolve_following` (9,944). The retained wave reduced guest-open-driven Darwin
`openat` **79,282 → 46,493** (−41.4%), total host opens **116,925 → 83,290**
(−28.8%), and amplification **31.45 → 19.68** opens per guest open. Durable
evidence and decisions live in
`docs/perf-results/native-fs-amplification.jsonl` and
`docs/perf-results/native-wall-time-campaign.md`.

The next hypothesis is H007: ordinary opens still recompute the same path
authority through resolver and final-open work. First re-run the exact caller
census on `564dd281`; only if `resolve_following`/final-open rewalks dominate,
spike one combined contained descriptor/metadata bundle through open dispatch.
If they do not dominate, pivot to the measured Carrick-only teardown
`unlinkat` population instead of forcing the hypothesis.

The earlier fusion/gateway work is on `main`; the continuation is committed on
the branch named above. The last-known pre-sidecar checkpoint had a green
`just ci` and clean `just conformance-native smoke --workers 4` (including
`go-sync` 52/52 and `cpython-threading` 193/193). Those are historical
receipts, not current-branch-tip results.

The current branch now includes `c65f4b0f`, which repairs the exact
default-path translation-cache regression introduced by `98e2f0d6`. Ordinary
private direct exits are compact 56-byte gateways again; immutable portable
translation units retain the 256-byte authority-aware precursor and
direct-binding recovery geometry. A freshly signed binary completed one
diagnostic sample and five clean retention samples inside the unchanged
64 MiB cache. The accepted current Carrick median is 21,005 ms, however, versus
`C0=19,375 ms`; keep the durable failure-to-completion repair, but do not call
it a Carrick wall-time win. The same serial campaign's Docker median drifted
to 1,367 ms, producing a 15.3658x ratio that must not be attributed to the
code change. Evidence:
`scripts/perf/evidence/native-go-build-wall-compact-exits-v1.json`.

Broad sampled-kernel attribution still has a live-symbolization blocker. The
preserved v2 partial profile reconciles 9,610 raw kernel PCs/stacks but omitted
the current boot runtime slide and has zero symbolized leaves. That no longer
blocks the syscall-reframe loop: synchronous Darwin syscall boundaries restore
the Carrick host stack, and exact image-base-keyed `ustack(64)` resolved the
dominant host callers. Restore post-stop, pre-handle-close deep-copy
symbolization before any future broad kernel capture, but do not pause H007 on
it.

The current branch includes repair `7cebf638` for Task 15's runtime-oracle
metadata compile failure. A clean retry at `8d440b61` passed the two native
crate suites but stopped fail-closed when the focused runtime oracle's
10,000-signal broad control missed `FinalBranch`. The signed rebuild,
codesign/DOF/marker checks, one-sample feasibility, and fail-closed mechanism
pair were not run. No current-branch-tip `just ci`, native smoke, signed
feasibility, or live mechanism result is claimed.

The current branch also includes `cbac611c`, which repairs deterministic
recovery after the `8d440b61` rejection. Its own focused/full verification is
structural repair provenance, not a Task 15 gate receipt. The later `b1700108`
retry below is the first Task 15 structural attempt after that repair.

Task 5 repaired the compact kernel-attribution runner's trace framing, and the
single authorized v2 attempt at clean `3fb91b09` reached Go compilation using
the unchanged signed binary. Run A then exhausted the 64 MiB DSR translation
cache before `BUILD_OK`; B and selection analysis are absent. A's partial
zero-drop profile reconciles 9,610 kernel PCs/stacks but has zero symbolized
leaves. This remains `MEASUREMENT_REPAIR_REQUIRED`: no kernel family,
performance result, or H006 exists.

A fresh retry at `b1700108` passed the two native crate gates but did not
complete the focused runtime gate. Its first four tests passed, then
`direct_binding_jittered_sigpipe_stress_preserves_state` consumed about one
CPU for more than 15 minutes without returning. The controller terminated only
the exact cargo/test PIDs and verified them gone. Gate 4, the signed rebuild,
feasibility sample, and mechanism pair were not run. The immediate next work
was deterministic per-sample synchronization diagnosis.

That synchronization repair is now present at clean starting commit
`ece8c497`. The complete four-command structural gate passed, and `just build`
produced a fresh signed binary with the entitlement, DOF section, and direct
binding marker. The authorized wrapper-free feasibility candidate reached Go
compilation but exhausted the 64 MiB DSR translation cache before `BUILD_OK`.
The feasibility JSON is absent, the captured error log is preserved, and the
mechanism pair was not run. H004 Variant 1 is rejected at feasibility; there
is still no current-branch-tip `just ci`, native smoke, mechanism vector, or
valid elapsed-performance result.

Reference workload: the conformance `go-build` case — `go build` of a
hello-world with a cold `GOCACHE`.

| state | wall | vs baseline |
|---|---|---|
| session start | 31,965 ms | — |
| + exclusive fusion (`8ffcbb4b`) | 23,650 ms | −26.0% |
| + gateway indirection (`26de3c07`) | **21,786 ms** | **−31.8%** |
| + two-way chaining + cold-publication cleanup (`deb9a80e`) | **19,485 ms** | **−39.0%** |
| Docker oracle | 942 ms (2.26 CPU-s) | — |

Every carrick figure is five untraced back-to-back runs on an idle machine,
median reported. **Measure this way or not at all** — see Traps.

The workload now has a checked-in runner:
`scripts/perf/native_go_build.py`. The authoritative continuation evidence is
`scripts/perf/evidence/native-go-build-post-cache-v1.json` (19,485, 19,392,
19,342, 19,707, 19,917 ms; clean commit and accepted idle-host preflight).

## 2026-07-27 continuation

### Default-path wins retained

- The per-thread indirect target cache is now two-way set associative (2 MiB
  per thread). Against the old direct-mapped profile, indirect resolver exits
  fell **1,509,230 → 862,580** (−42.9%) and total gateway entries fell
  **3,037,449 → 2,395,609** (−21.1%).
- Translation no longer captures source words unless artifact recording or
  shared-unit publication is enabled. Emitted PC maps, direct links and
  recovery metadata move into process ownership instead of cloning.
- AArch64 cold publication no longer enters a second mutex/B-tree arbitration
  index. `ProcessState::translate` already holds the process write guard and
  rechecks the authoritative block map under it; profiles recorded zero
  duplicates across ~1.87M translations. Clean-profile publication time fell
  **2.824 s → 1.148 s** (−59.3%).
- `InstructionMap` validates monotonic emitted offsets in one scan rather than
  allocating and sorting a second vector. Keep this as dead-allocation removal;
  its isolated five-run wall result was inside host noise.

Profile evidence:
`scripts/perf/evidence/native-go-build-post-cache-profile-v1.json`.

### Active wall-time attribution campaign

The next campaign is governed by
`docs/superpowers/specs/2026-07-27-native-wall-time-attribution-campaign-design.md`
and tracked in `docs/perf-results/native-wall-time-campaign.md`.

Its primary metric is the cold-GOCACHE `go-build` Carrick/Docker wall-time
ratio. The checked-in 19,485/942 ms pair is a historical 20.68x reference, not
the official campaign denominator: the first milestone refreshes five
untraced samples on both sides, in separate phases. Whole-process-tree DTrace
then partitions elapsed wall state and on-/off-CPU resource time before the
next optimization is selected. Node and CPython remain guardrails.

The measured official baseline is `C0=19,375 ms` (five fresh untraced Carrick
samples), `D0=1,007 ms` (five fresh native-arm64 Docker samples), and
`R0=19.2403x` (`C0 / D0`). It replaces neither the historical 19,485/942 ms
reference nor any one-sample screen.

The M1 attribution gate is now closed at commit `34ce4c3c`. The user explicitly
lowered the CPU classification threshold from 90% to 85% so the campaign could
return to wall-clock work. The clean `688357ef` pair classified 88.3%/89.8% of
CPU samples, reconciled 100% of wall samples with zero drops, and kept all
categories above 10% within five percentage points. Translated guest execution
and Darwin kernel work are about 71% of sampled CPU together.

The first post-M1 cache isolation found a concrete step-function seam:

| untraced one-sample screen | wall |
|---|---:|
| default control | 19.809 s |
| full shared translation | 40.211 s |
| full shared translation without publication `fsync` | 39.98 s |
| publish only; never load | 20.74 s |
| load/parse unit; skip eager block indexing | 22.78 s |
| cap unit to 10,000 / 1,000 / 250 / 100 blocks | 41.49 / 37.62 / 21.30 / 20.44 s |

The kept full-cache census contained four dylibs (about 28 MiB) and four
manifests (about 49 MiB). Publication is not the regression: removing all
durability syncs changed almost nothing, and publishing while translating
normally adds only about 0.93 s. A 100-block cap collapses the regression but
does not beat default, confirming a size cliff.

The first isolation made eager metadata indexing look responsible, but the
implementation spikes falsified that interpretation. Fully lazy metadata took
57.45 s; retaining only the compact guest-entry index took 39.12 s, barely
better than the original. Omitting the portable generation guard still took
38.73 s. All were reverted.

The reconciled shared-mode count profile identifies the real amplification:
**262,216,112 gateway entries**, including **68,932,094 direct resolver exits**
and **62,056,062 indirect resolver exits**, with 127.1 child CPU-s. The default
profile had 2,395,609 gateway entries, 1,433,321 direct exits, 862,580 indirect
exits and 43.8 child CPU-s. Translation fell only 1,867,805 → 1,256,885, nowhere
near enough to repay roughly 260 million additional exits. Filtering to a
transitively closed direct-target subset made things worse (55.24 s) and was
also reverted.

**At that checkpoint H004 was selected as `SPIKING`:** the first
immutable-code-compatible late-binding precursor carries exact
target authority through the two-way per-thread cache. It is correct across
private/shared and cross-unit targets, and translator ABI 2 rejects the old
16-byte cache population. Three untraced samples were stable at 25.169,
25.268 and 25.082 s. That recovers much of the 40.2 s shared-mode regression,
but it is still slower than the 19.375 s official baseline and is not a
retained primary-goal win. The later signed feasibility evidence below moves
H004 Variant 1 to `REJECT`.

A natural resolver-only DTrace run measured 941,784 remaining indirect misses.
Although 82,266/124,947 source sites were monomorphic, the top one/two targets
cover only 44.6%/54.9% of miss events; the hot tail is high-entropy. A second,
bounded trace saw 17,155,262 direct misses in 45 traced seconds. Its hottest
edge alone fired 1,473,595 times: `0x1a748 → 0x1a74c`, verified in the native
arm64 Docker oracle as Go `compile`'s `CBZ R1` fall-through.

Two conditional-edge spikes are rejected and reverted. Emitting the full
authority-aware lookup at every private/shared edge exhausted the 64 MiB
private JIT cache. Restricting it to portable artifacts produced one 24.664 s
sample, then crashed in Go runtime stack code on replication. Do not resurrect
that inline family.

**Immediate next action:** repair measurement before another live
authorization. Prove the intended default implementation completes the frozen
cold-Go workload within the existing 64 MiB cache bound, and restore at least
95% symbolized kernel-leaf coverage. Preserve and never rerun either
`target/perf/native-kernel-capture-7ec846a5-v1` or
`target/perf/native-kernel-capture-3fb91b09-v2`. Do not promote traced elapsed
time, infer a kernel family, create H006, enlarge the cache, or resume rejected
H004 Variant 1.

### Task 6 default-path kernel capture rejected during Go compilation

Task 5 removed the duplicate Carrick binary from the forwarded trace target and
passed 45 capture plus 17 attribution tests; independent review found no scoped
finding. Task 6 held the existing signed binary and native-arm64 image fixed.
Preflight at clean `3fb91b09afe0ec7e0aa240bcfc853f724abe166b`
matched binary SHA-256
`385e63d05ddf5ccfc55c9264a90f1f23302312c02647ccc23aa84e0844671fc0`,
v1 receipt SHA-256
`b8b17f409241a2f902ce6559e8de85d82fcdb550559ab5f5e162f652e88881f0`,
and v1 durable evidence SHA-256
`c09be20989146acbb018fa8bbe8171e89ed951cfa25579c3fc2d714eb9fa78af`.
Codesign, the native-wall marker, and `__TEXT,__dof_carrick` passed. Every v2
path was `lexists`-absent; the process, busy-host, and Docker-oracle censuses
were empty, with only two allowed `registry:2` containers.

The exact Task 6 controller command ran once. Repaired framing reached Go
compilation, then DSR cache allocation reported 1,080 bytes requested,
67,108,272 bytes used, and 67,108,864 bytes capacity. The compiler exited 125,
`BUILD_OK` count was zero, and the controller exited 1 after an observed
51.2214 seconds. No elapsed value from this trace is a performance result.

A nevertheless produced a complete natural zero-drop partial profile: 54
creates, 54 exits, zero live descendants, and 9,610 kernel PC samples exactly
matched by 9,610 kernel stack samples. Its 24,676 total CPU samples make the
partial diagnostic kernel fraction 155/398. Zero kernel leaves were
symbolized, so the 95% gate would also need repair after workload completion.

Receipt
`target/perf/native-kernel-capture-3fb91b09-v2/a.receipt.json` hashes to
`278f58ec3cefc4a55c6e5a6f9fbc3417798af08ba8274c1c7284389ff7193627`.
All seven bound artifact hashes revalidated, all 499 monitor samples were
uncontaminated, pre/post provenance matched, cleanup exited 0, and no owned
process survived. Every B path and `analysis.json` is absent; no analyzer was
run separately. Durable derived evidence is
`scripts/perf/evidence/native-go-build-kernel-attribution-v2.json`, SHA-256
`938052ebeefb0e34075e054fe1da2702c86b8e8e9f68fbdde3e68d941037e5c0`.

Outcome: **`MEASUREMENT_REPAIR_REQUIRED`**. The partial counts do not establish
`selectable` or `diffuse`, and no H006 or wall-clock win may be claimed.

### Task 4 default-path kernel capture rejected by trace framing

The attempt started at clean
`7ec846a5f8ed5ad3fc549e3f54363c69cceb01e8`. The preserved baseline and M1
attribution evidence hashes remained
`9c9e25f8c7e4f40feb8a86293a2dbd71e3406db3a22a6aeaa9b0dfff23958e13`
and
`fdb73ea7880fb2cf957bcbbc9c122ad57d739377eecf0e8e90da0bccb0ad67d8`.
Focused Task 1–3 gates passed 34 profile unit tests, six profile integration
tests, 17 attribution tests, 43 capture tests, Python compilation, and format.

The extra pre-capture `just ci` exited 101 at Clippy on three pre-existing,
untouched findings: `expect_used` at `direct_binding.rs:274`,
`too_many_arguments` at `emit.rs:1561`, and `vec_box` at `gateway.rs:58`.
Those files have no diff from `7c98887c` through `7ec846a5`; the controller
allowed measurement progress only. This is not a waiver for retention.

`just build` ran once. The 23,336,272-byte signed binary passed strict
codesign and hashed to
`385e63d05ddf5ccfc55c9264a90f1f23302312c02647ccc23aa84e0844671fc0`.
The native-wall marker was bundled, the target argv fixed
`--exec-backend native`, and the DOF listing hash was
`49788cb5195034d9f1354f8a8e0ec86341d75f4bd9e1e06fcc82d6fb8250dfca`.
The section is `__TEXT,__dof_carrick`; the brief's `__DATA` spelling was stale.

Preflight found every fixed output absent under `lexists` semantics, no
foreign workload, no real Docker oracle, and only the two `registry:2`
containers. The image was native `arm64`, ID and localhost repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.

The runner was invoked exactly once:

```sh
python3 scripts/perf/native_kernel_capture.py capture \
  --repo "$PWD" --binary target/release/carrick \
  --artifact-dir target/perf/native-kernel-capture-7ec846a5-v1 \
  --run-id native-kernel-capture-7ec846a5-v1 \
  --image localhost:5005/carrick-go-conformance:1.24 --timeout 180
```

It exited 1 during A. Trace stderr recorded:

```text
carrick trace: not root; re-executing under sudo
error: unrecognized subcommand '/Volumes/CaseSensitive/carrick/.worktrees/codex-native-aarch64-cache/target/release/carrick'
Error: native-wall profile has no wall samples
```

A emitted no `BUILD_OK` and no summary. Its rejected v2 receipt hashes to
`b8b17f409241a2f902ce6559e8de85d82fcdb550559ab5f5e162f652e88881f0`;
all six available artifact bindings revalidated. The 12-sample monitor stayed
uncontaminated, pre/post provenance matched, scoped cleanup exited 0, and no
owned process survived. The exact receipt errors are `trace command failed
with status 1` and `trace command did not emit exactly one BUILD_OK`.

Every B path and `analysis.json` is absent. No second analyzer ran. The raw
trace contains a 10,388,083 ns framing interval with zero wall samples; it is
diagnostic, never a workload-performance result. The root remains unchanged
under `target/perf` and must not be recycled. Durable audit evidence is
`scripts/perf/evidence/native-go-build-kernel-attribution-v1.json`.

Outcome: **`MEASUREMENT_REPAIR_REQUIRED`**. Repair the runner's trace target
argv contract and prove the actual auto-sudo shape red/green before allocating
a fresh base and versioned root. Do not infer `selectable`/`diffuse`, add H006,
or modify runtime code from this rejected attempt.

### Task 15 mechanism gate stopped at the structural prerequisite

Task 15 was attempted from a clean
`c4d54b92f45f091e39966fe9a856b93e352da8b0` checkout. Preflight found no
foreign Carrick/benchmark workload or real Docker oracle; only the
`carrick-registry-5050` and `vt-ferry-registry` `registry:2` containers were
running. The candidate image remained native `arm64`, ID and repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
The relevant ambient Carrick environment was empty. The unrebuilt stale
release binary remained
`sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`.

The serial structural result was:

| Command | Status | Receipt |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 101 | 25 compile-time `E0308` mismatches |
| `cargo fmt --all -- --check` | not run in gate sequence | stopped fail-closed; the required pre-commit hook later ran it and passed |

`native_darwin/dsr/oracle.rs` still constructs and matches `binding` with
`Option` (`None`/`Some(_)`) at 25 sites from line 1641 through 5336, while the
current `NativeDsrExit` field requires `DirectBindingExitMetadata`. The signed
build, codesign/DOF/`CARRICK_DSR_DIRECT_BINDINGS` marker checks, feasibility
sample, and fail-closed mechanism capture were therefore not run. No workload
or run ID existed and no cleanup was invoked; command status, exact
`BUILD_OK`, cleanup output/status, surviving descendants, child CPU, and
runner-frozen pre/post provenance are **not applicable**. There is no
performance or traced-timing result.

The following single-use paths remain absent and have no hashes:

- `target/perf/direct-binding-feasibility-v1.json`
- `target/perf/direct-binding-feasibility-v1-logs/`
- `target/perf/direct-binding-mechanism-v1.json`
- `target/perf/direct-binding-mechanism-v1/precursor/{trace.log,summary.jsonl,stdout.log,stderr.log,receipt.json}`
- `target/perf/direct-binding-mechanism-v1/candidate/{trace.log,summary.jsonl,stdout.log,stderr.log,receipt.json}`

Accordingly there are no receipt or bound-artifact SHA-256 values and no
precursor/candidate vectors to reconcile: all seven `NATIVEPERF1` exit kinds
(`syscall`, `direct`, `indirect`, `fault`, `kick`, `sensitive`,
`unsupported`), the six binding event kinds (`eligible`, `publish`,
`CAS loss`, `clear`, `validation failure`, `unit loaded`), raw-DTrace overlap,
gateway totals, translation attempts, unique `(pid,cell)` identities,
publication/clear bounds, typed reasons, or `S/D/G` collapse equations are
unobserved—not zero. Variant 1 is **rejected before mechanism evaluation**.
Commit `7cebf638` subsequently repaired this exact metadata mismatch and
records structural verification at that repair commit, but it did not rerun
Task 15's complete serial gate or any signed/live step. The current branch
includes that repair. At this historical checkpoint the instruction was to
restart Task 15 from clean current HEAD, fresh preflight, and fresh absent
artifact paths. That instruction is superseded by the later `8d440b61` retry
and deterministic recovery work at `cbac611c`. Do not tune the 22-word path
before an accepted mechanism decision.

### Task 15 retry stopped at bounded recovery coverage

The clean retry started at
`8d440b616ad163faf446078975d58aeb7788e233`. Repair `7cebf638` is included.
The process censuses found no foreign Carrick, benchmark, or spin-loop
workload; Docker had only the two excluded `registry:2` containers. The
relevant Carrick environment was empty. The native-arm64 image remained ID and
repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
All fixed single-use paths were absent. The unrebuilt executable still hashed
to `sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`;
it was not verified or executed.

The retry's structural vector was:

| Command | Status | Receipt |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 101 | compiled; 8 passed, 1 failed, 1,063 filtered |
| `cargo fmt --all -- --check` | not run | fail-closed stop after Gate 3 |

`direct_binding_jittered_sigpipe_recovers_every_preamble_phase` exhausted its
10,000-signal bound with:

```text
covered=[true, true, true, true, false, true, false, true]
recovered_words=[11, 152, 818, 26, 212, 54, 3, 17, 1808, 0, 0, 861, 75, 8, 511, 0, 0, 0, 0, 0, 0, 0, 0, 2, 126, 2756, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
signals=10000
```

The false index 4 is separately forced, assertion-exempt
`AuthorityInstall`; false index 6 is the required `FinalBranch` coverage that
rejected the gate. No rerun was substituted, and this checkpoint does not
decide whether the miss is a runtime defect or a probabilistic false red.

The signed build, codesign/entitlement, DOF, marker, feasibility, and mechanism
pair commands were not run. No run ID, guest, `BUILD_OK`, cleanup receipt,
child CPU, or runner-frozen provenance exists. Every feasibility, receipt,
raw, summary, stdout, stderr, and cleanup path remains absent and has no hash.
The complete exit/event vectors, reconciliations, process-cell bounds,
validation reasons, and collapse/reclassification equations are unobserved,
not zero. The 95% gate was not evaluated; there is no traced or untraced
performance result. Variant 1 remains rejected before mechanism evaluation,
and the 22-word path must not be tuned from this outcome.

Commit `cbac611c` subsequently added deterministic recovery coverage and fixed
the block-entry guest-`x17` recovery defect. Its own receipts are structural
repair provenance only. The later `b1700108` structural retry below does not
retroactively make those receipts Task 15 authority.

### Task 15 final retry stopped at a focused runtime hang

The final retry started at clean
`b1700108391058b7d0b18281028236d2e5b56960`. The process and spin-loop
censuses found no foreign Carrick or benchmark workload. Load averages were
`3.34 3.13 3.17`, recorded only as preflight context. Docker had only the two
excluded `registry:2` containers. The native-arm64 image remained ID and repo
digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
The relevant Carrick environment was empty and all four fixed single-use paths
were absent. The stale release executable still hashed to
`sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`;
it was not rebuilt, verified, or run.

The final retry's structural vector was:

| Command | Status | Receipt |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | terminated / rejected | first four focused tests passed; jitter stress started but did not return |
| `cargo fmt --all -- --check` | not run | fail-closed stop during Gate 3 |

At 15:07 elapsed, the controller observed cargo parent PID 25354 and test PID
25370. The test had accumulated 15:05.75 CPU, used about 99.6% of one CPU, and
was runnable (`R`). This establishes a structural-test hang; it does not reveal
which sample or synchronization phase was active and is not guest workload
performance. The controller interrupted the agent and sent `TERM` only to PIDs
25370 and 25354. A post-termination PID check found both absent, and the
workload census again found no foreign Carrick or benchmark process.

The prior repair receipt
`target/task14-fix5-jitter-stress-green.log`
(`sha256:dde7eb3ef5a9f3d0de148ec1743a51d287e71623b754d357e6954be40cace421`)
records the exact named stress test completing 10,000 signals and passing in
8.32 seconds. It is comparison evidence that makes the current spin a
diagnostic obligation, not authority to call the current Gate 3 green.

Gate 4, `just build`, codesign/entitlement, DOF, marker, feasibility, and
mechanism-pair commands were not run. The exact feasibility and mechanism
paths remained absent after termination. There is no current Gate 3 exit
status, run ID, guest, `BUILD_OK`, cleanup receipt, child CPU, frozen live
provenance, vector, reconciliation, process-cell bound, validation reason, or
collapse/reclassification equation. Those values are unobserved, not zero.
The 95% mechanism gate was not evaluated and no traced or untraced workload
performance was measured.

Variant 1 remains rejected before mechanism evaluation. Diagnose the focused
test's per-sample synchronization deterministically before another Task 15
attempt. Preserve the historical compile and bounded-coverage failures above;
this third rejection supersedes their restart instructions without erasing
them.

### Task 15 live retry passed structure but failed feasibility

The live retry started from clean
`ece8c49769ecf3420915dfa4215ab56e7f082852`. Preflight found no ambient
Carrick controls, foreign workload, or real Docker oracle; only the two
excluded `registry:2` containers were running. The candidate image remained
native `arm64`, with image ID and localhost repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.

The serialized structural vector completed normally:

| Command | Status | Receipt |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed; log `sha256:ad888ea14f7bf02d90f8a2ab07668e0ccb12d6e6428e48856445652682c7c308` |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed; log `sha256:a6980c18dc68dcc0679d6d0735cd70aca2aac63137e008c3f4fd85adb29ba69d` |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 0 | 10 passed; log `sha256:97e52e6d8ed3f883b069e7d4a55760abac36cbd80d0022db4ce6e5b84cea8de3` |
| `cargo fmt --all -- --check` | 0 | clean; empty-log SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

`just build` passed and produced release binary
`sha256:231afeda1ff693dd73f425143dc05c1f28265da897010c23bdd87a7a018c70bc`.
`codesign --verify` passed; the Hypervisor entitlement was true; the
`__TEXT,__dof_carrick` section and `CARRICK_DSR_DIRECT_BINDINGS` marker were
present.

The first feasibility invocation is preserved separately as invalid controller
evidence. Its outer `gtimeout ... | tee` wrapper appeared as foreign workload
to the runner's own census, so no guest launched and no official v1 JSON or
captured-output directory was created. The invalid log is
`target/task15-live-gate-ece8c497/11-feasibility-command.log`
(`sha256:0c87b605c813706d60db1061510d27a9325edfbbeb28fe2717f49b2c8e5d5a72`).
Those v1 names were never reused.

The explicitly authorized wrapper-free v2 recovery used shell process
replacement and fresh paths. It reached the workload under run ID
`native-go-build-carrick-50399-1785219847221505000-1` and exited 1:

```text
native Darwin guest thread 50572 error: unsupported in this backend: DSR translation cache exhausted: requested=696 used=67108188 capacity=67108864
runtime: /usr/local/go/pkg/tool/linux_arm64/compile: exit status 125
```

There was no exact `BUILD_OK`. The exception occurred before the runner wrote
`target/perf/direct-binding-feasibility-v2.json`, so that JSON is absent. The
captured workload error exists at
`target/perf/direct-binding-feasibility-v2-logs/carrick-1.log`
(`sha256:02ec397ab3c528d6a8fcd12e52569d76299c88623a2126b709d5c8179b6dbe4f`);
the v2 command log hashes to
`2b551358aaf66646229dc88ce69cac1458a233e9a4ca9d6b1591978e4e3192f5`.
No elapsed value from the failed command is valid performance evidence.

The runner entered its run-ID cleanup `finally` path, no cleanup exception
surfaced, and a post-stop census found no surviving guest or descendant. The
exception prevented serialization of exact cleanup status/output and the
in-memory provenance snapshots, so neither is claimed as accepted evidence.
Source remained clean and the release-binary hash remained stable.

The mechanism pair was not run. Its v2 JSON, directories, receipts, raw and
summary traces, stdout/stderr, exit and binding-event vectors, translation
counts, reconciliation/drop counts, process-cell bounds, publication/clear
reasons, and `S/D/G` collapse/reclassification equations are absent or
unobserved, not zero. The 95% gate was not evaluated.

H004 Variant 1 is **rejected at feasibility**. Return to current clean
default-path attribution and hypothesis selection. This result does not
authorize translation-cache-size changes, more Variant 1 tuning, the mechanism
pair, or Task 16.

### Portable translation reuse is correct but not a default performance win

The container-scoped design is implemented through image-digest keys, portable
artifact normalization, immutable signed Mach-O units, exec-carried authority,
unit-scoped generation bindings and cross-unit fail-closed chaining.
`CARRICK_DSR_ARTIFACT_SPIKE=1` and
`CARRICK_DSR_SHARED_TRANSLATION=1` remain explicit opt-ins:

- artifact replay median: 19,967 ms versus its 19,759 ms nearby control;
- signed shared-unit variants: 31–77 s, depending on unit policy.

The correctness seam is worth keeping, but enabling it by default would be a
regression. A later coarse-unit design, deferred until Task 15 closes, would
need to amortize signing/dlopen at a much coarser granularity and publish early
enough for sibling compiler processes to reuse the code.

### Experiments stopped

- startup Clap/bincode fast path: 19,748 ms versus 19,759 ms control;
- eager return-continuation priming: 19,676 ms versus 19,614 ms control;
- four-way 4 MiB target cache: 19,705 ms;
- two-way 1 MiB target cache: 19,735 ms;
- custom block-index hasher: 19,464 ms versus 19,466 ms control.

All were reverted. Do not resurrect them without new evidence.

### Historical verification receipts

These receipts predate the direct-binding sidecar and are not
current-branch-tip Task 15 results.

- Signed native demo: Linux `aarch64`, Go 1.24.13, compile and execute
  `native-go-ok`.
- `just conformance-native smoke --workers 4`: 23/23 MATCH, including
  `go-sync` 52/52, `cpython-threading` 193/193 and
  `cpython-subprocess` 278/278.
- `just ci`: green after the final implementation commits.
- Red-first tests cover cache collisions, trusted private-cache entry,
  shared-unit authority, cross-unit rejection, portable image isolation,
  metadata ownership, monotonic PC maps and redundant publication removal.

## Commits

| commit | what |
|---|---|
| `477d2df5` | Probes + tooling + the CPU attribution that found everything else. |
| `52011a46` | Root-cause writeup of the 40x CPU gap. |
| `8ffcbb4b` | **Biased-mode exclusive fusion enabled** — the big win. |
| `26de3c07` | **Gateway exit addresses moved into `DsrContext`** — smaller win, and the prerequisite for sharing translations. |
| `423895d5` | Container-scoped portable translation reuse plus the default two-way cache and allocation reductions. |
| `deb9a80e` | Remove redundant AArch64 cold-publication arbitration. |
| `7cebf638` | Repair direct-binding oracle metadata. |
| `cbac611c` | Recover guest `x17` at translated block entry and make direct-binding recovery coverage deterministic. |
| `b1700108` | Correct the deterministic recovery oracle's physical-`x16` model. |

Findings doc:
`docs/superpowers/specs/2026-07-26-native-cpu-attribution-findings.md`.

---

## Completed progress

### Exclusive load/store no longer traps on every atomic

76% of **38.9M gateway exits** on one hello-world build were
`sensitive_exclusive` — `LDXR`/`STXR`. Go takes an atomic on every mutex,
channel op, scheduler transition and GC write barrier, so this was most of what
the guest did.

The lowering that avoids it (`block::analyze_exclusive_region`) already existed,
and fused **nine** regions in that entire build while reporting **14,916,457**
sites as `fusion_eligible_backend_disabled`. Fusion shipped enabled only in
`Direct` address mode; production runs `Biased`.

The gate was one documented obligation that decomposed into two claims which are
not the same kind of thing:

- **Registers** — the lowering clobbers exactly two guest GPRs. Both are already
  spilled to context slots 1120/1128 before either changes, every emitted word in
  the clobber window already carries a `RecoverBiasedExclusive` entry, and
  `recover_rewrite_state` already restores both on the fault and kick paths. Live
  code, not new work.
- **NZCV** — nothing to roll back. No DSR-inserted word in the region writes
  flags. The correct gate is a **static assertion**, not a recovery mechanism.

Resume legality is per word via the PC map, not a rewind. A blanket
restart-from-load would be *unsound*: an accepted body may contain a
non-re-derivable `add w9, w9, #1` that restarting double-applies.

Result: `sensitive_exclusive` 29,589,283 → **0**; exits 38.9M → 8.9M; CPU
88.7s → 53.1s.

### Gateway addresses no longer baked into every block

Each block exit materialized its gateway entry point as a four-word
`movz`/`movk` chain — three words more than a load, on every exit, and it bakes
a **host code address** into translated bytes. Guest processes self-reexec with
different ASLR slides, so such a block is valid only in its emitting process.
Now `ldr x17, [x28, #off]; br x17`, with the six new `DsrContext` slots pinned by
`offset_of!` asserts on both the Rust and C sides.

### A latent trampoline bug, found by accident

The taken edge of a conditional direct exit was emitted as `0x1400_0012` —
hardcoded "branch forward 18 instructions", silently encoding the *length of the
gateway stub emitted after it*. Shortening that stub sent the taken edge three
instructions **into** it, past its `mov x17, <target>`, publishing whatever `x17`
held as the guest's branch target. Latent before this session: **any** change to
stub length would have mis-branched every conditional direct exit. Now a dynasm
label.

### Observability

The Darwin native lane fired **neither** `execve-argv` nor `guest-exit`, though
the shared and FreeBSD native lanes fire both — the shipped default backend was
invisible to tracing at process granularity. Both now fire, plus new
`host-image-base` / `guest-image-base` probes so each guest process announces its
own image base/slide/path and a profile can be symbolicated after the
(short-lived) process exits.

| path | what |
|---|---|
| `scripts/dtrace/guest-process-census.d` | Per-guest-process shape and lifetimes. Deliberately cheap. |
| `scripts/dtrace/guest-translation-census.d` | Translation volume per image. Expensive; counts only. |
| `scripts/dtrace/native-cpu-attribution.d` | Sampled CPU attribution, windowed + raw PC histogram. |
| `scripts/symbolicate.py` | Offline per-pid symbolication against host **and** guest images. |

---

## Where the remaining time goes

Post-fusion, on 53.1 thread-seconds of CPU (phases overlap where translation
nests, so they do not sum to 100%):

| phase | CPU | share |
|---|---|---|
| `phase_translate_ns` | 28.3 s | **53%** |
| `phase_translated_run_ns` | 19.9 s | 37% |
| `phase_prepare_index_ns` | 6.9 s | 13% |
| `phase_syscall_dispatch_ns` | 4.1 s | 8% |
| `phase_finish_exit_ns` | 0.7 s | 1% |

The residual **8.9M gateway exits** are now almost entirely one thing:

| exit kind | count | share |
|---|---|---|
| `exit_resolve_indirect` | 7,388,024 | **82.9%** |
| `exit_resolve_direct` | 1,415,702 | 15.9% |
| `exit_syscall` | 101,606 | 1.1% |
| `exit_sensitive` | 540 | 0.006% |

**Translation is now the largest single cost**, and it barely moved when fusion
landed (31.6 → 28.3 s): fusion merged exclusives into blocks but did not reduce
how many distinct blocks get translated. The same few binaries are translated
from scratch 65 times per build (27 `compile`, 34 `asm`, 2 `link`, the driver,
the output binary).

Separately measured and unaddressed: **~18% of all CPU is carrick re-running
container/capsule setup per guest process** — serde JSON 8.2%, SHA-256 of the
executable 3.9%, volume mountpoints 2.4%, clap arg parsing 1.2%. Docker does none
of this per process.

---

## Prior work ranking and disposition

### A. Translation cache — largest lever, 28.3 s

Scoped by the project owner to **the container's lifecycle**: share across the 65
guest processes of one `carrick run`. Durable cross-run caching is out of scope.

**Use the on-disk signed Mach-O path, not Mach named memory entries.**
`crates/carrick-native-darwin/src/aot.rs` (`2ae15078`) already emits a loadable
`MH_DYLIB` by hand with `HEADER_SLACK` reserved for `LC_CODE_SIGNATURE`, proven
end-to-end (emit → `codesign -s -` → `dlopen` → `dlsym` → call). A design pass
concluded file-backed executable memory was dead because raw
`mmap(FILE|*, r-x)` returns EPERM — that is a **false negative**: we do not
raw-mmap, we `dlopen` a *signed* dylib, which is the AMFI-sanctioned route, gets
cross-process sharing free via the unified buffer cache, and survives `execve`
trivially.

Publish costs from `crates/carrick-native-darwin/examples/aot_bench.rs`:
1 MiB = 80 µs emit / 15 ms sign / 105 ms cold dlopen; 64 MiB = 10 ms / 122 ms /
449 ms. Signing dominates and is a subprocess; an ad-hoc signature is just a
CodeDirectory of page hashes and could be emitted in-process.

**Remaining prerequisite before a block is portable:** gateway addresses are done,
but `GenerationAddress` / `GenerationExpected` are still process-varying and need
the same treatment.

**Do not re-derive per-block relocation.** `artifact_spike` already built
normalize-then-rebind and measured it **2.95% slower** at 71,244 cross-process
hits and **21.7% slower** at 931,094. Verdict `STOP_PER_BLOCK_ARTIFACT_CACHE`.
Any design that *writes* to a block per process collapses back into that.

**Highest-risk hazard, and it is silent:** *guest VA is not a code identity.* Two
guest images can hold different text at the same VA, so a VA-keyed shared cache
hands one process another's code — wrong compiler output, no crash, and LTP will
never see it. The key needs image identity (dev/ino/size/mtime, segment offset,
address-mode tag). Red-first test: two ELFs with identical load placement and
different text, run concurrently as siblings in one `carrick run`.

### B. Indirect branch chaining — 7.4M exits, 82.9% of the residual

`ret` is `br x30` on aarch64 and Go is call/return-heavy, so every function
return leaves translated code. The x86 lane already has edge patching
(`CARRICK_NATIVE_X86_EDGE_BARRIER`); aarch64 does not.

### C. Per-gateway-entry cost — 6.9 s over 38.9M entries (~290 ns each)

`phase_prepare_index_ns`. Only partially addressed by (B).

### D. Stop re-running capsule setup per guest process — ~18% of CPU

Hash the executable digest once; skip clap/serde re-parse on self-reexec.

### E. Calibration

Published same-ISA DBT (AArch32→AArch64, MAMBO, PLDI'16) runs under **7.5%**
overhead. We are far above that, so treat "translation is inherently expensive"
as refuted — the gap is defects, not physics.

## Next work, ordered by the current gate

1. **Repair kernel symbolization before another capture.** Default cold-Go now
   completes five times inside the existing 64 MiB cache. Implement live
   post-stop/pre-handle-close libdtrace symbolization and prove at least 95%
   exact kernel-leaf coverage.
2. **Preserve both single-use roots.** Neither v1 nor v2 may be rerun, deleted,
   or recycled. The v2 A receipt and raw artifacts are the authority for this
   rejection; B and analysis are absent, not zero.
3. **Do not reinterpret partial A as selection.** Its 9,610/9,610
   reconciliation is real, but the workload did not finish and symbolized-leaf
   coverage is zero. There is no selectable/diffuse result or H006.
4. **Keep `c65f4b0f`, but do not overclaim it.** It is a reviewed,
   five-completion capacity repair. Current Carrick wall seconds are slower
   than `C0`; the lower ratio reflects larger Docker drift, not a proven speed
   win.
5. **Do not tune the rejected mechanism.** Cache-size changes, the 22-word
   direct-binding path, another Variant 1 mechanism pair, and Task 16 require a
   new controller decision; none is authorized by this handoff.

---

## Traps — read before measuring or debugging here

**Never time a hot path by bracketing its own probes.** Bracketing
`dsr-translate-begin`/`-end` fires ~3M USDT probes and each pair's cost lands
*inside* the window being timed; it reported 17.7 s of translation inside a 19 s
window. Sample instead; use per-block probes only for exact counts.

**Guest processes self-reexec, so each has a different ASLR slide.**
Symbolicating against one assumed base yields plausible, wrong symbols — that is
what made bad64's decoder look like the hot path when it is 0.2%.

**Measurements are load-coupled, and this bit twice.** One run was 6x slow
because 44 orphaned spin loops — leaked by a subagent load-injection experiment
whose parent died before its `kill` — burned CPU for 93 minutes. Another was
invalid because it ran while three agents were compiling. Before any perf run:
`ps -eo pid,args | grep "while :"`, check `uptime`, let the machine go quiet.

**Agents sharing a worktree destroy each other's edits.** A subagent restoring its
red-first mutation with `git checkout <file>` silently reverted an unrelated
concurrent change in the same file.

**Disassemble before theorising.** Four hypotheses about the trampoline bug were
wrong; dumping the emitted block found it in one step. `bad64::decode` over
`emitted.entry()` is the fastest path to truth.

**Adversarially verify agent-written tests.** Of three, one was tautological: it
hardcoded the policy and called `plan_with_reader` directly, bypassing the very
function the change touched, so reverting the production mapping left it green.
Replaced by `biased_address_mode_selects_the_enabled_fusion_policy`, which was
*shown* to go red on that revert. Extracting `fusion_policy_for` from `plan_block`
is what made the shipped decision assertable at all.

**Docker/registry.** `just conformance-quick` blocks on `localhost:5005`
(`vt-ferry-registry`) to check image freshness. With Docker down it hangs on I/O
indefinitely — 44 minutes at 0.42 s CPU before it was noticed. Start Docker and
`docker start vt-ferry-registry` first.

---

## Open / unverified

- **Conformance perf outliers moved and it is unexplained.** Between two runs
  `node-app-smoke` went 27x → 48x and `cpython-glob` 38x → 48x. Very likely load
  (the second followed a full CI, unisolated) but **unmeasured**. Re-measure
  cleanly before reading anything into it. `go-build` is measured properly and
  improved.
- **The `InstructionMap` dead-`BTreeMap` removal shows no measurable wall-clock
  win**, against a 3–10 s estimate. Kept for dead-work and retained-memory
  reduction only (two maps per block × ~1.5M blocks). Not a speed win; do not
  claim one.
- **Exposing all 10 CPUs made things worse** (`CARRICK_EXPOSED_CPUS=10` →
  34.8/38.9 s vs ~31.4 s on the 4 P-cores). More guest parallelism currently
  costs more than it buys. `host_facts.rs` still exposes
  `hw.perflevel0.logicalcpu` behind an HVF-era rationale that does not apply to
  the native lane — the comment is stale even though the value is currently right.
- **The async-interrupt oracle test asserts on a microarchitecturally-determined
  PC distribution** (which words a kick lands on). It passed with wide margins
  here — 7,812 kicks, 15 distinct landing words, all five classes — but could
  false-red on other silicon. A reviewer also found
  `BiasedExclusiveResume::{Load,Exact,Retry}` semantically inert:
  `recover_rewrite_state` never reads it and resume semantics live entirely in the
  PC map, yet four tests pin it. Either wire it or delete it.
- **`cargo clippy -p carrick-runtime --all-features`** fails with ~67 pre-existing
  compile errors (broken feature combination), so that invocation is not a usable
  gate. Unrelated to this work.
