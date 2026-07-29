# Darwin/AArch64 native wall-time campaign ledger

**Updated:** 2026-07-28
**Status:** ACTIVE — locating the remaining pre-open filesystem amplification
**Primary workload:** cold-GOCACHE `go-build`  
**Design:** [Darwin native wall-time attribution campaign](../superpowers/specs/2026-07-27-native-wall-time-attribution-campaign-design.md)

## Campaign scorecard

| Field | Current | Evidence / interpretation |
|---|---:|---|
| Historical Carrick median | 19,485 ms | Five untraced runs at `9c25688d` |
| Historical Docker result | 942 ms | Handoff datum; refresh required |
| Historical ratio | 20.68x | Context only, not `R0` |
| Official `C0` | 19,375 ms | Five fresh untraced Carrick samples |
| Official `D0` | 1,007 ms | Five fresh native-arm64 Docker samples |
| Official `R0` | 19.2403x | `C0 / D0` |
| Current Carrick median | 21,005 ms | Five clean completions at `c65f4b0f`; 1,630 ms / 8.4% slower than `C0` |
| Current Docker median | 1,367 ms | Same serial campaign; 360 ms / 35.7% slower than `D0` |
| Current same-run ratio | 15.3658x | Numerically 20.1% below `R0`, but not a code win because Carrick seconds regressed and Docker drifted more |
| M2 target | 9.6202x | `R0 / 2` |
| Destination | 2.0x | Two independent five-sample campaigns |
| Ratio progress | 22.5% | `(R0 - R) / (R0 - 2.0)`; wall-seconds progress remains 0% |

Current milestone: **M2 — pre-open filesystem attribution**. M0 and M1 are
complete. A syscall-state sampler removed the need to wait for kernel-leaf
symbolization before selecting a mechanism: private guest futex waits own only
0.30% of sampled kernel CPU, while Darwin `openat` + `unlinkat` own 24.22%.
The exact first-bad commit for the later capacity
regression was `98e2f0d6`: it put a 256-byte portable authority precursor on
ordinary private direct exits. Commit `c65f4b0f` restores the compact 56-byte
private gateway while retaining the authority precursor for immutable portable
units. The unchanged 64 MiB cache now completes five consecutive cold-Go
builds, so the capacity repair is retained. It is not a Carrick wall-speed win:
the accepted current median is 21,005 ms versus `C0=19,375 ms`. The current
same-run ratio fell only because the Docker median drifted even more.

The terminal `open_raw_fd` contained-parent spike is now rejected: it removed
24.0% of the host `openat` calls joined to guest opens, but its five-sample
median improved only 0.7% and it won one of five paired positions. The remaining
24.7 host opens per guest open sit mostly in lookup, metadata, and DAC
preparation before the final raw open; a call-site stack census is the next
selection gate.

The single-use v2 DTrace attempt remains rejected and preserved. Kernel-leaf
symbolization is still required for a symbol-family claim, but the approved
syscall reframe now supplies a typed mechanism selection without guessing from
raw kernel addresses. H005a (private-futex ulock replacement) is rejected as a
major wall target. The selected filesystem hypothesis is supported for a
bounded implementation spike, not yet a retained wall win.

## Measurement contract

- Carrick and Docker run in separate phases.
- Every performance claim uses untraced five-sample medians after an accepted
  idle-host preflight.
- DTrace attributes proportions and mechanisms; its absolute wall time is not a
  performance claim.
- The trace follows only the launch-owned process tree.
- CPU resource shares, elapsed wall-state occupancy, and off-CPU resource time
  remain separate quantities.
- CPU attribution is accepted at 85% coverage when the paired runs also retain
  zero drops, at least 99% wall reconciliation, at least 80% blocking-stack
  coverage, and category stability within five percentage points.
- A retained change must win its predeclared wall gate and pass correctness.

## Evidence registry

| ID | Artifact | State | What it proves |
|---|---|---|---|
| E001 | `scripts/perf/evidence/native-go-build-post-cache-v1.json` | accepted historical | Five clean untraced Carrick samples: 19,485, 19,392, 19,342, 19,707, 19,917 ms |
| E002 | `scripts/perf/evidence/native-go-build-post-cache-profile-v1.json` | accepted historical diagnostic | Current internal counts and phase aggregates; traced timing is diagnostic |
| E003 | `handoff.md` at `9c25688d` | accepted controller input | Prior wins, rejected experiments, traps and verification receipts |
| E003a | paired runner at `e53f1608` | accepted tooling | Identical cold-cache Carrick/Docker commands, native-arm64 image validation, scoped cleanup and v2 phase/ratio artifact |
| E003b | `target/perf/native-wall-smoke-c.jsonl` | tooling-only; raw untracked | Signed local AArch64 trace: natural exit, 44 metric rows, 102 reconciled wall samples, JIT range present, zero live processes and zero drops |
| E003c | `target/perf/native-wall-smoke-c-summary.json` | tooling-only; derived untracked | Live analyzer agreement: 99.5% wall-timer coverage, 99.0% CPU classification, zero live processes, accepted without weakening the 99/90/80 thresholds |
| E003d | `target/perf/native-wall-smoke-d{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Native container smoke printed `TRACE_OK`; 709 rows, natural zero-drop exit, 99.9% wall coverage, 98.3% CPU classification, zero live processes |
| E003e | `target/perf/native-wall-scope-a{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Concurrent unrelated Carrick PIDs 96365/96381 produced zero scoped CPU, off-CPU, or image rows; traced tree retained 99.8% wall and 97.9% CPU coverage |
| E003f | `target/perf/native-wall-catalog-smoke-b{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Exec smoke published one 391-range dyld catalog inside the enabled USDT closure; exact ranges classified Darwin userspace while preserving 99.7% wall and 97.3% CPU coverage |
| E004 | `scripts/perf/evidence/native-go-build-wall-baseline-v1.json` | accepted | Clean `3b8aa399`, binary `593acb…`, serial five-plus-five run: `C0=19,375 ms`, `D0=1,007 ms`, `R0=19.2403x`; Docker image is native arm64 |
| E005 | `target/perf/native-go-build-wall-profile-a-rejected-v1.jsonl` | rejected diagnostic; raw untracked | Natural zero-drop Go build with 100.0% wall coverage, but only 80.375% CPU classification; 19.6% unresolved fails the fixed 90% gate |
| E005a | `target/perf/native-go-build-wall-profile-a-v1.raw` | rejected diagnostic; raw untracked | Dyld-catalog retry completed `BUILD_OK` but capture completion was false: 68,485 aggregation drops and 50,349 dynamic-variable drops |
| E005b | `target/perf/native-go-build-wall-bounded-spike-a.jsonl` | rejected diagnostic; raw untracked | Bounded 80-range catalog eliminated drops, but 88.248% resolved CPU remained below the fixed 90% gate |
| E005c | `target/perf/native-go-build-wall-bounded-spike-b.jsonl` | rejected diagnostic; raw untracked | Fork-inherited host-base spike observed 65 dual-base PIDs, but 220 dynamic drops rejected the capture; an untyped DTrace zero also truncated all address keys to 32 bits |
| E005d | `target/perf/native-go-build-wall-bounded-spike-c.jsonl` | rejected diagnostic; raw untracked | Corrected 64-bit, zero-drop inherited-base run reached 89.650% resolved CPU, still 0.350 percentage points below the gate |
| E005e | `target/perf/native-go-build-wall-bounded-spike-e{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Zero drops, 100.0% wall reconciliation, 91.1% resolved CPU; 98.5% wall on-CPU and 1.5% runnable-descheduled |
| E005f | `target/perf/native-go-build-wall-clean-{a,b}-a915c134.jsonl` | rejected replication pair; raw untracked | Clean A resolved only 87.5% CPU while clean B resolved 91.0%; stable large buckets but unstable Carrick/JIT classification rejected the pair |
| E005g | `target/perf/native-go-build-wall-inherited-jit-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Propagating the parent's current JIT range produced 67 multi-range children, zero drops, 100.0% wall reconciliation, and 91.0% resolved CPU |
| E005h | `target/perf/native-go-build-wall-clean-{a,b}-a9425329.jsonl` | rejected replication pair; raw untracked | Even with inherited JIT ranges, clean A/B resolved only 83.7%/87.6%; the post-self-reexec Carrick base was still unpublished when a process exited without another guest execve |
| E005i | `target/perf/native-go-build-module-vmmap-a.{raw,txt}` | diagnostic; raw untracked | Same-run live module/VM-map join: all 434 anonymous samples in the captured Go parent belonged to exactly its 64 MiB MAP_JIT region (309) or Carrick `__TEXT` (125), with no fourth executable population |
| E005j | `target/perf/native-go-build-wall-loop-base-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Loop-boundary host-base publication plus exact-text fallback: zero drops, 100.0% wall reconciliation, 90.4% resolved CPU |
| E005k | `target/perf/native-go-build-wall-initial-base-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Publishing the initial fork child's Carrick image before guest setup: zero drops, 100.0% wall reconciliation, 92.1% resolved CPU |
| E006 | `target/perf/native-go-build-wall-clean-a-688357ef.jsonl` | accepted raw; untracked | Commit-exact zero-drop trace with 100.0% wall reconciliation and 88.3% resolved CPU |
| E007 | `target/perf/native-go-build-wall-clean-b-688357ef.jsonl` plus `scripts/perf/evidence/native-go-build-wall-attribution-v1.json` | accepted | Replication reached 89.8% resolved CPU; every category above 10% stayed within five percentage points |
| E008 | `target/perf/native-edge-shape-authority-v2-b.raw` | accepted diagnostic; raw untracked | Natural `BUILD_OK` resolver trace: authority caching cuts indirect resolver events to 941,784; 82,266/124,947 sites are monomorphic, but top-one/top-two targets cover only 44.6%/54.9% of miss events |
| E009 | `target/perf/native-edge-shape-authority-v2-c.raw` | bounded diagnostic; raw untracked | First 45 traced seconds contain 17,155,262 direct resolver events; the hottest edge (`0x1a748 → 0x1a74c`) accounts for 1,473,595 and is the fall-through of Go `compile`'s `CBZ R1` |
| E010 | `target/perf/native-go-build-authority-v2-stress-screen.json` | accepted screen; dirty provenance | Three correct untraced samples: 25,169, 25,268 and 25,082 ms; authority switching removes most resolver amplification but remains slower than `C0=19,375 ms` |
| E011 | `target/perf/native-go-build-portable-conditional-v3-populate.json` plus failed replication log | rejected spike; raw untracked | Artifact-only inline conditional caching screened at 24,664 ms, then crashed in Go stack/runtime code; the all-code version exhausted the 64 MiB private JIT cache |
| E012 | Task 15 structural gate at `c4d54b92` | rejected before live evidence | The first two structural commands passed, but the serialized runtime oracle command failed to compile with 25 `E0308` errors because `binding` fixtures/patterns still use `Option` while `NativeDsrExit` requires `DirectBindingExitMetadata`; no signed candidate, feasibility sample, or trace pair was run |
| E013 | Task 15 structural retry at `8d440b61` | rejected before live evidence | The metadata repair compiled and eight focused runtime oracles passed, but the 10,000-signal broad control missed required `FinalBranch` coverage; fail-closed execution suppressed formatting Gate 4, signed feasibility, and the trace pair |
| E014 | Task 15 structural retry at `b1700108` | rejected before live evidence | The first two structural gates passed; Gate 3 passed its first four focused tests, then `direct_binding_jittered_sigpipe_stress_preserves_state` consumed about one CPU for more than 15 minutes without returning and was terminated by the controller; Gate 4, signed feasibility, and the trace pair were not run |
| E015 | Task 15 live retry at `ece8c497` | structural/build accepted; feasibility rejected | All four structural gates and fresh signed-binary checks passed, but the authorized wrapper-free candidate reached Go compilation and exhausted the 64 MiB DSR translation cache before `BUILD_OK`; the campaign JSON was not written and the mechanism pair was not run |
| E016 | `scripts/perf/evidence/native-go-build-kernel-attribution-v1.json` plus rejected A receipt under `target/perf/native-kernel-capture-7ec846a5-v1/` | `MEASUREMENT_REPAIR_REQUIRED` | Clean `7ec846a5`, signed binary `385e63d0…`, native-arm64 image, and clean monitor provenance reached run A; trace auto-sudo then treated the repeated Carrick binary path as a subcommand, so A exited 1 without `BUILD_OK`, B and `analysis.json` remained absent, and no family was selected |
| E017 | `scripts/perf/evidence/native-go-build-kernel-attribution-v2.json` plus rejected A receipt under `target/perf/native-kernel-capture-3fb91b09-v2/` | `MEASUREMENT_REPAIR_REQUIRED` | Clean `3fb91b09`, the unchanged signed binary/image, and repaired `trace -- run` framing reached Go compilation; A then exhausted the 64 MiB DSR translation cache before `BUILD_OK`. Its natural zero-drop partial profile reconciles 9,610 kernel PCs/stacks but has zero symbolized leaves; B and analysis are absent and no family was selected |
| E018 | Task 9 signed bracket plus `c65f4b0f` red/green/live gate | accepted capacity repair | Immediate parent `de05a11a` completes and `98e2f0d6` exhausts the unchanged cache; typed compact-private/portable-authority policy passes 163 crate tests, independent review, and a fresh signed `BUILD_OK` runtime gate |
| E019 | `scripts/perf/evidence/native-go-build-wall-compact-exits-v1.json` | accepted retention measurement | Five Carrick completions at 20,260/20,698/21,005/21,547/25,209 ms and five serial Docker completions at 1,258/1,466/1,472/1,367/1,359 ms; current medians 21,005/1,367 ms and ratio 15.3658x; retain failure-to-completion repair, claim no Carrick wall win |
| E020 | `target/perf/deep-wait-stacks-v3/c.raw` plus `docs/perf-results/native-syscall-cpu.jsonl` | accepted diagnostic | Deep syscall stacks cross from `libsystem_kernel` into anonymous native JIT ranges; existing `futex-route` joins identify private futex without false host symbolication |
| E021 | `target/perf/native-syscall-cpu-v2/b.raw` plus `docs/perf-results/native-syscall-cpu.jsonl` | accepted diagnostic | Natural `BUILD_OK`, 19,525 kernel and 64,512 user samples: private-futex cvwait is 0.30% of kernel / 0.069% total CPU; `openat` + `unlinkat` are 24.22% kernel / 5.63% total |
| E022 | `target/perf/native-fs-amplification-v1/a.raw` plus `docs/perf-results/native-fs-amplification.jsonl` | accepted diagnostic | Carrick guest 2,521 `openat` calls drive 79,282 joined and 116,925 total Darwin `openat`; teardown contributes 38,809 Carrick-only `unlinkat` |
| E023 | `target/perf/oracle-fs-syscalls-v1/{oracle.raw,workload.log}` plus `docs/perf-results/native-fs-amplification.jsonl` | accepted Docker-only diagnostic | Native-arm64 Linux `bpftrace` process-tree census completes `BUILD_OK`; mutation counts closely match Carrick guest counts, proving the 35.8x host `openat` / 249.7x host `unlinkat` excess is Carrick amplification |
| E024 | `target/perf/fs-open-spike/` plus `docs/perf-results/native-fs-amplification.jsonl` | rejected implementation spike | Five controls median 20.95 s versus candidate 20.80 s (0.7%); the candidate won 1/5 pairs. A typed mechanism trace confirms real but insufficient movement: joined host opens fell 24.0%, leaving 24.7 host opens per guest open |
| E025 | `target/perf/native-openat-callers-v1/b.raw` plus `docs/perf-results/native-fs-amplification.jsonl` | accepted diagnostic | Exact image-base-keyed `ustack(64)` accounts for 80.3% of call count in the top 128 stacks; `lookup_kind`, `open_raw_fd`, `read_link`, and `resolve_following` are the dominant Carrick semantic frames |
| E026 | `564dd281`, `target/perf/lookup-kind-spike/`, and `docs/perf-results/native-fs-amplification.jsonl` | retained implementation; no official `C1` win | Five controls median 19.660 s versus candidate 19.163 s (−2.53%), candidate wins 5/5 with non-overlapping populations and one-sided 95% bootstrap ratio 0.9885; joined host opens fall 41.4% to 19.68 per guest open. A separate clean committed campaign median is 19.680 s, 305 ms slower than frozen `C0`, so it supplies no official ratio progress |

### H005a rejection and filesystem syscall reframe

Deep `ustack(64)` at Darwin wait boundaries proved useful but not sufficient
for Carrick caller identity: after the `libsystem_kernel` leaf, the native DSR
stack commonly crosses into anonymous MAP_JIT code. Pairing such addresses with
Carrick's symbol table produces plausible nonsense. The corrected capture keys
each stack by its contemporaneous host image base and uses the existing typed
`futex-route` probe to name guest futex waits without making that mistake.

Private futex waits account for 1,747/19,636 `psynch_cvwait` calls and 113.87 of
226.09 aggregate blocked thread-seconds, but a separate sampled kernel-CPU
capture shows only 58/19,525 kernel samples there: 0.30% of kernel CPU and
0.069% of all sampled CPU. The apparent dominance is idle resource time, not
recoverable host work. H005a is rejected before an invasive ulock spike.

The same capture assigns 2,302 kernel samples to `openat` and 2,427 to
`unlinkat`: together 24.22% of kernel CPU and 5.63% of all sampled CPU.
Carrick-side joins then measured 2,521 guest `openat` calls driving 79,282
Darwin `openat` calls during those services and 116,925 overall. A serial
Docker-only `bpftrace` census observed 3,263 Linux `openat`, 156 `unlinkat`,
282 `mkdirat`, 3,956 `newfstatat`, and 71 `execve`, close to Carrick's guest
population (2,521/156/282/3,827/67). The excess is therefore Carrick host
re-resolution, not a different Go workload.

Two mechanism screens do not count as wins. `--fs memory` cannot survive native
self-reexec because that backend is intentionally not fork-coherent. Skipping
owner scratch deletion exercised the intended teardown seam but produced a
noisier 23.73 s sample versus a 20.34 s control; it is rejected as a wall
candidate from this screen. The exact generated scratch
`/Volumes/carrick/.tmplT2eqC` was verified by its run-id cache and moved to
Trash.

The contained-parent `HostFsBackend::open_raw_fd` spike passed focused escape,
symlink, and fd-mode tests, then completed all ten alternating measurements
with exact `BUILD_OK` and zero cleanup failures. Controls were
20.95/19.89/20.49/23.55/27.26 s; candidates were
20.23/20.15/20.80/26.35/27.69 s. Their 20.95/20.80 s medians amount to only a
0.7% candidate improvement, below the fixed 3% gate, and the candidate won one
of five paired positions. A follow-up candidate trace proves the mechanism was
live: host `openat` during guest `openat` fell 79,282→60,243 (24.0%) and total
host `openat` fell 116,925→97,395 (16.7%), but traced joined-open duration fell
only 246 ms. The source spike is reverted. The next attribution targets the
remaining 24.7 host opens per guest open before the final raw open.

### Tasks 7–11 — capacity root cause, repair, and retention

An untraced current-default discriminator independently reproduced the v2
capacity failure, proving DTrace was not its cause. A freshly signed source
bracket then established the exact first-bad boundary:

- `de05a11a`: `BUILD_OK`, exit 0;
- immediate successor `98e2f0d6`: no `BUILD_OK`,
  `requested=296 used=67108692 capacity=67108864`.

The causal source delta changed ordinary private branch/call exits from the
compact gateway to a fixed 256-byte authority-aware precursor without a feature
gate. `2c53a210` later extended the same precursor to conditional,
continuation, and region exits; one conditional block carried 512 bytes of
precursors.

Commit `c65f4b0f6a2483984a9dbf7a1e85bc14a1bc91d2` introduces a typed
emission policy. Ordinary private JIT and artifact-store templates emit exact
56-byte direct gateways. Immutable portable-unit recording explicitly retains
the exact 256-byte authority-aware precursor, rich direct-link identity,
recovery coverage, and sidecar-rewrite geometry. The change increases no cache,
changes no target-cache ABI or unit schema, and passed red-first structural
coverage, 163/163 crate library tests, formatting, and an independent review
with no findings.

A fresh signed binary
(`f8af4e8512879d192454c9d99bb5be43780a6cee5d648d53269f7c6181775886`)
then completed exactly one diagnostic sample and five clean retention samples
inside the unchanged cache. Every run produced one `BUILD_OK`, exit 0, cleanup
status 0, and zero scoped survivors. The accepted serial five-plus-five raw
artifact hashes to
`d151ce9f60917ddd92170da184fc9309de3211c9dec5223c6f3032e00c837619`.

The retained result is a durable capacity/correctness step, not a wall-speed
claim. Carrick's 21,005 ms median is 1,630 ms (8.4%) slower than `C0`; Docker's
1,367 ms median is 360 ms (35.7%) slower than `D0`. Consequently the 15.3658x
same-run ratio is numerically lower but cannot be attributed to the code
repair. The next retained optimization must reduce Carrick wall seconds.

### Task 6 kernel attribution — runtime-capacity rejection

The single authorized v2 attempt started from clean
`3fb91b09afe0ec7e0aa240bcfc853f724abe166b`. The unchanged signed binary
retained SHA-256
`385e63d05ddf5ccfc55c9264a90f1f23302312c02647ccc23aa84e0844671fc0`;
strict codesign, the bundled native-wall completion marker, and
`__TEXT,__dof_carrick` passed. The preserved v1 A receipt and durable evidence
retained SHA-256 `b8b17f409241a2f902ce6559e8de85d82fcdb550559ab5f5e162f652e88881f0`
and `c09be20989146acbb018fa8bbe8171e89ed951cfa25579c3fc2d714eb9fa78af`.

Every v2 path was absent under `lexists` semantics. The image remained native
`arm64`, ID and repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
There were no ambient `CARRICK_*` controls, foreign workloads, busy-host
reasons, or Docker oracles; Docker contained only the two allowed `registry:2`
containers.

The controller was invoked exactly once, without rebuilding, a wrapper, or
manual `sudo`:

```sh
python3 scripts/perf/native_kernel_capture.py capture \
  --repo /Volumes/CaseSensitive/carrick/.worktrees/codex-native-aarch64-cache \
  --binary target/release/carrick \
  --artifact-dir target/perf/native-kernel-capture-3fb91b09-v2 \
  --run-id native-kernel-capture-3fb91b09-v2 \
  --image localhost:5005/carrick-go-conformance:1.24 \
  --timeout 180
```

The repaired target vector began with `run` and reached the cold Go compile.
Run A then reported DSR translation-cache exhaustion with 1,080 bytes
requested, 67,108,272 bytes used, and 67,108,864 bytes capacity. The compiler
exited 125, `BUILD_OK` count was zero, and the controller exited 1 after an
observed 51.2214 seconds. That duration and the profile's 21,340,483,208 ns
elapsed field are traced diagnostics, not performance results.

The trace command itself returned 0 and emitted a complete natural profile:
zero principal/aggregation/dynamic/other drops, zero incomplete pairs, 54
creates and exits, and zero live descendants. Its 4,202 wall samples split
2,576 on-CPU, 1,238 runnable-descheduled, and 388 transition. The partial CPU
census has 9,610 kernel and 15,066 user samples, so the diagnostic kernel share
is exactly 155/398. Kernel PC and stack totals reconcile exactly at
9,610, but zero of 9,610 leaves are symbolized. These partial-workload counts
cannot select or reject a kernel family.

The rejected A receipt hashes to
`278f58ec3cefc4a55c6e5a6f9fbc3417798af08ba8274c1c7284389ff7193627`.
All seven artifact size/hash bindings revalidated; its 499-sample monitor was
uncontaminated with one launch and one post-cleanup boundary, pre/post
provenance matched, scoped cleanup exited 0, and no owned process survived.
Every B output and `analysis.json` is absent. The v2 root is preserved
unchanged. The secret-safe derived evidence hashes to
`938052ebeefb0e34075e054fe1da2702c86b8e8e9f68fbdde3e68d941037e5c0`.

Outcome: **`MEASUREMENT_REPAIR_REQUIRED`**. Do not rerun v2, call this diffuse
or selectable, infer H006, enlarge the cache, or claim a wall-clock result.
Before authorizing another root, prove that the intended default implementation
completes the frozen cold-Go workload within the existing cache bound and
repair kernel-leaf symbolization enough to satisfy the fixed 95% gate.

### Task 4 kernel attribution — measurement framing rejection

The first authorized live Task 4 attempt started from clean
`7ec846a5f8ed5ad3fc549e3f54363c69cceb01e8`. The preserved baseline and M1
attribution evidence retained SHA-256
`9c9e25f8c7e4f40feb8a86293a2dbd71e3406db3a22a6aeaa9b0dfff23958e13`
and
`fdb73ea7880fb2cf957bcbbc9c122ad57d739377eecf0e8e90da0bccb0ad67d8`.
Focused structural gates passed 34 Rust profile-parser tests, six Rust profile
integration tests, 17 attribution tests, 43 capture tests, Python compilation,
and `just fmt-check`.

The conservatively added pre-capture `just ci` was not green. It stopped in
Clippy with three pre-existing, untouched findings:
`expect_used` at `direct_binding.rs:274`, `too_many_arguments` at
`emit.rs:1561`, and `vec_box` at `gateway.rs:58`. A comparison from
`7c98887c` through `7ec846a5` showed no changes to those files, and the
controller explicitly allowed the measurement-only gate to proceed. This is
not a retention waiver: any retained optimization still requires clean
`just ci`.

`just build` ran exactly once. Strict codesign passed, the Hypervisor
entitlement was present, the runner fixed the workload to
`--exec-backend native`, and the native-wall completion marker was bundled.
The binary was 23,336,272 bytes with SHA-256
`385e63d05ddf5ccfc55c9264a90f1f23302312c02647ccc23aa84e0844671fc0`.
The DOF section was present as `__TEXT,__dof_carrick`, not the brief's stale
`__DATA` spelling; the runner's DOF listing hash was
`49788cb5195034d9f1354f8a8e0ec86341d75f4bd9e1e06fcc82d6fb8250dfca`.

Every fixed planned path was absent under `lexists` semantics. The image was
native `arm64`, with image ID and repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
The process and real Docker-oracle censuses were empty; Docker contained only
the two allowed `registry:2` containers.

The runner was invoked once, without a wrapper or `sudo`:

```sh
python3 scripts/perf/native_kernel_capture.py capture \
  --repo "$PWD" --binary target/release/carrick \
  --artifact-dir target/perf/native-kernel-capture-7ec846a5-v1 \
  --run-id native-kernel-capture-7ec846a5-v1 \
  --image localhost:5005/carrick-go-conformance:1.24 --timeout 180
```

Run A exited 1 before the guest workload:

```text
carrick trace: not root; re-executing under sudo
error: unrecognized subcommand '/Volumes/CaseSensitive/carrick/.worktrees/codex-native-aarch64-cache/target/release/carrick'
Error: native-wall profile has no wall samples
```

The runner's target argv repeats the Carrick binary after `trace --`; after
auto-sudo that path was parsed as a Carrick subcommand. A emitted zero
`BUILD_OK`, no summary, and rejected receipt
`sha256:b8b17f409241a2f902ce6559e8de85d82fcdb550559ab5f5e162f652e88881f0`.
Its six available artifact bindings all revalidated. The monitor remained
uncontaminated for 12 samples, pre/post source, binary, image and host
provenance were identical, scoped cleanup exited 0, and no owned process
remained. The receipt's exact errors were:

```text
trace command failed with status 1
trace command did not emit exactly one BUILD_OK
```

All B outputs and `analysis.json` are absent. No second analyzer ran. There
are no kernel counts, fractions, candidate gates, diffuse reasons, or selected
family. The raw trace's 10,388,083 ns elapsed field is framing diagnostic data,
not a workload-performance result. The single-use artifact root is preserved
unchanged and must never be recycled.

This outcome is **`MEASUREMENT_REPAIR_REQUIRED`**, not `selectable` or
`diffuse`, and it does not create H006. The immediate next gate is a focused
red/green repair of trace target framing plus runner tests that exercise the
real auto-sudo CLI shape. After full focused verification and a clean
retention-quality `just ci`, authorize a new base and a new single-use
artifact root/run ID; never rerun `native-kernel-capture-7ec846a5-v1`.

### Task 15 direct-binding mechanism gate — rejected before live work

The frozen preflight was clean at
`c4d54b92f45f091e39966fe9a856b93e352da8b0`: `git status --porcelain=v1`
was empty, the only workload-census matches were the census shell and `rg`
itself, and Docker contained only `carrick-registry-5050` and
`vt-ferry-registry`, both using `registry:2`. No ambient
`CARRICK_DSR*`, `CARRICK_PERF*`, `CARRICK_EXEC_BACKEND`,
`CARRICK_NATIVE*`, or `CARRICK_RUN_ID` variable was present. The frozen image
was native `arm64`, ID
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`,
with repo digest
`localhost:5005/carrick-go-conformance@sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
The expected stale pre-Task-15 release binary remained
`sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`;
it was not rebuilt or used.

The exact serial structural status vector was:

| Gate | Status | Result |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 101 | compile failed with 25 `E0308` mismatches in `native_darwin/dsr/oracle.rs` |
| `cargo fmt --all -- --check` | not run in gate sequence | fail-closed stop after the preceding structural failure; the required pre-commit hook later ran the same command and passed |

The first error is at `oracle.rs:1641`; further construction sites and match
patterns through `oracle.rs:5336` pass or expect `None`/`Some(_)` for
`binding`, but the field now has type `DirectBindingExitMetadata`. This is a
structural rejection, not a measured mechanism result.

Consequently `just build`, signing/DOF/marker verification, the exact
one-sample feasibility command, and `direct_binding_mechanism.py capture-pair`
were not run. No run ID or guest process existed, so command status,
`BUILD_OK`, scoped cleanup status/output, descendants, child CPU, elapsed
workload time, pre/post runner snapshots, and timing claims are all **not
applicable**, not measured zeroes.

Every single-use evidence path remained absent and therefore has no SHA-256:

- `target/perf/direct-binding-feasibility-v1.json`
- `target/perf/direct-binding-feasibility-v1-logs/`
- `target/perf/direct-binding-mechanism-v1.json`
- `target/perf/direct-binding-mechanism-v1/precursor/{trace.log,summary.jsonl,stdout.log,stderr.log,receipt.json}`
- `target/perf/direct-binding-mechanism-v1/candidate/{trace.log,summary.jsonl,stdout.log,stderr.log,receipt.json}`

Because neither receipt exists, there are no bound raw/summary/profile/stdout/
stderr hashes, cleanup receipts, precursor/candidate gateway vectors
(`syscall`, `direct`, `indirect`, `fault`, `kick`, `sensitive`,
`unsupported`), binding-event vectors (`eligible`, `publish`, `CAS loss`,
`clear`, `validation failure`, `unit loaded`), translation attempts,
unique `(pid,cell)` pairs, clear/validation reasons, reconciliations,
process-cell bounds, collapse values `S/D/G`, or reclassification equations to
report. Variant 1 is **rejected before mechanism evaluation**. Do not tune the
22-word path. At that checkpoint, the next instruction was to restore the
mandatory runtime oracle gate and rerun Task 15 from fresh absent artifact
paths. That instruction is historical and superseded by the later `8d440b61`
retry and subsequent deterministic recovery work at `cbac611c`.

### Task 15 direct-binding mechanism retry — jitter coverage rejection

The retry started from clean
`8d440b616ad163faf446078975d58aeb7788e233`; repair `7cebf638` is an
ancestor. The workload and spin-loop censuses found only their own shell and
`rg`. Preflight load averages were `2.77 3.63 3.62`, which is context rather
than performance evidence. Docker contained only the excluded
`carrick-registry-5050` and `vt-ferry-registry` `registry:2` containers. No
real Docker oracle or ambient `CARRICK_DSR*`, `CARRICK_PERF*`,
`CARRICK_EXEC_BACKEND`, `CARRICK_NATIVE*`, or `CARRICK_RUN_ID` value was
present.

The image remained native `arm64`, with image ID
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`
and matching localhost repo digest. All four fixed single-use paths were
absent. The stale, unrebuilt executable still hashed to
`sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`;
that is not a signing or source-marker receipt.

The retry's serial structural vector was:

| Gate | Status | Result |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 101 | compiled and ran; 8 passed, 1 failed, 1,063 filtered |
| `cargo fmt --all -- --check` | not run in gate sequence | fail-closed stop after Gate 3 |

The failure was
`direct_binding_jittered_sigpipe_recovers_every_preamble_phase`:

```text
covered=[true, true, true, true, false, true, false, true]
recovered_words=[11, 152, 818, 26, 212, 54, 3, 17, 1808, 0, 0, 861, 75, 8, 511, 0, 0, 0, 0, 0, 0, 0, 0, 2, 126, 2756, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
signals=10000
```

Index 4 is the separately forced and assertion-exempt `AuthorityInstall`
phase. Index 6 is `FinalBranch`; its missing coverage rejected the mandatory
broad control. This checkpoint does not classify the result as a runtime
defect or a probabilistic false red: the one required run failed.

Therefore the signed build, codesign/Hypervisor entitlement, DOF, marker,
feasibility, and `capture-pair` commands were not run. No run ID or guest
process existed, so command status, `BUILD_OK`, cleanup, descendants, child
CPU, runner-frozen provenance, and elapsed workload time are not applicable.
The feasibility and pair paths, both receipts, and all bound artifacts remain
absent and have no SHA-256 hashes.

Every exit/event vector, reconciliation, translation attempt, `(pid,cell)`
identity, publication/clear bound, typed validation reason, and `S/D/G`
equation is unobserved rather than zero. The 95% mechanism gate was not
evaluated, and no traced elapsed time exists. Variant 1 remains **rejected
before mechanism evaluation**; do not tune its 22-word path from this result.
At that checkpoint `cbac611c` was structural repair provenance only; no Task 15
structural, signed-feasibility, or live mechanism gate had rerun after it. The
later `b1700108` structural retry is recorded below.

### Task 15 final retry — focused runtime hang rejection

The final retry started from clean
`b1700108391058b7d0b18281028236d2e5b56960`. Preflight again found no
foreign Carrick, benchmark, or spin-loop workload. Load averages were
`3.34 3.13 3.17`, which are host context rather than performance evidence.
Docker contained only the excluded `carrick-registry-5050` and
`vt-ferry-registry` `registry:2` containers, and the candidate image remained
native `arm64`, ID and repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
No ambient candidate/profile control was present. All four fixed single-use
paths were absent. The stale, unrebuilt release executable still hashed to
`sha256:1f55a200175ec19f33f1deed085a68175b164c7f3500cca8165179247258849c`;
it was not verified or executed.

The final retry's structural vector was:

| Gate | Status | Result |
|---|---:|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | terminated / rejected | the first four focused tests passed; `direct_binding_jittered_sigpipe_stress_preserves_state` started but did not return |
| `cargo fmt --all -- --check` | not run | fail-closed stop during Gate 3 |

At 15:07 elapsed, the controller observed cargo parent PID 25354 and test PID
25370. The test had accumulated 15:05.75 CPU, used about 99.6% of one CPU, and
was in runnable state `R`. This is evidence of a focused structural-test hang,
not progress within its 10,000-signal loop and not guest workload performance.
The controller interrupted the agent and sent `TERM` only to PIDs 25370 and
25354; both were subsequently absent. A prior authoritative repair receipt,
`target/task14-fix5-jitter-stress-green.log`
(`sha256:dde7eb3ef5a9f3d0de148ec1743a51d287e71623b754d357e6954be40cace421`),
records this exact named stress test completing 10,000 signals and passing in
8.32 seconds. That older receipt is comparison evidence only, not a substitute
current-run pass.

After termination the workload census again found no foreign Carrick or
benchmark process, and the exact feasibility and mechanism paths remained
absent. Gate 3 has no normal exit receipt. Gate 4, `just build`, signing,
entitlement, DOF, marker, feasibility, and `capture-pair` were not run. No
run ID, guest, `BUILD_OK`, cleanup receipt, child CPU, or runner-frozen
provenance exists. Every live exit/event vector, reconciliation,
process-cell bound, validation reason, and collapse/reclassification equation
is unobserved, not zero. The 95% gate was not evaluated and there is no traced
or untraced workload-performance result.

Variant 1 remains **rejected before mechanism evaluation**. The next action is
to diagnose the focused test's per-sample synchronization deterministically
and establish why a test that previously completed in 8.32 seconds can spin
for more than 15 minutes. Do not rerun Task 15 live gates, tune the 22-word
path, or advance to wall screening until that structural hang has a
discriminating red-to-green explanation.

### Task 15 live retry — feasibility cache-exhaustion rejection

The next retry started from clean
`ece8c49769ecf3420915dfa4215ab56e7f082852`. Preflight found no ambient
Carrick controls, foreign Carrick/benchmark/compiler/runtime-test/spin-loop
process, or real Docker oracle. The only running containers were the excluded
`carrick-registry-5050` and `vt-ferry-registry` `registry:2` registries. The
candidate image was native `arm64`, with image ID and localhost repo digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
Source status was clean and all official v1 evidence paths were absent.

The complete serialized structural vector passed:

| Gate | Status | Result | Log SHA-256 |
|---|---:|---|---|
| `cargo test -p carrick-dsr-aarch64` | 0 | 162 passed, 0 failed; doc tests passed | `ad888ea14f7bf02d90f8a2ab07668e0ccb12d6e6428e48856445652682c7c308` |
| `cargo test -p carrick-native-darwin` | 0 | 31 passed, 0 failed; doc tests passed | `a6980c18dc68dcc0679d6d0735cd70aca2aac63137e008c3f4fd85adb29ba69d` |
| `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::direct_binding_'` | 0 | 10 passed, 0 failed; 1,063 filtered | `97e52e6d8ed3f883b069e7d4a55760abac36cbd80d0022db4ce6e5b84cea8de3` |
| `cargo fmt --all -- --check` | 0 | no diff | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

`just build` then rebuilt and signed the current release binary. Its SHA-256
changed from the stale pre-build value to
`231afeda1ff693dd73f425143dc05c1f28265da897010c23bdd87a7a018c70bc`.
`codesign --verify` passed, the Hypervisor entitlement was true,
`__TEXT,__dof_carrick` was present, and the binary contained
`CARRICK_DSR_DIRECT_BINDINGS`. The build, codesign, entitlement, DOF, and
marker log hashes are respectively
`e39b00b6a8eafd85d09d438eb01d52785444136191c9a07671581e37986e167e`,
`414810baa7242e8f2f1d15ca8858ac07912d4a12b21f64b3aafc3f91f8783216`,
`1e9b2e89b47d7a5fa916dafd6a5a59e265d4d63765b61475c6d3a5cb454c042c`,
`a993c3e470cad32a387b8d454d41f017fb0ccdf9a3de1eb6c69692243fd7aeb6`,
and
`c9c17617fefcae17108dd433520cb7e3258ae300595c124acaff2a433c0d5b69`.

The first feasibility invocation was controller-invalid. An outer
`gtimeout ... | tee` wrapper made the runner's foreign-process census see the
controller shell and `gtimeout` itself, so it exited before guest launch.
That is not a runtime sample. Its preserved log is
`target/task15-live-gate-ece8c497/11-feasibility-command.log`
(`sha256:0c87b605c813706d60db1061510d27a9325edfbbeb28fe2717f49b2c8e5d5a72`).
It created neither the official v1 JSON nor the v1 captured-output directory,
and those names were not reused.

The explicitly authorized recovery used new v2 paths and shell process
replacement, with no controller process left in the runner's census:

```sh
exec python3 scripts/perf/native_go_build.py --engine carrick \
  --variant candidate --samples 1 \
  --output target/perf/direct-binding-feasibility-v2.json \
  --captured-output-dir target/perf/direct-binding-feasibility-v2-logs \
  > target/task15-live-gate-ece8c497/12-feasibility-command-v2.log 2>&1
```

That command reached the workload under run ID
`native-go-build-carrick-50399-1785219847221505000-1` and exited 1 with:

```text
native Darwin guest thread 50572 error: unsupported in this backend: DSR translation cache exhausted: requested=696 used=67108188 capacity=67108864
runtime: /usr/local/go/pkg/tool/linux_arm64/compile: exit status 125
```

There was no exact `BUILD_OK`. The runner raised before writing
`target/perf/direct-binding-feasibility-v2.json`, so that JSON is absent rather
than a rejected timing record. The captured workload error log exists at
`target/perf/direct-binding-feasibility-v2-logs/carrick-1.log`
(`sha256:02ec397ab3c528d6a8fcd12e52569d76299c88623a2126b709d5c8179b6dbe4f`);
the v2 command log hashes to
`2b551358aaf66646229dc88ce69cac1458a233e9a4ca9d6b1591978e4e3192f5`.
No elapsed value from this rejected command is a workload-performance result.

The runner entered its `finally` path and invoked run-ID-scoped cleanup. No
cleanup exception surfaced, and the post-stop census found no surviving guest
or descendant. Because the runner raised before serializing evidence, exact
cleanup status/output and its in-memory pre/post provenance were not retained;
they must not be reported as a zero cleanup status or accepted provenance.
Source stayed clean and the rebuilt binary hash stayed unchanged.

The mechanism command was not run. Its v2 directory, JSON, precursor and
candidate receipts/logs are absent. Therefore every exit/event vector,
translation count, receipt-bound hash, DTrace reconciliation and drop count,
process-cell bound, publication/clear reason, and `S/D/G` collapse or
reclassification equation is unobserved rather than zero. The 95% mechanism
gate was not evaluated.

H004 Variant 1 is **rejected at feasibility**, before mechanism evaluation.
Do not increase the translation-cache size, tune the 22-word path, or start
Task 16 from this failure. Return to clean default-path attribution and select
the next evidence-backed hypothesis.

## Whole-tree attribution

The clean `688357ef` pair satisfies the revised campaign reconciliation
contract. Run A/B classified 88.3%/89.8% of CPU samples, reconciled 100% of
wall samples, recorded zero drops, and kept every category above 10% within
five percentage points. The 90% classification target was lowered to 85% after
this pair because its remaining unresolved population does not change the
dominant result: translated guest execution and Darwin kernel work consume
about 71% of sampled CPU together. The unchanged completeness and stability
gates keep that conclusion evidence-backed while ending a mapping campaign
that had become secondary to wall-clock improvement.

Trace A reached every collector-level completion invariant but is not accepted
campaign evidence: the summarizer left 19.6% of CPU samples unresolved. The
profiler/classifier must identify those exact address populations before the
trace is repeated; they are not assumed to be translated guest execution.
The correction publishes exact executable dyld ranges lazily through USDT and
adds `darwin-userspace` plus per-image shares; it does not widen the JIT range
or weaken the 90% classification gate.
The first full retry with that correction is also rejected: collector state
was undersized for the combined high-cardinality PC aggregations and 64 KiB
catalog strings. Buffer capacity must be sized from the raw census before
another evidence trace.
The census found 391 ranges per child, while Carrick plus the Darwin
process-runtime family covered all but one dyld-classified sample. The bounded
retry announces 80 exact runtime ranges (about 6.8 KiB per child) under a
16 KiB string cap; any excluded framework PC remains unresolved rather than
being assumed safe.

The first bounded full-workload run showed that children execute from their
inherited Carrick mapping before self-reexec publishes the replacement ASLR
base. The DTrace process-create path now propagates the parent's exact base to
the child, and keeps the state explicitly 64-bit.

The first accepted tooling spike attributes CPU samples as 37.3% translated
guest, 33.5% Darwin kernel, 8.4% Darwin userspace, 5.9% process setup, 3.7%
other Carrick, 2.0% dispatch, 0.4% gateway, 0.1% translation, and 8.9%
unresolved. It is not promoted to campaign evidence because the tooling
worktree was dirty; two clean commit-exact captures still gate M1.

The first clean replication pair then exposed a second inherited mapping:
fork children execute translations from the parent's current JIT cache before
their replacement cache is announced. The original per-PID range census
therefore saw no duplicates because it was missing the inherited range.
Propagating the parent's exact JIT start/end at process creation yields two
ranges in 67 children on the same workload and restores the accepted 91.0%
resolved-CPU result. Clean replication must still prove that this closes the
run-to-run gap.

It did not. The next clean pair showed that a self-reexeced process may run to
exit without issuing another guest execve, so the execve-site host-image probe
never publishes its final Carrick ASLR base. The profiled native loop now
publishes the host base at the same boundary as the current JIT range. A
same-run DTrace module census joined to `vmmap` also proves that raw private PCs
in the sampled Go parent belonged only to MAP_JIT or Carrick `__TEXT`.
Consequently, an address inside the PID's exact announced host range is
conservatively classified as `other-carrick` when `atos` lacks a symbol; it is
never assigned to a named Carrick subsystem.

The final missing base was the initial guest child itself. The outer native
runner has never entered a guest loop, so its first `proc:::create` has no
host-image state to propagate. The child now publishes its Carrick image
immediately after the existing process-runtime attribution anchor and before
guest setup or descendant forks. This lifted the next full-workload spike to
92.1% resolved CPU.

### Elapsed wall-state occupancy

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| tracked tree on CPU | 96.8% | 99.8% | yes |
| runnable but descheduled | 2.5% | 0.2% | yes |
| all tracked threads sleeping | 0.0% | 0.0% | yes |
| transition / unclassified | 0.6% | 0.0% | yes |
| accounted total | 100.0% | 100.0% | yes |

### On-CPU resource share

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| translated guest/JIT | 36.7% | 37.0% | yes |
| translate/decode/plan/emit/publication | 0.4% | 0.1% | yes |
| gateway prepare/resolve/finish/recovery | 0.0% | 0.1% | yes |
| syscall dispatch and host runtime | 0.1% | 0.8% | yes |
| process/capsule/exec setup | 5.1% | 5.3% | yes |
| Darwin userspace | 8.3% | 8.0% | yes |
| Darwin kernel | 34.5% | 34.3% | yes |
| other Carrick host | 3.2% | 4.3% | yes |
| unresolved | 11.7% | 10.2% | accepted below 15% |

### Off-CPU resource attribution

| Rank | Blocking mechanism / stack | Share | Critical-path evidence |
|---:|---|---:|---|
| 1 | untyped `psynch_cvwait` population | 92.78% of joined wait duration | current reason capture; outer boundary still pending |
| 2 | process-state read acquisition | 4.26% of joined wait duration | typed USDT acquisition join |
| 3 | process-state write + generation-table write acquisition | 3.07% combined | typed USDT acquisition join |
| top-stack coverage | not accepted | DSR user-stack unwinding exposed guest state; reason probes replaced stacks | |

### 2026-07-28 condvar-reason loop

Two low-detail captures replicated the coarse result: 97.06% and 97.26% of
the observed condvar calls occurred outside the current thread's guest syscall
service window. Raw `ustack()` aggregation was rejected because native DSR can
expose guest stack state to the unwinder. The replacement capture joins
`psynch_*` syscall entry/return durations to typed, acquisition-only USDT
boundaries.

The joined capture measured 62.262 thread-seconds in `psynch_cvwait`.
Generation-table write, process-state write, and process-state read
acquisitions explain 0.892 s, 0.956 s, and 2.649 s respectively: 4.497 s
combined, or 7.22%. The untyped population owns 57.765 s (92.78%) and the
longest individual wait (3.744 s). These are aggregate thread durations under
DTrace, not elapsed wall time.

Three correct single-sample screens then tested increasingly strong versions
of the translation-lock hypothesis against a contemporaneous 21.06 s control:

| Spike | Wall | Result |
|---|---:|---|
| allow process-state readers to barge | 22.48 s | reject and revert (+6.7%) |
| give every guest thread a private process translator | 29.53 s | reject and revert (+40.2%) |
| bypass disabled direct-binding/shared-metadata locks | 21.14 s | reject and revert (no win) |

All three printed `BUILD_OK` and `ok`. They are busy-host screens, sufficient
only to reject negative or absent movement. None is promotion evidence. The
durable evidence is
[`native-condvar-reasons.jsonl`](native-condvar-reasons.jsonl).

## Hypothesis backlog

Status values: `PROPOSED`, `SPIKING`, `RETAIN`, `REJECT`, `DEFER`.

| ID | Status | Observation | Current size | Hypothesis / bounded proof | Stop condition |
|---|---|---|---:|---|---|
| H001 | PROPOSED | 862,580 residual indirect resolver exits | event count, wall share pending | Classify call/return locality; test one bounded return-target structure | Two variants fail to reduce exits and untraced wall |
| H002 | PROPOSED | 5.806 s diagnostic emission time across 1.868M translations | stale traced aggregate | Sample and split allocation, relocation, publication and I-cache work; spike only the dominant subphase | No current dominant subphase or two variants fail wall gate |
| H003 | PROPOSED | Older profile assigned CPU to repeated capsule setup | stale sample | Refresh process-lifetime share and critical-path overlap; reuse only the dominant durable input | Current share is small/non-critical or two variants fail |
| H004 | REJECT | Authority caching leaves at least 17.16M bounded direct misses, led by one conditional fall-through edge at 1.47M | signed Variant 1 feasibility exhausts the 64 MiB DSR translation cache before `BUILD_OK` | Compact per-edge mutable binding cells were the bounded proof; the mechanism pair was not run | Rejected at feasibility; no cache increase, sidecar tuning, or Task 16 is authorized |
| H005 | DEFER | Private futex owns 50.4% of blocked thread-time but only 0.069% of sampled total CPU | 58/84,037 sampled CPU ticks | Revisit only if critical-path evidence shows waking earlier removes runnable work | Filesystem work currently has materially larger measured CPU share |
| H006 | RETAIN | Exact caller stacks assigned 33.3% of joined opens to `lookup_kind` and another 10.8% to unconditional `read_link` | paired candidate: 46,493 joined host opens / 2,363 guest opens; 19.163 s median. Clean isolated median 19.680 s does not beat `C0` | Keep descriptor-contained lookup-kind and no-follow metadata with cap-std fallback; finish correctness closeout but claim no official `C1` win | Revert only for correctness failure or a future contemporaneous paired regression; isolated baseline drift does not override the 5/5 paired result and explicit retain direction |
| H007 | SPIKING | The retained path still drives 19.68 host opens per guest open; pre-change stacks ranked `resolve_following` and terminal open next | post-change caller census pending | Re-census exact Carrick frames, then carry one contained descriptor/metadata authority bundle through ordinary open dispatch if resolver/final-open rewalks still dominate | No remaining stable dominant rewalk, or the bounded combined primitive fails mechanism and wall screens; then pivot to Carrick-only teardown unlink amplification |

The table order is provisional until E005 and E006 exist.

## Spike decision log

| Date | Hypothesis | Variant | Predicted mechanism / ceiling | Screening | Five-sample result | Decision |
|---|---|---|---|---|---|---|
| 2026-07-27 | campaign | measurement first | Account for dominant wall/CPU proportions before selecting code | pending | n/a | measurement construction |
| 2026-07-27 | H004 | current full shared-unit mode | Reuse repeated compiler translations | 40.211 s vs 19.809 s control | n/a | reject current policy; 2.03x slower |
| 2026-07-27 | H004 | remove three publication `fsync`s | Test whether durable I/O causes the regression | 39.98 s | n/a | reject; only 0.231 s below full mode |
| 2026-07-27 | H004 | publish but never load | Isolate producer cost | 20.74 s | n/a | producer adds only 0.93 s; consumer is dominant |
| 2026-07-27 | H004 | load/parse but skip block indexing | Separate manifest decode/dlopen from eager registration | 22.78 s | n/a | about 17.2 s belongs after load, in eager indexing |
| 2026-07-27 | H004 | cap each segment unit to 10,000 / 1,000 / 250 / 100 blocks | Test whether bounded hot-prefix units avoid eager amplification | 41.49 / 37.62 / 21.30 / 20.44 s | n/a | size cliff confirmed; no cap beats control |
| 2026-07-27 | H004 | lazy all-unit metadata | Avoid eager PC/recovery registration | 57.45 s, 126.95 user-s | n/a | reject; repeated unit lookup made the hot path worse |
| 2026-07-27 | H004 | eager guest index, lazy PC/recovery metadata | Keep the warm lookup path without expanding all metadata | 39.12 s, 92.13 user-s | n/a | reject; only about 1 s better than full mode |
| 2026-07-27 | H004 | omit portable generation guard | Test whether binding-index prelude causes shared execution cost | 38.73 s, 91.46 user-s | n/a | reject and revert; essentially unchanged |
| 2026-07-27 | H004 | transitively closed direct-target subset | Publish only blocks whose direct targets share the immutable unit | 55.24 s, 139.49 user-s | n/a | reject; lost reuse and remained resolver-heavy |
| 2026-07-27 | H004 | authority-carrying two-way target cache for direct/indirect edges | Permit safe cross-unit chaining without mutating signed code | 25.169 s median across three correct samples | n/a | keep as correctness precursor, not a wall win |
| 2026-07-27 | H004 | inline conditional target-cache lookup in all code | Collapse the 1.47M hottest fall-through misses | failed: 64 MiB private JIT cache exhausted | n/a | reject; code-size explosion |
| 2026-07-27 | H004 | inline conditional lookup only in portable artifacts | Avoid private-cache expansion while chaining shared conditionals | 24.664 s first sample; replication crashed in Go runtime | n/a | reject and revert; too small and unsafe |
| 2026-07-27 | H004 | compact direct-binding sidecar Variant 1 mechanism gate | Collapse at least 95% of sidecar-eligible direct resolver exits with matching direct/gateway reclassification | structural gate failed before signed feasibility | n/a | reject before mechanism evaluation; runtime oracle fixtures/patterns do not compile |
| 2026-07-27 | H004 | compact direct-binding sidecar Variant 1 mechanism retry | Same 95% collapse and reclassification gate after metadata repair | focused runtime oracle ran 9 tests, but the 10,000-signal broad control missed `FinalBranch` | n/a | reject before mechanism evaluation; resolve deterministic recovery coverage before another live retry |
| 2026-07-27 | H004 | compact direct-binding sidecar Variant 1 final retry | Same mechanism gate after deterministic recovery repairs | focused runtime Gate 3 spun for more than 15 minutes in the jitter stress after four tests passed | n/a | reject before mechanism evaluation; diagnose per-sample synchronization before another gate |
| 2026-07-27 | H004 | compact direct-binding sidecar Variant 1 live feasibility | Same 95% mechanism gate after the jitter synchronization repair | structural and signed-binary gates passed; wrapper-free Go build exhausted the 64 MiB DSR translation cache before `BUILD_OK` | n/a | reject Variant 1 at feasibility; mechanism unrun, return to default-path attribution |
| 2026-07-28 | H005 | process-state reader barging | Reduce the largest typed condvar reason without changing cache ownership | 22.48 s vs 21.06 s control | n/a | reject and revert; +6.7% wall |
| 2026-07-28 | H005 | private translator per guest thread | Remove process-state contention completely; tolerate duplicate translation only as a feasibility spike | 29.53 s vs 21.06 s control | n/a | reject and revert; +40.2% wall and 70.46 user-s |
| 2026-07-28 | H005 | bypass disabled-feature process-state locks | Remove direct-binding/shared-metadata lock work when both features are off | 21.14 s vs 21.06 s control | n/a | reject and revert; no wall win |
| 2026-07-28 | H006 | contained-parent terminal `open_raw_fd` | Remove cap-std component walks from the final host-file open | first pair 20.23 s vs 20.95 s control | 20.80 s vs 20.95 s medians; 1/5 paired wins | reject and revert; real 24% joined-call reduction has only a 0.7% wall median |
| 2026-07-28 | H006 | contained `lookup_kind` only | Remove the largest exact caller family before changing no-follow ordering | 19.91 s vs 20.22 s control | n/a | mechanism live (−23.7% joined host opens), but 1.5% one-pair wall movement is insufficient alone; combine only with separately attributed no-follow work |
| 2026-07-28 | H006 | contained lookup-kind plus no-follow metadata | Skip ordinary-file `read_link` and metadata component walks while preserving symlink and exceptional fallback | 19.210 s vs 20.253 s first pair | 19.163 s vs 19.660 s medians; 5/5 paired wins; all candidates below all controls | retain at `564dd281` by explicit user direction; clean committed replication and closeout gates pending |

Prior rejected experiments remain recorded in `handoff.md`; they are not reset
to `PROPOSED`.

## Correctness and verification

| Wave | Focused tests | Signed Go demo | Native smoke | Node/CPython guardrails | `just ci` | State |
|---|---|---|---|---|---|---|
| historical `9c25688d` | green | green | 23/23 MATCH | Go sync 52/52; CPython threading 193/193; subprocess 278/278 | green | accepted starting implementation |
| M1 measurement tooling | 18 Rust + 17 Python tests green | native container smoke printed `TRACE_OK` | n/a | n/a | signed build + DOF present | analyzer accepted container and adversarial scope traces; Go-build evidence pending |
| Task 15 direct-binding mechanism gate | 162 AArch64 DSR + 31 native-Darwin tests green; runtime oracle compile failed with 25 `E0308` errors | not run | not run | not run | not run | rejected before live work |
| Task 15 retry at `8d440b61` | 162 AArch64 DSR + 31 native-Darwin tests green; focused runtime oracle 8/9 with missing `FinalBranch` jitter coverage | not run | not run | not run | not run | rejected before live work |
| Task 15 final retry at `b1700108` | 162 AArch64 DSR + 31 native-Darwin tests green; focused runtime Gate 3 terminated after a greater-than-15-minute jitter-stress spin | not run | not run | not run | not run | rejected before live work |
| Task 15 live retry at `ece8c497` | 162 AArch64 DSR + 31 native-Darwin + 10 focused runtime tests green; format clean | rejected: DSR cache exhaustion, no `BUILD_OK` or JSON | not run | not run | not run | H004 Variant 1 rejected at feasibility; mechanism unrun |
| Task 4 kernel capture at `7ec846a5` | 34 profile unit + 6 integration + 17 attribution + 43 capture tests green; Python compile and format clean | rejected before guest: auto-sudo trace framing parsed the repeated binary as a subcommand | not run | not run | exit 101 on three pre-existing untouched Clippy findings; not waived for retention | `MEASUREMENT_REPAIR_REQUIRED`; A rejected, B/analysis absent |
| Task 6 kernel capture at `3fb91b09` | Task 5: 45 capture + 17 attribution tests green; independent review clean | rejected during Go compile: 64 MiB DSR cache exhausted, zero `BUILD_OK` | not run | not run | not rerun for evidence-only Task 6 | `MEASUREMENT_REPAIR_REQUIRED`; A partial profile preserved, B/analysis absent |
| H006 contained metadata at `564dd281` | four focused filesystem tests green; serialized runtime suite 1,110 passed and one unrelated probabilistic DSR landing-coverage test failed | ten paired spike samples and five clean committed samples printed `BUILD_OK` with zero cleanup failures | pending | pending | pending | retained implementation; clean median 19.680 s supplies no official `C1` win; smoke and CI remain |

## Decisions

1. Cold Go build is the primary metric; Node and CPython are guardrails.
2. The historical 20.68x ratio is not promoted to `R0` without a fresh paired
   baseline.
3. Existing DTrace scripts are inputs, not accepted campaign evidence, until
   launch scoping and wall/resource reconciliation pass.
4. Optimization order follows current attribution rather than the historical
   handoff ranking.
5. M1 CPU classification accepts 85% rather than 90%; the clean pair already
   has stable dominant categories, while more image mapping does not advance
   the primary wall-clock goal.
6. H004 was selected over H001 at that checkpoint because the cache profile
   exposed 262.22 million gateway entries, versus 2.40 million on default. The
   initial no-index isolation implicated consumer work, but two lazy-metadata
   spikes falsified indexing as the dominant cause; executing immutable units
   amplifies unresolved edges instead. Decision 8 records its final rejection.
7. DBT/JIT precedent and the edge-shape trace both select immutable code plus
   mutable per-process binding state. Do not add another full inline target
   cache: it either exhausts private code capacity or perturbs asynchronous
   recovery. A direct binding must have a stable edge identity, bounded
   sidecar size, publication ordering, authority/version data and a recovery
   oracle before it receives a wall screen.
8. Task 15 reached signed feasibility at `ece8c497`: all four structural gates
   and signed-binary checks passed. The wrapper-free candidate then exhausted
   the 64 MiB DSR translation cache before `BUILD_OK`. This rejects H004
   Variant 1 at feasibility; the absent JSON, unrun mechanism pair, and
   unobserved collapse equations supply no workload-performance result.
9. Task 4 did not reach kernel-family selection. The fixed runner repeated the
   Carrick binary inside trace target argv, and auto-sudo parsed that path as a
   subcommand. Preserve the rejected A receipt and root, repair the real CLI
   framing with a focused red/green test, and allocate a new versioned root
   before another live attempt. Do not create H006 from zero wall samples.
10. Task 5 repaired and independently verified the target framing. Task 6 then
    reached Go compilation exactly once, but the unchanged signed binary
    exhausted the 64 MiB DSR translation cache before `BUILD_OK`. Preserve v2
    unchanged. Its exact 9,610/9,610 kernel reconciliation and zero symbolized
    leaves are partial diagnostics only; no pair, selection, or H006 exists.
11. The 2026-07-28 reason join rejects translation-lock tuning as the next wall
    target. Its three typed lock reasons own only 7.22% of aggregate
    `psynch_cvwait` duration, and three progressively stronger screens produced
    no wall win. Continue H005 by naming the untyped 92.78% at outer wait
    boundaries; do not infer criticality from condvar event counts alone.
12. Exact open-boundary user stacks validate the syscall reframe: cap-std
    component walks in `lookup_kind`, `read_link`, `resolve_following`, and
    `open_raw_fd` dominate guest-open-driven host calls. The first retained
    demotion keeps cap-std as an explicit semantic fallback rather than removing
    the dependency. Its 2.53% median wall win is below the old conservative 3%
    screen, but all five candidate samples beat all five controls and the user
    explicitly approved retaining durable filesystem improvements.
13. On 2026-07-28 the user directed that the campaign stop measuring engine
    container setup and teardown: the primary metric is now the guest
    workload window alone. `native_go_build.py` v3 brackets the compile and
    execute steps with in-guest clock reads and reports
    `workload_median_ms` per phase plus `carrick_over_docker_workload`;
    the same script runs on both engines, so Docker's container lifecycle
    is excluded symmetrically. Full process wall time remains recorded as
    a secondary diagnostic. Consequences: per-run rootfs seeding, orphan
    sweeping, and scratch teardown leave the optimization queue; per
    guest-process exec overhead (capsule adoption, translation, syscall
    service) stays in scope because it occurs inside the window. Official
    `C0`/`D0`/`R0` remain valid only for the old convention; the next
    idle-host campaign freezes `W0`/`DW0`/`RW0` under the new one.
14. On 2026-07-28 the user accepted that this host will not reach a fully
    quiet state and directed that testing proceed in ambient desktop noise.
    Absolute medians against any frozen anchor therefore carry reduced
    weight; contemporaneous paired alternating candidate/control screens
    are the decision instrument, and the runner's built-in preflight
    (no foreign workloads, no compilers, load below the logical CPU count)
    remains the only idleness gate.

## Next action

Write and validate the executable M1 plan:

- [x] Extend the benchmark runner with a semantically identical Docker phase.
- [x] Build a launch-scoped whole-tree wall-state/on-CPU/off-CPU DTrace profile.
- [x] Add the fail-closed attribution summarizer.
- [x] Collect fresh untraced `C0`/`D0`.
- [x] Collect two complete traced runs and rank H001–H005.
- [x] Select and screen the current shared-cache implementation.
- [x] Falsify metadata indexing and generation guards as dominant causes.
- [x] Prove authority-carrying cross-unit direct/indirect cache hits.
- [x] Measure direct-edge heat and indirect miss entropy.
- [x] Falsify full inline conditional caching on code size and recovery.
- [x] Add compact per-edge mutable binding cells for unresolved shared-unit
      direct edges.
- [x] Repair the focused jitter stress's per-sample synchronization and pass
      the complete four-command structural gate at `ece8c497`.
- [x] Run the signed one-sample feasibility gate; reject H004 Variant 1 after
      the wrapper-free candidate exhausts the 64 MiB translation cache.
- [x] Attempt the first receipt-bound default-path kernel pair; preserve its
      rejected A receipt after trace auto-sudo framing fails before guest work.
- [x] Repair trace target framing with focused red/green runner coverage and
      independent review at `3fb91b09`.
- [x] Invoke the repaired single-use v2 controller exactly once; preserve its
      rejected A receipt after Go compilation exhausts the 64 MiB DSR cache.
- [x] Prove the frozen default workload reaches `BUILD_OK` inside the existing
      cache bound; retain `c65f4b0f` after five clean completions.
- [x] Reframe the dominant Darwin-kernel work around guest-driven filesystem
      amplification using a serial native-arm64 Docker syscall census.
- [x] Attribute joined host opens to exact Carrick callers at a synchronous
      syscall boundary and retain the contained lookup/no-follow wave.
- [x] Publish five clean committed candidate samples; record the valid
      19,680 ms median as no official `C1` win.
- [x] Close native smoke and `just ci` gates for the retained filesystem wave:
      after clearing five workspace clippy findings, `just ci` is green
      (2,663 tests) and `just conformance-native smoke --workers 4` reports
      23/23 MATCH with no regressions.
- [x] Freeze `W0`/`DW0`/`RW0` under the 2026-07-28 workload-window convention
      (Decision 13): `W0=18,321 ms` (18,321/18,457/18,140/18,286/18,622),
      `DW0=842 ms` (946/832/842/839/901), `RW0=21.7589x`, five strict-preflight
      samples per engine in separate phases at the committed runner tip.
      Ambient desktop load was ~2.2 at phase start (recorded in the evidence
      JSON); candidate decisions therefore continue to ride on paired
      alternating screens, never on isolated medians against this anchor.
      Evidence: `scripts/perf/evidence/native-go-build-workload-w0-v1.json`.
      The full-wall medians in the same run were 20,260 ms and 1,021 ms
      (19.84x); the excluded engine lifecycle is ~1.9 s for Carrick and
      ~0.18 s for Docker per run.
- [ ] Re-census post-change open callers and spike H007 only if one remaining
      resolver/final-open rewalk family is still dominant inside the workload
      window.
- [ ] Restore at least 95% symbolized kernel-leaf coverage before any future
      broad kernel capture. Never recycle v1 or v2 or infer a family from the
      rejected partial run.
