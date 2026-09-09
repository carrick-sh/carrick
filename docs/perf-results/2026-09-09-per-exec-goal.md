# Per-exec overhead: baseline and next goal

Measured 2026-09-09 on main e7db055ae; no runtime changes. The signed binary SHA-256 is afccec0cc339993c1ac265a3e6bf9c4c609f16da4d07150247a90201ab10d953, identical to the latest campaign receipt at 62c63d979; intervening changes are documentation only. LC_UUID 21E916E9-C9CD-3A7B-A0AB-9AB490809A71; hypervisor entitlement and __dof_carrick verified.

## Baseline

Five batches of 50 checked subprocess completions after five warmups, guest monotonic timing, one sequential workload, no overlapping Docker/Carrick phases. Both timing arms use python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a (arm64). Initial tag-based Carrick results were superseded after detecting a mutable-tag mismatch. These are diagnostic baselines, not interleaved candidate acceptance.

| Spawn | Carrick median ms | Docker median ms | Ratio |
|---|---:|---:|---:|
| /bin/true | 2.6705 | 0.1746 | 15.29 |
| python3 -S -c pass | 12.7274 | 3.6206 | 3.52 |
| python3 -c pass | 14.0619 | 4.2736 | 3.29 |

Evidence directory: target/perf/exec-overhead-20260909 (workload.py, pinned-baseline.out/.err, oracle.out/.err, exec-profile.raw, profile.out/.err).

## Sampling lead

The existing hvpatch-phase4-exec-profile.d captured 501 balanced begin/end windows, natural completion, zero reported probe errors, 1,537 CPU samples: 730 user and 807 kernel. PageTableManager::new accounts for 447 user samples (61.2% of user, 29.1% of total window CPU), with 219 attributed callers in build_page_tables_manager_from_live and 227 in prepare_global_exec_plan. This profile used the older Carrick python:3.12-slim image and is a mechanism lead requiring requalification on the pinned fixture. Traced timings are not performance evidence; the window excludes post-exec interpreter initialization and exit.

Source inspection identifies discover_next_free_spare in PageTableManager::new scanning every spare page for nonzero bytes before truncating the image. Establish the exact bytes scanned/copied and why each reconstruction occurs before choosing a change. Preserve last-nonzero-page semantics, zero holes, owner generations, rollback and publication invariants.

## Active objective

Bring the pinned Python spawn benchmark to <=2x native-arm64 Docker (currently approximately 8.55 ms target versus 14.06 ms baseline), diagnosing and removing unnecessary per-exec work beginning with repeated page-table reconstruction. Track /bin/true and Python -S separately so improvements cannot hide another phase. Validate impact on cpython-subprocess and cpython-multiprocessing_main_handling with correctness intact and paired interleaved base/candidate runs at fixed worker counts. Retain the overall <=2x ecosystem objective; this scoped goal does not assert full conformance closure.

Require mechanism evidence, red-first regression coverage through conformance-next/embed where applicable, serial host runtime tests and the full relevant signed probe family, exact final artifact receipts and scoped cleanup. Do not accept trace timings, cross-run four-worker comparisons, stale cached timings for changed images, skipped assertions or an unmeasured later binary. No push is authorized.

## First measured candidate: spare-cursor discovery

Pinned-image requalification produced 501 balanced exec windows with zero errors, 703 user samples and 832 kernel samples; `PageTableManager::new` held 436/703 user samples (62.0%). The separate low-frequency latency trace completed 201/201 execs, zero marker/probe errors: 2.262 ms average complete exec window, comprising 0.496 ms load/plan, 1.182 ms replacement and 0.585 ms publication tail. These are attribution timings, not an untraced performance gate. The much larger end-to-end spawn time requires additional startup/exit diagnosis.

The runtime-stage capture is **invalid**: it reports 101 completion errors because its join expects the old ASID at completion, while successful exec has a new ASID. The requested JSON output is also unsupported. Neither the raw stage rows nor the failed CLI invocation is a passing receipt.

`discover_next_free_spare` formerly inspected every spare page in the 1.75 MiB primary table image, testing the bytes individually. The candidate searches backward for the last nonzero page and compares each page to a zero page in bulk. It preserves zero holes below the high-water mark and ignores an incomplete trailing page. No owner, mapping, publication, rollback or allocation semantics change.

Red-first: `spare_cursor_discovery_stops_at_the_last_used_page` visits **440** pages on the original algorithm and **1** on the candidate for an occupied last page. The companion test covers all 4,096 byte positions in a spare page, interior holes, partial tails and constructor cursor clamping. All **193 carrick-mem lib tests pass**. Logs: `spare-red.log`, `spare-green.log`.

Untraced, serial ABBA on the pinned image; two runs per arm, each containing five 50-spawn batches after five warmups. Table values are the mean of each arm's two batch medians. Baseline/source and candidate binary identities are in `scan-provenance.json`; exact commands and all output are retained beside `scan-abba.json`.

| Spawn | Base ms | Candidate ms | Reduction |
|---|---:|---:|---:|
| /bin/true | 2.7821 | 1.9791 | 28.9% |
| python3 -S -c pass | 13.5011 | 12.6646 | 6.2% |
| python3 -c pass | 14.8452 | 14.1577 | 4.6% |

Candidate SHA-256: `ad86e454304484b579ce23ca6c2ddb9adad26ea4e191fefb05e07963ccba2993`. This is a measured dirty-source development artifact, **not** a final integrated acceptance binary. The shift from the initial 14.06 ms baseline to the paired base's 14.85 ms is why the improvement is computed within the pair, not against the earlier measurement. The <=2x goal remains open.

The whole-workload startup service trace (`scan-service.raw`) completed with status=ok and zero errors. It ranks `newfstatat`, `getdents64`, `brk` and `mmap` as leads; its high-perturbation durations are not CPU savings estimates. Follow up with low-perturbation phase/operation attribution and preserve the two ecosystem workload checks in the active objective.

Checkpoint validation: `just test` and `just clippy` exited zero. The serial runtime suite reports 2,574 passed / 2 existing ignored; HVF reports 471 passed / 3 existing ignored. `just conformance-probes` exited zero, including 873 generic execution announcements, the signed negative controls, 24 case tests, CLI contract and the retained lane (46 tests passed / 1 existing ignored). Full log: `probes.log`; the generic and case artifact manifests were copied separately before the shared receipt path could be overwritten. No `carrick:execdiag` process remained after the gate. There are no line-pinned inventory entries naming `crates/carrick-mem/src/page_table.rs`; this edit does not move other source files. Full ecosystem comparisons and final goal acceptance remain outstanding.

## Next diagnostic checkpoint: mmap faults dominate the event population

The first implementation is committed as `e1ce4909c`.

A same-binary ABBA of the existing `CARRICK_FAULT_WINDOW_BYTES` control (64 KiB vs 256 KiB) found no improvement. Ordinary Python averaged 13.563 ms at 64 KiB and 13.710 ms at 256 KiB; Python -S was 12.159 vs 12.499 ms. No default was changed. Evidence: `window-abba.json` and `measure-window.py`.

New durable instrument: `scripts/dtrace/hvpatch-exec-startup-census.d`. This samples logical host CPU placement and counts EL0 fault classes plus exec/COW lifecycle populations, with natural-exit and error checks. It does not mistake a repeated VA in another MM for a repeated page. These are diagnostic counts, not traced performance timings.

The first capture (`startup-census.raw`, 300 child spawns) records 301 balanced execs, 1,032 CPU samples, 167,082 faults, zero errors and no bound hit. The saved `host-cpu-topology.txt` identifies logical CPUs 0–5 as E and 6–9 as P; 1,014/1,032 samples (98.3%) are on P cores. E-core placement is therefore not the main explanation. Every fault is in the mmap VA region. The amortized fault population is approximately 557 per child spawn, including the parent's fixed startup.

The expanded capture (`startup-cow-census.raw`, 100 child spawns) records 101 balanced execs, 56,479 faults, natural success and zero errors:

- 23,944 translation faults (23,336 writes, 608 reads).
- 32,535 write permission faults.
- Exactly 32,535 permission-triggered COW transactions, each with stage-2, stage-1 and commit records. They are real COW transactions, not merely stale fault retries.

`startup-provenance.json` binds the final instrument and signed binary hashes. The corresponding `.out`/`.err` files retain the successful trace invocations. Scoped cleanup was verified.

Source fences for the next change: `FirstTouchArming` and `resident_fault_plan` in runtime `dispatch/mem.rs` deliberately observe anonymous page residency one Linux page at a time. `ensure_sparse_mmap_backing_censused` in HVF `trap.rs` can materialize a wider physical window but limits its pending publication receipt to the requested range. Separately, `materialize_private_file_backing` arms file views for page-granular COW so still-clean neighbouring Linux pages keep tracking file writes. A Darwin MAP_PRIVATE snapshot is explicitly not a substitute for that contract. Attribute file-page versus fork COW and per-fault cost next; do not equate a wider physical allocation with permission to mark neighbouring pages dirty/resident.

The <=2x performance objective remains active. The two full ecosystem workload comparisons and final integrated-artifact acceptance are still pending.

## COW attribution and instrument correction

The census now verifies the target's `syscall::exit` status, in addition to
natural process exit. The original script could accept a guest that exited
nonzero. `cow-maps.raw` is explicitly invalid (a guest Python quoting error),
and `cow-profile.raw` is invalid (zero sampled COW windows). Earlier successful
census populations are diagnostic observations, not a qualified target-status
gate. Final negative controls `sampling-negative.raw` and
`census-negative-final.raw` both record guest exit 23 and make the trace command
fail. The final positive captures below require and record exit zero.

`cow-maps-valid.raw` records two successful execs. The child's maps place the
large writable libpython mapping at `6000500000-600065e000`; most of the child's
322 committed COWs fall there. The parent's 335 COWs are reported separately.
This identifies interpreter startup writes to private file pages as a large
population, rather than assuming these are parent-after-fork copies.

The expanded census uses `[pid, tid]` for interrupted-thread COW windows;
`self->` state yielded zero profile joins on this host. `cow-kernel.raw` records
301 balanced execs, 167,082 faults and 96,935 balanced COW windows, zero errors,
no bound hit and target exit zero. Its sampled kernel stacks mostly return to
armed fault/COW probe functions: the four leading resolved probe return sites
alone account for 330 samples. They are instrument overhead, **not evidence of
an expensive HVF operation**. Installed KDKs do not match host build 26A5425a;
no kernel symbol names are inferred from those mismatched images.

The complementary `scripts/dtrace/hvpatch-exec-cpu-sampling.d` uses only 499 Hz
user/kernel stacks and target/error checks, without high-rate USDT probes.
`sampling-final.raw` completes 500 child spawns with target exit zero, zero
errors and no bound hit: 2,043 user and 2,493 kernel samples. Counts use DTrace
aggregations rather than a racy shared increment. Offline PIE load-base
qualification matches all 1,309 unique Carrick return sites to BL/BLR
instructions (load base `0x1027a0000`), using the identical code in the preserved
`carrick-scan` artifact. Inclusive user-stack counts include:

- `perform_frame_cow`: 471/2,043 (23.1%).
- Detached address-space retirement: 307/2,043 (15.0%).
- `resolve_mutating_fault`: 169/2,043 (8.3%).
- Within those paths, `retire_process_aliases` has 108 samples,
  `commit_cow_inventory_split` 52, `physical_cow_source_in` 51 and
  `cow_inventory_split_shape` 41. These nested counts must not be added to
  their parents.

This is a ranking, not a promise of recoverable wall time; unresolved kernel
stacks remain unattributed. Source inspection finds full extent iteration in
`cow_inventory_split_shape` and a scope-wide alias scan in
`physical_cow_source_in`, but neither should be rewritten without preserving
all overlapping/retained mapping and owner-generation cases and measuring a
paired untraced improvement. Physical 16 KiB copy size alone does not authorize
marking neighbouring Linux 4 KiB pages dirty.

`cow-sampling-provenance.json` binds the scripts and signed runtime artifact;
`sampling-final.symbols.json` retains every resolved user stack. No production
code changed in this diagnostic checkpoint. The performance goal, full ecosystem
comparisons and final integrated-artifact gates remain open.

## Rejected COW alias-window candidate

A candidate replaced `physical_cow_source_in`'s full process-scope alias search
with the existing size-class VA window index, retaining the exact predicate
and newest sequence. The red-first complexity test visited 2,051 rows before
the change; the candidate passed its bounded query test and all 472 HVF host
tests (3 existing ignored). However, untraced ABBA did not establish a useful
spawn improvement, so the production edit and test were discarded.

| Spawn | Accepted scan binary ms | Window candidate ms |
|---|---:|---:|
| /bin/true | 2.0374 | 2.2370 |
| Python -S | 12.9391 | 13.8365 |
| Python | 14.6010 | 14.5107 |

Ordinary Python's 0.62% change is too small to accept alongside the adverse
other rows and within-arm variation. Receipts: `cow-window-abba.json`,
`cow-window-provenance.json`, `cow-window-red.log`, `cow-window-green.log`,
and `cow-window-rejected.patch`. Candidate SHA-256:
`e80c0feb9530ea34042732f267db3c4a9e0cf74cea8497947c80dfec260c1954`.
The preserved `carrick-cow` is a rejected experiment, not the accepted runtime.
The next measured candidate targets the repeated removed-alias searches in
address-space retirement.

## Rejected removed-alias retirement candidate

The next candidate carried the first original alias alongside each affected
key, eliminating a repeated linear search of `removed_owned`. Instrumenting
the original search made a 512-alias retirement visit 131,841 rows; the candidate
passed the bounded-work assertion while preserving first-duplicate physical
identity and replay-epoch semantics. All 472 HVF host tests passed, with 3
existing ignored tests.

The paired untraced spawn results again did not establish a useful improvement:

| Spawn | Accepted scan binary ms | Retirement candidate ms |
|---|---:|---:|
| /bin/true | 2.0875 | 2.1283 |
| Python -S | 12.9430 | 12.9922 |
| Python | 14.4322 | 14.3276 |

Ordinary Python improved only 0.72%, while the other rows worsened slightly.
The production edit and regression test were discarded. Receipts:
`retirement-abba.json`, `retirement-provenance.json`, `retirement-red.log`,
`retirement-green.log`, and `retirement-rejected.patch`. Candidate SHA-256:
`c0643dc4de40510e708450b146aeb89032f48be06ce0ef95c4791e73cce27937`.
`carrick-retire` and the current `target/release/carrick` are this rejected
experiment; rebuild the CLI from tracked source before using the default path
for acceptance. `carrick-scan` remains the measured accepted optimization.

These experiments reject the two local scan changes as sufficient progress on
the spawn target, despite their synthetic scaling wins. Inspect the per-fault
COW transaction's larger combined cost next, preserving Linux 4 KiB clean-page
tracking, live owner authentication, and rollback across both translation
stages and inventory. No further runtime improvement is claimed from this
checkpoint. The original <=2x goal and every pending final gate remain active.

## Kernel-caller qualification and layered-dirent candidate

The accepted tracked runtime was rebuilt after the rejected experiments;
`carrick-accepted-current` has SHA-256
`8b5870b8a36cd89776dcaa85501cb3a283126b7ee639fc5e466ae0d6a6830f76`.
`kernel-caller.raw` adds interrupted user stacks to kernel-mode samples without
arming USDT. It completed 500 child spawns, target exit zero, no errors or
bound hit, with 2,091 user and 2,490 kernel samples. All 415 unique Carrick
return sites in the kernel-mode user stacks validate as BL/BLR at load base
`0x102774000`; the exact binary and script are in
`kernel-caller-provenance.json`.

Of the kernel samples, 1,494 are beneath ordinary `next_syscall` guest execution;
those remain guest/HVF time, not a named host optimization opportunity. COW has
494 user and 171 kernel samples inside `perform_frame_cow`; its kernel samples
include 93 in stage-1 maintenance and 78 in inventory reservation. Directory
reads have 260 combined user/kernel samples in `getdents64`, 246 through
`list_directory_entries`, and 224 through `layered_directory_entries`.

The directory path still collects sizes and full metadata per child even
though getdents needs only names, types and inode numbers. The current candidate
adds an optional dirent-only backend stream and merges upper/lower names with
the same whiteout and shadowing rules. Marker-node interference, an unsupported
stream, and unknown host record types select the old exact fallback. The
full-metadata API remains separate. Each host stream gets an independent open
description before using the existing reader. Candidate tests cover real inode
and type equality, marker refusal, layered additions/shadows/deletions, and
internal sidecars in both host and memory lower layers. The initial stream test
failed before implementation (`dirent-red.log`). Performance and final candidate
acceptance are still pending.

The first untraced ABBA supports retaining this candidate for broader checks:

| Spawn | Accepted current ms | Dirent candidate ms | Reduction |
|---|---:|---:|---:|
| /bin/true | 2.1313 | 2.1317 | -0.02% |
| Python -S | 13.2033 | 12.4950 | 5.36% |
| Python | 14.4554 | 14.0052 | 3.11% |

Candidate SHA-256:
`d54c4feb004ceec828cc8637a8d2a239508f1d94df6f01ab3b07a4804094d7a8`.
`dirent-abba.json` and `dirent-provenance.json` bind the exact development
artifact and paired runs. Runtime tests passed 2,576/2 ignored before the
memory-sidecar edge was added; the subsequent full backend module passed all
88 tests including that edge. The host override was then restricted to macOS
(the measured lane) so other platforms use the existing None fallback without
performing speculative directory opens. Signed probes, lint, inventory
reconciliation and final integrated-artifact performance remain pending.

## Decision reset: wall budget before the next optimization

The signed dirent probe gate subsequently exited zero (`dirent-probes.log`):
three generic shards, 24 scenario tests, the CLI boundary test, and 46 retained
tests passed (one retained test ignored); both unsigned negative controls passed.
Report-only amd64 differences remain outside this arm64 acceptance. This does
not close the pending full workloads, inventory reconciliation, or final
integrated-artifact performance comparison.

The investigation has identified CPU consumers, but has not yet established an
exclusive wall-time budget for the measured parent spawn-and-wait operation.
Inclusive stack counts overlap; kernel samples underneath guest execution are
not automatically runtime overhead. Neither is a valid additive savings budget.
Hold additional optimization edits until this gap is addressed.

### Hypotheses and refutations

| Hypothesis | Evidence / attempted refutation | Current conclusion |
|---|---|---|
| Repeated spare-page discovery dominates exec reconstruction | Original exec samples concentrated in PageTableManager::new; reverse/bulk scan reduced paired normal-Python spawn by 4.6% and true by 28.9% | Supported and partially removed; remeasure remaining reconstruction |
| Slow core placement explains the gap | 1,014 of 1,032 placement samples were on performance cores | Refuted as the primary explanation in that capture |
| Increasing the anonymous fault window removes substantial cost | 64 KiB versus 256 KiB paired runs did not improve normal Python or -S | Not supported; retain existing default |
| Most faults are redundant retries | Fault census had balanced real COW transactions; child COW addresses concentrated in writable libpython mapping | Retry explanation refuted; private-file startup writes remain relevant |
| COW kernel samples prove a large HVF bottleneck | High-rate armed USDT return sites dominated the earlier kernel capture | That attribution is invalid; use the no-USDT capture |
| COW alias lookup or retirement lookup is the next large saving | Both synthetic scaling improvements yielded under 1% normal-spawn improvement and worsened other controls | Both candidates discarded; not a claim that their scaling is ideal |
| getdents pays unnecessary full metadata cost | Source and qualified samples agree; dirent candidate improves paired normal spawn 3.11% and -S 5.36%, true unchanged | Supported candidate; broader workload and final artifact acceptance pending |
| The combined COW transaction is the largest recoverable remaining cost | 494 user + 171 kernel samples in perform_frame_cow in latest capture | Plausible, not established in exclusive wall milliseconds; individual transaction costs and safe avoidability unknown |

### Measurements needed to choose successfully

1. Refresh same-image native-arm64 Docker and Carrick measurements serially,
   preserving distributions, exact artifacts, and the true/-S/normal controls.
   The historical 14.06 ms / 4.274 ms = 3.29x baseline is not a current ratio.
2. Partition the parent's measured spawn-and-wait interval into non-overlapping
   critical-path intervals: launch/fork through exec entry; exec reconstruction;
   post-publication interpreter execution; exit through parent wait return.
   Parent blocked time overlaps child work and must not be added to it. Account
   for timestamp boundaries, failed joins, and residual/unattributed time.
3. Within the largest interval, measure counts and service cost per operation,
   separating useful guest execution, syscall service, COW/translation work,
   teardown, and scheduling delay. Treat true/-S/normal differences as controls,
   not mechanically additive phase estimates.
4. Validate low-frequency phase instrumentation against untraced controls and
   reject captures with missing joins, failed guests, bounds, errors, or drops.
   The existing exec-latency script covers only exec-begin to publication; it
   cannot supply a complete spawn budget on its own.
5. Run the two full CPython subprocess/multiprocessing workloads to check that
   the microbenchmark explains a useful workload and preserves correctness.

### Greedy selection rule

Rank by credible removable milliseconds per spawn, not sample count or ease of
editing. Estimate each opportunity as measured exclusive phase cost times the
fraction plausibly avoidable, with uncertainty and semantic constraints stated.
Choose the largest supported opportunity, state the predicted effect and an
explicit refutation before editing, then make one bounded change. Accept only
with paired untraced end-to-end evidence and the required correctness gates;
otherwise revert. Remeasure and rerank after each accepted change. Retain an
explicit residual instead of forcing an unexplained budget to sum by inference.
The <=2x target and all original final acceptance requirements remain active.

### Fresh comparison and a refuted wall-budget instrument

`budget-refresh.json` records serial Docker / accepted / candidate / candidate /
accepted / Docker runs, with the same pinned arm64 Python image and five batches
of 50 spawns per command per arm. Docker inspection reconfirmed arm64 and the
exact digest. Averaging the two per-run medians:

| Command | Docker ms | Accepted current ms | Dirent candidate ms |
|---|---:|---:|---:|
| true | 0.1517 | 2.0922 | 2.0223 |
| Python -S | 3.5713 | 13.5943 | 12.4437 |
| Python | 4.4035 | 14.6397 | 13.7253 |

The refreshed normal-Python candidate ratio is 3.117x, with 4.918 ms still to
remove to meet twice this oracle. The development candidate remains separate
from final integrated-artifact acceptance. Run-to-run variation remains visible
in the raw batches; do not infer precision from the displayed decimal places.

The new low-frequency `hvpatch-spawn-wall-boundaries.d` capture completed 100
children with target exit zero, 403 events, zero errors and no bound hit. After
sorting per-CPU output by timestamp, every child had identity-consistent ordered
phases 1/6/2/5. However, subtracting these spans from guest spawn-and-wait totals
produced 23 negative residuals (minimum -1.285 ms). This REFUTES their use as an
exclusive wall budget, despite complete joins. Source inspection explains why:
`record_process_exit_begin` prepares an event, but retirement `complete` emits
it after resources retire; parent wait return can precede that emission.

The capture's 1.355 ms mean exec-entry-to-publication window is a diagnostic
span; the 11.910 ms publication-to-phase-5 span includes retirement and can
overlap subsequent work. It must not be labeled interpreter startup or added
to a parent critical-path budget. `wall-boundaries.raw`, `.out`, `.err`, and
`wall-boundaries-analysis.json` retain the attempted analysis and artifact hash;
the analysis's old `published_to_exit_begin_ns` field is MISLABELED and invalid
as exit-begin evidence. The script header now records the corrected boundary.
Next instrumentation must distinguish guest exit request, wait completion, and
asynchronous retirement rather than assuming lifecycle event names locate them.

### Qualified syscall boundaries and retirement interference hypothesis

The boundary script now also arms service-begin (clone/clone3, exit/exit_group,
wait4) and successful wait4 return. Predicates restrict output, but the generic
USDT sites still fire per syscall: these are potentially perturbing diagnostic
captures, not performance acceptance. A positive wait4 result identifies the
child without relying on host-thread identity across executor suspension.
`scripts/perf/hvpatch_spawn_wall.py` sorts per-CPU records, validates one ordered
lifecycle and exact exit/wait joins per child, checks unique clone attribution,
target success/errors/bounds, and rejects negative outside-window residuals.
It accepts the new 100-child captures and rejects the original lifecycle-only
capture for missing exit/wait joins. `wall-budget-provenance.json` binds the
current executable and instruments.

The normal-Python `wall-syscall` run yielded this exclusive diagnostic budget:

| Interval | Mean ms |
|---|---:|
| Clone service entry to child prepared | 1.440 |
| Prepared to exec entry | 0.258 |
| Exec entry to publication | 1.613 |
| Publication to exit service entry | 10.432 |
| Exit service entry to successful parent wait return | 0.057 |
| Parent work outside those boundaries | 0.070 |
| Total measured spawn-and-wait | 13.869 |

All 100 children joined, with no negative residual. Three matching untraced
controls averaged 13.878, 13.599 and 13.700 ms. This does not establish a precise
perturbation bound, but supports the broad phase ranking. All raw output and
validated rows are under `wall-syscall*` and `wall-control*`.

The `wall-true` and `wall-nosite` controls also validate 100/100. Respectively,
clone-to-prepared is 0.278 / 1.230 ms, exec is 1.152 / 1.278 ms, and
publication-to-exit-request is 0.565 / 8.878 ms. These separately timed runs
are structural controls, not an additive subtraction proof.

New hypothesis: the next clone's apparent preparation cost includes interference
from the previous child's deferred retirement. Test: insert 5 ms sleep OUTSIDE
each measured spawn, giving retirement time to settle. Prediction: clone cost
falls while child startup remains similar; refutation: clone cost persists.
`wall-spaced` supports the hypothesis: clone-to-prepared falls to 0.188 ms;
publication-to-exit-request remains 10.093 ms, and total measured spawn becomes
11.850 ms. Retirement still completes 1.357 ms after parent wait on average.
This is one diagnostic experiment, not a performance optimization: the sleeps
increase total workload time and are never an acceptance strategy. It suggests
roughly 1.2 ms of removable interference, conditional on repeatability and exact
attribution of the shared resource. Do not claim that asynchronous retirement
is free merely because it lies after wait return.

Greedy priorities now have stronger bounds: interpreter execution/startup is
the dominant interval (about 10 ms), with COW/translation and syscall service
the leading subdivisions to quantify; prior-child retirement interference is
a smaller approximately 1.2 ms opportunity; exec reconstruction is approximately
1.2-1.6 ms total, so cannot alone supply the remaining approximately 4.9 ms.
The next experiment should attribute the largest startup subdivision on the
current binary, while preserving the retirement-interference hypothesis for
the next ranking. No new runtime optimization was made during this budget work.

### Current-candidate CPU attribution and next COW hypothesis

`current-cpu.raw` profiles 500 normal Python children on the signed current
dirent candidate without USDT probes: 1,866 user and 2,342 kernel samples,
target exit zero, no errors or bound hit. Exact return-site qualification found
1,184/1,184 user and 404/404 kernel-user BL/BLR sites at load base
`0x102714000`. `current-cpu-analysis.json` and `carrick-current-profile` retain
artifact identity and classification. Each stack is assigned once, in the
recorded precedence order, avoiding inclusive-frame double counting.

| Classified path | User samples | Kernel samples | Approx sampled CPU ms/child |
|---|---:|---:|---:|
| COW resolution | 536 | 156 | 2.77 |
| Syscall service | 289 | 209 | 2.00 |
| Deferred retirement | 358 | 71 | 1.72 |
| Translation fault resolution | 177 | 56 | 0.93 |
| Ordinary guest run through HVF | 106 | 1,497 | 6.42 |
| Other/unclassified | 400 | 353 | 3.02 |

Conversion is samples / 499 Hz / 500 children, not measured exclusive wall
time. Startup and overlapping retirement are both sampled; the guest-run bucket
includes useful guest execution. The profile's mean spawn was 15.73 ms versus
the preceding untraced controls around 13.7 ms, so sampling perturbed the run.
Use this as a ranking, not an additive savings forecast or performance receipt.

The next COW hypothesis targets transaction scope rather than another small
collection scan: `resolve_frame_cow_fault` supplies the same full-ASID
maintenance callback used for broader edits. Every successful private-page COW
therefore runs `invalidate_asid_on_vcpu`, evicting translations outside the
changed span. Hypothesis: this adds both direct maintenance cost and repeated
translation refill work in the much larger guest-run bucket. It is not yet
proved to be a major saving. Before an experiment, derive the complete changed
descriptor range (including table splits/coalescing and rollback), establish
the architectural invalidation requirements, and preserve inner-shareable
publication plus exact owner/root/ASID generation proof. A VA-local invalidation
must never be substituted merely from the fault address alone. Compare one
bounded candidate against the same untraced base; reject if the end-to-end gain
does not support pursuing the added complexity. No invalidation edit exists yet.

Full workload acceptance also resumed: the conformance harness was rebuilt from
current source. The first invocation rejected the obsolete `--results` option
without running guests; the driver now uses the verified `--jsonl` flag. The
serial two-suite ABBA run completed its first Carrick phase and entered the
fresh pinned arm64 Docker phase. No full-workload verdict is claimed yet.

### Full dirent workload comparison completed

All four arms subsequently exited zero and both declared suites MATCH in every
arm: multiprocessing has 39 passed; subprocess has 297 passed and 44 skipped,
with no new or known differences. The fresh oracle is the pinned arm64 CPython
manifest recorded in `cpython-image-pin.json`; later arms used its two cached
rows. `cpython-exec-abba.json` records binary SHA-256 and exact commands;
per-arm JSONL files retain assertion pairs and run IDs. Scoped inspection found
no remaining Carrick processes or named Docker containers from these arms.

| Full workload | Base A seconds | Candidate B seconds | Candidate B seconds | Base A seconds | Docker seconds |
|---|---:|---:|---:|---:|---:|
| multiprocessing_main_handling | 12.063 | 9.861 | 10.251 | 9.841 | 3.473 |
| subprocess | 58.297 | 59.305 | 59.160 | 59.531 | 20.590 |

Do not call the 8.18% multiprocessing mean reduction a repeatable gain: the
first base arm is slower and the last base matches the candidates. Subprocess
means differ by only 0.54% in the slower direction. This establishes full-suite
correctness for the development candidate and no clear full-suite performance
gain, alongside the separately measured microbenchmark improvement. Final
integrated-artifact provenance/gates remain distinct. The exact final runtime
unit suite is being rerun after the last sidecar test addition.

### Bounded invalidation experiment contract

Source inspection confirms COW can touch a clipped 4 KiB page or 16 KiB
compound. `repoint_preserving_attributes` may split parent blocks while finding
L3 leaves. Therefore the engine must not infer a safe invalidation range solely
from the fault address. The existing undo journal records every descriptor
preimage and arena allocation state under the COW transaction lock. A candidate
can conservatively authorize a local range only when that journal proves all
edits are existing, non-global L3 leaves inside the authenticated span, with no
table topology or arena changes. Otherwise retain full-ASID maintenance.
Rollback, kernel-only writes and losing-winner retries retain the existing full
scope initially. The backend must supply the checked range to the flush callback
before discarding the journal; engine-side inspection before acquiring the COW
lock would race. Preserve barriers, inner-shareable invalidation, maintenance
root validation, and vCPU register restoration. Red tests should reject parent
splits, out-of-range edits, missing journals and global/invalid leaf transitions.

Architectural reference: Arm's memory-management guide describes VA/ASID
selection and inner-shareable invalidation; this is necessary background, not
a proof that Carrick's particular edit is narrow:
https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/LearnTheArchitecture-MemoryManagement-101811_0100_00_en.pdf
No invalidation implementation has been changed yet.

The final serial runtime suite completed with 2,577 passed, zero failures and
two ignored (`dirent-runtime-final.log`). The dirent change is committed as
`747876a48`; its last source adjustment only corrected the moved reader's
pre-existing misleading dup/offset comments. The code and tests remain the
validated implementation. Line-pinned inventories and final integrated artifact
receipts remain pending; this commit is not <=2x acceptance.

### COW invalidation experiment in implementation

Inventory positions were reconciled and reviewed in `dc089daab`; the following
`just lint-domains` passed (`dirent-lint-domains.log`). That closes the dirent
inventory follow-up, not the final goal's future integrated-artifact gate.

The invalidation candidate is now implemented but unmeasured. A private-field
`LeafInvalidationRange` is minted only from the open page-table undo journal:
all edited words must be existing non-global L3 leaves inside a <=16 KiB
aligned-page span, with only PA/AP changes, no contiguous hint in either old or
new descriptor, and unchanged arena/allocation state. Empty or missing journals,
outside edits, parent splits, global/invalid transitions and overflow refuse the
proof. The backend computes it under the COW locks before journal discard and
passes it through the fault-specific callback. Rollback, winner retries,
kernel-only and non-fault COW retain full-ASID maintenance.

The EL1 loop uses DSB, VAE1IS per page, DSB, ISB and HVC completion, retaining the
existing carrier-root checks and restoring the additional X1 scratch register.
`leaf-maint.s` / `.o` independently qualify all eight opcode words with clang;
the branch returns to the TLBI instruction. Proof tests were red first (two
positive assertions failed with the conservative None stub after correcting a
test's unmapped block setup). Then all 196 memory tests, 49 AArch64 tests, and
471 serial HVF host tests passed (three HVF tests ignored). A signed CLI build
is in progress. No guest correctness or performance result is claimed yet.

Pre-measurement prediction: retaining unrelated translations should improve
normal Python spawn materially, targeting at least 5% (~0.7 ms) to justify this
additional mechanism. Refutation: repeated untraced pairs fail to show that
benefit, controls regress, or exact guest/probe checks fail. In that case revert
the candidate rather than retain complexity solely for its narrower semantics.
Use `carrick-current-profile` as the exact saved pre-invalidation code artifact;
the dirent source changes since it was linked were comment-only. Final oracle
and all broader final acceptance requirements remain active.

### COW invalidation hypothesis tested and candidate discarded

Two untraced ABBA comparisons did not meet the predeclared benefit threshold:

| Experiment | Command | Base mean ms | Candidate mean ms |
|---|---|---:|---:|
| Initial | true | 2.0772 | 2.1160 |
| Initial | Python -S | 12.4938 | 12.5154 |
| Initial | Python | 13.8482 | 13.9149 |
| Explicit scope probe present but unarmed | true | 1.9934 | 1.9857 |
| Explicit scope probe present but unarmed | Python -S | 12.0954 | 12.3925 |
| Explicit scope probe present but unarmed | Python | 13.5798 | 13.6497 |

Normal Python worsened about 0.5% in both comparisons; -S worsened 2.46% in
the second. A private pid-provider entry capture yielded zero events even
though lifecycle events proved host == target, so it was rejected. An explicit
USDT scope probe then qualified the mechanism on the second exact artifact:
`cow-scope-usdt.raw` completed ten children, eleven execs, and 5,185 invalidations
with target exit zero/errors zero/bound zero: 3,557 single-page invalidations and
1,628 full-ASID invalidations. Narrowing really was active; this was not merely
a benchmark of universal fallback. That rejects this implementation as useful
progress toward the spawn target, not a proof that ASID maintenance costs zero
or that COW itself is cheap.

The range proof, narrow callback, EL1 loop, and their tests were reverted. The
complete experimental diff is retained as `cow-invalidation-rejected.patch`.
`invalidation-abba.json` / `invalidation-scope-abba.json` and their provenance
files bind the two development artifacts. The first artifact SHA-256 is
`30fc3d5a7bc2bf7ca01945199be5e222439366053a10623a7fca40e45cea52b6`.
Only the general scalar `hvpatch-tlb-invalidation` diagnostic remains, reporting
zero pages for the restored full-ASID routine; its D script fails closed on
missing events or unsuccessful targets. The unqualified private-ABI attempt is
recorded in the script header instead of being mistaken for zero usage.

A signed CLI rebuild of the restored runtime plus diagnostic is in progress.
Until it finishes, `target/release/carrick` is still the rejected candidate;
saved `carrick-current-profile` remains the pre-experiment runtime. No source
change from this experiment improves the accepted ratio. Next ranking must
address COW transaction work or retirement interference, not assume that
narrowing an architectural invalidation is an end-to-end optimization.

The restored signed build has now completed (`post-invalidation-rebuild.log`).
`post-invalidation-provenance.json` binds its SHA-256, UUID and source diff.
`cow-scope-restored.raw` completed five children with 2,942 full-ASID selections
and no local selections; target exit/errors/bound were all zero. The negative
control (`cow-scope-negative.raw`) observed target exit 23 and the trace command
failed as required. After restoration, all 49 AArch64 and 82 observability unit
tests passed (`post-invalidation-unit.log`). No candidate proof/type/trampoline
or narrow callback remains in source; the diagnostic call is disabled unless
armed. Later final artifact and inventory gates still belong to the eventual
accepted optimization checkpoint.

Next evidence question: how many neighboring private-file 4 KiB COWs each create
separate 16 KiB physical owners, and how much ownership/retirement work that
amplifies. Count exact task/mm and source-physical groups before proposing reuse.
Any reuse must preserve fresh-file visibility of untouched 4 KiB pages, avoid
overwriting a compound shared with a fork peer, and authenticate current owner
generations. A smaller physical allocation count alone is not performance proof.
