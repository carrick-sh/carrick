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

### Neighboring COW amplification: repeated census, reuse still unproven

Two ten-child captures on the restored signed artifact agree exactly. Each
child has one MM and 322 committed COW transactions, 322 distinct destination
FrameIds and 322 distinct destination 16 KiB IPAs. Grouping by exact
`(guest, mm, old_frame, old_ipa)` produces 87 source compounds per child:
75 groups have four transactions, three have three, four have two, and five
have one. Every source group corresponds to exactly one aligned 16 KiB VA
group. This is not an IPA-only join across unrelated MMs or frame identities.

`scripts/dtrace/hvpatch-cow-compound-census.d` captures adjacent scalar
identity/data probes. `scripts/perf/hvpatch_cow_compounds.py` requires exact
phase 0/1/2 triples with identical payloads for every transaction, including
the parent, and validates target exit, bounds, errors, event totals and child
population. It ignores traced durations. Both captures contain 10,671 events
(3,557 transactions including parent), target exit zero, errors zero and no
bound termination. Synthetic missing/duplicate phases, payload drift, failed
target, dropped records and missing-child controls were rejected. The revised
script initially failed compilation because `self->ready` was read before a
type-defining assignment; it was corrected in BEGIN and rerun successfully.

Receipts under `target/perf/exec-overhead-20260909/`:
`cow-pack-validated.json` validates the original capture, whose script is saved
as `cow-pack-original.d`; `cow-pack-repeat-analysis.json` validates the revised
script capture `cow-pack-validated.raw/.out/.err`.
`cow-pack-validated-provenance.json` binds source HEAD `3129c5099`, script,
command and binary SHA-256
`e33490c116541179fbf30c02d7253144ab0c54bc6bb692b0ff5c6eb9e951af24`.
The scoped process check found no remaining run command. The parent maps name
libpython's writable range at `0x6000500000..0x600065e000`; 287 first-child
receipts fall there. This associates receipts with the captured parent map,
not a directly captured child map.

The next hypothesis is that packing independently touched 4 KiB pages into
one private physical compound can reduce owner registration, inventory growth
and subsequent retirement work. The observed shape gives a potential owner
count of 87 instead of 322 (235 fewer, 73%); it does not establish that all
groups are eligible or that 73% of COW time can be saved. Fault handling,
quiescence, source authentication and per-page publication still remain.

Source inspection identifies the decisive unknown: `stage_cow_inventory_split`
and `commit_cow_inventory_split` currently create and authenticate a new whole
16 KiB mapping on every transaction, and reject an existing destination key.
A packing cache alone cannot bypass those contracts. A bounded candidate
must prove destination owner generation and exclusivity under the topology
lock, reject fork-shared destinations, copy fresh source bytes only for the
newly touched page, and publish source retirement plus destination projection
with rollback. Clean neighbors must continue observing file changes until
their own COW, and a failed attempt must not overwrite any published lane.
No packing implementation or performance result exists yet.

Greedy decision rule: prioritize expected removable wall time, using CPU
sampling only to rank candidates. For this candidate, predeclare at least a
5% normal-spawn improvement (~0.7 ms) in repeated untraced ABBA, no reproducible
control regression, reduced owner counts in a separate diagnostic capture,
and passing correctness gates. Refute or discard it if ownership eligibility
rarely holds, the required bookkeeping consumes the saving, or any private-file,
fork, generation, rollback or publication contract fails. Re-rank after each
accepted improvement. Retirement interference remains the next independent
hypothesis; the sleep experiment has not proved a usable optimization.

The current accepted measurement remains 13.725 ms versus Docker 4.404 ms
(3.12x). About 4.92 ms must still be removed to reach 2x on that pair. The
goal remains active; these diagnostics do not improve that ratio or satisfy
the eventual final artifact and broad gates.

### Retained source mapping churn tested and discarded

Before attempting destination packing, source inspection found that a retained
COW source was unmapped and republished even when all its physical coverage
remained live. The experiment preserved the old MappingId and reference counts
when fragment coverage equalled the original extent, and avoided fragmenting
a larger fully retained extent. Reservations then needed only two replacement
mapping events rather than unmap plus source prepare/publish plus replacement.
Both local and foreign COW paths used the same change. An explicit exact
`mapping_is_live` check replaced the old unmap event's source authentication
before any physical mutation; source and destination ownership remained intact.

The old-mapping identity assertion and the wider retained-extent assertion were
red first (`retain-source-red.log`, `retain-source-wide-red.log`). With the
candidate, all 471 HVF host tests passed, three ignored
(`retain-source-qualified-unit.log`). Two ptrace test doubles initially refused
the new check because they knew only newly published mappings; their exact
initial mapping inventories were added. A test incorrectly treated the
mapping-count-error double as a mapping-liveness-error double and was corrected.
These were test fixture corrections, not a weakening of runtime authentication.

Two repeated untraced ABBA comparisons failed to show meaningful benefit:

| Comparison | Command | Base ms | Candidate ms | Candidate change |
|---|---|---:|---:|---:|
| First | true | 2.13175 | 2.17319 | +1.94% |
| First | Python -S | 12.67558 | 12.77322 | +0.77% |
| First | Python | 14.10526 | 14.11727 | +0.09% |
| Repeat | true | 2.05937 | 2.09706 | +1.83% |
| Repeat | Python -S | 12.69070 | 12.55742 | -1.05% |
| Repeat | Python | 14.09106 | 14.07015 | -0.15% |

The candidate was discarded. It does not establish that source bookkeeping
costs zero, but it does not justify a standalone optimization and does not
refute destination packing. All runtime and test changes were reverted; the
experiment is saved as `retain-source-rejected.patch`. The two ABBA JSON files
and `retain-source-provenance.json` bind candidate SHA-256
`9b1490c6673f605da8f4cc6912d94061ce1afd3f97a55a29ee3c83721a008d48`.
The saved signed base was restored byte-for-byte to `target/release/carrick`
(SHA-256 `e33490c116541179fbf30c02d7253144ab0c54bc6bb692b0ff5c6eb9e951af24`),
codesign verification passed, and five Python child spawns completed with exit
zero (`retain-source-restored.json`). The first restoration smoke command had
bad shell quoting and produced a Python SyntaxError; its rejected receipt is
retained separately and the corrected command uses `shlex.quote`.

Destination owner registration, inventory growth and retirement remain the
larger COW hypothesis. Reusing lanes needs an authenticated, MM-local occupancy
record and an exclusivity check that remains valid across fork; the preserved
source path may be useful inside that transaction but has no accepted benefit
on its own. No new performance improvement or final gate is claimed here.

### Destination lane reuse candidate: mechanism and first paired evidence

An uncommitted candidate now reuses an unpublished 4 KiB lane of a neighboring
private compound. Selection occurs under COW quiescence/topology. It requires
one backend frame reference, one exact extent reference, one stage-2 reference,
one authoritative kernel mapping, an exact live MappingId/FrameId/extent, and
an exact pinned host-owner generation. Every alias in the physical-start bucket
must name that owner and this MM, and none may cover the lane. Stale, foreign,
malformed or overlapping aliases decline reuse. No occupancy cache is retained
across fork or remapping. Eligibility is restricted to guest-visible, 4 KiB,
non-kernel private-file COW; other paths retain fresh-owner allocation.

The copy refreshes only the touched page. The inventory transaction keeps the
existing destination identity/reference counts and still splits/retires source
coverage. Failed publication does not retire the reused owner: the written lane
was unpublished and will be refreshed again before a later publication attempt.
The source-mapping optimization rejected above is not included. Foreign COW
continues to allocate fresh destinations.

Red-first checks: `pack-lane-red.log` refused the valid free-lane case with a
conservative stub; `pack-inventory-red.log` rejected an existing destination as
a collision. The implemented checks also reject occupied/foreign/stale aliases,
and the commit test verifies unchanged destination counts plus stale-owner
rejection before source mutation. `pack-integrated-unit.log`: 473 HVF host
tests passed, three ignored. `pack-runtime-unit.log`: 2,577 runtime host tests
passed, two ignored.

`private_file_cow_lanes.rs` runs an in-process regression with the exact Python
fixture under `tests/workloads/`: fresh file bytes on a second COW, preservation
of dirty neighbors, clean-page visibility, and independent parent/child writes
to both previously dirty and still-clean pages. Native arm64 Docker passed on
the pinned image (`pack-lanes-oracle.json`), then the signed embed runner passed
with its unentitled negative control and zero remaining scoped guests
(`pack-lanes-embed.log`). The initial runner command incorrectly supplied cargo's
`--test` flag; it was rejected before execution and rerun with the supported
exact libtest filter. These semantic assertions are regression coverage; the
pre-change runtime is not claimed semantically wrong by this optimization.

The first signed development artifact, SHA-256
`fe5ff30b9038ec84934555abef89ecdf9b7ba3d93ede26f2eb09cfe4e0c7f426`,
completed ten children with 322 COW transactions but only 87 destination owners
each (`pack-candidate-analysis.json`). All phase triples balanced. The census
parser now keys transactions by semantic page/source/destination, since a
destination FrameId is intentionally reusable across pages. Original captures
and a synthetic repeated-destination parser control still validate.

Two untraced ABBA comparisons show a useful relative gain:

| Artifact | Command | Base mean ms | Candidate mean ms |
|---|---|---:|---:|
| Initial | true | 2.07522 | 2.06531 |
| Initial | Python -S | 12.47446 | 11.46547 |
| Initial | Python | 13.98807 | 12.88705 |
| Copy diagnostic restored, unarmed | true | 2.24059 | 2.26558 |
| Copy diagnostic restored, unarmed | Python -S | 13.12178 | 11.86317 |
| Copy diagnostic restored, unarmed | Python | 14.47563 | 13.31865 |

Normal spawn improves about 8% in both pairs. True changes -0.48% then +1.12%,
so its control result is inconclusive, not a demonstrated improvement. This is
not yet a fresh oracle ratio or final acceptance.

The rebuilt candidate emits copy hashes for the exact refreshed 4 KiB range.
`hvpatch-cow-copy-census.d` is a separate, deliberately perturbing content/count
instrument: `pack-copy.raw` records 3,557 copies, 2,588 at 4 KiB and 969 at
16 KiB, 26,476,544 total bytes, equal source/destination hashes, successful
target and no errors/bound termination. `pack-copy-provenance.json` binds the
new artifact and source diff; `pack-copy-abba.json` measures it with probes
unarmed. The existing whole-compound fork-fixture validator remains unchanged
and cannot qualify the page-reuse path; the new census does not claim its
stronger fork-ordering proof.

The public full probe gate completed successfully (`pack-full-probes.log`, run
ID `execdiag-sep09-pack-probes`): 876 unique generic announcements (438 musl,
438 gnu), 25 case tests including the new regression, both unentitled negative
controls, the CLI contract, and the retained harness (46 passed, one ignored).
The amd64 musl lane has 30 report-only DIFFs and the gnu binaries are absent;
this is not x86 acceptance. The exact gated CLI is saved as `carrick-pack-gated`,
SHA-256 `b9b8195edccf6f56b4fde053af709aa409be96fe37e93742f19b4597d7030bf3`;
`pack-gated-provenance.json` records signature, UUID, entitlement and DOF.
Full CPython ABBA, clippy/inventory reconciliation, a fresh same-image oracle
and final artifact acceptance remain pending. Runtime/test changes are intentionally uncommitted
until those results are reviewed. The <=2x objective remains active.


### Destination lane reuse validation completed

The full pinned CPython ABBA completed with MATCH in all eight suite results
(`cpython-pack-abba.json`, `cpython-pack-summary.json`). Each arm has 39 passing
multiprocessing cases and 297 passing subprocess cases. The fresh oracle took
3.053 s and 20.603 s respectively. Baseline/candidate means were 9.9575/9.665 s
for multiprocessing and 59.3895/59.120 s for subprocess. Subprocess is effectively
unchanged; multiprocessing varies enough that its apparent 2.9% improvement is
tentative. Neither suite meets 2x. No full-suite 8% gain is claimed.

A subsequent serial Docker/base/candidate/candidate/base/Docker microbenchmark
on the exact gated binary refreshed the pinned arm64 oracle (`pack-refresh.json`,
`pack-refresh-summary.json`, `pack-refresh-image.json`):

| Command | Docker ms | Base ms | Candidate ms | Candidate / Docker |
|---|---:|---:|---:|---:|
| true | 0.15832 | 2.16704 | 2.12612 | 13.43x |
| Python -S | 3.73900 | 12.92697 | 11.76346 | 3.15x |
| Python | 4.59645 | 14.36835 | 13.25350 | 2.88x |

Normal spawn saves 1.11485 ms (7.76%), consistent with both earlier pairs.
Another 4.06061 ms must be removed to reach 2x this contemporaneous oracle.
True remains a much larger ratio because its useful execution is very short;
its small relative change is not the basis for accepting this optimization.
`just clippy` passed (`pack-clippy.log`), as did `git diff --check`. The candidate
is accepted as a scoped reduction in COW allocation amplification. Inventory
position reconciliation remains to be completed after the code commit. The
next greedy step is to refresh CPU attribution on this exact artifact, since
its reduced allocation and retirement work can change the prior ranking.
The full <=2x goal remains active.


### Accepted packing checkpoint and refreshed ranking

Code commit `486a4305f` and inventory commit `7a0ee177c` are local only.
Inventory reconciliation changed positions/capture bindings only (31 host
sites, one abort fingerprint); reviewed memberships and rationale text remain
unchanged. `just lint-domains` passed (`pack-lint-domains.log`). Its host-authority
census is explicitly the macOS subset; the listed Linux/FreeBSD/NetBSD profiles
remain pending, not newly qualified. `pack-scoped-cleanup.json` records zero
remaining Carrick processes after all tests, measurements and profiling.

`pack-cpu.raw` samples the exact gated candidate, 500 normal Python spawns,
without USDT enabled. The first attempt at the saved binary path was rejected
by sudo before any guest execution. The allowed `target/release/carrick` path
had the identical SHA-256 and completed naturally: target zero, zero errors,
no bound hit, 1,645 user and 2,355 kernel samples. BL/BLR return-site validation
found 1,171/1,171 user and 375/375 kernel-user sites at `0x1021fc000`. Source
and artifact records are retained with the capture. Sampling raised mean spawn
to 15.138 ms versus 13.254 ms untraced; these are directional CPU rankings,
not additive wall-time savings. Each stack is assigned once according to the
explicit rules in `pack-cpu-analysis.json`:

| Classified path | User samples | Kernel samples | Sampled CPU ms/child |
|---|---:|---:|---:|
| COW resolution | 452 | 185 | 2.553 |
| Syscall service | 361 | 205 | 2.269 |
| Deferred retirement | 159 | 81 | 0.962 |
| Translation/materialization fault | 148 | 46 | 0.778 |
| Exec preparation | 73 | 4 | 0.309 |
| Ordinary guest run | 109 | 1533 | 6.581 |
| Other/unclassified | 343 | 301 | 2.581 |

COW is still the largest named runtime service bucket, with syscall service
close behind. The next discriminating investigation should split COW's
remaining publication work: inventory reservation/application, page-table
journal publication, alias publication, and stage-1 maintenance. The sample
contains 90 reserve and 54 apply descendants, and 103 maintenance descendants;
these inclusive subcounts overlap and cannot be summed as independent savings.
Narrower invalidation alone was already empirically rejected. A new experiment
must show avoidable transaction work before revisiting that path. In parallel
as a sequence of local investigations, syscall attribution should separate
getdents/openat/mmap from generic dispatch: the current inclusive service
samples include 99 getdents, 91 openat, and 60 mmap descendants. Neither set of
samples yet proves which removable operation can recover the remaining 4.06 ms.
No new speculative runtime edit is present at this checkpoint.


### Remaining reservation cost: host entropy requests

Static inspection of `kernel/frame_inventory.rs::prepare_reservation` found a
32-byte `getrandom::fill` per transaction. The pinned getrandom 0.3.4 Darwin
backend issues `getentropy` calls in at most 256-byte chunks. The current COW
reservation profile has 79 kernel-user samples in one host syscall, compared
with only a few samples in allocations and reservation-map insertion. Thus
host entropy is a better bounded reservation hypothesis than another map edit.

The new durable `hvpatch-host-entropy-cost.d` qualified the host entry provider
and SDK `(buffer, size)` ABI, then captured 500 normal Python children. It does
not read or emit entropy bytes. `pack-entropy.raw` records 212,115 balanced
entry/return pairs, all result zero, successful target, no errors or bound:
210,608 calls requested 32 bytes (421.216 per child), taking 359.443 ms total
under tracing, or 0.719 ms/child. Other sizes were 8, 16 and 24 bytes, about
500 calls each. Static source plus CPU stacks support inventory provenance as
the dominant 32-byte caller; the syscall count itself is not a caller census.
Mean spawn under this instrument was 13.594 ms. Trace duration is perturbed and
cannot be cited as fully recoverable untraced time.

A separate untraced host-only ctypes control alternated 32/256/256/32-byte OS
requests, five batches of 20,000 each. Median call costs were 889/934/939/925 ns
(`entropy-host-batch-control.json`); that includes Python/FFI overhead. Larger
requests do not cost eight times as much, supporting a bounded batch-of-eight
experiment, but the instrumented 0.719 ms is an overestimate of likely savings.
No key bytes were logged, and the temporary buffer was cleared.

Next candidate contract: retain fresh OS entropy for each provenance token,
batch at most eight 32-byte tokens, consume each once, erase consumed slots,
discard inherited cached bytes after a host PID change, and fail closed on any
refill error without exposing partially filled or previously consumed bytes.
Keep reservation/commit authentication and transaction IDs unchanged. Red-first
host tests should inject an entropy source to verify refill count, exhaustion,
PID invalidation, and failed-refill recovery. Compare untraced paired binaries
before accepting the added state; reject the candidate if the expected small
saving is not repeatable. No runtime entropy change exists at this checkpoint.


### Entropy batching candidate: red-first and paired timing

An uncommitted authority-owned `ProvenanceEntropyBatch` consumes eight distinct
32-byte slices of each 256-byte OS fill. It introduces no PRNG or derived key.
A mutex serializes draws; consumed slots are replaced with zero arrays. The
buffer's Debug implementation omits entropy bytes. A host PID change discards
remaining tokens before drawing, and a failed partial refill clears all slots
without setting availability. Transaction IDs, commit provenance checks,
reservation candidate registration, and rollback remain unchanged.

`entropy-batch-red.log` proves the baseline per-token source fails the new
17-draw/three-refill check. The implemented batch then passes all 22 frame
inventory tests (`entropy-batch-green.log`), including PID invalidation and
partial-refill recovery. The full serial runtime suite passes 2,579 tests,
with two ignored (`entropy-batch-runtime.log`). Signed development artifact
`carrick-entropy-batch` SHA-256
`096c74028bb5cbf198e5c5b36246b20626ccb94d7b16b305866219cea5c66ed9`
is bound by `entropy-batch-provenance.json` and `entropy-batch-source.patch`.

Two untraced ABBA runs (`entropy-batch-abba.json`, `entropy-batch-abba2.json`)
compare against accepted `carrick-pack-gated`:

| Run | Command | Base mean ms | Candidate mean ms |
|---|---|---:|---:|
| 1 | true | 2.06849 | 2.00468 |
| 1 | Python -S | 11.37946 | 11.13238 |
| 1 | Python | 12.78423 | 12.49042 |
| 2 | true | 2.14165 | 2.02619 |
| 2 | Python -S | 11.75597 | 11.13779 |
| 2 | Python | 12.86089 | 12.58057 |

Normal spawn improves 2.30% and 2.18%; the larger control changes are variable
and should not be overinterpreted. `batch-entropy.raw` confirms exactly 26,326
256-byte calls replacing 210,608 32-byte calls, eightfold, with the same other
size populations. All 27,833 entry/return pairs balance, all calls succeed,
the target exits zero, and the trace has no errors/bound hit. Its durations
are perturbed and not a timing acceptance result.

The full signed public probe gate is running as
`execdiag-sep09-entropy-probes` (`entropy-batch-probes.log`). Full CPython ABBA,
fresh oracle timing, final artifact binding, clippy, and inventory review are
pending. The new host PID query requires an explicit host-authority review row;
it selects only the current host process for cache invalidation, never a guest
identity. No final acceptance or new absolute oracle ratio is claimed yet.


### Entropy candidate gates and final paired measurement

The full public signed gate exited zero (`entropy-batch-probes.log`): 876
unique generic runs, 25 signed case tests, both negative entitlement controls,
the CLI contract, and 46 passing retained tests with one ignored. Report-only
amd64 musl differences and unavailable gnu binaries are not x86 acceptance.
The gated CLI is saved as `carrick-entropy-gated`, SHA-256
`b9117bffa97b5bae49c97a99524d8345b1d1a58f59d35dae0a08215e87adb462`;
`entropy-gated-provenance.json` binds signature, UUID, entitlement and DOF.

Full pinned CPython ABBA also passed all eight suite results, 39 multiprocessing
and 297 subprocess passes per arm (`cpython-entropy-summary.json`). Fresh Docker
times were 2.845 s and 20.569 s. Base/candidate averages were 9.4235/9.3605 s and
59.066/59.0505 s respectively: effectively unchanged, not a full-suite speedup.

The exact gated artifact's serial Docker/base/candidate/candidate/base/Docker
refresh (`entropy-refresh.json`, `entropy-refresh-summary.json`) measured:

| Command | Docker ms | Base ms | Candidate ms | Candidate / Docker |
|---|---:|---:|---:|---:|
| true | 0.15463 | 2.00397 | 2.01941 | 13.06x |
| Python -S | 3.59054 | 11.25823 | 11.05890 | 3.08x |
| Python | 4.44899 | 12.55271 | 12.31022 | 2.77x |

Normal spawn saves another 0.24250 ms (1.93%), supporting the two development
artifact pairs. True is 0.77% slower in this pair, contrary to the earlier
improvements; no repeatable true effect is established. The pinned image's
native arm64 identity is recorded in `entropy-refresh-image.json`. Another
3.41224 ms must be removed to reach 2x the current oracle. Do not interpret the
change in ratios across dated oracle refreshes as the isolated optimization
benefit; the paired base/candidate comparison supplies that number.

`just clippy` passed (`entropy-batch-clippy.log`), and
`entropy-scoped-cleanup.json` records no remaining Carrick processes. Runtime
code is accepted as a small measured improvement. The required new host-PID
inventory review and position reconciliation follow the code commit; domain
closure is not claimed until that check passes. No push is authorized or made.


### Entropy inventory closure and next attribution

The entropy code is committed as `9c4002871`. Host PID use is explicitly
reviewed as `HA-000649`: current-host identity invalidates inherited entropy
only. The first domain retry caught noncanonical ordering of the appended
review row; the next caught shifted K1 inventory positions with unchanged
operation counts. The review was reordered without content changes, then 215
K1 line numbers were reconciled with identical operation contents and taxonomy.
The complete `just lint-domains` now passes
(`entropy-batch-lint-domains-reconciled.log`). The host-authority receipt remains
a macOS subset and does not qualify the pending non-macOS profiles.

`hvpatch-fs-op-ledger.d` now includes mmap/munmap and fails closed on missing
windows, unpaired windows, DTrace errors, or an unsuccessful target exit. The
first compile exposed an undeclared TLS type in the new overlap check, before
any guest execution; an explicit BEGIN initialization fixed it. A zero-window
`--version` negative control now rejects an otherwise successful target.
`entropy-fs-ledger.raw` completes 50 Python children with 8,327 balanced FS
windows, zero errors, successful target and no bound. Its 19.99 ms mean is
heavily perturbed; counts and syscall shapes, not time, are the evidence.
The census includes parent Python startup as well as the children.

| Guest operation | Calls | Host calls / guest call |
|---|---:|---:|
| mmap | 1,198 | 1.53 |
| openat (non-create) | 1,290 | 2.14 |
| getdents64 | 518 | 6.46 |
| fstat | 1,265 | 2.02 |

The directory path uses getdirentries64 plus descriptor setup/teardown; source
inspection confirms its listing is already cached after the first read, so
repeated full directory enumeration per getdents call is refuted. mmap/openat
remain comparable attribution targets; counts alone do not prove removable
work. `entropy-fs-ledger-analysis.json` retains the full breakdown.

A same-boot host shared-cache `dladdr` lookup resolves previously anonymous
user-library frames in the existing exact-binary packing CPU sample
(`pack-cpu-host-symbols.json`, boot receipt alongside it). This independently
identifies the reservation syscall as getentropy and exposes a stronger copy
lead: 87 samples show bzero under `build_linux_initial_stack`, while 37 show
memmove under `prepare_exec_region_raw_in` and 28 under `execve_rebuild_inner`.
These are old, perturbed samples, not a new measured saving. Source confirms
`LINUX_STACK_SIZE` is 8 MiB and `build_linux_initial_stack` allocates and zeros
that entire buffer before writing argv/env/auxv near its top. Exact copy sizes
and the minimal initialized tail still need qualification.

The next greedy experiment should quantify that initial-stack payload versus
full-size zero/copy work before changing representation. Preserve the complete
semantic stack extent, zero-filled untouched memory, page alignment, argument
limits, auxv/AT_RANDOM/AT_EXECFN addresses, rollback and fork isolation. Compare
this measurable copy hypothesis against the remaining filesystem cost before
committing to smaller descriptor-wrapper savings. No stack/runtime change is
present at this checkpoint. Current accepted normal spawn remains 12.310 ms /
4.449 ms = 2.77x; the <=2x goal remains active.

### Compact initial-stack payload experiment (in validation)

Source review refutes a full 8 MiB HVPatch guest-stack copy: the default
`CARRICK_HVPATCH_SPARSE_EXEC_STACK` path already copies only the initialized
stack tail. The avoidable work is earlier: `build_linux_initial_stack` creates
and zeros an 8 MiB host Vec. The candidate retains the semantic stack extent
while storing an aligned initialized window. Legacy byte-slice consumers
materialize a zero prefix lazily; direct GuestMemory reads copy only the
intersection and return zero elsewhere. Writes retain copy-on-write isolation.
The HVPatch mapping plan consumes the compact window directly. No stack limit,
address, permission, ownership or publication contract is intentionally changed.

`initial_stack_keeps_a_compact_tail_and_full_zero_extent` failed against an
initial dense-payload accessor (`stack-tail-red.log`) and passes with the new
representation. The initial full memory run passed 194 tests; the serial HVF
run passed 473 with 3 ignored. These are development checks, not final gate
closure. Additional argument/auxv boundary coverage has been added and awaits
its test run. Full runtime, public signed probes and final artifact checks
remain required.

The signed development artifact `carrick-stack-tail` has SHA-256
`5f63ef3fcf7063f1f8640d62ab899bd80ed88643bb0d9b10b4d8910e13dd7053`, UUID
`F334088E-583F-3FE7-9EA7-EB972C109A90`; `stack-tail-provenance.json` binds its
source patch, signature, entitlement and DOF. It predates the extra boundary
test and explanatory comment; it is not claimed as the final gated artifact.

Two untraced fixed-concurrency ABBA pairs against `carrick-entropy-gated`
support the mechanism. The first normal-spawn pair improves 3.83%; the second
improves 3.76%. The second was bracketed by fresh Docker runs on the identical
pinned native-arm64 image (`stack-tail-refresh-image.json`):

| Command | Docker ms | Entropy base ms | Stack candidate ms | Candidate / Docker |
|---|---:|---:|---:|---:|
| true | 0.17473 | 2.03948 | 1.77254 | 10.14x |
| Python -S | 3.82773 | 11.33587 | 10.99779 | 2.87x |
| Python | 4.62343 | 12.78987 | 12.30901 | 2.66x |

`stack-tail-abba.json` and `stack-tail-refresh.json` retain every batch and
artifact hash. Fresh oracle drift accounts for part of the ratio change;
paired base/candidate improvement is the isolated claim. The complete CPython
subprocess and multiprocessing_main_handling ABBA is running next, using a
fresh oracle then its exact declaration cache. No acceptance or <=2x closure
is claimed at this checkpoint.

The full development-artifact CPython ABBA completed with all eight suite
verdicts MATCH (`cpython-stack-tail-summary.json`): multiprocessing has 39
passes per run; subprocess has 297 passes and 44 expected skips. Mean
multiprocessing time is 9.3655 s base / 9.4755 s candidate (1.17% slower);
subprocess is 59.0935 s / 58.9715 s (0.21% faster). Fresh Docker times are
2.910 s and 20.877 s respectively. These results do not establish a broad
suite-level speedup. The focused spawn gain remains the performance evidence.

The added argument/auxv boundary test initially failed to compile because its
helper lived in a sibling test module; a local auxv decoder fixes the test
scope. The expanded full memory suite now passes 195/195
(`stack-tail-mem-expanded.log`), including payload-page crossings, zero extent,
clone isolation and overfull-stack rejection. The full serial runtime gate is
in progress (`stack-tail-runtime.log`); signed public gates and final artifact
refresh remain pending. No optimization acceptance is claimed yet.

The full serial runtime suite completed successfully: 2,579 passed, 2 ignored,
zero failures (`stack-tail-runtime.log`). `just conformance-probes` has now
started, rebuilding/signing the CLI before the public guest gates; output is
in `stack-tail-public-probes.log`. This later artifact still needs its own
provenance and untraced refresh. Clippy/domain checks and scoped final cleanup
also remain outstanding.

The signed public gate has completed successfully (`stack-tail-public-probes.log`):
876 unique generic arm64 rows, 25 dedicated cases, both entitlement negative
controls, the CLI boundary and 46 retained tests (1 ignored). The existing
30 amd64-musl report-only DIFFs and absent amd64-gnu probes remain outside
this arm64 acceptance scope. The final CLI SHA-256 is
`225ae58d75d6eb4f03adafe990be96b952809f8ff4274117b500531c86c9ddb6`, UUID
`6977A88A-CC93-3C5F-8AB5-300F4926D8DA`; `stack-tail-gated-provenance.json`
binds its source patch, signature, entitlement and DOF, and the release binary
still matches that hash after the gate. It differs from the development
artifact and must be timed separately.

The first domain check reached host-authority compiler capture and refused the
uncommitted tracked snapshot. It is not a successful domain receipt; rerun it
after the validated code commit. Clippy is running. Final-artifact timing,
profiling, domain closure and cleanup remain pending; the <=2x goal is active.

Clippy passed (`stack-tail-clippy.log`). The final gated CLI's fresh serial
Docker/base/candidate/candidate/base/Docker comparison also supports the change
(`stack-tail-gated-refresh.json`, summary and native-arm64 image receipt):

| Command | Docker ms | Entropy base ms | Gated stack ms | Gated stack / Docker |
|---|---:|---:|---:|---:|
| true | 0.17096 | 2.12874 | 1.74480 | 10.21x |
| Python -S | 3.82332 | 11.37561 | 10.89461 | 2.85x |
| Python | 4.64051 | 12.86964 | 12.43167 | 2.68x |

The isolated paired gains are 18.04%, 4.23%, and 3.40%. Normal spawn remains
3.15065 ms above twice the contemporaneous oracle. The final-artifact full
CPython ABBA is running (`cpython-stack-tail-gated-abba.log`); earlier
full-suite results belong to the development artifact and are not substituted
for that run.

A fresh 500-child CPU capture on the exact gated CLI completed naturally with
zero errors/bound termination (`stack-tail-cpu.raw`, accompanying provenance).
It retains 1,685 user and 2,243 kernel-mode samples; all 1,192 user return sites
and 400 kernel-mode interrupted-user return sites validate against the binary
at base 0x102880000. Host shared-cache symbols were resolved with dladdr on the
same boot. Traced mean spawn is 14.995 ms versus the untraced 12.432 ms; use
this capture only for attribution.

No sampled stack contains `build_linux_initial_stack`, consistent with removal
of its full-buffer zeroing. Inclusive COW windows still contain 447 user / 143
kernel-mode samples. Within them alias registration appears in 70 user
samples, while stage-1 maintenance appears in 49 user / 106 kernel samples.
These are overlapping diagnostic counts, not additive wall-time savings.
Copy leaves remain under exec preparation (12 user / 33 kernel-mode samples)
and exec rebuilding (12 / 21), plus COW. The remaining exec copy sizes are
still unqualified; do not revive the refuted full-stack-copy explanation.

The next greedy question is whether fault count itself contains avoidable
work: classify COW faults by anonymous versus private-file backing and qualify
adjacent-page ownership before proposing a change. Any potential anonymous
page optimization must preserve fork isolation, aliases, permissions and
transaction rollback; private-file clean-neighbor visibility at Linux 4 KiB
remains mandatory. Narrower TLB invalidation and alias/retirement collection
changes were already measured without useful gains; this profile alone does
not justify retrying them. No second runtime candidate is present yet.

The final-artifact full CPython ABBA completed with all eight MATCH verdicts
(`cpython-stack-tail-gated-summary.json`). Subprocess means are 58.8095 s base /
58.8285 s candidate (effectively unchanged), Docker 20.570 s. Multiprocessing
means are 9.035 s / 9.249 s, Docker 2.846 s: a 2.37% slowdown, consistent in
direction with the development pair. An additional balanced eight-arm
multiprocessing-only comparison also matches in every arm and measures
9.4675 s base / 9.66775 s candidate (2.12% slower). The samples are retained in
`cpython-stack-tail-mp-repeat-summary.json`. Do not describe full-suite
performance as universally unchanged or improved: the small multiprocessing
regression remains unresolved and must be carried into later comparisons.

A qualified multiprocessing CPU sample (`stack-tail-mp-cpu.raw`) has 3,724 user
and 4,245 kernel-mode samples, with 1,760/1,760 and 695/695 return sites
validated. No sampled stack contains RegionPayload compatibility materialization
or initial-stack construction. This weakens, but does not mathematically
exclude, the hypothesis of repeated 8 MiB compatibility allocation causing the
slowdown. It does not identify the actual cause. The focused spawn gain is
retained as progress toward the primary objective with this explicit tradeoff;
no broader performance closure is claimed.

Source review sharpens the next COW hypothesis: `PrivateFileSource::ImmutableLower`
already grants a host MAP_PRIVATE view because copy-up preserves the original
inode, yet sparse preparation gives it the same page-granular COW arm and
PrivateFileView inventory identity as Mutable. This may force unnecessary
Carrick COW transactions for immutable interpreter pages. It requires direct
signed guest proof of HVF-coherent host-private writes, immutable source
preservation, independent mappings, fork isolation and 4 KiB discard behavior
before changing the arming rule. Mutable clean-page visibility remains
mandatory. No immutable-view optimization has been implemented at this point.

### Stack closure and immutable-view qualification blocker

The stack implementation is committed as `0809c1f91`. Source-location-only
inventory reconciliation is committed as `6889e6e4a`: 16 positions and their
rationale line references changed, with unchanged operation counts and
classifications (`stack-tail-inventory-diff-check.json`). The complete
`just lint-domains` passes (`stack-tail-lint-domains-reconciled.log`), retaining
the macOS-subset scope of its host-authority capture. Final scoped cleanup
found no Carrick processes (`stack-tail-final-cleanup.json`). The primary
measurement remains 2.68x, with the recorded ~2% multiprocessing regression
still unresolved; neither the per-exec nor wider ecosystem goal is complete.

The proposed immutable-view optimization has NOT been implemented. Its new
signed conformance-next fixture, `immutable_private_file.rs`, maps an existing
immutable lower `/bin/sh` privately and checks source preservation, independent
views, fork isolation and a 4 KiB MADV_DONTNEED with a dirty neighbor. Native
arm64 Docker passes (`immutable-private-file-values-oracle.json`, source hash
bound). The unchanged runtime fails specifically at discard restoration:
Carrick returns byte **0**, while the source/Docker value is **105**
(`immutable-private-file-baseline-values.log`). All earlier assertions in that
fixture pass; the signed negative control passes and scoped cleanup is zero.
The initial failure without value diagnostics is separately retained in
`immutable-private-file-baseline-embed.log`.

Source identifies the existing cause in the dispatcher MADV_DONTNEED path:
`meta.writable && !meta.shared` invokes zero_backing even for private FILE
VMAs. Restoring source bytes must preserve the mapping's original file identity
after fd close/unlink, not reopen its pathname. Existing shared-file alias
metadata already retains FileDescription ownership; private mmap currently
has a snapshot helper but lacks equivalent durable source ownership in
MemState. Deferred private-file recipes are removed as ranges materialize,
so they alone cannot serve later discard. The correction must preserve dirty
neighbors, fork isolation, mutable clean-page visibility, offsets and partial
unmap/remap metadata, and work for read-only/PROT_NONE ranges. Keep this red
fixture; do not remove the discard assertion to make the optimization gate
pass. Diagnose/fix this contract before accepting a changed immutable COW rule.


### Private-file discard lifetime correction in progress

The extended native-Docker-passing fixture exposed two more concrete issues:
restored mprotect permissions leave proc-map fragments that mremap refused
with EFAULT, then closing Python mmap's internal duplicate fd destroyed the
OpenDescription backing while the moved mapping still needed it (EBADF).
Retaining an Arc<FileDescription> alone is not a backing lifetime guarantee:
on_last_fd_ref replaced its payload with Closed.

The current uncommitted correction retains an explicit MappedFileReference
across mapping fragments/fork/remap. Logical fd counts remain distinct; final
fd-close notifications still fire immediately, and backing resource cleanup
waits for both descriptors and mapping references to disappear. Exec reset
replaces MemState, releasing its mapping registry. Two lifecycle unit tests
pass (mapped-file-reference-unit.log). The signed extended guest now passes
(private-file-discard-lifetime-embed-3.log), including the previously failing
close/unlink/remap/partial-unmap sequence, with the entitlement negative
control passing and zero scoped leftovers. Prior failing receipts remain
private-file-discard-lifetime-embed.log (EFAULT) and
private-file-discard-lifetime-embed-2.log (EBADF).

This is not acceptance or a performance gain. The immutable-view arming
optimization remains unimplemented. Remaining correction review includes
boot ELF private-file provenance, noncongruent direct-view fallback semantics,
transaction failure behavior, and remap metadata coverage; broad runtime,
signed conformance, lint and exact-artifact performance gates remain due.

The combined signed private_file filter passes all selected cases across three
executables, including existing mutable clean-page visibility/fork isolation,
both new discard cases, and the negative control; cleanup is zero
(private-file-discard-focused.log). The full serial runtime suite passes
2,581 tests with two ignored (private-file-discard-runtime-full.log). The
candidate patch and fixture hashes are preserved in
private-file-discard-lifetime-checkpoint.json and its companion patch. These
passes qualify the lifetime correction so far; the outstanding review and
broader acceptance requirements above remain open.


### Immutable lower COW experiment: isolated gain, acceptance still open

Sparse preparation now experimentally classifies ImmutableLower host-private
views as private inventory backing without initial page-granular COW arming.
Mutable file views retain their existing PrivateFileView identity and 4 KiB
COW; ordinary fork COW remains in force. The signed private_file focus passes
all four selected guest cases across three executables plus the negative
control, with zero scoped leftovers (immutable-unarmed-focused.log).

Two untraced serial Docker/base/candidate/candidate/base/Docker comparisons
show a substantial effect. The first includes the discard correction versus
the accepted stack artifact: normal spawn 12.37885 -> 9.23020 ms, Docker
4.65950 ms (1.98094x). The second isolates only immutable arming, retaining the
same discard/lifetime correction in both binaries: normal spawn 12.23281 ->
9.14226 ms, Docker 4.63781 ms (1.97125x, 25.26% reduction). Python -S is
10.91182 -> 7.79380 ms; /bin/true is 1.76122 -> 1.55999 ms. Raw batches and
artifact hashes are in immutable-unarmed-isolated.json; summary is adjacent.
The candidate SHA is 0d75939624e00eb1ae4fbfa0623a1a635e8ff8f6b5570c5e6d83d51dc4d253c9;
control SHA is dacc52dee0de91bcf6550c4440e6845255f900c9966b62234ae32cffd6936760.
Both have recorded signature/CDHash, UUID, entitlement, DOF and source patch.

These are promising threshold-crossing screens, not goal completion. The
full CPython ABBA is running (cpython-immutable-unarmed-abba.log), with a
fresh serial oracle phase. COW-count attribution, remaining discard API
correctness review, full signed probes, source/lint inventories and final
exact-artifact qualification remain required. The existing materialization
API refuses guest/file offsets noncongruent at host page size, and can retire
prior aliases before a later materialization error; the new discard caller's
use of it must not be declared transactionally complete without addressing
those cases. No commit or broader acceptance is claimed here.


The full CPython ABBA is complete: all eight verdicts MATCH. Multiprocessing
means are 9.4185 s control / 7.8260 s candidate (16.91% improvement); subprocess
means are 58.6695 s / 57.0955 s (2.68% improvement). The fresh oracle measures
2.839 s and 20.555 s respectively. Both full suites still exceed 2x overall;
the 1.97x result is the scoped normal-spawn microbenchmark, not ecosystem
closure. See cpython-immutable-unarmed-summary.json. Captured runtime source
patches differ only in sparse_materialization.rs, confirming isolated attribution.

The original startup census rejects the optimized artifact because it
requires nonzero sampled COW windows. Preserve that rejected capture; do not
cite it as a passing profiler receipt. The new durable
scripts/dtrace/hvpatch-exec-cow-counts.d requires repeated balanced execs,
live guest fault events, balanced COW phases, successful natural exit and zero
errors, while permitting zero COW when paired with a positive control. Both
artifacts pass: for 200 child spawns and 201 balanced exec lifecycles, control
records 64,735 stage2/stage1/commit events each; candidate records zero in all
three phases. Fault totals fall from 111,780 to 47,045, exactly the removed
COW count. No errors or bounded exits occur. The single /bin/true negative
control rejects its zero exec-lifecycle population as required. Receipts:
immutable-counts-*.raw and corresponding provenance/output files. Traced
wall times are not performance evidence. Final checkpoint cleanup finds no
Carrick processes, and target/release/carrick is the exact candidate artifact
(immutable-unarmed-checkpoint-cleanup.json).

The goal stays active. This turn establishes a large, isolated performance
gain and its mechanism, with full CPython correctness preserved. Remaining
acceptance: finish the discard semantic/failure review; full signed public
probes and HVF host gates on the resulting source; clippy/domain inventory
checks and narrow commits; then final exact-artifact performance refresh.
No push is authorized or performed.


### Shifted private-file discard review: new red acceptance case

The new private_file_discard_shifted.py fixture moves an 8-page private file
mapping by a 4 KiB-incongruent offset, dirties one page, discards it, then
writes the source again. All three source/destination variants pass native
Docker (private-file-discard-shifted-variants-oracle.json, final source hash):
anonymous temp file + shared destination, named file + shared destination,
and named file + private destination. Carrick restores the first source byte
97 but fails to observe the subsequent write 98 with a shared destination.
The dirty neighbor remains preserved. Keep this red assertion.

An experimental layout correction now derives a file view's semantic host/IPA
delta from file offset rather than guest VA and removes the congruence guard
in the HVF materialization entry. Non-identity stage-1 can represent these
separately aligned 4 KiB domains. This alone does NOT fix the shared-destination
case. With that candidate, the private-destination variant passes, whereas
both named and anonymous sources fail with a shared destination. The address
receipt identifies source 0x6000bb4000 and destination 0x9000001000: the latter
is the shared aperture, outside the private file-view API's accepted mmap
arena. This refutes source naming as the cause and identifies a second
eligibility boundary beyond alignment. The remaining fix must support private
file restoration at the moved semantic VA without treating shared aperture
backing as privately owned or weakening publication/retirement guarantees.

Receipts: private-file-discard-shifted-embed.log (original failure),
private-file-discard-shifted-fixed.log (alignment change insufficient),
private-file-discard-shifted-named.log,
private-file-discard-shifted-private-dest.log (pass), and
private-file-discard-shifted-addresses.log (range qualification). All signed
negative controls pass and scoped leftovers are zero. The two shared-destination
cases remain red. These new runtime changes have not been rebuilt into the
CLI or performance-qualified: the 1.97x receipt still belongs to the earlier
immutable-unarmed-screen artifact. Do not claim the current tree accepted.


### Shared-aperture private-file restoration corrected in candidate

Allowing the shared aperture at both file-view API entry points changed the
failure from stale data to ENOMEM. The existing mmap_lowering_error USDT probe
now reports discard replacement failures too. A direct Python CLI reduction
under trace_lowering_verdict.d reproduces the signed embed case and reports:
"private file view at VA 0x9000003000 overlapped a mapping published
mid-materialization" (private-file-aperture-direct-lowering.raw; 41 lowering
events, zero trace errors). The shell-wrapped reduction instead fails earlier
at mremap(EFAULT), so that capture is not used as discard evidence.

The generic MappingView lookup falls back to the globally shared boot identity
row after the old private overlay retires. The candidate now distinguishes
only a globally shared, identity-mapped view fully inside the shared aperture
from a concurrent live private frame mapping. The file-view loop and sparse
publisher may replace that boot lookup fallback; live private aliases and
owner-generation-authenticated mappings still obstruct publication, and
non-private/non-dynamic ownership preflight remains unchanged. This does not
grant ownership of the boot shared storage; replacement allocates fresh backing
and repoints stage-1. File-view host/IPA offset uses the file-offset delta,
allowing the separate 4 KiB guest VA alignment.

All three shifted cases pass (private-file-discard-aperture-identity-fixed-3.log).
The strengthened fixtures then verify post-discard guest writes preserve the
source file and bytes immediately outside the moved mapping remain unchanged.
All three variants pass Docker with final source hash
(private-file-discard-shifted-neighbors-oracle.json). The full private_file
signed focus passes seven guest cases in three executables plus entitlement
negative control, with zero scoped leftovers
(private-file-discard-aperture-all-focused.log). The HVF host suite passes
473 tests, three ignored; runtime and shared-engine gates are being recorded
in private-file-aperture-host-gates.json. No final artifact or performance
acceptance is claimed for these additional changes yet.

The host gates finished successfully: carrick-runtime 2,581 passed / two
ignored; carrick-vmm-hvf 473 passed / three ignored; carrick-aarch64 49 passed.
Clippy for runtime, HVF, aarch64 and conformance-next across all targets passes
with warnings denied (private-file-aperture-clippy.log). The signed public
probe gate is now running under just conformance-probes, including its CLI
rebuild (private-file-aperture-public-probes.log). The runtime source must
remain fixed for that gate; final artifact provenance, inventory reconciliation
and renewed timing comparisons are still due.


### Final-artifact probe attribution in progress

The full public invocation completed its three generic shards, all 30 dedicated
cases, both signed negative controls and the CLI boundary contract, but the
retained phase failed one gating row: arm64:musl:sigchld printed
sigchld_handler_ran=false (other lines match; exit 0). Its GNU counterpart
passes. The 30 existing amd64 report-only differences remain non-gating. Do
not label this invocation green. Generic and dedicated signed receipts were
copied separately before replacement by the next phase.

The rebuilt candidate is preserved as carrick-private-file-aperture-candidate,
SHA b73f6a85d43940ae939deedc8b8b203409ebac7181ea3a72a7eece54dbe178d7,
UUID 5FA41DD4-5EDD-3AD0-A7C3-309C58D5DA07, with full provenance and source patch.
A focused SIGCHLD ABBA/BAAB passes all eight arms, four on the accepted stack
artifact and four on the candidate (sigchld-attribution.json). This does not
attribute the full-phase failure. Four full retained-phase arms are now running
base/candidate/candidate/base (retained-attribution.json and per-arm logs),
using the identical retained population and concurrency as the public gate.
No runtime fixes or probe assertion changes were made for this failure.

Inventory review classified the two new mapping-reference counter invariant
aborts as carrier faults, with explicit rationales. K1 lexical inventory adds
12 mapping-word rows (test/reference lifetime and remap metadata), and drops
one description_guard row because snapshot_private_mmap_file now delegates
to the retained-description snapshot helper. The guard itself remains in that
helper. The exact delta and removed taxonomy row are receipted in
private-file-k1-delta.json and private-file-k1-taxonomy-removed.json. Remaining
inventory drift is source position/fingerprint rebinding; host-authority capture
requires committed clean tracked inputs. No source commits yet.

All four full retained-phase attribution arms pass (two baseline, two candidate;
46 tests passed, one existing ignored in each). The candidate's initial SIGCHLD
failure remains recorded as intermittent and not attributed to a source change;
it did not reproduce in four focused and two full-phase candidate repeats.
Do not describe it as proven pre-existing on the baseline. The exact candidate
has now passed each broad gate component, but the original public invocation
remains failed in the log. A fresh complete public invocation and renewed
performance verification will qualify the final committed artifact.
