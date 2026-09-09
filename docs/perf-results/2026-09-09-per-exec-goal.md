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
