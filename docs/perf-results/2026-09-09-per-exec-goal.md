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
