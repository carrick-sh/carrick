# Native-Default Conformance Campaign Ledger

**Started:** 2026-07-13

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-default-conformance-quality-design.md`](superpowers/specs/2026-07-13-native-default-conformance-quality-design.md)

## Campaign rules

- Record measurements only after the command completes.
- Keep projections and desired outcomes in `Target`, never in `Measured`.
- Do not bless crashes, timeouts, load instability, unexplained regressions, or
  real-workload blockers.
- Keep Carrick and Docker phases separate and use scoped run IDs.
- Preserve raw logs, JSONL, LLDB output, and cores under `target/conformance/`;
  this ledger records the durable path and conclusion.

## Starting manifest

| Ecosystem | Suites | Smoke | Full-only |
| --- | ---: | ---: | ---: |
| CPython | 438 | 6 | 432 |
| Go | 194 | 5 | 189 |
| Node | 3 | 2 | 1 |
| LTP | 1,492 | 10 | 1,482 |
| **Total** | **2,127** | **23** | **2,104** |

The ecosystem counts come from the checked-in suite manifest at campaign
start. Smoke/full membership remains authoritative in
`scripts/conformance/suites.toml`.

## Measured ladder

| Date | Revision | Gate | Workers | Measured | Artifact | Classification / next action |
| --- | --- | --- | ---: | --- | --- | --- |
| 2026-07-13 | `df43c414` | `smoke --lane macos-native-dsr --force` | 4 | 15 MATCH; 4 REGRESSION; 3 TIMEOUT; 1 CARRICK_CRASH | `target/conformance/native-default-goal-smoke-20260713.jsonl` | Starting baseline. Split into exec reservation, fork-lock, and post-fork-thread clusters. |
| 2026-07-13 | `df43c414` | `go-runtime`, `go-sync` isolated | 1 | deterministic failure | `target/conformance/native-default-go-isolated-r1-20260713.jsonl` | `pthread_create` receives deliberate `EOPNOTSUPP` after fork-to-exec. Real-workload blocker; fix forward. |
| 2026-07-13 | `df43c414` | `cpython-threading` isolated | 1 | TIMEOUT at 300.265 s | `target/conformance/native-default-cpython-threading-isolated-r1-20260713.jsonl` | LLDB captured fork child in inherited `THREAD_WAITERS` mutex. Add contended-fork red test. |
| 2026-07-13 | `df43c414` | one CPython shutdown method | 1 | PASS; 0.683 s method, 3.0 s total | `target/conformance/logs/lldb-runs/native-goal-cpython-threading-one.guest.log` | Falsified the first method-level attribution; full-file failure is lifecycle/load related. |
| 2026-07-13 | `df43c414` | unbuffered `test_threading` diagnostic | 1 | completed in 33.5 s with 19 failures | `target/conformance/logs/lldb-runs/native-goal-cpython-threading-unbuffered.guest.log` | Nineteen child interpreters cannot create threads after fork-to-exec. Separate from the inherited-lock timeout. |
| 2026-07-13 | `df43c414` | `go-build` LLDB deadline | 1 | TIMEOUT at 45 s | `target/conformance/logs/lldb-runs/native-goal-go-build.lldb.txt` | Compiler child is still executing with one host thread; capture the exact clone/guard interaction before changing lifecycle code. |
| 2026-07-13 | `6d3cf627` | contended `THREAD_WAITERS` fork reducer | 1 | RED at 2 s before fix; GREEN in 0.07 s after fix | `host_signal::tests::fork_child_resets_contended_thread_waiters` | Deterministically proved copied parking-lot contention. Child now publishes a preallocated empty backing without touching the inherited queue. |
| 2026-07-13 | `6d3cf627` | `cpython-threading` isolated | 1 | REGRESSION; 175/194 pass, 19 fail, 1 skip; no timeout/crash | `target/conformance/native-waiter-cpython-threading-serial.jsonl` | Originating 300 s waiter timeout is gone. Remaining failures are the separately tracked post-fork thread rejection. |
| 2026-07-13 | `6d3cf627` | `cpython-threading` repeat stability | configured 4; 1 selected suite | 3/3 REGRESSION; each 175/194 pass, 19 fail, 1 skip; no timeout/crash | `target/conformance/native-waiter-cpython-threading-repeat-r{1,2,3}.jsonl` | Repeat-stable single-suite result. Not counted as concurrent load evidence; multi-suite smoke remains required. |
| 2026-07-13 | `2a7d3046` | Node-sized split Direct range reducer | 1 | RED `Redirected` to `0x7000000000`; GREEN segment-wise | `host_proc::imp::direct_vm_reservation_tests::fork_child_split_canonical_range_is_accepted_segmentwise` | Measured target crosses adjacent delegated dyld-empty regions, not one region plus a vacant tail. Every genuine gap is now owned exactly. |
| 2026-07-13 | `2a7d3046` | `ltp-eventfd01` isolated | 1 | MATCH; carrick 4/4, oracle 4/4 | `target/conformance/native-direct-reservation-eventfd01-mach2-060.jsonl` | Originating gzip exec collision is fixed end-to-end. |
| 2026-07-13 | `2a7d3046` | Node app/V8 smoke isolated | 1 | 2 REGRESSION; both complete wrapper and abort `rc=134`, no reservation collision | `target/conformance/native-direct-reservation-node-mach2-060.jsonl` | Direct reducer reaches Node startup assertion on `uv_thread_create`; this is the P1 post-fork thread rejection, not a mapping failure. |
| 2026-07-13 | worktree | `forkexecpthread` staged reducer | 1 | Production RED: stage2 reached, `pthread_create_errno=11`; unsafe diagnostic GREEN; Docker GREEN | `conformance-probes/src/bin/forkexecpthread.rs` | The blanket guard is real, but one post-fork pthread is not enough to prove Apple runtime safety. |
| 2026-07-13 | worktree | Node app/V8 with unsafe post-fork threads | 1 | app REGRESSION; V8 MATCH | `target/conformance/native-postfork-node-unsafe.jsonl` | V8 closes its originating `uv_thread_create` failure. App reaches a repeatable host `SIGTRAP` inside libdispatch. |
| 2026-07-13 | worktree | Go build/runtime/sync with unsafe post-fork threads | 1 | build TIMEOUT; runtime CARRICK_CRASH 17/18; sync REGRESSION 51/52 | `target/conformance/native-postfork-go-unsafe.jsonl` | Subprocess tests reach the same libdispatch trap. Runtime also exposes a separate user-arena memory fault for P2 triage. |
| 2026-07-13 | worktree | CPython threading with unsafe post-fork threads | 1 | REGRESSION; 174/194 pass, 20 fail, 1 skip; 21 fatal trap records | `target/conformance/native-postfork-cpython-threading-unsafe.jsonl` | Unsafe thread creation replaces `EOPNOTSUPP` with deterministic libdispatch failures; not a viable production repair. |
| 2026-07-13 | worktree | common host-trap symbolication | 1 | PC `0x1877f2410` = libdispatch deduplicated trap +36; LR `0x1877be4b8` = `_dispatch_sema4_wait+56` | `target/conformance/raw/conf-{63249,64365,69065}-*.err` | Apple libdispatch fork-of-multithreaded-parent state is the first common failure boundary. Select PID-preserving host self-reexec. |
| 2026-07-13 | worktree after `05e06fab` | capsule transport and host-root authority | 1 | PID before/after identical; malformed resume rejected; exact root reattached; substituted root rejected | `native_self_reexec_transport_preserves_pid`; `fs_backend::tests::*reexec_authority*` | Versioned one-shot transport and durable `--fs host` authority are green. Capsule version 1 still rejects memory-fs and non-bare fd tables before host exec. |
| 2026-07-13 | worktree after `05e06fab` | signed `forkexecpthread` through host self-reexec | 1 | official test PASS; 5/5 direct repeats report all six success fields true | `native_conformance_dsr_fork_exec_can_create_thread`; run IDs `native-selfreexec-pthread-repeat-{1..5}` | First production path creates and joins a guest pthread after fork/exec with no unsafe switch. Initial EAGAIN was descendant cleanup-lock ownership; next RED was a missing native memory layout in the fresh dispatcher. Both are fixed and pinned. Expand exec-surviving fd/process state before ecosystem promotion. |
| 2026-07-13 | `6d9a0757` | Node app/V8 before fd expansion | 1 | 2 REGRESSION; shell helpers fail `EOPNOTSUPP`, no trap/crash/timeout | `target/conformance/native-selfreexec-node.jsonl` | Fail-closed capsule gate measured non-`CLOEXEC` command-substitution pipes, redirected files, then Unix-socket stdio. Implement these ordinary survivor classes; keep libuv epoll/eventfd state omitted by `CLOEXEC`. |
| 2026-07-13 | worktree after `6d9a0757` | Node app/V8 after host fd snapshots | 1 | 2 MATCH; app 10.185 s, V8 8.843 s; no host trap | `target/conformance/native-selfreexec-node-green.jsonl` | Host pipes, regular files, sockets, and descriptor aliases survive PID-preserving host exec with kernel identity/type validation. First real ecosystem blocker is closed; performance is explicitly out of campaign scope. |
| 2026-07-13 | worktree | stale any-child process-record reducer | 1 | RED: reaped child remained in watched set; GREEN after live-host filtering | `io_wait::tests::any_child_watch_excludes_a_reaped_stale_process_record` | Live LLDB found `wait4(-1)` parked on an already-reaped PID while no host children existed. Any-child waits now filter the fork-coherent table against current direct-child identity and redispatch immediately when the set is empty. |
| 2026-07-13 | worktree | native vfork completion across host self-reexec | 1 | RED: both pipe ends had descriptor flags `0`; GREEN: both carry `FD_CLOEXEC` | `native_darwin::tests::native_vfork_completion_pipe_closes_across_host_exec` | The child reached Go after self-reexec but the parent waited forever because the private completion writer survived. Successful host exec now closes it atomically; failed guest exec retains normal vfork completion ownership. |
| 2026-07-13 | worktree | exact fresh-cache Go build workload | 1 | `BUILD_OK`; real 55.20 s, user 86.38 s, sys 56.21 s | live signed workload; harness evidence below | Replaced whole-map exclusive invalidation on every 64-byte `DC ZVA` with an overlap-bounded range scan. The prior sample remained live after 222.88 s inside `invalidate_exclusive_range`; the fixed run completes. |
| 2026-07-13 | worktree | `go-build --lane macos-native-dsr` | 1 | MATCH; Carrick Success in 54.077 s; cached oracle Success | `target/conformance/native-go-exclusive-range-green.jsonl` | First Go real-workload lane is green after software exclusive reservations, self-reexec wait/vfork repairs, the 2 TiB biased aperture, SIMD lowering repair, and honest HWCAP advertisement. Continue with Go runtime/sync before promotion to the full ecosystem. |
| 2026-07-13 | worktree | `go-sync --lane macos-native-dsr` | 1 | MATCH; 52/52 on both sides; Carrick 10.578 s | `target/conformance/native-go-runtime-sync-r1.jsonl` | The synchronization workload is green. Performance ratio is report-only and out of campaign scope. |
| 2026-07-13 | worktree | Go UserArena alias-reuse reducer | 1 | RED: writable `MAP_FIXED` retained prior `PROT_NONE` page metadata; GREEN after replacement reset; focused workload 3/3 PASS | `native-go-userarena.trace`; `native_darwin::tests::biased_alias_remap_discards_stale_page_protection` | The 103,311-line syscall trace showed 8 MiB UserArena chunks reserved, protected none, then remapped writable before a direct `STP` fault. Alias replacement now retires native-page, write-exec, and Linux-4K subpage protection caches at host-page granularity. |
| 2026-07-13 | worktree | `go-runtime --lane macos-native-dsr` after alias fix | 1 | MATCH; 52/52 on both sides; Carrick 32.418 s | `target/conformance/native-go-runtime-alias-remap-green.jsonl` | The originating UserArena crash is closed. Go build/runtime/sync smoke lanes are all measured MATCH; next ladder rung is CPython threading/subprocess. |
| 2026-07-13 | `07f18852` | `cpython-threading --lane macos-native-dsr` | 1 | REGRESSION; 191/193 pass; no crash/timeout | `target/conformance/native-cpython-threading-subprocess-r1.jsonl` | Only fork-without-exec then pthread creation remains. Production keeps the measured libdispatch safety guard; review these two esoteric cases as native-only gaps after ordinary workload state is complete. |
| 2026-07-13 | `07f18852` | `cpython-subprocess --lane macos-native-dsr` | 1 | TIMEOUT at 300.188 s | `target/conformance/native-cpython-threading-subprocess-r1.jsonl` | LLDB found a self-reexec `/bin/sh` blocked on inherited stdin. Its capsule had resolved `/bin/sh` but retained only the original script argv. |
| 2026-07-13 | `73774b18` | CPython shebang subprocess reducers | 1 | RED: two stable hangs; GREEN: 2/2 pass in 0.678 s | `POSIXProcessTestCase.test_args_string`; `POSIXProcessTestCase.test_call_string` | Native self-reexec now carries the argv after shebang resolution, so the interpreter receives the script operand instead of entering interactive mode. |
| 2026-07-13 | `73774b18` | `POSIXProcessTestCase` extended shard | 1 | completed 77 tests in 556.087 s; 14 failures, 2 errors, 3 skips | live signed workload | Proved the old timeout became a deadline issue after the shebang fix and exposed ordinary process-state gaps. SIGINT/SIGTERM, credentials, umask, dispositions, and closed stdio were separated. |
| 2026-07-13 | worktree | cross-process signal ring across native self-reexec | 1 | RED: `terminate`/`send_signal` both fail after 60.741 s; GREEN: 2/2 pass in 0.637 s | `native-cpython-subprocess-signals-green`; `xsig::tests::reexec_backing_fd_maps_the_same_shared_ring` | `MAP_SHARED|MAP_ANON` vanished across host exec, so parents wrote the old ring. The ring is now file-backed and capsule-adopted; `lsof` proved parent and resumed child share device `1,16`, inode `335855434`, size 10,240. |
| 2026-07-13 | worktree | `cpython-subprocess --lane macos-native-dsr` with native timeout scale | 1 | REGRESSION; 271/275 vs oracle 280/280; completed in 578.932 s | `target/conformance/native-cpython-subprocess-xsig-green.jsonl` | No crash/timeout; signal and shebang blockers are closed. Remaining raw failures cluster in exec-surviving credentials/groups, umask, signal disposition reporting, and closed-stdio edge cases. |
| 2026-07-13 | worktree | CPython exec-surviving process-state reducers | 1 | credentials/groups/umask/signals 6/6 in 5.079 s; closed stdio 2/2 in 6.030 s; pre-exec `RLIMIT_NOFILE=(64,64)` preserved | focused signed workloads plus `process_state_round_trip_preserves_credentials_groups_umask_and_ignored_signals` and `stdio_closed_or_cloexec_before_exec_restores_closed` | The typed native capsule now preserves credential overrides, supplementary groups, umask, ignored dispositions, rlimit overrides, and post-exec closed stdio. |
| 2026-07-13 | worktree | `cpython-subprocess --lane macos-native-dsr` canonical oracle refresh | 1 | MATCH; Carrick 278/278, Docker 278/278; Carrick 577.471 s, Docker 20.895 s | `target/conformance/native-cpython-subprocess-oracle-refresh.jsonl`; `scripts/conformance/oracle-cache.jsonl` | Removed a stale oracle-only `nofile=1024` cap. Unmodified Docker and Carrick both advertise a high descriptor limit and skip the same two applicability checks. The suite is fully green; performance is report-only. A worktree-only scoped-cleanup sudo warning left no Carrick process alive at Docker phase entry. |
| 2026-07-13 | worktree before `089d5918` | canonical `perf_fork_exec`, five signed native repetitions | 1 | native p50 21.47 ms; Docker p50 0.408 ms; 52.6x | exact-source static-PIE probe; 1,100 completed spawn cycles | Process-spawn latency is a correctness blocker, not report-only. Stage timing placed 97% before the exec'd guest reached `main`; two capsule durability flushes contributed about 9.5 ms. |
| 2026-07-13 | `089d5918` | canonical `perf_fork_exec` after removing capsule durability flushes | 1 | five native p50s 11.891-12.391 ms, median 12.102 ms; Docker median 0.392 ms; 30.8x | live exact-source static-PIE runs; 1,100 completed spawn cycles | The inherited anonymous regular file needs coherence, checksum, nonce, and one-shot consumption, not stable-storage durability. Removing both `sync_data` calls cuts p50 about 42% with all spawn cycles and the signed fork-exec-pthread gate green. The remaining ratio is still pathological. |
| 2026-07-13 | `05e06fab` vs `089d5918` | same-host, identical-probe self-reexec A/B | 1 | fork-only 1.380 vs 1.425 ms; fork+exec 5.193 vs 12.255 ms | isolated signed historical build; current canonical probe binaries | DSR is present on both sides and fork cost is effectively unchanged. Activating PID-preserving host self-reexec adds about 7.0 ms per exec on this host; it is the dominant regression selected to preserve proven libdispatch correctness. |
| 2026-07-13 | `458ad8df` | `dsr-fork` host-self-reexec waterfall | 1 | 220 samples per phase; natural completion; 3,084 metric rows; 0 incomplete pairs; 0 drops | `target/conformance/native-fork-exec-waterfall-r2.{raw,jsonl}` | Traced p50 attribution: preflight 1.417 ms, capsule preparation 1.329 ms, host exec 25.873 ms (startup 24.907 ms, kernel 0.745 ms, CLI dispatch 0.231 ms), capsule adoption 0.345 ms, restore 1.918 ms (dispatcher 0.654 ms, duplicate image load 1.148 ms, reset 0.019 ms). DTrace inflates startup but preserves the phase ordering and exposes the duplicate work. |
| 2026-07-13 | `1d0788c8907f89ee96821dabdb3b576467b1eabc` | measured RED: canonical `perf_fork_exec`, five signed native repetitions plus `dsr-fork` lifecycle | 1 | five native p50s 11.528083-12.026333 ms, median 11.953750 ms; 5/5 `iters=200`; 220 legacy `host-self-reexec-image-load` pairs; 0 prepared-build/map phases; natural completion; 0 incomplete pairs; 0 drops | signed binary SHA-256 `cea50968844222d7f7f9ee222fe942325523789c294fbc82638598455b1f6ce4`; canonical probe SHA-256 `d68eb0e9feaa23358a682720b3886f8500f3b2ce0cc49ff3f79d0583f6baed0f`; uncommitted `target/conformance/native-prepared-image/red/` | Frozen pre-implementation authority. The controller command required `run-elf --raw` so the exact-source probe's stdout, including iteration and p50 evidence, was captured; the original non-raw logs are retained beside the measured runs as evidence of that corrected plan defect. |
| 2026-07-13 | `5d7f95e8` | Task 8 artifact rebuild and exec reducer ladder | 1 | 431 musl + 431 GNU native-PIE probes rebuilt; signed Carrick verified; exact static, dynamic, shebang, descriptor, process-state, fork/exec/thread, and both-page-profile reducers green | `target/conformance/native-prepared-image/correctness/{provenance.txt,build-probes.log,exec-probe-reducers-both-profiles.log,dynamic-gnu-exec-reducers.log,exec-integration-reducers.log,exec-thread-reducers.log}` | Correctness authority was rebuilt from current sources. Frozen binary SHA-256 was `fbdcdd1f...a242ecf5`, CDHash `0818429c...18019eb`; the prepared-image marker is present. |
| 2026-07-13 | worktree | complete signed native probe gate, then exact failed-probe rerun | 1 | initial 372 PASS / 9 FAIL in 224.58 s; three self-reexec state failures fixed; exact rerun leaves 6 FAIL and 3 PASS | `target/conformance/native-prepared-image/correctness/{conformance-probes-complete.log,conformance-probes-nine-serial-after-fixes.log}` | `keydeny`, `ltpcheckpointexec`, and `traceexecstop` are now green. The remaining `exitgroupthreads`, `futexforkwakegroups`, `mtsigrelease`, `procladder_epollmgr`, `procladder_mixed`, and `procladder_mt` all hit the deliberate post-fork-without-exec pthread `EAGAIN` safety guard. Keep them explicit; do not bless the probe gate yet. |
| 2026-07-13 | `9e39fec5..1b5a6c57` | signed self-reexec state restoration regressions | 1 | bind-mount topology, seccomp policy, ptrace ownership, kernel-arena identity, and cross-exec futex waiter authority red-first then green | focused unit gates plus `target/conformance/native-prepared-image/correctness/{bind-mount-green.log,policy-ptrace-arena-final.log,shared-authorities-final.log}` | Prepared host self-reexec was losing ordinary durable runtime state. Typed capsule snapshots and validated inherited backing authorities close the three originating probe failures without weakening the safety guard. |
| 2026-07-13 | worktree after state fixes | Node full ecosystem | 1 | 3/3 MATCH; Carrick/oracle ratios 29.33x, 23.01x, and 18.96x | `target/conformance/native-prepared-image/correctness/node-full-serial.jsonl` | Content coverage is green, including the full-only libuv row. The two successful suites remain pathologically above the oracle; this is correctness-blocking performance evidence, not a bless. |
| 2026-07-13 | worktree before `0263eee1` | Go full ecosystem, interrupted at row 99/194 | 1 | 94 MATCH; 2 DIFF; 2 REGRESSION; `go-go_internal_srcimporter` wedged; no full-lane verdict | `target/conformance/native-prepared-image/correctness/go-full-serial.jsonl`; `target/conformance/native-prepared-image/correctness/cores/go-srcimporter-*.{core,bt.txt}` | Core evidence proved a `parking_lot` bucket / `SignalState` lock inversion in futex park validation. Do not count the partial rows as a full Go result. |
| 2026-07-13 | `0263eee1` | futex signal lock-order reducer and exact Go c94/c99 repeats | 1 | deterministic lock cycle red-first then green; arrival race and lock-order tests 100/100; c99 naturally completed in 277.672 s without the old cycle | unit gates plus `target/conformance/native-prepared-image/correctness/{go-c94-c99-r3.jsonl,cores/go-types-r2-*.{core,bt.txt}}` | A monotonic interrupt generation removes the bucket-to-signal lock inversion. A prior c99 repeat was stopped prematurely; its core showed active compiler work, not the old deadlock. |
| 2026-07-13 | `7006c2ac` | exact Go cgo SIMD-pair DSR reducer and bounded import check | 1 | `ldp q1, q2, [x1, #32]!` red-first then exact emitted-code green; DSR 127/127; signed `cgo -h` reaches normal usage exit; `TestImplicitsInfo` no longer reports `EFAULT` but fails after 15.90 s at 1,000,000 traps | emitted-code oracle `biased_simd_pair_preindex_preserves_register_files_and_writeback`; bounded run ID `task8-go-types-implicits-7006` | The DSR overlap guard had conflated SIMD q-register numbering with GPR x-register numbering. The decode error is fixed; the bounded real import now exposes pathological instruction/trap volume instead of `bad address`. |
| 2026-07-13 | `7006c2ac` | `go-go_internal_srcimporter` after SIMD-pair fix | 1 | scoped stop after 1,392.649 s; Carrick CARRICK_CRASH vs cached Docker success; 516.56x (1,392,649 ms vs 2,696 ms); 42 scoped processes, 19 runnable, about 856-950% aggregate CPU | `target/conformance/native-prepared-image/correctness/go-c94-after-simd-pair.jsonl` | This is a P0 real-workload correctness blocker. The compiler subprocesses were active, not deadlocked, but none completed before the bounded stop. Do not restart full Go/CPython/load laddering until this is understood and reduced. |
| 2026-07-13 | `0263eee1` + dirty DSR fix | bounded broad `dsr` profile of one-file cgo | 1 | 45 s diagnostic; 117,707 block hits, 67,199 misses/publishes across 14 PIDs; translate 1.678 s, resolve 1.919 s, prepare 0.308 s, dispatcher 0.317 s; no drops/capacity/invalidation | `target/conformance/native-prepared-image/correctness/{cgo-mini-dsr-summary.jsonl,cgo-mini-dsr-raw.log}` | DTrace inflation is acceptable and expected to scale proportionally, but untraced runs remain timing authority. The trace proves repeated per-process cold caches; its roughly 4.2 s of measured DSR/control work does not by itself explain the entire 45 s bounded run, so an AOT cache is only one hypothesis. |

## Active failure clusters

| Priority | Cluster | Authority | Current status | Target |
| ---: | --- | --- | --- | --- |
| P0 | Native process spawn is pathologically slower than Linux | canonical exact-source probes, same-host historical A/B, untraced phase timestamps, and complete `dsr-fork` waterfall | durable flushes fixed in `089d5918`, reducing fork+exec p50 about 42%; current median remains 12.102 ms vs Docker 0.392 ms (30.8x) | account for every millisecond, remove redundant self-reexec work without weakening libdispatch safety, then establish a non-pathological native/Docker ratio before workload laddering |
| P0 | `THREAD_WAITERS` remains locked in a fork child | live LLDB stack plus deterministic contended-fork reducer | fixed in `6d3cf627`; four signed single-suite runs complete, multi-suite load proof pending | no CPython timeout in workers=4 smoke repeats |
| P0 | Direct-exec target reservation rejects split dyld range | red/green Node-sized reducer plus signed eventfd/Node runs | fixed in `2a7d3046`; eventfd MATCH, Node reaches downstream thread guard; multi-suite load proof pending | no reservation collision in workers=4 smoke repeats |
| P1 | Post-fork exec child cannot create guest threads | red/green staged reducer plus Node/Go/CPython unsafe samples and libdispatch symbolication | signed reducer + 5/5 repeats pass without bypass; Node app/V8 and Go build/runtime/sync are MATCH through self-reexec; CPython remains | `forkexecpthread`, Node, Go, and CPython run after PID-preserving host self-reexec |
| P1 | Native self-reexec loses process state | red/green exact reducers plus canonical CPython subprocess MATCH | fixed: shebang argv, file-backed xsignal continuity, credentials/groups, umask, ignored dispositions, rlimits, and closed stdio survive host exec | keep `cpython-subprocess` MATCH under smoke load and broader workloads |
| P0 | Go compiler/import workloads have pathological native execution volume | untraced c94 and exact `TestImplicitsInfo`, plus bounded broad DSR profile | exact SIMD/GPR decode defect fixed; c94 still reaches 516.56x with active compiler children, and the import reducer exhausts 1,000,000 traps in 15.90 s | decompose instructions, traps, DSR cache misses, self-reexec/process startup, syscalls, and scheduler time; reduce the dominant term before resuming the correctness ladder |
| P2 | Remaining ecosystem/LTP differences | no fresh full native run yet | unknown | classify from measured full run after P0/P1 blockers clear |

## Bless checklist

- [x] `just ci`
- [ ] signed native conformance probes
- [ ] smoke serial
- [ ] smoke workers=4, three consecutive runs
- [x] Node full ecosystem content parity (performance remains blocking)
- [ ] Go full ecosystem
- [ ] CPython full ecosystem
- [ ] LTP full ecosystem
- [ ] complete candidate run, workers=1
- [ ] complete load run, workers=4
- [ ] every non-MATCH row diagnosed and reviewed
- [ ] full unfiltered native overlay bless
- [ ] post-bless full run with no gating regression
- [ ] live real-workload demonstration

## Current next action

Task 8 is incomplete and Task 9 has not started. Stop correctness laddering on
the measured Go compiler/import performance blocker: c94 reached 516.56x with
active compiler children, while the exact import reducer exhausted one million
traps after 15.90 seconds. First account for instructions, traps, DSR cache
misses, process/self-reexec startup, syscalls, and scheduler time with bounded
profiles and untraced timing authority. A persistent/AOT DSR cache remains a
hypothesis, not the diagnosis: the broad trace proves per-process cold caches
but attributes only part of the observed wall time to translation/control.
After reducing the dominant term to a non-pathological ratio, resume at the Go
c94 reducer, then the remaining Go lane, CPython, workers=4 smoke, and the full
bless ladder.


## Task 3 measurement campaign (2026-07-14, signed, at 3e091fce lineage)

Provenance: clean tree, signed binary
`1c1d6737ffde92530e62871a32f4a4d19726e89233495213c4cf513ee3ba88bb`, Mac16,12,
macOS 27.0, 10 CPUs, AC power, image
`sha256:61998068...`. All runs scoped, cleaned, and re-parsed through the
strict wire; evidence committed under `docs/perf-results/`.

**Plane A (untraced absolute authority, warmup+5 per engine/workload):**

| Workload | Carrick p50 | Docker p50 | Ratio | Outcome |
| --- | --- | --- | --- | --- |
| W1 import reducer | 19.360 s | 1.600 s | ceiling-truncated (>=12.1x) | all 5 typed `max-traps` at the 1,000,000-gateway ceiling |
| W2 frozen compile | 3.520 s | 0.220 s | **16.00x** | all 5 completed, work product `5db57566...` |

**Plane B (W2 ABBA off/on, warmup+5 per mode):** profile tax 1.13 percent
(<=10 percent, durations usable); all 12 completed with clean scoped cleanup;
45 complete thread groups over 23 PIDs per profiled run.

**Additive model outcome — FAIL-CLOSED.** The committed analyzer raises
`additive CPU reconciliation differs by more than 2%: 0.653181`. Exclusive
DSR phases cover only 23-43 percent of measured user+system CPU (residual
57-77 percent across one-thread and multithreaded runs). The residual tracks
the blocked wall segments (~1.1-1.3x), not PID count: one-thread
`exclusive 1.46 s + blocked 1.66 s ~= cpu 3.41 s`; the retained W1 ceiling
profile shows `exclusive 21.2 s + blocked 42.1 s ~= cpu 69.0 s`. Untraced W2
runs are system-time dominated (user 1.44 s / sys 2.31 s). Measured blocked
wall is 55.0 percent of untraced wall (design rung threshold 30 percent). The
evidence indicates the runtime burns host CPU during guest blocked segments
(parking/wake machinery), an unprofiled term the additive model correctly
refuses to overlook.

**Count-scope outcome — FAIL-CLOSED.** Hottest-thread exclusive share is
47.1 percent (selects `sensitive-exclusive`); aggregate-threads exclusive is
21.7 percent (selects nothing at the 30 percent rung; aggregate is
resolver-heavy at 58.4 percent with recurrence unproven). The scoped analyzer
refuses to select a slice while the scopes disagree.

**Plane C (fresh dtrace shape):** completed naturally, zero drops, zero
incomplete pairs, 23 reconciled per-PID totals, 1,445 temporal ordering
entries, exit mix by kind ordinal `{1: 7954, 2: 108042, 3: 107896, 5: 567,
6: 235178}`. DTrace wall magnitude is inflated and excluded from decision
inputs.

**One-thread control (warmup+3 per plane):** untraced p50 3.490 s, profiled
p50 3.490 s; per-run exclusive terms stable (translation 0.823-0.827 s,
dispatch 0.408-0.412 s); residual 56.6-57.3 percent, consistent with the
multithreaded runs.

**Decision:** no typed decision row exists. The committed ladder fails closed
on both the additive gate and scope reconciliation, exactly as designed. The
measured dominant unaccounted term is blocked-segment host CPU burn. The
follow-on plan (`docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md`)
instruments park/wake and per-process startup CPU attribution so the additive
model reconciles, repairs the parking/wake burn per the design's
blocked-residual rung, and re-runs this campaign to obtain the typed decision
row. No timeout, `max_traps`, or semantic weakening is involved.


## Task 3 re-run with typed attribution (2026-07-14) — RETRACTED

**This section's decision row and conclusions are RETRACTED.** The campaign at
`081c0d7d` emitted a typed decision row selecting `helper-cpu` (30.86 percent)
and concluded that host-side machinery was ~72 percent of CPU while guest
execution was a ~31 percent minority. That conclusion is wrong and its
supporting term is mislabeled.

`helper-cpu` is a DERIVED residual (`process_cpu - sum(flushed thread_cpu)`),
and guest worker threads do not flush their profile records: on `exit_group`
the leader thread calls `_exit(2)`, which kills every sibling worker instantly
— they run no code, so they emit no record while their DSR CPU remains in the
process rusage gauge. Measured on the committed evidence, the Go compiler
process flushed 299 ms of thread CPU against 1,290 ms of real process CPU
(77 percent unattributed); across all guest processes 1.098 s of 2.281 s
(48 percent) of guest CPU never reached a thread record. The residual is
therefore mostly UNATTRIBUTED GUEST EXECUTION, not host pumps or watchers.

What survives from that run and is NOT retracted:

- Untraced Plane A authority: W2 completes at 16.00x Docker (p50 3.520 s vs
  0.220 s); W1 remains ceiling-truncated (p50 19.200 s, 11.93x).
- ABBA profile tax 1.42 percent; one-thread control and Plane C clean.
- The supervisor term is directly measured (its own rusage record, not a
  residual): supervisor self CPU is ~1.555 s, ~41.6 percent of untraced CPU.
  This is real host-side overhead regardless of how the guest-side residual
  redistributes.
- Startup CPU (~1 ms) and blocked-segment thread CPU (~3 ms) are measured
  negligible; those two pre-attribution hypotheses ARE refuted.

An upper-plausibility guard now rejects any profile whose derived helper
residual exceeds half a process's CPU, so this class of mis-attribution
cannot silently produce a decision again. The campaign will be re-run once
worker-thread flushing is fixed at the `exit_group` path, and a corrected
decision row will replace this section.

---

## Superseded measurements from the retracted run (2026-07-14, at 081c0d7d)


The attribution increments (NATIVEPERF v2 frames, per-era thread CPU across
self-reexec, the supervisor record with its pid-identity guard, the two-gate
tree reconciliation, and count-rung abstention on scope disagreement) closed
the additive model: gate1 (time-vs-rusage) and gate2 (children cover guests)
both pass within +-0.5 percent on every profiled run.

**The committed ladder emitted its first typed decision row**
(`docs/perf-results/native-compiler-budget-v2.jsonl`, `analyze --check`
green): `selected_slice = "helper-cpu"`, share 30.86 percent of untraced CPU,
scope `process-cpu`, basis measured-cpu-attribution, profile tax 1.42
percent. The count rungs abstained (hottest-thread exclusive ~47 percent vs
aggregate ~22 percent still disagree — honestly recorded, not adjudicated).

Measured attribution over the five profiled ABBA runs (medians over the
3.740 s untraced CPU):

| Term | Median | Share |
| --- | --- | --- |
| supervisor self CPU | 1.555 s | 41.6 percent |
| in-guest-process helper threads | 1.154 s | 30.9 percent |
| guest threads (all DSR execution) | 1.143 s | 30.6 percent |
| syscall-dispatch (thread wall) | 0.361 s | 9.6 percent |
| blocked-segment thread CPU | 0.003 s | 0.1 percent |
| process startup | 0.001 s | ~0 percent |

Host-side machinery (supervisor + helpers) is ~72 percent of all CPU; guest
execution is ~31 percent. The pre-attribution hypotheses (startup cost,
blocked-machinery churn, AOT-shaped translation dominance) are refuted by
measurement. Plane A held steady (W2 16.00x, 3.520 s vs 0.220 s; W1 ceiling
19.200 s, 11.93x truncated); one-thread control passes all gates with
helper >= 0; Plane C complete with zero drops and 23 reconciled PIDs.

The repair investigation now targets the helper-cpu slice first (per the
decision row) with supervisor-cpu (41.6 percent) as the immediate next term —
both are host-side runtime overhead, not DSR translation. No timeout,
`max_traps`, or semantic weakening occurred anywhere in this campaign.


## Task 3 CORRECTED campaign (2026-07-14, signed, at 69464cea)

Run after the attribution repairs (worker threads killed by `exit_group` now
flush via a profiling-gated registry with exactly-once arbitration; per-era
thread CPU across self-reexec; supervisor rusage record). Unattributed guest
CPU fell from 48 percent to 6.4 percent; the heavy compiler process now
reports 7 thread groups instead of 2.

**Typed decision row** (`docs/perf-results/native-compiler-budget-v3.jsonl`,
`analyze --check` green): `selected_slice = "sensitive-exclusive"`, share
**47.07 percent of gateway exits**, basis reconciled-profile-counts, scope
`hottest-thread+aggregate-threads` (BOTH scopes agree: 47.1 percent hottest,
33.2 percent aggregate, each above the committed 30 percent rung). Profile tax
3.08 percent, inside the 10 percent gate.

The earlier scope disagreement that blocked the previous campaign was itself an
artifact of the unflushed worker threads: with the workers' records present,
the aggregate scope converges with the hottest thread.

Measured CPU attribution (medians over five profiled ABBA runs, 4.170 s
untraced CPU):

| Term | Median | Share |
| --- | --- | --- |
| guest thread CPU (DSR execution) | 2.374 s | 56.9 percent |
| supervisor self CPU | 1.800 s | 43.2 percent |
| syscall-dispatch (thread wall, subset of guest) | 0.457 s | 11.0 percent |
| in-process helper threads (derived) | 0.162 s | 3.9 percent |
| blocked-segment thread CPU | 0.005 s | 0.1 percent |
| process startup | 0.002 s | ~0 percent |

Guest execution — not host machinery — is the dominant CPU term, and within it
AArch64 exclusive-instruction emulation is the dominant gateway exit. Plane A:
W2 14.28x Docker (3.570 s vs 0.250 s), W1 9.76x ceiling-truncated. One-thread
control passes every gate including the plausibility guard; Plane C complete,
23 PIDs, zero drops.

**Selected repair (per the design's rung 1):** reduce the `Exclusive` sensitive
boundary via faithful translated exclusive regions or typed atomic lowering.
The design explicitly forbids replacing Linux atomics with a coarse lock. The
supervisor term (43.2 percent) is the next measured target and is tracked
separately.

## 2026-07-15 — Native memory-lock retirement Phase 2 (Mutex→RwLock) measured

Retired the process-wide `Arc<parking_lot::Mutex<NativeMappedMemory>>` big lock
to a read-mostly `RwLock` (design/plan under `docs/superpowers/{specs,plans}/
2026-07-14-native-memory-lock-*`). The read-mostly hot syscall/trap path now
runs concurrently; only mapping-mutating syscalls (mmap/munmap/mprotect/
madvise/brk/exec + the mlock/shm family) take the exclusive write guard.
Correctness backbone: a read guard yields `&NativeMappedMemory`, so a mutator
cannot compile under it (all metadata fields are plain, no interior-mutability
back door). Two MT hazards the refactor surfaced were fixed: concurrent
host-page lift/restore (reference-counted) and its partial-failure rollback.

Rigorous back-to-back measurement on the Go W1 reducer (go_types.test
`TestImplicitsInfo`, 1M-trap ceiling), same load, Phase-1 (Mutex) rebuilt and
measured minutes after Phase-2 (RwLock):

| metric | Phase-1 (Mutex) | Phase-2 (RwLock) | delta |
| --- | --- | --- | --- |
| psynch cvwait+cvsignal (host condvar) | 2.34M | 1.17M | **-50%** |
| untraced wall | 19.28s | 16.83s | **-12.7%** |
| untraced sys CPU | 21.83s | 17.94s | **-17.8%** |
| untraced user CPU | 43.44s | 43.10s | flat |

Correctness: full native probe gate + the atomic/futex/thread stress suite
(9 hazard-class probes 10/10 each; `exitgroupthreads` remains the pre-existing
post-fork pthread-guard gap) + `just ci` green at each phase boundary.

Residual: ~1.17M psynch remains, from reader<->writer contention — Go's
frequent `mmap` arena writers take the exclusive write guard and parking_lot's
`RwLock` blocks readers behind a queued writer. The next perf lever is sharding
the mapping-mutator write path so `mmap` does not globally exclude readers.
