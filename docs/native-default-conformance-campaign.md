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

## Active failure clusters

| Priority | Cluster | Authority | Current status | Target |
| ---: | --- | --- | --- | --- |
| P0 | `THREAD_WAITERS` remains locked in a fork child | live LLDB stack plus deterministic contended-fork reducer | fixed in `6d3cf627`; four signed single-suite runs complete, multi-suite load proof pending | no CPython timeout in workers=4 smoke repeats |
| P0 | Direct-exec target reservation rejects split dyld range | red/green Node-sized reducer plus signed eventfd/Node runs | fixed in `2a7d3046`; eventfd MATCH, Node reaches downstream thread guard; multi-suite load proof pending | no reservation collision in workers=4 smoke repeats |
| P1 | Post-fork exec child cannot create guest threads | red/green staged reducer plus Node/Go/CPython unsafe samples and libdispatch symbolication | signed reducer + 5/5 repeats pass without bypass; Node app/V8 and Go build/runtime/sync are MATCH through self-reexec; CPython remains | `forkexecpthread`, Node, Go, and CPython run after PID-preserving host self-reexec |
| P1 | Native self-reexec loses process state | red/green exact reducers plus canonical CPython subprocess MATCH | fixed: shebang argv, file-backed xsignal continuity, credentials/groups, umask, ignored dispositions, rlimits, and closed stdio survive host exec | keep `cpython-subprocess` MATCH under smoke load and broader workloads |
| P2 | Remaining ecosystem/LTP differences | no fresh full native run yet | unknown | classify from measured full run after P0/P1 blockers clear |

## Bless checklist

- [x] `just ci`
- [ ] signed native conformance probes
- [ ] smoke serial
- [ ] smoke workers=4, three consecutive runs
- [ ] Node full ecosystem
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

Run the full smoke tier at four workers to provide the first real concurrent
load proof for the P0 fixes and the completed native self-reexec path. Attribute
every non-MATCH row before changing code. Keep the two measured
fork-without-exec pthread cases separate for explicit native-gap review, then
repeat the smoke tier until stable before climbing full ecosystem lanes.
