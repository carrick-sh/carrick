# Carrick exact conformance closure handoff

**Updated:** 2026-08-17

**Canonical host/lane:** macOS, Apple Silicon, HVF/HVPatch, Linux arm64 guest

This file is the live controller for the next session. It supersedes the old
native/Tier-D handoff that previously occupied this path. Do not resume the
retired native campaign or restart the completed closure-harness work.

## Objective — preserve verbatim

On the canonical macOS/HVF arm64 HVPatch lane, first make the conformance gate
fail closed and freeze the current 2,127-suite declared surface; then achieve
100% executed assertion-level parity with native-arm64 Linux across all
applicable suites and arm64 musl/GNU conformance probes, with zero gaps,
excuses, false matches, skips, crashes, timeouts, empty results, oracle
failures, or retry-recovered acceptance. After correctness closes, bring the
Go, CPython, Node, and LTP ecosystem aggregates plus cold go-build to no more
than 2.0x native-arm64 Docker, treating every valid completing suite at or
above 10x as a correctness blocker. Permit evidence-driven rearchitecture;
require red-first deterministic reducers, Docker bpftrace ground truth,
carrick trace/DTrace or lldb/core diagnosis, isolated subagent work, serialized
authoritative Carrick/Docker measurements, exact signed-artifact provenance,
and durable phase-boundary reports. Complete only when gate integrity,
correctness, and performance all pass together on the final integrated
artifact.

The goal is still active. Do not mark it complete, bless a baseline, weaken the
denominator, add an excuse, accept a retry, or start final performance work.

## Resume here

```sh
git log -6 --oneline
python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
```

Read these next:

1. `AGENTS.md`
2. `docs/conformance-closure-ledger.md`
3. `docs/perf-results/2026-08-17-post-sigchld-closure/README.md`
4. `docs/superpowers/plans/2026-08-16-conformance-first-discovery.md`
5. `docs/superpowers/plans/2026-08-17-libuv-child-lifecycle.md`, but apply the
   plan correction in “Next cluster” below before executing it.

Use the `ltp-conformance`, `carrick-trace`, and `carrick-lldb` skills as the
case requires. Preserve the TDD red-first contract. Use isolated worktrees for
mechanism clusters; the coordinator alone integrates and runs authoritative
full measurements. Never run Carrick and Docker oracle workloads concurrently.

## Branch and commits

Current checkpoint before this handoff:

```text
96a23ca7d docs(conformance): record post-sigchld closure
abcc37282 docs(conformance): freeze post-sigchld artifact
3ef2bf7a8 fix(hvpatch): recapture child-exit signal authority
689ac91ef docs(conformance): render validated source provenance
6d6995eca docs(conformance): correct checkpoint source objects
651d77a74 test(conformance): validate provenance ancestry
```

Earlier reviewed root-exec transaction commits are already integrated. Do not
re-merge `codex/node-exec-stage2-lease` or `codex/node-worker-teardown`. The
latter contained superseded intermediate signal behavior; only its reviewed
final cumulative diff was squashed into `3ef2bf7a8`.

**The campaign now lives on `main`, not on a worktree branch.** `96a23ca7d` is
an ancestor of `main`'s HEAD, and the `.worktrees/conformance-first` worktree no
longer exists. `codex/conformance-first` still exists as a branch but is not
where work happens. Nothing has been pushed.

Commits added on 2026-08-17 after the checkpoint above (oracle repair and the
first libuv correctness cluster):

```text
3656a4692 fix(runtime): stop fabricating a link-local IPv6 on bridge uplinks
f894506e2 fix(runtime): pass IPv4 multicast membership through to the host
e479f238d fix(runtime): stamp the creator as owner of a bound AF_UNIX socket
5b2992981 fix(runtime): accept IPV6_MULTICAST_IF index 0 as Linux's clear
a6d877666 fix(runtime): report real boot time in /proc/uptime
2e4e37496 fix(runtime): scope nice and ioprio to the Linux process
60a415773 fix(conformance): stop pinning --user on the node-libuv oracle
3fc77ed7c feat(conformance): fill one suite's docker oracle by profile
```

Commits added later on 2026-08-17 (the memory/inventory cluster — these close
two of the three "next clusters" listed further down):

```text
af86c4ce4 fix(runtime): reclaim stage-1 tables when the edit is already exclusive
a6fd9e6fb refactor(runtime): drop the unreachable aperture-file mremap grow
34765e4cd fix(runtime): grow a shared file mapping on mremap
c64096131 fix(runtime): grow a shared anonymous mapping in place on mremap
c08221355 docs(conformance): narrow the alias-retirement FATAL to an orphaned extent
```

## What is complete

### Fail-closed closure surface

- Exactly 2,127 declared suites: 438 CPython, 194 Go, 3 Node, 1,492 LTP.
- Assertion-exact closure parsing for LTP, Go, CPython, TAP, and shell rows.
- No baseline or known-gap consultation in closure mode.
- Exact inventory enforcement and separate semantic, infrastructure,
  unexercised, and valid-pathology ledgers.
- Exactly 429 probe sources: 409 generic and 20 dedicated.
- Exactly 858 required probe rows: every source under arm64 musl and GNU.
- Missing binaries, missing oracles, skipped/report-only rows, duplicate rows,
  and partial inventories fail closed.
- Frozen source, binary, manifest, live image, result, and probe provenance.

### Root exec stage-2 transaction

The original Node pre-entrypoint crash is fixed and reviewed. Root pid 1 no
longer enters persistent exec with identity mappings and an empty lease map.
Root/child exec planning now shares the same sparse/RO/aperture transforms,
uses fresh global-frame authority, prebuilds replacement backing, switches
stage 2 reversibly, defers predecessor retirement/publication, verifies exact
rollback authority, and gates Kernel inventory publication after backend
success. Failure-after-0/1, repeated root exec, root exec with a live child,
generation, sparse, and rollback tests are present.

### Post-exec child-exit signal authority

The Node app/V8 wrapper timeout is fixed and reviewed. The root cause was a
runtime endpoint retaining a pre-exec `KernelContext`/Sighand. The final design
retains a generation-safe `KernelTaskBinding` and captures an immutable current
Sighand plus exact live-thread roster under the registry read lock. It handles
retired leaders, rejects PID reuse, avoids mixed exec generations, and keeps
default-ignored SIGCHLD from incorrectly waking `rt_sigsuspend`.

The focused reducer passed three times with both Worker markers and zero
leftovers. Post-integration focused and full closure runs make
`node-app-smoke` and `node-v8-smoke` exact TAP MATCH.

## Current authoritative signed checkpoint

> **A NEWER closure run is in flight on the memory/inventory artifact below.**
> Do not quote the post-libuv numbers as current once it lands; they predate
> `ltp-mremap01`/`04` closing and the `cpython-multiprocessing_spawn` crash fix,
> which together move well over a thousand assertion rows.
>
> ```text
> HEAD                    af86c4ce4143a76d0804ec98bf68a243fd72e667
> binary sha256           195e11b8759a3514aa69033a72992a0dc4adea362064596a91e3c0e1ad8a9dab
> CDHash                  1a5a5840f243cd288638e564eb1dc6580a3d317c
> hypervisor entitlement  present
> __TEXT,__dof_carrick    present
> ```
>
> Built from a clean tree at that exact HEAD with nothing newer than the binary.

> **SUPERSEDED 2026-08-17.** A full closure run has been taken on the
> post-libuv artifact — see
> `docs/perf-results/2026-08-17-closure-post-libuv/README.md`. Current numbers:
> **1,201 MATCH / 926 INCOMPLETE, semantic gaps 2,947 (was 4,761), unexercised
> 5,598 (was 7,775)**, on binary
> `5ab52d7b893f56fa8caf8abf784b39d7d33fdca4a624802a1420f5489107eb34`. Every
> count in the section below, and in `docs/conformance-closure-ledger.md`,
> predates the `node-libuv` and `go-os`/`go-net` oracle repairs and must not be
> quoted. The ledger itself has NOT been regenerated (that needs a probe-phase
> log as well).

## Superseded checkpoint (pre-libuv-repair)

The post-SIGCHLD checkpoint is review-approved. The full Carrick phase ran all
2,127 rows before the 84 Docker cache-miss rows. The strict probe phase emitted
all 858 rows. No retries, waivers, or baseline blessing were used.

Artifact:

- binary source: `3ef2bf7a8f04dd31ffba54ae4a036ced96e149e2`
- frozen-scope commit: `abcc37282`
- checkpoint/report commit: `96a23ca7d`
- signed SHA-256:
  `f559bfac450706ea7cac7e0054ed5982e603187dddbb9e6890805f87d88fa95c`
- CDHash: `72d8a02c66e89dc4b7333978e2dff083a74b2da4`
- LC_UUID: `196E6ADB-5BC6-3B46-BFF9-DD78FFD1BDAC`
- hypervisor entitlement: present/true
- `__TEXT,__dof_carrick`: present
- manifest SHA-256:
  `36042b91814ca767d61a6615c0023aa07773b7f5649fc65038fae6c34367d282`

Frozen image digests:

- Go: `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
- Node: `sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718`
- CPython: `sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30`
- LTP: `sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`

Current counts:

- suites: 1,199 MATCH / 928 INCOMPLETE;
- semantic assertion gaps: 4,761;
- unexercised assertion rows: 7,775;
- infrastructure-affected suites: 605;
- blocked timeouts: 6;
- probes: 844 PASS / 14 semantic FAIL, zero missing/infrastructure/unexercised;
- valid completing `>=10x` pathologies: 6.

Delta from the post-root-exec checkpoint:

- semantic gaps: 7,006 -> 4,761;
- unexercised: 10,037 -> 7,775;
- suite headline: 1,198 -> 1,199 MATCH;
- app/V8: both exact MATCH;
- `cpython-asyncio`: 64 observed passes -> 2,521 passes, but 18 skips still
  make it incomplete;
- `node-libuv`: 180-second timeout at assertion 332 -> all 507 TAP positions
  emitted in 58.299 seconds: 490 pass, 8 fail, 9 skip;
- probe counts unchanged, but `childsubreaper` rotated from musl FAIL/GNU PASS
  to musl PASS/GNU FAIL.

The six valid `>=10x` rows are:

- `cpython-multiprocessing_main_handling` 11.01x
- `go-crypto` 32.39x
- `go-crypto_internal_fips140deps` 15.45x
- `go-go_build` 32.28x
- `go-go_doc_comment` 24.05x
- `ltp-timerfd_settime02` 32.50x

Do not treat the libuv 145.02x ratio as performance evidence: its cached Docker
row was an invalid setup failure. That row has since been REPAIRED (see
`docs/perf-results/2026-08-17-libuv-oracle-repair/`); the docker side now runs
in 45.5 s and carrick in ~58 s, so the real ratio is near 1.3x. The counts in
this section, and in `docs/conformance-closure-ledger.md`, still describe the
PRE-repair state: 507 libuv positions were ledgered `docker = absent`
(unexercised) and are now real comparisons. Re-run the closure gate before
quoting any of these numbers again.

Timeout identity rotated under the eight-worker discovery run. Cleared:
`cpython-compileall`, `cpython-concurrent_futures`, and
`cpython-multiprocessing_main_handling`. Newly timed out:
`cpython-multiprocessing_fork`, `ltp-kill10`, and `ltp-shmctl05`.
`ltp-waitpid13` also moved MATCH -> INCOMPLETE. Isolate and repeat these before
attributing them; do not accept retry-recovered results.

## Durable evidence

**The artifacts listed below are GONE.** They lived in `target/` inside the
`.worktrees/conformance-first` worktree, which no longer exists; only the
committed docs survived. The hashes are kept as a record of what the checkpoint
claimed, not as something you can inspect. Do not plan work that depends on
re-reading them — re-measure instead.

Evidence produced from 2026-08-17 onward is committed under
`docs/perf-results/` rather than left in `target/`, precisely because of this.

```text
target/conformance/closure-after-sigchld/results.jsonl
target/conformance/closure-after-sigchld/suites.log
target/conformance/closure-after-sigchld/probes.log
target/conformance/closure-after-sigchld/probes-build.log
target/conformance/closure-after-sigchld/probes-generic.log
target/conformance/closure-after-sigchld/probes-dedicated.log
target/conformance/closure-after-sigchld/just-ci.log
target/conformance/raw/conf-23205-c1686.{out,err}  # node app
target/conformance/raw/conf-23205-c1687.{out,err}  # node v8
target/conformance/raw/conf-23205-c1688.{out,err}  # node libuv
```

Hashes:

- results JSONL:
  `023879245685a900891eebf6bf9ce7a2b78b3c145d93bf7b0dbb95da1763f499`
- suite log:
  `f1aa80aa7c0569a6dc94fd84087d5138e445be886cd5a16a91e5799e7a0accd1`
- aggregate probe log:
  `743ed399a669bb5bf42662e3741b0cc3627f8367133aea4106003cc6fdb162cc`
- CI log:
  `a998c51854849da30d91e4dd0703d2186e045415862da78cac5ba5d5d4de8102`

`RUST_TEST_THREADS=1 just ci` exited 0 on binary source `3ef2bf7a8`.
Strict probe builds produced 430 selected binaries for each libc. Suite closure
exited 1 because 928 rows remain explicitly incomplete; generic and dedicated
probe commands exited nonzero because 14 real semantic gaps remain. Scoped
Carrick cleanup and `conf-*` Docker cleanup were zero. The binary hash remained
unchanged through every gate.

## Next cluster: finish Node libuv

Step 1 (repair the Docker oracle) is DONE, and eight of the twelve divergences
are closed. Full evidence, provenance, per-row root causes and the measured
Darwin capability table are in
`docs/perf-results/2026-08-17-libuv-oracle-repair/README.md` (oracle repair) and
`phase-2-libuv-correctness.md` (the Carrick side). Do not redo them.

The oracle emits 507 positions (499 pass / 0 fail / 8 skip) and its raw TAP is
committed at
`docs/perf-results/2026-08-17-libuv-oracle-repair/docker-oracle-libuv.tap`, so
the Carrick side can be diffed WITHOUT re-running Docker. Run Carrick with the
argv from `--dry-run` on the suite and diff position-by-position.

Closed, each proven red-first: `platform_output` (uptime), `thread_priority`
(nice scope), `eintr_handling` (spurious EINTR), `pipe_set_chmod` (AF_UNIX
owner), `udp_multicast_interface6` (ifindex 0), `udp_multicast_join` (blanket
ENODEV), `tcp_reuseport` + `udp_reuseport` (SO_REUSEPORT distribution),
`tty_pty_partial` (Darwin destroys queued pty data at slave close), and
`udp_recvmsg_unreachable_error` + its v6 twin (no `IP_RECVERR`, no error
queue).

**libuv is at 2 divergent positions, down from 12.**

### Remaining, in recommended order

**libuv is at 2 divergent positions, down from 12** — 500 ok / 6 skip / 1 fail
against the oracle's 499 ok / 8 skip, on binary `ba4c0603…c564714d3`. Both
remaining rows have the SAME cause, and it is not a bug in the feature either
names.

1. **Carrick's bridge networking breaks glibc's `getaddrinfo`** — fix this
   first, because it is a crash in a shipped network mode AND it blocks the
   other two rows:

   ```
   carrick run --network bridge ... python3 -c \
     'import socket; socket.getaddrinfo("localhost", 80)'
   Fatal glibc error: getaddrinfo.c:1673 (rfc3484_sort): assertion failed:
     a1->source_addr.sin6_family == PF_INET6
   ```

   Host mode resolves fine. The same resolution path also produced a fork-time
   ObjC abort (`+[NSNumber initialize] … Crashing instead`) earlier in the
   workload. It is PRE-EXISTING — it reproduces on the network model from
   before this campaign touched it.

   Already RULED OUT by measurement, so do not repeat any of it:
   - `getsockname` after `connect` on an `AF_INET6` UDP socket returns the
     right family in both modes, for `::1` and for a v4-mapped
     `::ffff:127.0.0.1`, matching the Docker oracle exactly;
   - bridge-mode `/proc/net/if_inet6` correctly holds only `::1` on `lo`;
   - the synthetic netlink `RTM_GETADDR` reply, which really did differ and
     has since been corrected to match the oracle's shape byte for byte —
     the crash survives it.

   What still correlates: bridge mode has NO non-loopback IPv6 address while
   host mode does. Docker's netns is in the same position and does not crash.
   Every cheap differential hypothesis is now exhausted, so the next step is to
   observe the actual syscall sequence glibc makes in each mode — `carrick
   trace` on the Carrick side, bpftrace inside Docker for ground truth.

2. **The netns asymmetry** (`tcp_connect6_link_local` 370 inversion,
   `udp_multicast_join6` 472). `carrick run` defaults to `--network host` while
   `docker run` defaults to bridge, so the two sides enumerate different
   interfaces — the oracle container has only `::1/128` on `lo`, while Carrick
   in host mode truthfully surfaces the Mac's `en0` link-local, and libuv's
   skip conditions scan for `fe80::`. The bridge model is already corrected to
   match the oracle netns, so the fix is to give the suite
   `--network bridge`: that changes only `carrick_flags`, which is excluded
   from the oracle key, so the oracle stays valid. Blocked on (1).

3. **`tcp_try_write_error` — non-deterministic**, 8 of 20 isolated runs fail.
   NOT in the divergence list precisely because it usually passes, which is why
   it must be fixed before any clean final pass. Genuine Heisenbug: under
   `carrick trace` it passed 6 of 6 (~4.7% likely by chance), so use the event
   ring via `carrick-lldb`, NOT a tracer.

   **Do NOT look in the socket layer.** The `-11` the test reports is
   libuv-INTERNAL, not a syscall result: `uv_try_write2` returns `UV_EAGAIN`
   with no syscall at all when `stream->connect_req != NULL ||
   stream->write_queue_size != 0` (`src/unix/stream.c:1436`). The client never
   queues a write, so the failing condition is `connect_req != NULL` — the
   client's `connect_cb` had not run when the server's `incoming_close_cb`
   did. It is a LOOP-ORDERING divergence, not a write bug.

   Ruled out by measurement against the Docker oracle, so do not redo it:
   - guest `send` and `writev` on a socket whose peer closed both return
     EPIPE/ECONNRESET, never EAGAIN — 120 tight-race iterations, zero EAGAIN,
     the same distribution Docker produces;
   - the host itself returns ECONNRESET after ~27 four-byte writes.

   The remaining suspect is readiness ORDERING: libuv runs its io callbacks
   before its closing-handle phase, so a batch containing BOTH the listener's
   EPOLLIN and the client's EPOLLOUT passes, while a batch with only the
   listener fails. A 30-trial probe put Carrick at 29/30 both-in-one-batch
   against Docker's 30/30 — the right shape but far short of the observed ~40%
   failure rate, so the probe is not yet reproducing the real condition.
   Instrument the actual failing run.

### Next clusters, from the fresh closure run

Measured, not inferred — see `docs/perf-results/2026-08-17-closure-post-libuv/`.

- **`ltp-mremap01`: 1,314 rows — FIXED (`c64096131`, `34765e4cd`).** Now
  `TPASS`, rc=0, matching the oracle; `ltp-mremap04` also went failing -> TPASS
  and `ltp-mremap05` 2/6 -> 3 passing (the rest is unimplemented
  `MREMAP_FIXED`). `mremap` refused to grow ANY `MAP_SHARED` mapping; it now
  grows shared-anonymous in place via `SharedAperture::grow`, and re-establishes
  a live shared-FILE alias over the same descriptor at the new length (a byte
  copy would silently unshare it).

  Read `docs/perf-results/2026-08-17-closure-post-libuv/reducers/README.md`
  before touching this area — the original entry here was WRONG about the shape
  in a way that cost several rounds. `mremap01` is not the shared-anonymous case
  at all, and its file is not the 1 byte its `write` calls suggest: LTP builds
  it SPARSELY with lseek+write, so the mapping is a live alias entirely inside
  an 8 MiB file. What settled it was extending the gated `CARRICK_FAULT_DEBUG`
  hatch with an `mremap GROW` line, not another reducer.
- **CPython multiprocessing + concurrent_futures, ~1,200 rows, TWO NAMED
  CRASHES.** Both were read straight out of the closure run's `.err` files —
  no new instrumentation needed, and neither is a "carrick is slow" problem:

  -1. **UPDATE 2026-08-18 (later): the ENTIRE multiprocessing crash family is
     FIXED** (`1e970696e` — maintenance writes now authenticate an exclusive
     frame claim; full root-cause narrative and every wrong turn in
     `docs/perf-results/2026-08-17-closure-post-libuv/reducers/README.md`).
     Measured on the signed binary: `test_multiprocessing_spawn` SUCCESS 4/4,
     `test_multiprocessing_forkserver` SUCCESS 4/4 (from ZERO assertions),
     `test_concurrent_futures` SUCCESS 8/8, fork's `test_misc` SUCCESS and
     `test_processes` completing with ONE isolated deterministic error left:
     `WithProcessesTestPicklingConnections.test_pickling` (recv EOF standalone
     under carrick, OK under Docker — an fd-passing/pickled-connection gap,
     nothing to do with memory; the next reducer target).
     `cpython-importlib` did NOT move — its deep-run SIGSEGV is a different
     bug. Every entry below this point is historical.
  0. **UPDATE 2026-08-18: the fork/forkserver HANG is gone** (post-`10c62b8cb`
     the suite completes test files) and the remainder is reduced to a 2.5 s
     deterministic two-test reducer for a CHILD SIGSEGV — see
     `docs/perf-results/2026-08-17-closure-post-libuv/reducers/README.md`
     ("multiprocessing fork/forkserver SIGSEGV"), which also records the exact
     fault signature, the PYTHONFAULTHANDLER technique, and three dead ends
     already paid for. `test_manager` at 3m32s is a separate, unmeasured item.
     The entry below is the pre-fix state, kept for history.
  1. **`cpython-multiprocessing_fork` and `cpython-concurrent_futures`**:
     ```
     carrick: trap engine failed: hypervisor operation failed:
       map hvpatch child VA 0x2d00020000 to global/root-slot IPA
       0x9a00000000: OutOfTables
     ```
     Stage-2 page-table SPARE-POOL exhaustion in the child-mapping path
     (`crates/carrick-vmm-hvf/src/trap.rs:11255` ->
     `crates/carrick-mem/src/page_table.rs`). The mechanism is already
     documented in-tree at `page_table.rs:959-963`, which names this exact
     workload: the pool is **440 entries** and "a churning guest (CPython
     multiprocessing maps+unmaps 400+ SemLock/Pool shm files) hits
     OutOfTables". That comment covers freeing the per-2-MiB L3 table for
     `mmap(MAP_SHARED, fd)` aliases; the HVPatch per-child VA mapping is a
     second consumer of the same pool and appears not to be returning its
     tables. Start by instrumenting `spare_tables_available()` /
     `free_table` (`page_table.rs:317`, `:427`) across a fork storm and see
     whether the pool actually drains or merely leaks.
     `cpython-multiprocessing_fork` gets 78 of 317 assertions out before it
     dies.

  2. **`cpython-multiprocessing_spawn` — FIXED (`af86c4ce4`).** It now runs all
     397 tests with 3 of its 4 test files passing (was 88 assertions then a
     crash), and only `test_misc` fails.

     The FATAL and the `OutOfTables` above turned out to be the SAME cluster,
     stacked. The abort was the outer symptom: a failed stage-1 install ran the
     RETIREMENT path over an extent that had been staged but never published.
     Underneath it was the pool leak — and the reason reclaim never ran is a
     POPULATION mismatch, not a missing free: the engine gated reclaim on
     `Arc::strong_count(&page_tables) > 1` (live engine HANDLES) while the
     runtime decides exclusivity from `has_peer_guest_executor()` (threads that
     can run guest code). `carrick_hal::stage1_exclusive` now publishes the
     runtime's answer instead. Note the guess recorded in item 1 above — "the
     HVPatch per-child VA mapping is a second consumer of the same pool" — was
     NOT the cause; the ordinary `mmap(MAP_SHARED, fd)` alias path was leaking
     because its reclaim was disabled.

     Reducer: `reducers/alias-churn-fatal.py` (deterministic in ~5 s) plus
     `reducers/alias-churn-variants.py` for the size/sharing/inode variants that
     refuted the obvious hypotheses.

  3. **`cpython-multiprocessing_forkserver`** emits ZERO assertions with an
     EMPTY stderr — a third shape. Recover its transcript with `run -t` or
     `stdbuf -o0` before assuming it shares either cause.

  These are CRASHES, so they outrank wrong answers, and one of them has a
  ready-made in-tree hypothesis. They are also the reason the cluster looks
  like a huge `docker = absent` count.
- **`cpython-importlib` 351** and **`cpython-concurrent_futures` 239** both got
  much DEEPER after `af86c4ce4` and changed shape, so re-triage rather than
  trusting the descriptions above. Re-measured on that artifact:
  `test_concurrent_futures` now runs hundreds of tests and HANGS at
  `test_gh105829_should_not_deadlock_if_wakeup_pipe_full` (leaving a `core`
  behind from a child that died during `test_process_pool`), and
  `test_importlib` now reaches
  `test_locks.Source_DeadlockAvoidanceTests.test_deadlock` and takes a GUEST
  SIGSEGV there. That class passes 3/3 in isolation, so the crash needs the full
  run's context — go at it with a core and `carrick-lldb` on the CARRIER, not
  with another reducer.
  **`go-go_types`** closed itself (574 unexercised -> 0, `success 571/571`) once
  the stage-1 pool stopped exhausting; confirm rather than assume.
  **`ltp-splice07` + `ltp-ioctl_ficlone04` ~209 rows** — the cause is NOT a
  missing syscall. `AssertionCollector::push`
  (`crates/carrick-conformance/src/parsers/mod.rs`) keys every LTP assertion by
  POSITIONAL occurrence (`file.c:line#N`), so one extra or missing fd type in
  carrick's `tst_fd` inventory shifts every later ordinal and compares
  unrelated rows against each other (`accept03.c:46` #13-#15 line fanotify up
  against inotify). That both inflates the count and MASKS genuine per-fd-type
  divergences. Every LTP line already carries the fd type verbatim
  (`splice07.c:56: TPASS: splice() on file -> unix socket : EINVAL (22)`), so
  the fix is to key on that text. Do NOT "fix" it by implementing
  `memfd_secret`: a verifier ran the analyst's own model forward and it makes
  the cluster WORSE (96 -> 120), because divergence scales with the
  inventory-size delta.

  **Cost that is not obvious and must be planned for: this needs a full oracle
  re-bless.** `scripts/conformance/oracle-cache.jsonl` stores per-assertion
  `ids`, and the cache KEY does not include the id scheme. Changing the scheme
  would leave every cached LTP oracle holding old-style ids while fresh carrick
  runs emit new-style ones — every row Absent on one side, a false-divergence
  storm rather than a clean miss. So the change must add an id-scheme
  determinant to `OracleKey` (the `docker_platform` precedent in AGENTS.md) so
  the whole cache invalidates and refills in one deliberate `--refresh-oracle`
  pass. Give it its own cycle; do not fold it into another change.

  **`ltp-splice07` + `ltp-ioctl_ficlone04` 410** (LTP `tst_fd.c` fd-type
  inventory differs, shifting every ordinal).
- **`ltp-setpriority01`: CLOSED.** 3 TPASS / 0 TFAIL, rc=0, matching the
  repaired oracle; setpriority02, getpriority01/02 and nice01-04 all still
  green (nice05's 2-row gap is pre-existing and unrelated). Three stacked
  fixes: `resolve_prio_process_target`'s stale ESRCH refusals (nice is
  per-`Task` since `2e4e37496`, so a peer's nice IS serviceable through the
  kernel graph), `getpriority` reading the CALLER's nice for a peer target,
  and — the part the first fix attempt missed — PRIO_PGRP/PRIO_USER no-opping
  entirely. LTP sweeps all three classes; the TFAIL storm after the
  PRIO_PROCESS TPASS was the group/user sweeps. Selection is per POSIX
  (effective uid), `who == 0` denotes the caller's REAL uid per the man page;
  both class reads return the members' minimum nice.

  The original entry below is retained for its oracle-repair history:
  oracle FIXED, 198 rows -> 3. The oracle was failing 120 of its own assertions because
  raising priority needs `CAP_SYS_NICE`, which Docker's default cap set drops;
  granted via `docker_flags` (exact name — `setpriority02` tests the
  rejections and must NOT have it), the oracle now passes 3.

  What remains is a REAL carrick gap, reduced to one line:
  **`setpriority`/`getpriority` with `PRIO_PROCESS` and a live CHILD's pid
  returns ESRCH**, where Linux succeeds. It is specific to that path — in the
  same guest, for the same child pid, `kill(pid, 0)` succeeds,
  `sched_getscheduler(pid)` succeeds, and `/proc/<pid>` exists. So the pid is
  resolvable; only `resolve_prio_process_target` ->
  `SyscallDispatcher::guest_process_target` -> `Kernel::live_task_process_euid`
  fails to find it. Note the doc comment on `PrioTarget::Other` says an
  unpublished peer should read as root, while the code does
  `.and_then(|t| t.euid())` and turns `None` into `NotFound` — worth checking
  first. Reducer: fork a child that blocks on a pipe, then
  `setpriority(PRIO_PROCESS, child, 5)` from the parent.

**Check the oracle first on any suite with a large `docker = absent` count.**
Two of the three biggest "carrick gaps" this session were oracle defects
(`node-libuv`'s `--user 65534`, `go-os`/`go-net`'s missing `-t`). Both looked
identical from the ledger: a huge absent count plus an implausible performance
ratio (145.02x and 67.02x, both of which were the oracle hanging).

### Also found, recorded rather than fixed

- **A `MAP_SHARED` file mapping that runs PAST its file's EOF silently loses
  writes.** Such a mapping becomes an arena snapshot under carrick and is never
  written back: store to offset 0, `munmap`, re-read — Docker gives the stored
  byte, carrick gives the original. This is silent data loss, it is independent
  of `mremap`, and no current row covers it. Reducer:
  `docs/perf-results/2026-08-17-closure-post-libuv/reducers/mremap-eof-shape.c`
  with `NOREMAP=1`, about a second.
- **`mremap` gaps left deliberately, both stated in comments rather than
  hidden:** a grow WITHOUT `MREMAP_MAYMOVE` still reports ENOMEM (matching a
  measurement of real Linux 6.12 for both shared shapes, but Linux would
  succeed where the space above is free), and if the runtime's host mmap fails
  after a shared-file re-alias has already reclaimed the source, the guest loses
  the source mapping where Linux would keep it.
- `fchmod` on a bound AF_UNIX socket fd resolves no path and silently returns
  0, so a mode set through the fd alone is lost. No current row covers it.
- `dispatch/time.rs`'s `RLIMIT_CPU_GENERATION` is a carrier-global static
  gating a per-process limit, so one guest process's `setrlimit(RLIMIT_CPU)`
  can cancel another's enforcement. Same class as the `nice`/`ioprio` statics
  fixed this session. Not measured by any current row.
- Socket calls are absent from the `SA_RESTART` restartable set on purpose:
  they DO restart on Linux, but only without `SO_RCVTIMEO`/`SO_SNDTIMEO`, and
  the decision point sees only the syscall number, not the fd. Plumb the
  timeout before adding them.
- The previous checkpoint's durable evidence is GONE: it lived in `target/`
  inside the `.worktrees/conformance-first` worktree, which no longer exists.
  The campaign commits are on `main` (`96a23ca7d` is an ancestor of HEAD) and
  the committed docs survived, but every raw artifact the old handoff cited is
  unrecoverable. Evidence that matters is now committed under
  `docs/perf-results/`.

## Measurement discipline

- Always build guest-running Carrick with `just build`; a plain Cargo build is
  unsigned and produces `HV_DENIED`. After runtime changes, relink
  `carrick-cli` and sign before a guest run.
- A signed result belongs to one exact artifact. Record source HEAD, binary
  SHA-256, CDHash, LC_UUID, entitlement, and `__dof_carrick` before claiming a
  checkpoint.
- `just build` relinks/resigns and changes the binary hash even with identical
  source. For an authoritative checkpoint, build once, freeze, then invoke the
  harness/probes directly without another `just build`.
- Run every Carrick suite arm before Docker. Carrick-vs-Carrick and
  Docker-vs-Docker parallelism are allowed; Carrick-vs-Docker concurrency is
  not.
- Stamp `CARRICK_RUN_ID` and clean only through
  `scripts/sudo/kill.sh <run-id>`. Never `pkill -f carrick`.
- Use `grep -a`/`rg -a` on raw outputs because they may contain binary bytes.
- Docker syscall ground truth is bpftrace inside native-arm64 Docker. Never use
  guest strace as oracle evidence.
- For hangs, take a carrier-aware modified-memory core with
  `carrick debug lldb-run`; for reproducible live flow, use bounded
  `carrick trace`/DTrace with `progenyof`, nonzero-event, and drop checks.
- Preserve D scripts and phase receipts under `scripts/dtrace/` and
  `docs/perf-results/`.
- Do not infer broad completion from CI, a focused MATCH, or a probe count.
- Final completion requires two exhaustive clean correctness passes on the
  final integrated signed artifact, then controlled paired <=2x measurements
  with every valid >=10x row already eliminated.

## Do not redo

- Do not rebuild the closure harness or broaden it into a certification
  framework; it already fails closed and has been exhaustively exercised.
- Do not revisit the root-exec identity-lease diagnosis or the superseded
  default-SIGCHLD workaround.
- Do not investigate Node Worker teardown: the carrier core proved Worker
  teardown completed; stale post-exec signal authority was the blocker.
- Do not run libuv `spawn_exit_code` as the next reducer; it now passes.
- Do not treat cached node-libuv Docker output as an oracle.
- Do not quote timeout-duration or invalid-oracle ratios as performance.
- Do not merge to `main`, push, bless, or switch to performance until the full
  goal is actually satisfied.
