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

- **`ltp-mremap01`: 1,314 rows from ONE bug, already root-caused and reduced.**
  Carrick cannot GROW a mapping outside the mmap arena even with
  `MREMAP_MAYMOVE` (`dispatch/mem.rs` supports resize-down for the non-arena
  case then falls through to an unconditional ENOMEM). Reducer: mmap one page
  `MAP_SHARED|MAP_ANONYMOUS`, `mremap` it to two pages with `MREMAP_MAYMOVE` —
  carrick EINVAL, Linux ok; the same with `MAP_PRIVATE` passes on both. Linux
  is free to MOVE the mapping, which is what it does. Everything else in that
  suite (1,313 TBROK and a segfault) is cascade from this one failure.
- **CPython multiprocessing, ~946 rows, TWO distinct bugs.** `fork` and
  `forkserver` emit ZERO assertions at 5-6x Docker's wall — a hang killed at
  the budget, whose block-buffered stdout was discarded (AGENTS.md's crash
  signature; recover with `run -t` or `stdbuf -o0`). `spawn` emits 88 at
  **0.72x** — a fast crash, and the cheaper reducer. Do `spawn` first.
- **`cpython-importlib` 351**, **`cpython-concurrent_futures` 239** (also a
  fast crash at 0.62x), **`go-go_types` 574** (untriaged),
  **`ltp-splice07` + `ltp-ioctl_ficlone04` 410** (LTP `tst_fd.c` fd-type
  inventory differs, shifting every ordinal).
- **`ltp-setpriority01` 198 is an ORACLE problem**, not a carrick gap: Docker
  fails 120 of its own assertions because `setpriority` lowering needs
  `CAP_SYS_NICE`, which Docker's default cap set drops. Confirm with and
  without the capability, then grant it via `docker_flags` as fanotify and
  add_key already do. It was NOT closed by the nice/ioprio scope fix.

**Check the oracle first on any suite with a large `docker = absent` count.**
Two of the three biggest "carrick gaps" this session were oracle defects
(`node-libuv`'s `--user 65534`, `go-os`/`go-net`'s missing `-t`). Both looked
identical from the ledger: a huge absent count plus an implausible performance
ratio (145.02x and 67.02x, both of which were the oracle hanging).

### Also found, recorded rather than fixed

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
