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
ENODEV), `tcp_reuseport` + `udp_reuseport` (SO_REUSEPORT distribution).

### Remaining, in recommended order

1. **`tcp_try_write_error` — non-deterministic, 8 of 20 isolated runs fail.**
   Do this before anything that needs a clean measurement. It is a genuine
   Heisenbug: under `carrick trace` it passed 6 of 6 (~4.7% likely by chance at
   its base rate), so use the always-on event ring via `carrick-lldb`, NOT a
   tracer. Known: `uv_try_write` returns EAGAIN where Linux gives EPIPE/
   ECONNRESET after the peer closes; Darwin itself returns ECONNRESET after ~27
   writes and `blocking_io` really does call the host write, so the peer's host
   socket was still open. Suspect a lingering `HostFdRef` delaying the host
   close behind the guest's `close`.
2. **`tty_pty_partial` — deterministic and already reduced.** 64512 of 65536
   bytes arrive, i.e. EXACTLY 1024 lost, every run. A host-only C reducer doing
   the same 8x8192 slave writes and master reads loses nothing, so it is
   Carrick's. A round 1024 points at a fixed-size buffer or a dropped final
   partial chunk on the slave-close/EOF edge. Not yet localised.
3. **UDP error queue** (`udp_recvmsg_unreachable_error` and `...6`). The design
   is SETTLED and the feasibility measured — see "Settled design for the UDP
   error queue" in the phase-2 report. Darwin will not report an ICMP error on
   an unconnected UDP socket, but a shadow socket bound to the same local
   addr:port with SO_REUSEADDR|SO_REUSEPORT and connected to the destination
   will, without changing the wire packets or what the real socket receives.
   That was verified with a host-only program.
4. **The netns asymmetry** (`tcp_connect6_link_local` inversion,
   `udp_multicast_join6`). `carrick run` defaults to `--network host` while
   `docker run` defaults to bridge, so the two sides enumerate different
   interfaces. The bridge model is already corrected to match the oracle netns
   (verified inside the image: only `::1/128` on `lo`), but the suite cannot be
   switched to bridge until the blocker below is fixed.

### Blocker: `--network bridge` aborts

Running the libuv workload with `--network bridge` exits 134 with zero stdout:

```
objc[...]: +[NSNumber initialize] may have been in progress in another thread
when fork() was called. ... Crashing instead.
```

A trivial `--network bridge ... sh -c 'echo hello'` succeeds, so it is
workload-specific, not setup. Known fork-unsafe CoreFoundation/ObjC class.
Likely entry point is `getaddrinfo` via `to_socket_addrs` in
`crates/carrick-runtime/src/network/dns.rs`; `scutil` in `vfs/resolvconf.rs` is
a `posix_spawn` subprocess and is NOT the culprit. Attach the VM carrier with
`carrick debug lldb-run` and break on `objc_initializeAfterForkError`. This is a
crash, so it outranks a wrong answer.

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
