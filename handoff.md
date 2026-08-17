# Carrick exact conformance closure handoff

**Updated:** 2026-08-17

**Canonical host/lane:** macOS, Apple Silicon, HVF/HVPatch, Linux arm64 guest

**Active worktree:** `/Volumes/CaseSensitive/carrick/.worktrees/conformance-first`

**Active branch:** `codex/conformance-first`

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
cd /Volumes/CaseSensitive/carrick/.worktrees/conformance-first
git status --short --branch
git log -6 --oneline
python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
```

Expected before new edits:

- branch `codex/conformance-first`;
- this handoff commit is the tip and the worktree is clean;
- `main` is `4365c1d7bc9dbcc4c320729712bd980eac472c06`;
- the campaign branch was 53 commits ahead of `main` before this handoff commit
  and has no commits on the `main` side;
- scope check reports exactly 2,127 suites.

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

Earlier reviewed root-exec transaction commits are already integrated in this
branch. Do not re-merge `codex/node-exec-stage2-lease` or
`codex/node-worker-teardown`. The latter contained superseded intermediate
signal behavior; only its reviewed final cumulative diff was squashed into
`3ef2bf7a8`.

No push or merge to `main` has been performed. Keep the campaign isolated until
the real correctness and performance goal is complete.

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
row is an invalid setup failure.

Timeout identity rotated under the eight-worker discovery run. Cleared:
`cpython-compileall`, `cpython-concurrent_futures`, and
`cpython-multiprocessing_main_handling`. Newly timed out:
`cpython-multiprocessing_fork`, `ltp-kill10`, and `ltp-shmctl05`.
`ltp-waitpid13` also moved MATCH -> INCOMPLETE. Isolate and repeat these before
attributing them; do not accept retry-recovered results.

## Durable evidence

All ignored runtime artifacts remain in this worktree. Do not rebuild before
inspecting them.

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

## Next cluster: repair and close Node libuv

The existing `2026-08-17-libuv-child-lifecycle.md` plan is stale after the
SIGCHLD fix. Do not run its old `spawn_exit_code` LLDB campaign: the prior
child-exit blocker cleared and both `spawn_exercise_sigchld_issue` and
`spawn_exit_code` pass. Of the 30 spawn positions, 28 pass; `spawn_quoted_path`
and `spawn_setuid_setgid` remain skipped, with the latter still requiring a
privilege-correct comparison. Revise the plan before implementation.

### 1. Repair the Docker oracle first

The Docker row does not reach libuv:

- `scripts/conformance/suites.toml:80` adds `--user 65534`;
- `crates/carrick-conformance/src/generate.rs:520` regenerates it;
- `docker/nodejs-conformance/nodejs-conformance:245-267` must create/copy and
  chown the fixture, then call `setgid(1000)` and `setuid(1000)`.

The raw cached oracle is chown/setgid EPERM, not Linux libuv behavior. Remove
the `--user 65534` flags from both manifest and generator and add a
generator/manifest regression test so regeneration cannot restore them. The
wrapper still drops the actual test to uid/gid 1000. No image rebuild is
needed. The OracleKey changes, so run only the corrected node-libuv Docker row
in a serialized Docker-only phase and preserve proof that TAP begins after the
drop. Do not refresh all 2,127 oracles for this change.

### 2. Classify against the repaired 507-position oracle

Current Carrick failures:

- `platform_output`: `uv_uptime()` is zero. `host_uptime_secs` silently falls
  back to zero when Darwin `KERN_BOOTTIME` fails or has the wrong shape.
- `tcp_reuseport` and `udp_reuseport`: both listeners bind, but all traffic
  lands on one listener. Existing probe coverage checks bind/readback, not
  Linux load distribution.
- `thread_priority`: high-confidence process-scope bug. `NICE_VALUE` is a
  carrier-global static even though HVPatch logical processes share the
  carrier. An earlier libuv test leaves nice at 19; a later logical process
  setting self to 4 receives EACCES.
- `tty_pty_partial`: exact 1,024-byte loss after a 65,536-byte write. The
  upstream test is labeled nondeterministic; sample corrected Docker and
  Carrick at least three times before filing a mechanism.
- `udp_multicast_interface6`: default/null IPv6 interface setup returns EINVAL.
- `udp_recvmsg_unreachable_error` v4/v6: Carrick has no Linux UDP error queue;
  MSG_ERRQUEUE is hard-coded EAGAIN and IPv6 RECVERR is not modeled.

Nine skips remain. Some are expected Windows/platform or headless-TTY skips;
`pipe_set_chmod`, multicast joins, and `spawn_setuid_setgid` are not acceptable
coverage conclusions until compared with the repaired oracle and, where
needed, given a privilege-correct sublane.

### 3. Recommended implementation order

1. Repair and refresh only the libuv oracle.
2. Add a red `nice_process_isolation` probe: logical child A sets nice 19 and
   exits; logical child B sets nice 4 and must succeed/read back 4. Move nice
   authority into Task/process state, not another global or host-PID shim.
3. Add a bounded `reuseport_distribution` probe covering TCP and UDP with many
   distinct source sockets. Require both listeners to receive traffic.
4. Prove Linux ground truth for reuseport inside Docker with bpftrace over
   setsockopt/bind/listen/accept4/recvmsg. Do not use strace.
5. Trace the red Carrick reducer with bounded `carrick trace` plus the existing
   epoll/accept events. If tracing perturbs or wedges it, use
   `carrick debug lldb-run`, the VM carrier core, event ring, and `bt all`.
6. Implement only after distinguishing Darwin host distribution from a Carrick
   epoll/waiter dispatch defect.
7. Then reduce UDP RECVERR, uptime, multicast, and PTY residuals in that order.

The cheapest high-confidence first fix is nice-state isolation. The largest
visible libuv failure fan-out is reuseport distribution (two of eight current
failures). After each fix, re-run the deterministic reducer, the exact libuv
row against the repaired oracle, focused tests, full `just ci`, then let the
coordinator run the next broad closure checkpoint.

## Other live backlog after libuv

- Isolate the three newly timed-out rows and `ltp-waitpid13` three times on the
  frozen artifact before attributing a regression.
- The 14 probe failures are listed exactly at the end of
  `docs/conformance-closure-ledger.md`. They include `ioctlcluster`, `mqueue`,
  `oomscoreadj`, GNU `aliassize`, GNU `childsubreaper`, GNU `coredumpfile`, GNU
  `termiosbits`, and the two dedicated bridge failures under both libcs.
- The largest remaining assertion fan-out is CPython multiprocessing/process
  isolation, followed by Go process/epoll clusters and broad LTP
  infrastructure. Use the generated ledger rather than the stale baseline.
- Valid `>=10x` rows are correctness work, but correctness parity remains the
  ordered first gate. Do not optimize elapsed ratios for incomplete rows.

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
