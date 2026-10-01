# EL1 real-workload A/B: runbook (instrument ready, not yet measured)

**Status (2026-10-01):** the instrument is built and validated. **No evidence
has been taken.** The rows quoted under "Instrument validation" come from a
shared, busy host, one sample per arm, and are there only to show what each
instrument prints. Do not cite them.

## The question

Where do real workloads spend their overhead against native arm64 Docker, and
does the EL1 guest descriptor lane (`CARRICK_EL1_DESCRIPTOR_LANE`) change
that? The answer ranks the next EL1 work:

| If the overhead is mostly... | ...then the next work is |
|---|---|
| syscall-bucket exits and host syscall time, dominated by `clone`/`exit`/`futex`/`wait4` | thread lifecycle in EL1 |
| fault-bucket exits (direct EL0 aborts plus `hvc #2` ec=0x24) and fault-service CPU | the mmap reservation switch-on |
| `read`/`write`/`pipe2`/`ppoll`/`epoll_pwait` in the forwarded histogram | pipe/poll in EL1 |
| guest share high, exits low, overhead still high | not exits: faults inside EL1, table work, scheduling (`sched` share) |

## What each piece is

- **Runner:** [`scripts/perf/el1_workload_ab.py`](../../../scripts/perf/el1_workload_ab.py)
  (tests: `scripts/perf/test_el1_workload_ab.py`). It reuses
  `native_go_build.py` (go-build workload, preflight, foreign census, cleanup),
  `native_go_build_abba.py` (codesign, LC_UUID, entitlement, `__dof_carrick`),
  `embed_go_build_abba.py` (CDHash) and `paired_stats.py` (estimators).
- **Workloads (defaults):**
  - `go-build`: native_go_build.py's cold-`GOCACHE` hello-world build, the same
    guest script, with an in-guest `WORKLOAD_NS` window.
  - `cpython-threading`: the `cpython-threading` suite from
    `scripts/conformance/suites.toml` (`python3 -m test test_threading`, 208 tests).
  - `node-core-worker-message-port`: Node's own `tools/test.py` over
    `parallel/test-worker-message-port*` (26 tests), declared in
    [`scripts/perf/manifests/el1-real-workloads-v1.toml`](../../../scripts/perf/manifests/el1-real-workloads-v1.toml).
    The suites.toml Node rows (`app-smoke`, `v8-smoke`, `npm-smoke`) all finish
    in under a second and measure little beyond startup.
  Any other suites.toml name can be passed with `--workload` (repeatable).
  Suite workloads are launched with the conformance harness's own argv rules;
  `plan --check-harness` proves it.
- **Arms:** A = `lane-off` (`CARRICK_EL1_DESCRIPTOR_LANE=0`), B = `lane-on`
  (the binary default). Each arm scrubs the other's keys, and any ambient
  `CARRICK_*` variable is refused. Override with `--arm label[:KEY=VAL,...]`,
  exactly twice.
- **Attribution profiles** (`carrick trace`, Rust-registered, hashed D programs):
  - `hvpatch-exit-attribution`
    ([`scripts/dtrace/hvpatch-exit-attribution.d`](../../../scripts/dtrace/hvpatch-exit-attribution.d)):
    host exits by `HostExitClass` and by bucket (syscall, fault, kick/idle,
    other; `hvc #2` exits that carry an EL0 abort are moved to fault), on-CPU
    guest time against host time on the executor threads (host time is charged
    to the exit class that caused it), and the host-forwarded syscall histogram
    by Linux number. It needs the `vcpu-run-enter`, `vcpu-run-exit` and
    `vcpu-hvc-not-svc` probes, added on this branch.
  - `hvpatch-carrier-cpu-attribution` (existing): the whole-carrier sampled
    split of guest, syscall, fault, scheduling, EL1 mailbox and lock time.

## The binary

On `main`, `CARRICK_EL1_DESCRIPTOR_LANE` does not exist, so the two arms are
control/control. The lane is on by default on `work/s3-t2`. **Measure one
artifact:** build `work/s3-t2` with this branch's commits on top, so the timed
binary and the attributed binary are the same file. Cherry-pick only the code
commits (instrument, runner, node manifest, summary helper). The `chore:` commits on this branch only re-pin `main`'s
inventories, they conflict on `work/s3-t2`'s, and they do not change the binary.
As of 2026-10-01 this applies cleanly on `work/s3-t2` (`784815bfd`):

```sh
git worktree add .worktrees/wt-el1ab-measure -b work/el1ab-measure work/s3-t2
cd .worktrees/wt-el1ab-measure
ln -s /Volumes/CaseSensitive/carrick/conformance-probes/target conformance-probes/target
git cherry-pick 702c3931a 44b5d783e b0f4ead64 b96d509e1
just build                     # signed; no guest may be alive while it relinks
strings target/release/carrick | grep -c vcpu__run__exit   # must be > 0
```

Run everything below from that worktree. Its `target/release/carrick` is the
default `--binary`. To time a plain `work/s3-t2` build instead, pass
`--binary <path> --source-repo <its worktree>` to `plan`, `carrick` and
`attribution`. The `attribution` phase then refuses every row, naming the
missing `vcpu-run-*` probe, because that build lacks them.

## Commands, in order

Use one campaign id throughout (it prefixes every `CARRICK_RUN_ID`), for
example `C=el1ab-$(date +%Y%m%d%H%M)`. Outputs go to
`target/perf/el1-workload-ab/`.

```sh
C=el1ab-$(date +%Y%m%d%H%M)
O=target/perf/el1-workload-ab

# 0. Before the quiet window (it compiles carrick-conformance): prove the argv.
python3 scripts/perf/el1_workload_ab.py plan --check-harness --campaign $C

# 1. Carrick timing phase: quiet host, Docker Desktop QUIT, no other Carrick.
#    ABBA: 1 warm-up per arm, then 6 quads (A1 B1 B2 A2), per workload.
python3 scripts/perf/el1_workload_ab.py carrick --campaign $C --quads 6 \
  --output $O/$C-carrick.json

# 2. Carrick attribution phase (instrumented, separate runs): 3 workloads x 2 arms x 2 profiles.
python3 scripts/perf/el1_workload_ab.py attribution --campaign $C \
  --output $O/$C-attribution.json

# 3. Docker phase: only after 1 and 2 have finished and every Carrick is gone.
#    Start Docker Desktop now. 1 warm-up + 5 samples per workload.
python3 scripts/perf/el1_workload_ab.py docker --campaign $C --samples 5 \
  --output $O/$C-docker.json

# 4. Join.
python3 scripts/perf/el1_workload_ab.py report \
  --carrick $O/$C-carrick.json --attribution $O/$C-attribution.json \
  --docker $O/$C-docker.json --output $O/$C-report.json
```

Every phase exits nonzero if any sample failed. Failed samples stay in the
JSON with their run id, return code and output tail.

**Guards.** The `carrick` and `attribution` phases refuse to start while a Docker
oracle container runs, even with `--allow-busy`. Each sample also refuses a busy
host (active compiler, foreign Carrick, load above the CPU count) unless
`--allow-busy` is passed, which is recorded. The `docker` phase refuses while
any Carrick process is alive. Timing evidence requires a clean harness tree.
The binary's SHA-256, CDHash, LC_UUID, entitlement digest and `__dof_carrick`
are recorded, then re-checked after each workload. A changed binary aborts the
phase.

**Cleanup.** Each sample is reaped with `scripts/sudo/kill.sh <run-id>`, and
the result is recorded in the sample's `cleanup` field. A wedged run times out
at the workload's own budget: 180 s for go-build, 300 s for the two suites.

## Expected duration

These figures are scaled from the validation runs on a shared host, so treat
them as rough. Carrick wall time per run was about 1.7 s for go-build, about
14.5 s for cpython-threading and about 2.1 s for the Node shard. The first run
of an image adds its pull.

| Phase | Runs | Expected |
|---|---|---|
| plan --check-harness | none | 1 to 5 min (first compile of carrick-conformance) |
| carrick, 6 quads | 3 x 26 = 78 | about 10 min (cpython is about 7 of that) |
| attribution | 12 traced runs | about 3 to 5 min (each profile adds 2 to 4x; aggregation output at exit) |
| docker, 5 samples | 3 x 6 = 18 | about 3 to 6 min, plus Docker Desktop startup |
| report | none | seconds |

For a finer resolution, raise `--quads`. Read the achieved resolution in
`summary.<metric>.resolution` before claiming an effect.

## How to read the output

`report` prints one row per workload and arm:

```
| workload | arm | wall ms | window ms | cpu s | wall/docker | window/docker | exits syscall/fault/kick-idle/other | host ms syscall/fault/kick-idle/other | carrier CPU % guest/syscall/fault/sched |
```

1. **Overhead:** `wall/docker` (and `window/docker` for go-build, which excludes
   container setup on both engines). This is the ratio the AGENTS.md
   two-gates rule ranks. `cpu s` is Carrick's RUSAGE_CHILDREN floor. Docker's
   client CPU is not the container's CPU, so never compare CPU across engines.
2. **Did the lane move it?** In the carrick JSON,
   `workloads.<w>.summary.<metric>` holds the B/A per-quad median ratio
   (`median_ratio_candidate_over_control`, below 1 means lane-on is faster),
   the bootstrap 95% interval, the exact sign test and the resolution. Claim
   only effects larger than `resolution.smallest_resolvable_effect_percent`.
3. **Where the overhead goes:** the attribution columns.
   - The **exit buckets** (counts are citable) say how often the guest leaves.
     `hvc #2` aborts appear under fault, and the raw per-class census is kept
     in `summary.by_class` / `hvc_not_svc`.
   - **Host ms by bucket** is the on-CPU host time charged to each exit kind
     on executor threads. It is inflated by probe cost, so compare buckets,
     not absolute numbers.
   - **Carrier CPU %** is the sampled whole-carrier split. It is the less
     perturbed of the two time views and the only one that sees non-executor
     threads.
   - `attribution.workloads.<w>.<arm>.hvpatch-exit-attribution.summary.forwarded`
     ranks host-forwarded syscalls by count, with wall time (including
     blocking) and on-CPU service time per number.
4. Apply the table under "The question".

Attribution rows come from instrumented runs. Never quote their wall or CPU
time as a timing result. Timing comes only from the `carrick` phase.

## Instrument validation (2026-10-01, NOT evidence)

This was run on a shared host with other workers' guests alive (`--validation`
implies `--allow-busy`), one sample per arm. The binary was built from
`702c3931a` on top of `main` (`910503a5a`); the Rust tree is unchanged through
`b0f4ead64`, the recorded harness HEAD. SHA-256 `342a567b...`, CDHash
`8f26e401...`. On `main` the lane variable has no effect, so both arms are the
same configuration, which is what the near-identical rows show.

- **Timing, campaign `el1ab-val2`** (run ids
  `el1ab-val2-t-<workload>-validation-{a,b}`): all 6 samples ok, and every
  scoped reap left 0 processes. go-build: 1665/1620 ms wall, 3.07/3.12 s CPU,
  1588/1552 ms window. cpython-threading: 14590/14397 ms. Node shard:
  2110/2111 ms.
- **Attribution, campaign `el1ab-val2`** (run ids
  `el1ab-val2-a-<workload>-<arm>-{exit,carrier-cpu}-attribution`): all 12
  captures were accepted by their strict readers.

| workload | arm | exits syscall/fault/kick-idle/other | host ms by bucket | carrier CPU % guest/syscall/fault/sched |
|---|---|---|---|---|
| go-build | lane-off | 60073/10497/14940/6918 | 676/113/88/96 | 65/17/3/11 |
| go-build | lane-on | 60402/10409/15033/7327 | 690/111/88/102 | 64/18/3/11 |
| cpython-threading | lane-off | 51881/39150/6735/25373 | 1130/450/102/638 | 48/23/15/13 |
| cpython-threading | lane-on | 51399/39041/6741/25210 | 1080/452/96/633 | 48/21/17/13 |
| node shard | lane-off | 176906/48281/23136/19887 | 1305/588/208/274 | 43/20/13/20 |
| node shard | lane-on | 176649/46517/18894/20391 | 1304/576/161/268 | 40/21/12/19 |

  Top forwarded syscalls: go-build `fcntl` 12062, `rt_sigaction` 11115, `read`
  5893. cpython `newfstatat` 6862, `fstat` 5645. Node `clock_gettime` 50122,
  `epoll_pwait` 28166.
- **Zero-event probes fail closed** (run id `el1ab-val2-zero`): the same D
  program was run with `--require-script-exit` on a `main` binary built before
  the probes. It printed `saw_enter=0|saw_exit=0|status=error`, and
  `carrick trace` exited 1 ("violated its required exit receipt"). The Rust
  reader refuses `saw_enter=0`, `saw_exit=0` and `saw_service=0`, naming the
  probe, as well as zero paired exits and zero forwarded syscalls. Unit tests
  cover each of these.
- **Final branch binary** (`b96d509e1` Rust tree, SHA-256 `34a4b78e...`,
  CDHash `212c5ce5...`, after the summary-writer refactor): one
  `hvpatch-exit-attribution` capture of `go version`, run id
  `el1ab-val3-final`. It was accepted and its `--summary-jsonl` was written:
  1416 exits, 883 forwarded, buckets syscall/fault/kick-idle/other =
  885/87/242/202.
