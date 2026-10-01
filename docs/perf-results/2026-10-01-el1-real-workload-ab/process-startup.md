# What does a process cost to start under Carrick?

**Status (2026-10-01):** diagnosis only, Carrick side, on main 1c7406a7f
(binary f5e93503, lane off). The host was shared throughout (load average
12–30 on 10 CPUs). Counts are citable. Times under the DTrace profiles are
inflated (instrumented runs are about 3–4× slower than untraced), so use
them as shares, not durations. Untraced latencies suggest. The Docker side
is not run; commands are in [Docker side](#docker-side-to-be-run-by-the-director).

## Answer in one paragraph

Starting a process costs Carrick 8–20× what it costs Linux. This is not one
slow step; three structural costs each scale with work Linux does in
microseconds.

1. **Process creation itself.** `fork` arms copy-on-write for the whole
   parent address space by walking its page tables, and the child then
   COW-faults through the frame-inventory machinery until it reaches
   `execve`. `execve` then rebuilds a stage-1 page-table manager and an exec
   plan for the new image, and exit tears all of it down. A bare
   fork+exec+wait of `/bin/true` from bash takes 8.5 ms untraced, and
   12.9–15.8 ms from python, whose larger address space makes the fork
   costlier. That is about 60% of `/bin/true`'s carrier CPU.
2. **Every address-space mutation the dynamic loader and runtime make.**
   Node does about 220 `mmap`/`munmap`/`mprotect`/`madvise`/`brk` per start.
   Each is forwarded to the host, and each mutating one usually also costs
   a host-driven TLB-maintenance round trip into the guest (`hvc #1`, 158
   per node start). That is about 55% of node's host-side start cost.
3. **First-touch and COW page faults:** about 550 per node start at roughly
   14 µs (instrumented) each, about 15%.

File namei matters only for python import, at about 25% of `test.py`
import's host time. Guest execution (V8 and python bytecode) runs at native
speed and is not Carrick overhead.

**At `-j10`, boot does not triple because of a lock.** Four guest vCPUs
saturate. Throughput plateaus at about 35 node starts/s from three lanes on,
so per-start latency grows with queue length. Off-CPU lock waits add about
20 ms per start at ten lanes: the exec cache, the alias-registry
retirement and frame-grant inventory locks.

## Method

- Short commands run in a loop inside the image
  ([`process-startup/loop.sh`](process-startup/loop.sh): `lanes` parallel
  loops of `N` runs). They ran under two Rust-registered profiles, plus one
  off-CPU capture:
  - `carrick trace --profile hvpatch-exit-attribution`: host exits by
    class, forwarded syscalls with counts and on-CPU time, guest and host
    on-CPU time.
  - `carrick trace --profile hvpatch-carrier-cpu-attribution`: sampled
    carrier CPU with the leaf-most classifier, including the
    `fault_service/cow`, `lifecycle/fork-clone` and `teardown` buckets.
  - An off-CPU capture (`sched:::off-cpu` → `on-cpu` with user stacks on
    the carrier) for the ten-lane case.
- Per-process figures subtract a no-op baseline (`loop.sh 1 0`:
  `ps-exit-noop`) and divide by `N`. The loop's own bash fork is part of
  every process start, as it is for `test.py`'s spawns.
- Untraced latencies: [`startup.sh`](process-startup/startup.sh) (1, 4 and
  10 lanes) and [`scale.sh`](process-startup/scale.sh) (1–10 lanes, node
  only).
- Run ids, all reaped with `scripts/sudo/kill.sh`:
  - `ps-lat-1`, `ps-scale-1`, `ps-rusage-1` (untraced latency).
  - `ps-exit-{noop,true1,py1,node1,testpy,node10}` (exit attribution).
  - `ps-cpu-{true1,py1,node1,node10}` (carrier CPU).
  - `ps-off-node10` (off-CPU).
  - `ps-pyc-1`, `ps-tools-1` (pyc cache and image tool checks).
- Summaries are in [`process-startup/captures/`](process-startup/captures/).

## Untraced latency (`ps-lat-1`, load ~22, and `ps-scale-1`, load ~12)

| command | 1 lane | 4 lanes | 10 lanes |
|---|---|---|---|
| `/bin/true` (bash fork+exec+wait) | 8.5 ms | 9.1 ms | 25.9 ms |
| `python3 -c pass` | 18.4 ms | 31.4 ms | 83.4 ms |
| `node24 -e 0` | 41 ms (66 at load 12 in `ps-scale-1`) | 67–112 ms | 203 ms (load 12) to 550 ms (load 22) |
| `python3 tools/test.py --help` (import) | 110–180 ms | | |
| `carrick run … sh -c 'echo hi'` (container start) | 63 ms | | |
| fork+exec+wait from python (`rusage.py`) | `/bin/true` 15.8, `python -c pass` 38.4, `node -e 0` 55.5, `test.py --help` 136.4 ms (p50) | | |

`node -e 0` throughput, `ps-scale-1`:

| lanes | node starts/s |
|---|---|
| 1 | 15 |
| 2 | 30 |
| 3 | 34 |
| 4 | 36 |
| 6 | 36 |
| 8 | 43 |
| 10 | 49 |

Latency rises linearly from three lanes on, which is queueing.

## Exec → first instruction → first JS / bytecode, per process (exit attribution, baseline subtracted)

| per process | `/bin/true` | `python3 -c pass` | `node -e 0` | `test.py --help` |
|---|---|---|---|---|
| host exits | 117 | 490 | 1340 | 1878 |
| forwarded syscalls | 37 | 334 | 571 | 1160 |
| EL0 aborts (first-touch and COW faults) | 31 | 86 | **549** | 581 |
| TLB-maintenance exits (`hvc #1`) | **42** | 63 | **158** | 129 |
| mm syscalls (`mmap`/`munmap`/`mprotect`/`madvise`/`brk`) | 13 | 51 | **220** | 139 |
| file syscalls (`openat`/`*stat*`/`close`/`getdents64`/`readlinkat`) | ≈0 | 145 | 28 | **765** |
| guest on-CPU (instrumented) | ~0 | 8.8 ms | 25.4 ms | 76.7 ms |
| host on-CPU (instrumented) | 7.8 ms | 17.9 ms | 48.9 ms | 55.5 ms |
| ↳ syscall service | 4.4 | 12.0 | 30.8 | 37.4 |
| ↳ of which mm syscalls | 0.9 | 3.7 | **17.7** | 14.2 |
| ↳ of which file syscalls | — | 2.0 | 0.7 | **13.4** |
| ↳ fault service | 0.7 | 2.6 | 7.6 | 12.8 |
| ↳ TLB maintenance | 2.4 | 3.1 | **8.9** | 5.1 |

Per-call costs (instrumented, `node -e 0`):

| call | cost each |
|---|---|
| `munmap` | 77 µs |
| `mmap` | 88 µs |
| `mprotect` | 150 µs |
| `madvise` | 51 µs |
| a TLB-maintenance exit | 56 µs |
| a page fault | 14 µs |

`test.py` import pays `openat` at 67 µs each (122 per import) and `brk` at
147 µs each (49 per import).

Carrier CPU by bucket (sampled, `ps-cpu-*`):

| bucket | `/bin/true` ×200 | `python -c pass` ×40 | `node -e 0` ×30 |
|---|---|---|---|
| samples per process | 11 | 31 | 84 |
| guest execution | 14% | 41% | 39% |
| `execve` | **23%** | 10% | 8% |
| `fault_service/cow` (the bash child before exec) | **18%** | 14% | 17% |
| `lifecycle/fork-clone` | **12%** | 3% | 2% |
| `lifecycle/teardown` | 5% | 3% | 3% |
| mmap family | 4% | 3% | 6% |
| openat/getdents/stat | 3% | 9% | 2% |
| executor scheduling | 8% | 4% | 6% |
| fault service other (grant/stage-2/settle) | 2% | 1% | 3% |
| lock wait | 1% | 1% | 0% |

Where the process-creation CPU goes
([`captures/ps-cpu-true1.top-stacks.txt`](process-startup/captures/ps-cpu-true1.top-stacks.txt)):

- **`execve`:** `execve_rebuild` builds a fresh
  `build_page_tables_manager_from_live` (reading descriptors with
  `read_gpa`). Then `prepare_global_exec_plan_with_root_backing` and
  `map_aliased_with_flags`/`split_block` rebuild mappings descriptor by
  descriptor; retiring the old image's alias and inventory indexes
  follows.
- **`fork`** (`prepare_in_process_fork` → `build_process_spec`): walks the
  parent's page tables (`host_ptr_for_range`/`read_desc` dominate) to build
  the child's process plan and arm COW.
- **COW** (`resolve_frame_cow_fault` → `perform_frame_cow`): per-fault
  frame-inventory events (`apply_event` BTreeMap inserts), COW
  arm/disarm, alias-registry mutation and descriptor reads.

## Why boot triples at `-j10`

- **Saturation, not a single lock.**
  - Carrier CPU per node start barely changes with concurrency: 84 samples
    at one lane, 93 at ten (`ps-cpu-node1` against `ps-cpu-node10`).
  - Throughput plateaus at about 35/s from three lanes. Each start needs
    roughly 90 ms of carrier CPU, and the guest has 4 vCPUs (`nproc` = 4),
    so 3–4 lanes fill them.
  - Latency then grows with queue length (66 → 203 ms from one to ten
    lanes at load 12).
  - The extra rise to 550 ms at load 22 is host contention from other
    workloads on the machine.
- **Lock contention is present but second-order.**
  - Sampled `lock_wait` rises from 0.2% to 2.5%.
  - The off-CPU capture (`captures/ps-off-node10.offcpu.txt`) shows
    `lock_slow` stacks totalling about 1.3 s over 60 starts, so about
    20 ms per start, led by:
    - `with_hvpatch_exec_cache` in `load_execve_image` (0.38 s);
    - alias-registry retirement, `try_commit_process_alias_retirement` and
      `plan_process_alias_retirement` (0.42 s);
    - `prepare_el1_frame_grant` (0.20 s);
    - `mapping_for_range_in`/`try_init` (0.24 s).
  - Also visible: fork quiesce (`PtQuiesce`, 0.43 s) and
    `execve_rebuild` file-backing attach (0.95 s off-CPU, mostly I/O).
  - Most off-CPU time is idle executors in `park_spare` (44 s), which is
    capacity, not contention.

## Ranked levers (none implemented here)

Shares are of node start's host-side cost; native counterparts are pending
the Docker capture.

1. **Address-space mutations: ~55% (mm syscalls 36% + TLB maintenance
   18%).**
   - 220 forwarded mm syscalls per node start, at 50–150 µs each where
     Linux takes 1–3 µs.
   - On top of those, 158 host-driven TLB-maintenance exits (`hvc #1`, a
     full `hv_vcpu_run` round trip each).
   - Structural candidates:
     - Serve reservation-only `mmap`/`munmap`/`mprotect` of the calling
       mm without a host forward, as the EL1 descriptor lane does for
       grants.
     - Batch the stage-1 edits of one syscall into one invalidation.
     - Have EL1 invalidate its own TLB at the next entry, instead of a
       host-driven maintenance round trip per edit.
   - This is also the largest lever for every dynamically linked binary.
2. **Process creation (fork arm + pre-exec COW + execve rebuild +
   teardown): ~60% of `/bin/true`, ~30% of node start.**
   - Every subprocess pays 8.5–16 ms against about 0.5–1 ms native, and
     the fork part grows with parent size.
   - Candidates:
     - `vfork`/`posix_spawn` semantics for fork-then-exec, skipping COW
       arming of the parent; bash and python both fork-then-exec.
     - Make the `execve` rebuild reuse the page-table arena instead of
       rebuilding from live descriptors.
     - Cut per-fault frame-inventory events on COW.
3. **Page-fault service (~15%):** 550 faults per node start at ~14 µs. Fault
   batching or larger first-touch grants would shrink the count; the EL1
   descriptor lane would shrink the cost.
4. **File namei for python import (~25% of `test.py` import host time):**
   765 file syscalls per import, `openat` at 67 µs each. A carrick-side
   negative and positive dentry cache under `--fs host` would help.
5. **Concurrency:** the alias-registry, exec-cache and frame-inventory locks
   cost about 20 ms per start at ten lanes; the larger effect is plain vCPU
   saturation. The guest CPU count (4 here) caps parallel starts; see the
   node-critical-path note on `-j`.

**Side finding (conformance):** `wait4`'s `rusage` for exited children is
all zero under Carrick (`ru_utime`, `ru_stime`, `ru_minflt` and
`ru_nvcsw` are 0 for node, python and `/bin/true`; `ps-rusage-1`). Linux
reports the child's CPU and faults. Tools that rely on it (`/usr/bin/time`,
build systems, python's `resource.getrusage(RUSAGE_CHILDREN)`) see zeros.
This is worth its own contract.

## Docker side (to be run by the director)

The image has no `strace`, `perf`, `bpftrace` or GNU `time`.
[`rusage.py`](process-startup/rusage.py) reports per-child wall,
user/system CPU, page faults and context switches from `wait4` rusage,
which is native and exact under Docker. Mount this directory at `/ps`.

```sh
D=$PWD/docs/perf-results/2026-10-01-el1-real-workload-ab/process-startup
IMG=localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0

# Per-process native cost (wall, user, sys, faults, context switches):
docker run --rm --platform linux/arm64 -v "$D":/ps --entrypoint /usr/bin/python3 "$IMG" /ps/rusage.py 20
# Latency at 1/4/10 lanes and node -e 0 throughput scaling (same scripts as Carrick):
docker run --rm --platform linux/arm64 -v "$D":/ps --entrypoint /bin/bash "$IMG" /ps/startup.sh 20
docker run --rm --platform linux/arm64 -v "$D":/ps --entrypoint /bin/bash "$IMG" /ps/scale.sh

# Native syscall counts per category (needs network inside the container for apt):
docker run --rm --platform linux/arm64 --cap-add SYS_PTRACE --entrypoint /bin/bash "$IMG" -c \
  'apt-get update -qq && apt-get install -y -qq strace >/dev/null &&
   for c in "/bin/true" "python3 -c pass" "/opt/nodejs-conformance/bin/node24 -e 0" \
            "python3 /opt/node-src/v24/tools/test.py --help"; do
     echo "== $c"; strace -f -c -o /dev/stdout $c >/dev/null 2>&1 | tail -25; done'
```

The Carrick counterparts, in a quiet window with no Docker alive:

```sh
CARRICK_RUN_ID=ps-q-1 CARRICK_EL1_DESCRIPTOR_LANE=0 target/release/carrick run --name ps-q-1 \
  --max-traps 18446744073709551615 --fs host -v "$D":/ps --entrypoint /bin/bash "$IMG" /ps/startup.sh 20
scripts/sudo/kill.sh ps-q-1
# Per-category counts and host time:
CARRICK_RUN_ID=ps-q-2 CARRICK_EL1_DESCRIPTOR_LANE=0 target/release/carrick trace \
  --profile hvpatch-exit-attribution -- run --name ps-q-2 --max-traps 18446744073709551615 --fs host \
  -v "$D":/ps --entrypoint /bin/bash "$IMG" /ps/loop.sh 1 20 /opt/nodejs-conformance/bin/node24 -e 0
scripts/sudo/kill.sh ps-q-2
```

Compare per process: `strace -c` mm-family and file-family call counts
against the exit profile's forwarded counts (they should match). Then the
per-call cost (Linux µs against Carrick's per-call on-CPU), the faults per
start (`rusage` `minflt` against EL0 aborts), and the native
`user+sys` per start against Carrick's guest plus host on-CPU, scaled by the
instrumentation factor.
