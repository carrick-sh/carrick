# HVF Fork Floor E2.2 Host Fork RSS Decomposition Evidence

Date: 2026-07-08

This follows `docs/2026-07-08-hvf-fork-e21-evidence.md` and tests whether the
remaining HVF fork floor is driven by inherited host address-space/RSS cost in
`libc::fork` or by Carrick runtime pre-engine bookkeeping.

## Verdict

The E2.2 evidence points to **host-fork/RSS reduction** as the next
implementation track.

Increasing the guest footprint by 256 MiB increased the Mach resident sample by
268,517,568 bytes and the guest mmap arena high-water by 268,439,552 bytes while
leaving the Mach VM region count unchanged at 387. Across that footprint
increase:

- `perf_fork` p50 grew from 3419.250 us to 6097.417 us, and p95 grew from
  3812.208 us to 7916.125 us.
- `perf_fork_exec` p50 grew from 9263.250 us to 13220.792 us, and p95 grew from
  9825.541 us to 13988.291 us.
- The focused one-fork DTrace sample recorded host `fork(2)` at 2593 us parent /
  2753 us child for the small probe and 13807 us parent / 13908 us child for the
  256 MiB probe.

Runtime role 0 phase 5 did not scale with the footprint: it was 1272 us for the
small sample and 1285 us for the 256 MiB sample. Its only material subphase was
phase 52, `kernel.fork.prepare_host_fork()`, at 1267-1277 us. That is a real
constant overhead, but it is not the driver of the footprint-dependent fork
floor.

Do not pivot to VM/vCPU create, teardown, admission, or stage-2 replay
optimization on this evidence. The larger footprint did make `freeze_ram_for_fork`
larger in the single DTrace sample (376 us to 2236 us), but host `fork(2)` moved
by far more and is the primary scaling point.

## Instrumentation Added

E2.2 keeps the E2.1 `fork__lifecycle` probe and adds:

- `fork__footprint(phase, vm_region_count, arena_high_water, resident_bytes,
  virtual_bytes)`.
- `carrick_host::host_proc::self_vm_region_count()` on macOS using
  `mach_vm_region`, with inert non-macOS stubs.
- A runtime-published AArch64 arena high-water cache emitted immediately before
  host `libc::fork`.
- Runtime role 0 phase 5 subphases:

| Role | Phase | Meaning |
|---:|---:|---|
| 0 | 50 | arena high-water publication |
| 0 | 51 | pidfd/vfork pipe setup input bucket |
| 0 | 52 | `kernel.fork.prepare_host_fork()` |
| 0 | 53 | paused-lock acquisition |
| 0 | 54 | child parent/subreaper/ns-pid allocation |
| 0 | 55 | `prepare_child_record_pre_fork` |
| 0 | 5 | unchanged total pre-engine bucket |

The perf probes accept `FORK_MEM_MB=<usize>`. `clonebasic` accepts either
`FORK_MEM_MB` or an optional numeric argv value for DTrace direct-launch runs,
because this host's DTrace refused `/usr/bin/env` and `/bin/sh` as `-c` targets
with `Operation not permitted`.

## Performance Measurements

Raw logs are under `target/conformance/logs/hvf-fork-e22/`.

| Probe | Footprint | p50 us | p95 us | min us | Iters | Log |
|---|---:|---:|---:|---:|---:|---|
| `perf_fork` | 0 MiB | 3419.250 | 3812.208 | 3194.833 | 300 | `perf_fork-small-20260707T200036.log` |
| `perf_fork` | 256 MiB | 6097.417 | 7916.125 | 5281.333 | 300 | `perf_fork-large-20260707T200036.log` |
| `perf_fork_exec` | 0 MiB | 9263.250 | 9825.541 | 8510.708 | 200 | `perf_fork_exec-small-20260707T200036.log` |
| `perf_fork_exec` | 256 MiB | 13220.792 | 13988.291 | 12425.666 | 200 | `perf_fork_exec-large-20260707T200036.log` |

## Focused DTrace Samples

| Sample | Parent pre-to-post us | Child pre-to-post us | Host fork parent us | Host fork child us | Log |
|---|---:|---:|---:|---:|---|
| small `clonebasic` | 3535 | 4079 | 2593 | 2753 | `fork-phases-small-20260707T200036.log` |
| `clonebasic -- 256` | 16650 | 17185 | 13807 | 13908 | `fork-phases-large-20260707T200036.log` |

`pre-to-post` is the DTrace interval from `fork-pre` to `fork-post`; host fork is
the AArch64 role 2/3 phase 3 lifecycle value emitted immediately around
`libc::fork`.

### Runtime Phase 0/5 Subphases

| Subphase | Meaning | Small us | 256 MiB us |
|---:|---|---:|---:|
| 50 | arena high-water publication | 0 | 0 |
| 51 | pidfd/vfork pipe setup input bucket | 0 | 0 |
| 52 | `kernel.fork.prepare_host_fork()` | 1267 | 1277 |
| 53 | paused-lock acquisition | 0 | 0 |
| 54 | child parent/subreaper/ns-pid allocation | 0 | 0 |
| 55 | `prepare_child_record_pre_fork` | 0 | 0 |
| 5 | total pre-engine bucket | 1272 | 1285 |

### Host Footprint

| Sample | VM regions | Arena high-water | Resident bytes | Virtual bytes |
|---|---:|---:|---:|---:|
| small `clonebasic` | 387 | 412316876800 | 41435784 | 539352055808 |
| `clonebasic -- 256` | 387 | 412585316352 | 309953352 | 539352039424 |

The region count staying flat while RSS and arena high-water rise means this
measurement is about inherited resident/dirty footprint, not more Mach mappings.

## Verification Commands

- `cargo fmt -p carrick-observability -p carrick-host -p carrick-aarch64 -p carrick-runtime`
  - Result: passed.
- `rustfmt conformance-probes/src/bin/clonebasic.rs conformance-probes/src/bin/perf_fork.rs conformance-probes/src/bin/perf_fork_exec.rs`
  - Result: passed.
- `cargo check -p carrick-observability -p carrick-host -p carrick-aarch64 -p carrick-runtime -p carrick-vmm-hvf`
  - Result: passed.
- `just build`
  - Result: release build passed and re-signed `target/release/carrick`.
- `scripts/build-probes.sh`
  - Result: exited 0 and built the required AArch64 Linux probe binaries.
- `otool -l target/release/carrick | rg -a 'dof|__dof_carrick|segname|sectname'`
  - Result: `sectname __dof_carrick` present.
- `codesign -d --entitlements - target/release/carrick`
  - Result: `com.apple.security.hypervisor` entitlement present and true.
- Carrick-only `perf_fork`, small:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 240 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 3419.250 us, p95 3812.208 us, rc 0.
- Carrick-only `perf_fork`, 256 MiB:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'`
  - Result: p50 6097.417 us, p95 7916.125 us, rc 0.
- Carrick-only `perf_fork_exec`, small:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 9263.250 us, p95 9825.541 us, rc 0.
- Carrick-only `perf_fork_exec`, 256 MiB:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 360 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'`
  - Result: p50 13220.792 us, p95 13988.291 us, rc 0.
- Small DTrace:
  `timeout 240 sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'`
  - Result: rc 0; host fork 2593 us parent / 2753 us child.
- Large DTrace:
  `timeout 240 sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 256'`
  - Result: rc 0; host fork 13807 us parent / 13908 us child.
- `scripts/run-probe.sh clonebasic`
  - Result: `MATCH clonebasic`, rc 0.

No Carrick guest/probe and Docker oracle command were run concurrently.
`scripts/run-probe.sh clonebasic` ran its Carrick and Docker phases
sequentially.

## Next Track

Proceed with a host-fork/RSS reduction plan. The plan should keep the
one-Linux-process-to-one-host-process invariant and avoid any hot-path daemon,
supervisor RPC on fork/block/wake, or guest-kernel fallback.

Concrete next implementation questions:

1. Identify which host mappings/pages are resident or dirty at the fork point
   because Carrick needs them in the child versus because the parent retained
   avoidable footprint.
2. Reduce inherited fork-time footprint without changing Linux process identity:
   candidate directions are arena residency reduction, pre-fork discard/inherit
   policy, mapping layout changes, or a fork child snapshot path that avoids
   copying parent-private host RSS that the child will never observe.
3. Keep `perf_fork`, `perf_fork_exec`, and `fork-phases.d` small/large footprint
   runs as the regression gate.
4. Treat the constant `prepare_host_fork()` cost as secondary follow-up work
   after the RSS-scaling path, unless a narrower trace proves it is hiding a
   cheap win with no architectural tradeoff.
