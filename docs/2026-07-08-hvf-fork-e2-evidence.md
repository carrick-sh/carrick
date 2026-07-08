# HVF Fork Floor E2 Evidence

Date: 2026-07-08

This records the E2 follow-up to the E1 parent-keeps-VM refutation in
`docs/2026-07-08-architecture-evidence-gates.md`.

## Verdict

E2 lazy stage-2 replay is **not the next material fork-floor implementation
track** on the current evidence.

The measured eager stage-2 replay in a one-fork HVF sample is 14 `hv_vm_map`
calls per side, taking 75 us in the parent and 105 us in the child. The full
fork-pre-to-post spans for the same sample are 2845 us parent and 3380 us child,
and the steady-state `perf_fork` probe reports p50 3165.583 us and p95
3559.667 us. Removing every eager map in this sample could not move fork p50
near the sub-1 ms target; the dominant cost is outside the descriptor replay
loop E2 would delete.

Do not land a flag-gated lazy ordinary-region remapper as the next change. It
would add new correctness obligations around `HvfMappedRegion` materialization
state, EL0 translation-fault retry, sibling-union mappings, and the child vvar
RNG stamp, but the measured local replay budget is only about 75-105 us on the
current fork probe.

## Instrumentation Added

The committed diagnostics add `fork__rebuild` as a five-argument USDT probe:

- `role`: `0=parent`, `1=child`
- `phase`: `0=begin`, `1=local-map-end`, `2=sibling-map-end`, `3=restore-end`
- `desc_count`: local descriptor count, or sibling candidate count for phase 2
- `map_count`: completed `hv_vm_map` calls for that phase
- `elapsed_us`: phase elapsed time, except phase 3 which is total `fork_rebuild`
  elapsed

This is intentionally five arguments. A first six-argument version was rejected
by live evidence because macOS DTrace reported the sixth argument as zero in
this provider path. The existing `guest__mem__region` probe documents the same
host-side limit.

## Measurements

| Measurement | Result | Evidence |
|---|---:|---|
| `perf_fork` p50 | 3165.583 us | `target/conformance/logs/hvf-fork-e2/perf_fork-cr-e2-perf-fork-20260707-191645.log` |
| `perf_fork` p95 | 3559.667 us | `target/conformance/logs/hvf-fork-e2/perf_fork-cr-e2-perf-fork-20260707-191645.log` |
| `perf_fork` min | 2849.750 us | `target/conformance/logs/hvf-fork-e2/perf_fork-cr-e2-perf-fork-20260707-191645.log` |
| `perf_fork_exec` p50 | 7992.416 us | `target/conformance/logs/hvf-fork-e2/perf_fork_exec-cr-e2-perf-fork-exec-20260707-191657.log` |
| `perf_fork_exec` p95 | 8496.375 us | `target/conformance/logs/hvf-fork-e2/perf_fork_exec-cr-e2-perf-fork-exec-20260707-191657.log` |
| `perf_fork_exec` min | 7564.500 us | `target/conformance/logs/hvf-fork-e2/perf_fork_exec-cr-e2-perf-fork-exec-20260707-191657.log` |
| parent local descriptors | 14 | `target/conformance/logs/hvf-fork-e2/fork-phases-cr-e2-dtrace-clonebasic-20260707-192115.log` |
| parent local `hv_vm_map` calls | 14 | same DTrace log |
| parent local replay elapsed | 75 us | same DTrace log |
| parent total `fork_rebuild` elapsed | 185 us | same DTrace log |
| parent fork-pre-to-post elapsed | 2845 us | same DTrace log |
| child local descriptors | 14 | same DTrace log |
| child local `hv_vm_map` calls | 14 | same DTrace log |
| child local replay elapsed | 105 us | same DTrace log |
| child total `fork_rebuild` elapsed | 627 us | same DTrace log |
| child fork-pre-to-post elapsed | 3380 us | same DTrace log |
| parent sibling replay candidates/maps | 0 / 0 | same DTrace log |

The DTrace timing sample uses `run-elf clonebasic` to avoid nested shell quoting
inside `dtrace -c`; the p50/p95 rows use the conformance-style `carrick run`
base64 injection path.

## Verification Commands

- `cargo check -p carrick-observability -p carrick-vmm-hvf`
  - Result: passed after the five-argument probe fix.
- `just build`
  - Result: release build passed and re-signed `target/release/carrick`.
- `scripts/build-probes.sh`
  - Result: exited 0 and produced the needed aarch64 musl perf probes. The
    script emitted expected keep-going warnings and arch-specific probe errors
    for non-required probe targets.
- `test -x conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork`
  and `test -x conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec`
  - Result: both probes present.
- `otool -l target/release/carrick | grep dof`
  - Result: `sectname __dof_carrick`.
- `codesign -d --entitlements - target/release/carrick`
  - Result: `com.apple.security.hypervisor` entitlement present.
- Carrick-only `perf_fork` run:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 3165.583 us, p95 3559.667 us, rc 0.
- Carrick-only `perf_fork_exec` run:
  `base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'`
  - Result: p50 7992.416 us, p95 8496.375 us, rc 0.
- DTrace replay-count sample:
  `sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'`
  - Result: rc 0; parent and child each replayed 14 maps; parent/child local
    replay elapsed 75/105 us.
- `scripts/run-probe.sh getrandomvdsofork`
  - Result: `MATCH getrandomvdsofork`, `child_reused=false`.
- `scripts/run-probe.sh vforkvmshare`
  - Result: `MATCH vforkvmshare`, `clone_vm_shared_write_visible=true`.

`scripts/run-probe.sh` runs the Carrick phase and Docker oracle phase
sequentially; no Carrick guest and Docker oracle were run concurrently.

## Next Track

1. Keep the `fork__rebuild` instrumentation and use it on a higher-mapping
   workload before revisiting lazy stage-2 replay. A useful trigger is a trace
   where local map replay is at least 25 percent of `perf_fork` p50 or where
   sibling replay is nonzero and repeated.
2. Do not make E3 map coalescing the immediate fork-floor track unless a fresh
   DTrace sample shows map replay, not fork teardown/host fork/VM creation, is
   dominant. Coalescing the current 14-map sample can only save a small fraction
   of the measured fork p50.
3. Reduce the next architecture step to measured fork lifecycle decomposition:
   add or reuse probes that split `fork_prepare_and_teardown`, `hv_vcpu_destroy`,
   `hv_vm_destroy`, host `fork(2)`, `hv_vm_create`, `hv_vcpu_create`, register
   restore, and child `_exit`/wait. The next implementation decision should
   target the phase that accounts for the missing multi-millisecond span between
   local replay and fork-pre-to-post.
