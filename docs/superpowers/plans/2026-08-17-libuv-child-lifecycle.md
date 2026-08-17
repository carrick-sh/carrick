# libuv child lifecycle and oracle closure

## Goal

Make the complete 507-test libuv TAP plan execute against a valid native-arm64
Docker oracle. Current Carrick reaches assertion 332, with 29 per-test process
timeouts plus one independent uptime assertion; Docker fails during wrapper
setup before libuv.

## Phase 1: repair the oracle contract

The manifest starts the wrapper as uid 65534, but `run_libuv` must chown its
fixture and then drop to uid/gid 1000. Add a Docker-only red test proving the
current EPERM setup failure, launch this row as root, and verify the wrapper
drops privileges before the first libuv assertion. Refresh only the exact
digest-bound libuv oracle after review.

## Phase 2: process-exit/wait reducer

Use `spawn_exit_code` directly under a modified-memory carrier core:

```sh
target/release/carrick debug lldb-run --deadline-seconds 3 \
  --out-dir target/conformance/libuv-spawn-lldb --run-id libuv-spawn-exit -- \
  --max-traps 18446744073709551615 --raw --fs host \
  --entrypoint /opt/libuv-src/build/uv_run_tests_a \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 spawn_exit_code
```

Compare later, in a separate Docker-only phase, with the same direct binary and
test. Join child HVPPEXIT begin/end to the parent's HVPWAIT target:

- begin without end means terminal publication is incomplete;
- end with an open parent wait means a lost wake/predicate;
- neither means the child is stuck before exit.

Add a minimal fork/exec/_exit plus parent-wait reducer for the proven topology,
then fix that invariant red-first. Do not assume all 29 libuv timeouts share one
cause until they rerun green.

## Phase 3: uptime assertion

Add `uptime_nonzero` to `linuxsysinfo` red-first. Diagnose why Darwin
`KERN_BOOTTIME` falls back to zero before changing `host_uptime_secs`; preserve
Linux boot-time semantics rather than substituting wall clock.

Completion requires the full 507 assertion plan under Carrick and the repaired
Docker oracle, focused tests/clippy/fmt, full `just ci`, strict probes, and a
coordinator-owned closure checkpoint.
